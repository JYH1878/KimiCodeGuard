//! install / uninstall 集成测试：原子写、幂等、逐字节还原、注入块合法性。

use std::fs;
use std::process::Command;

mod common;
use common::TempDir;

fn guard_hook() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guard-hook"))
}

#[test]
fn torn_write_leaves_original_untouched() {
    let dir = TempDir::new("kcg-test", "torn");
    let config = dir.join("config.toml");
    let original = "model = \"kimi\"\n";
    fs::write(&config, original).unwrap();
    // 制造 tmp 路径冲突：tmp 名已被一个目录占用，File::create 必失败
    fs::create_dir_all(format!("{}.kcg-tmp", config.display())).unwrap();

    let status = guard_hook()
        .args(["install", "--config"])
        .arg(&config)
        .args(["--dump-dir", "D:/d"])
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
}

#[test]
fn install_is_idempotent_and_backup_kept() {
    let dir = TempDir::new("kcg-test", "idem");
    let config = dir.join("config.toml");
    let original = "model = \"kimi\"\n";
    fs::write(&config, original).unwrap();

    let run = || {
        guard_hook()
            .args(["install", "--config"])
            .arg(&config)
            .args(["--dump-dir", "D:/d"])
            .status()
            .unwrap()
    };
    assert!(run().success());
    let first = fs::read_to_string(&config).unwrap();
    // 篡改备份再跑第二次：备份不应被覆盖
    let bak = format!("{}.kcg-bak", config.display());
    assert_eq!(fs::read_to_string(&bak).unwrap(), original);
    assert!(run().success());
    assert_eq!(fs::read_to_string(&config).unwrap(), first);
    assert_eq!(fs::read_to_string(&bak).unwrap(), original);
    // 块只出现一次
    assert_eq!(first.matches("# BEGIN KimiCodeGuard").count(), 1);
}

#[test]
fn uninstall_restores_byte_for_byte() {
    for (tag, original) in [
        ("plain", "model = \"kimi\"\n"),
        ("noeol", "model = \"kimi\""),
        ("empty", ""),
        ("crlf", "model = \"kimi\"\r\n\r\n[permission]\r\n"),
    ] {
        let dir = TempDir::new("kcg-test", tag);
        let config = dir.join("config.toml");
        fs::write(&config, original).unwrap();
        let dump = dir.join("dump");
        fs::create_dir_all(&dump).unwrap();

        let ok = guard_hook()
            .args(["install", "--config"])
            .arg(&config)
            .arg("--dump-dir")
            .arg(&dump)
            .status()
            .unwrap();
        assert!(ok.success(), "install failed for {tag}");

        let ok = guard_hook()
            .args(["uninstall", "--config"])
            .arg(&config)
            .status()
            .unwrap();
        assert!(ok.success(), "uninstall failed for {tag}");
        assert_eq!(
            fs::read(&config).unwrap(),
            original.as_bytes(),
            "not byte-identical for {tag}"
        );
    }
}

#[test]
fn install_over_orphan_block_dedupes() {
    let dir = TempDir::new("kcg-test", "orphan");
    let config = dir.join("config.toml");
    // 裸块：marker 被 Kimi 重写剥掉后的注入段（2026-08-15 真机实测形态）
    let original = "model = \"kimi\"\n\n[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"\\\"D:\\\\old\\\\guard-hook.exe\\\" hook\"\ntimeout = 75\n";
    fs::write(&config, original).unwrap();

    let ok = guard_hook()
        .args(["install", "--config"])
        .arg(&config)
        .status()
        .unwrap();
    assert!(ok.success());
    let content = fs::read_to_string(&config).unwrap();
    // 裸块被去重：PreToolUse 只剩一份（指向新 exe），marker 块注入
    assert_eq!(content.matches("event = \"PreToolUse\"").count(), 1);
    assert_eq!(content.matches("# BEGIN KimiCodeGuard").count(), 1);
    assert!(!content.contains("D:\\\\old\\\\guard-hook.exe"));
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    assert_eq!(parsed["hooks"].as_array().unwrap().len(), 3);

    // uninstall 移除 marker 块后剩原首行（裸块已在 install 时去重）
    let ok = guard_hook()
        .args(["uninstall", "--config"])
        .arg(&config)
        .status()
        .unwrap();
    assert!(ok.success());
    assert_eq!(fs::read_to_string(&config).unwrap(), "model = \"kimi\"\n");
}

#[test]
fn install_without_dump_dir_injects_plain_hook_command() {
    let dir = TempDir::new("kcg-test", "nodump");
    let config = dir.join("config.toml");
    let original = "model = \"kimi\"\n";
    fs::write(&config, original).unwrap();

    // 不给 --dump-dir：注入块 command 必须就是 "<exe>" hook，不带落盘参数
    let ok = guard_hook()
        .args(["install", "--config"])
        .arg(&config)
        .status()
        .unwrap();
    assert!(ok.success());

    let content = fs::read_to_string(&config).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let hooks = parsed
        .get("hooks")
        .and_then(|h| h.as_array())
        .expect("hooks must be an array");
    // M3 起：PreToolUse + 两条生命周期（SessionStart/SessionEnd，timeout=5；
    // SessionHeartbeat 是 v2 独有，注入会让 v1 静默忽略整个 hooks 段，永不注入）
    assert_eq!(hooks.len(), 3);
    let hook = hooks[0].as_table().unwrap();
    // 字段严格限定：event/command/timeout，多一个都不行
    let mut keys: Vec<&str> = hook.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["command", "event", "timeout"]);
    assert_eq!(hook["event"].as_str().unwrap(), "PreToolUse");
    assert_eq!(hook["timeout"].as_integer().unwrap(), 75);
    let command = hook["command"].as_str().unwrap();
    assert!(command.starts_with('"'), "got: {command}");
    assert!(command.contains("guard-hook"), "got: {command}");
    assert!(command.ends_with("\" hook"), "got: {command}");
    assert!(!command.contains("dump-dir"), "got: {command}");
    let exe_part = command.trim_start_matches('"').split('"').next().unwrap();
    assert!(std::path::Path::new(exe_part).is_absolute(), "{exe_part}");
    // 生命周期三条：不带 --daemon-path 时仅上报
    let mut events: Vec<&str> = hooks[1..]
        .iter()
        .map(|h| h["event"].as_str().unwrap())
        .collect();
    events.sort_unstable();
    assert_eq!(events, ["SessionEnd", "SessionStart"]);
    for h in &hooks[1..] {
        assert_eq!(h["timeout"].as_integer().unwrap(), 5);
        assert!(h["command"]
            .as_str()
            .unwrap()
            .contains("lifecycle --event "));
        assert!(!h["command"].as_str().unwrap().contains("--daemon-path"));
    }

    // uninstall 字节级还原不回归
    let ok = guard_hook()
        .args(["uninstall", "--config"])
        .arg(&config)
        .status()
        .unwrap();
    assert!(ok.success());
    assert_eq!(fs::read(&config).unwrap(), original.as_bytes());
}

#[test]
fn injected_block_is_strictly_valid() {
    let dir = TempDir::new("kcg-test", "valid");
    let config = dir.join("config.toml");
    fs::write(&config, "model = \"kimi\"\n").unwrap();

    let ok = guard_hook()
        .args(["install", "--config"])
        .arg(&config)
        .args(["--dump-dir", "D:/dump dir"])
        .status()
        .unwrap();
    assert!(ok.success());

    let content = fs::read_to_string(&config).unwrap();
    // 整块 config 必须能被 TOML 解析（标记行是合法注释）
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    let hooks = parsed
        .get("hooks")
        .and_then(|h| h.as_array())
        .expect("hooks must be an array");
    // M3 起：PreToolUse + 两条生命周期（SessionStart/SessionEnd）
    assert_eq!(hooks.len(), 3);
    let hook = hooks[0].as_table().unwrap();
    // 字段严格限定：event/command/timeout，多一个都不行
    let mut keys: Vec<&str> = hook.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["command", "event", "timeout"]);
    assert_eq!(hook["event"].as_str().unwrap(), "PreToolUse");
    // ask 弹窗要等 60s，官方默认 30s 超时不够（HANDOFF 五.4），注入 75
    assert_eq!(hook["timeout"].as_integer().unwrap(), 75);
    let command = hook["command"].as_str().unwrap();
    // 命令 = 加引号的 exe 绝对路径 + hook --dump-dir + 加引号的目录
    assert!(command.starts_with('"'));
    assert!(command.contains("guard-hook"));
    assert!(command.contains("\" hook --dump-dir \""));
    assert!(command.ends_with("D:/dump dir\""));
    // exe 路径必须是绝对路径
    let exe_part = command.trim_start_matches('"').split('"').next().unwrap();
    assert!(std::path::Path::new(exe_part).is_absolute(), "{exe_part}");
    // 生命周期三条（含 dump-dir 时 PreToolUse 照旧，不受生命周期注入影响）
    let mut events: Vec<&str> = hooks[1..]
        .iter()
        .map(|h| h["event"].as_str().unwrap())
        .collect();
    events.sort_unstable();
    assert_eq!(events, ["SessionEnd", "SessionStart"]);
}
