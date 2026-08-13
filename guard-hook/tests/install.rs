//! install / uninstall 集成测试：原子写、幂等、逐字节还原、注入块合法性。

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("kcg-test-{}-{}-{}", tag, std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn guard_hook() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guard-hook"))
}

#[test]
fn torn_write_leaves_original_untouched() {
    let dir = temp_dir("torn");
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
    let dir = temp_dir("idem");
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
        let dir = temp_dir(tag);
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
fn injected_block_is_strictly_valid() {
    let dir = temp_dir("valid");
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
    assert_eq!(hooks.len(), 1);
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
}
