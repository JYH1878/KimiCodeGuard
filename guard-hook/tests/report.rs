//! M3 任务 3：hook 事件上报（events 管道 fire-and-forget + spool 兜底）、
//! lifecycle 子命令（SessionStart/SessionEnd/SessionHeartbeat）、install 生命周期注入扩展。
//!
//! 契约（GOAL.md 设计定案）：
//! - 事件 JSON：{event, ts, session_id, cwd, tool_name?, decision?, reason?, payload=原始stdin全文}
//! - 上报连不上事件管道（200ms）→ 追加写 spool（目录不存在要重建）；绝不阻塞热路径、绝不 panic
//! - lifecycle 连不上管道时 best-effort spawn daemon（detached 不等待），事件走 spool
//! - install 追加注入两条生命周期 [[hooks]]（SessionStart/SessionEnd，无 matcher，timeout 5），
//!   幂等，不破坏 PreToolUse 块；SessionHeartbeat 是 v2 独有，注入会让 v1 静默忽略整段，永不注入

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

mod common;
use common::TempDir;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn guard_hook() -> Command {
    Command::new(env!("CARGO_BIN_EXE_guard-hook"))
}

fn run_with_stdin(cmd: &mut Command, stdin_data: &[u8]) -> std::process::Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin_data).unwrap();
    child.wait_with_output().unwrap()
}

/// 指向不存在的事件管道名（连接立即失败，走 spool）
fn dead_pipe(tag: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(
        r"\\.\pipe\KCG.test.events.dead-{}-{tag}-{n}",
        std::process::id()
    )
}

/// 让 hook 走「无 daemon」路径：KCG_EVENTS_PIPE 指向死管道，KCG_EVENTS_SPOOL 指向临时文件
fn hook_offline(tag: &str) -> (Command, TempDir, PathBuf) {
    let dir = TempDir::new("kcg-test-report", tag);
    let spool = dir.0.join("spool").join("events.jsonl"); // 目录故意不建：上报端必须自建
    let mut cmd = guard_hook();
    cmd.env("KCG_EVENTS_PIPE", dead_pipe(tag))
        .env("KCG_EVENTS_SPOOL", &spool);
    (cmd, dir, spool)
}

fn spool_lines(spool: &Path) -> Vec<serde_json::Value> {
    let text =
        fs::read_to_string(spool).unwrap_or_else(|e| panic!("读 spool {}: {e}", spool.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("spool 行非法 JSON: {l} ({e})")))
        .collect()
}

fn pretool_payload(command: &str, session: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "cwd": "D:/work",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_call_id": "call-1",
    })
    .to_string()
}

// ---------- 上报：无 daemon → spool 落盘且 exit 码不变 ----------

#[test]
fn allow_reports_to_spool_and_exit_zero() {
    let (mut cmd, _dir, spool) = hook_offline("allow");
    let payload = pretool_payload("pwd", "s-allow");
    let out = run_with_stdin(cmd.arg("hook"), payload.as_bytes());
    assert!(out.status.success(), "allow 必须 exit 0");
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");

    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1, "spool 必须恰好一条事件");
    let ev = &lines[0];
    assert_eq!(ev["event"], "PreToolUse");
    assert_eq!(ev["decision"], "allow");
    assert_eq!(ev["session_id"], "s-allow");
    assert_eq!(ev["cwd"], "D:/work");
    assert_eq!(ev["tool_name"], "Bash");
    assert_eq!(ev["payload"], payload, "payload 必须是原始 stdin 全文");
    assert!(ev["ts"].as_i64().unwrap() > 0, "ts 必须是 Unix 毫秒");
}

#[test]
fn deny_reports_deny_and_exit_2() {
    let (mut cmd, _dir, spool) = hook_offline("deny");
    let payload = pretool_payload("rm -rf /tmp/x", "s-deny");
    let out = run_with_stdin(cmd.arg("hook"), payload.as_bytes());
    assert_eq!(out.status.code(), Some(2), "deny 必须 exit 2");

    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1);
    let ev = &lines[0];
    assert_eq!(ev["event"], "PreToolUse");
    assert_eq!(ev["decision"], "deny");
    assert_eq!(ev["session_id"], "s-deny");
    let reason = ev["reason"].as_str().expect("deny 必须带 reason");
    assert!(
        reason.contains("rm-force"),
        "reason 含规则名，got: {reason}"
    );
}

#[test]
fn ask_unavailable_reports_ask_deny_and_exit_2() {
    let (mut cmd, _dir, spool) = hook_offline("askdeny");
    // ask 管道也指向死管道（覆盖真实 daemon 可能在跑的环境），超时缩短保测试快
    cmd.env("KCG_ASK_PIPE", dead_pipe("ask"))
        .env("KCG_ASK_TIMEOUT_MS", "600");
    let payload = pretool_payload("git push --force origin main", "s-ask");
    let out = run_with_stdin(cmd.arg("hook"), payload.as_bytes());
    assert_eq!(
        out.status.code(),
        Some(2),
        "ask 连不上必须 fail-safe exit 2"
    );

    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1);
    let ev = &lines[0];
    assert_eq!(ev["event"], "PreToolUse");
    assert_eq!(ev["decision"], "ask_deny");
    assert_eq!(ev["session_id"], "s-ask");
}

// ---------- lifecycle 子命令 ----------

#[test]
fn lifecycle_session_start_spool_when_daemon_down() {
    let (mut cmd, _dir, spool) = hook_offline("lcstart");
    let stdin = r#"{"session_id":"s-lc","cwd":"D:/work","source":"startup"}"#;
    let out = run_with_stdin(
        cmd.args(["lifecycle", "--event", "SessionStart"]),
        stdin.as_bytes(),
    );
    assert!(
        out.status.success(),
        "lifecycle 必须 exit 0（绝不阻塞会话）"
    );

    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1);
    let ev = &lines[0];
    assert_eq!(ev["event"], "SessionStart");
    assert_eq!(ev["session_id"], "s-lc");
    assert_eq!(ev["cwd"], "D:/work");
    assert_eq!(ev["payload"], stdin, "payload 必须是原始 stdin 全文");
    assert!(ev.get("decision").is_none() || ev["decision"].is_null());
}

#[test]
fn lifecycle_bad_daemon_path_still_exit_zero() {
    let (mut cmd, _dir, spool) = hook_offline("lcspawn");
    let out = run_with_stdin(
        cmd.args([
            "lifecycle",
            "--event",
            "SessionEnd",
            "--daemon-path",
            "C:/nonexistent-dir/kcg-daemon.exe",
        ]),
        br#"{"session_id":"s-x","cwd":"D:/work","reason":"exit"}"#,
    );
    assert!(out.status.success(), "spawn 失败必须静默，exit 0");
    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "SessionEnd");
}

#[test]
fn lifecycle_empty_stdin_no_panic() {
    let (mut cmd, _dir, spool) = hook_offline("lcempty");
    let out = run_with_stdin(cmd.args(["lifecycle", "--event", "SessionHeartbeat"]), b"");
    assert!(out.status.success(), "空 stdin 也必须 exit 0 不崩");
    let lines = spool_lines(&spool);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "SessionHeartbeat");
}

/// 假 events daemon 在时：事件必须送达管道、不写 spool
#[cfg(windows)]
#[test]
fn lifecycle_reports_to_pipe_when_daemon_up() {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pipe = format!(r"\\.\pipe\KCG.test.events.live-{}-{n}", std::process::id());
    let server = fake_events_daemon::serve_once(&pipe);
    std::thread::sleep(std::time::Duration::from_millis(100)); // 等管道实例建好（客户端也有重试兜底）

    let dir = TempDir::new("kcg-test-report", "lclive");
    let spool = dir.0.join("spool").join("events.jsonl");
    let mut cmd = guard_hook();
    cmd.env("KCG_EVENTS_PIPE", &pipe)
        .env("KCG_EVENTS_SPOOL", &spool)
        .args(["lifecycle", "--event", "SessionStart"]);
    let out = run_with_stdin(&mut cmd, br#"{"session_id":"s-pipe","cwd":"D:/work"}"#);
    assert!(out.status.success());

    let received = server.join().expect("假 daemon 线程 panic");
    let ev: serde_json::Value = serde_json::from_str(received.trim()).expect("管道收到合法 JSON");
    assert_eq!(ev["event"], "SessionStart");
    assert_eq!(ev["session_id"], "s-pipe");
    assert!(!spool.exists(), "管道通时不许写 spool");
}

/// 只建一次实例、读一行就返回的假 events daemon（fire-and-forget 服务端最小复刻）
#[cfg(windows)]
mod fake_events_daemon {
    use std::thread::{self, JoinHandle};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FlushFileBuffers, ReadFile, PIPE_ACCESS_INBOUND,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    pub fn serve_once(pipe_name: &str) -> JoinHandle<String> {
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        thread::spawn(move || unsafe {
            let h = CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                8192,
                8192,
                0,
                std::ptr::null(),
            );
            assert!(h != INVALID_HANDLE_VALUE && !h.is_null(), "建假管道失败");
            assert_ne!(ConnectNamedPipe(h, std::ptr::null_mut()), -1);
            let mut buf = [0u8; 8192];
            let mut read = 0u32;
            let mut data = Vec::new();
            loop {
                let ok = ReadFile(
                    h,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                );
                if ok == 0 || read == 0 {
                    break; // 客户端断开
                }
                data.extend_from_slice(&buf[..read as usize]);
                if data.contains(&b'\n') {
                    break;
                }
            }
            let _ = FlushFileBuffers(h);
            let _ = DisconnectNamedPipe(h);
            let _ = CloseHandle(h);
            String::from_utf8(data).expect("utf8")
        })
    }
}

// ---------- install 生命周期注入扩展 ----------

fn install_cmd(config: &Path) -> Command {
    let mut cmd = guard_hook();
    cmd.args(["install", "--config"]).arg(config);
    cmd
}

fn parse_hooks(config: &Path) -> Vec<toml::Value> {
    let content = fs::read_to_string(config).unwrap();
    let parsed: toml::Value = toml::from_str(&content).unwrap();
    parsed
        .get("hooks")
        .and_then(|h| h.as_array())
        .expect("hooks must be an array")
        .clone()
}

#[test]
fn install_with_daemon_path_injects_lifecycle_hooks() {
    let dir = TempDir::new("kcg-test-report", "injd");
    let config = dir.0.join("config.toml");
    fs::write(&config, "model = \"kimi\"\n").unwrap();

    let ok = install_cmd(&config)
        .args(["--daemon-path", "C:/x dir/guard-daemon.exe"])
        .status()
        .unwrap();
    assert!(ok.success());

    let hooks = parse_hooks(&config);
    assert_eq!(hooks.len(), 3, "PreToolUse + 两条生命周期");

    let pre = hooks[0].as_table().unwrap();
    assert_eq!(pre["event"].as_str().unwrap(), "PreToolUse");
    assert_eq!(
        pre["timeout"].as_integer().unwrap(),
        75,
        "既有 timeout=75 不许动"
    );
    assert!(pre["command"].as_str().unwrap().ends_with("\" hook"));

    let mut events: Vec<&str> = Vec::new();
    for h in &hooks[1..] {
        let t = h.as_table().unwrap();
        let mut keys: Vec<&str> = t.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["command", "event", "timeout"], "字段严格限定");
        assert_eq!(t["timeout"].as_integer().unwrap(), 5, "生命周期 timeout=5");
        let cmd = t["command"].as_str().unwrap();
        assert!(cmd.contains("lifecycle --event "), "got: {cmd}");
        assert!(cmd.contains("--daemon-path"), "got: {cmd}");
        assert!(cmd.contains("C:/x dir/guard-daemon.exe"), "got: {cmd}");
        events.push(t["event"].as_str().unwrap());
    }
    events.sort_unstable();
    assert_eq!(events, ["SessionEnd", "SessionStart"]);
}

#[test]
fn install_without_daemon_path_still_injects_lifecycle_report_only() {
    let dir = TempDir::new("kcg-test-report", "injnd");
    let config = dir.0.join("config.toml");
    fs::write(&config, "model = \"kimi\"\n").unwrap();

    let ok = install_cmd(&config).status().unwrap();
    assert!(ok.success());
    let hooks = parse_hooks(&config);
    assert_eq!(hooks.len(), 3);
    for h in &hooks[1..] {
        let cmd = h["command"].as_str().unwrap();
        assert!(cmd.contains("lifecycle --event "), "got: {cmd}");
        assert!(
            !cmd.contains("--daemon-path"),
            "无 daemon-path 时不带该参数，got: {cmd}"
        );
    }
}

#[test]
fn install_lifecycle_idempotent() {
    let dir = TempDir::new("kcg-test-report", "injidem");
    let config = dir.0.join("config.toml");
    fs::write(&config, "model = \"kimi\"\n").unwrap();

    let run = || {
        install_cmd(&config)
            .args(["--daemon-path", "C:/x/guard-daemon.exe"])
            .status()
            .unwrap()
    };
    assert!(run().success());
    let first = fs::read_to_string(&config).unwrap();
    assert!(run().success());
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        first,
        "重复 install 内容不变"
    );
    assert_eq!(first.matches("# BEGIN KimiCodeGuard").count(), 1);
}

#[test]
fn reinstall_over_m2_block_keeps_pretooluse_entry() {
    let dir = TempDir::new("kcg-test-report", "injm2");
    let config = dir.0.join("config.toml");
    // M2 时代的注入块：只有 PreToolUse
    let m2 = "model = \"kimi\"\n\n# BEGIN KimiCodeGuard\n[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"\\\"C:/old/guard-hook.exe\\\" hook\"\ntimeout = 75\n# END KimiCodeGuard\n";
    fs::write(&config, m2).unwrap();

    let ok = install_cmd(&config)
        .args(["--daemon-path", "C:/x/guard-daemon.exe"])
        .status()
        .unwrap();
    assert!(ok.success());

    let content = fs::read_to_string(&config).unwrap();
    assert_eq!(
        content.matches("# BEGIN KimiCodeGuard").count(),
        1,
        "块只出现一次"
    );
    assert!(content.starts_with("model = \"kimi\"\n"), "块外内容不丢");

    let hooks = parse_hooks(&config);
    assert_eq!(hooks.len(), 3);
    let pre = &hooks[0];
    assert_eq!(pre["event"].as_str().unwrap(), "PreToolUse");
    assert_eq!(pre["timeout"].as_integer().unwrap(), 75);
    assert!(pre["command"].as_str().unwrap().ends_with("\" hook"));
}

#[test]
fn uninstall_after_lifecycle_inject_restores_byte_for_byte() {
    let dir = TempDir::new("kcg-test-report", "injun");
    let config = dir.0.join("config.toml");
    let original = "model = \"kimi\"\n";
    fs::write(&config, original).unwrap();

    let ok = install_cmd(&config)
        .args(["--daemon-path", "C:/x/guard-daemon.exe"])
        .status()
        .unwrap();
    assert!(ok.success());
    let ok = guard_hook()
        .args(["uninstall", "--config"])
        .arg(&config)
        .status()
        .unwrap();
    assert!(ok.success());
    assert_eq!(
        fs::read(&config).unwrap(),
        original.as_bytes(),
        "逐字节还原"
    );
}
