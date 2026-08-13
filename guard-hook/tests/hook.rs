//! hook 子命令测试：fail-safe，任何异常都必须 exit 0 且 stdout 为 {}。

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("kcg-test-{}-{}-{}", tag, std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_hook(stdin_data: &[u8], dump_dir: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guard-hook"))
        .args(["hook", "--dump-dir", dump_dir])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin_data).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn garbage_json_still_exits_zero() {
    let dir = temp_dir("garbage");
    let out = run_hook(b"not json", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
}

#[test]
fn empty_stdin_still_exits_zero() {
    let dir = temp_dir("empty");
    let out = run_hook(b"", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}

#[test]
fn missing_dump_dir_still_exits_zero() {
    let dir = temp_dir("missing").join("does-not-exist");
    let out = run_hook(b"{\"a\":1}", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}

#[test]
fn valid_payload_is_dumped_verbatim() {
    let dir = temp_dir("verbatim");
    let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
    let out = run_hook(payload, dir.to_str().unwrap());
    assert!(out.status.success());
    let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let dumped = fs::read(entries[0].as_ref().unwrap().path()).unwrap();
    assert_eq!(dumped, payload);
}

#[test]
fn huge_payload_no_panic() {
    let dir = temp_dir("huge");
    let payload = vec![b'x'; 4 * 1024 * 1024];
    let out = run_hook(&payload, dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}
