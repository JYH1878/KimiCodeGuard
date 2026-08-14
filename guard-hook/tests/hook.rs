//! hook 子命令测试：fail-safe，任何异常都必须 exit 0 且 stdout 为 {}。

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;
use common::TempDir;

fn run_hook(stdin_data: &[u8], dump_dir: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_guard-hook"))
        .args(["hook", "--dump-dir", dump_dir])
        // 上报走死管道 + 本测试目录 spool：不碰真机事件管道/审计库（M3）
        .env(
            "KCG_EVENTS_PIPE",
            format!(r"\\.\pipe\KCG.test.events.dead-hook-{}", std::process::id()),
        )
        .env("KCG_EVENTS_SPOOL", Path::new(dump_dir).join("spool.jsonl"))
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
    let dir = TempDir::new("kcg-test", "garbage");
    let out = run_hook(b"not json", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
}

#[test]
fn empty_stdin_still_exits_zero() {
    let dir = TempDir::new("kcg-test", "empty");
    let out = run_hook(b"", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}

#[test]
fn missing_dump_dir_still_exits_zero() {
    let guard = TempDir::new("kcg-test", "missing"); // 守卫活到测试结束（hook 的 spool 会在其下重建目录）
    let dir = guard.join("does-not-exist");
    let out = run_hook(b"{\"a\":1}", dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}

#[test]
fn valid_payload_is_dumped_verbatim() {
    let dir = TempDir::new("kcg-test", "verbatim");
    let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
    let out = run_hook(payload, dir.to_str().unwrap());
    assert!(out.status.success());
    // 只数 dump 的 payload（.json）；M3 起上报兜底 spool（spool.jsonl）也落在同目录
    let entries: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    assert_eq!(entries.len(), 1);
    let dumped = fs::read(entries[0].path()).unwrap();
    assert_eq!(dumped, payload);
}

#[test]
fn huge_payload_no_panic() {
    let dir = TempDir::new("kcg-test", "huge");
    let payload = vec![b'x'; 4 * 1024 * 1024];
    let out = run_hook(&payload, dir.to_str().unwrap());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "{}");
}
