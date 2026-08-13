//! ask 命名管道客户端（M1）。M2 的 guard-daemon 按本契约实现服务端。
//!
//! 契约（与 daemon 的约定，定死于 M1 任务书）：
//! - 管道名默认 `\\.\pipe\KimiCodeGuard.ask.<用户名>`（USERNAME 环境变量，缺省 "default"）。
//! - 请求：一条 JSON + `\n`，字段 rule / tool / command / session_id。
//! - 回复：一条 JSON + `\n`，`{"decision":"allow"}` 或 `{"decision":"deny","reason":"..."}`。
//! - 超时默认 60000ms（D2 fail-safe：超时/连不上/回复非法一律由调用方转 exit 2）。
//! - `KCG_ASK_PIPE` / `KCG_ASK_TIMEOUT_MS` 两环境变量仅供测试覆盖。
//!
//! 实现说明：用 std 文件 API 打开管道路径（Windows 命名管道即特殊文件），
//! 超时用「工作者线程 + mpsc recv_timeout」实现，零 unsafe、零新增依赖。
//! 超时后工作者线程可能仍阻塞在管道读上，但 hook 进程随即退出，由 OS 回收。

use serde_json::json;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// ask 交互结果。Unavailable 涵盖：连不上 / 超时 / 回复非法（调用方统一转 exit 2）。
pub enum AskOutcome {
    Allow,
    Deny(String),
    Unavailable(String),
}

/// 向 daemon 发起一次 ask。本函数总返回，永 panic。
pub fn ask(rule: &str, tool: &str, command: &str, session_id: Option<&str>) -> AskOutcome {
    let pipe_name = std::env::var("KCG_ASK_PIPE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_pipe_name);
    let timeout_ms = std::env::var("KCG_ASK_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    let request = json!({
        "rule": rule,
        "tool": tool,
        "command": command,
        "session_id": session_id.unwrap_or(""),
    })
    .to_string();

    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("kcg-ask".to_string())
        .spawn(move || {
            let _ = tx.send(ask_inner(&pipe_name, &request));
        });
    if spawned.is_err() {
        return AskOutcome::Unavailable("无法创建 ask 工作者线程".to_string());
    }
    match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
        Ok(outcome) => outcome,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            AskOutcome::Unavailable(format!("等待确认超过 {timeout_ms}ms"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            AskOutcome::Unavailable("ask 工作者线程异常退出".to_string())
        }
    }
}

fn default_pipe_name() -> String {
    let user = std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    format!(r"\\.\pipe\KimiCodeGuard.ask.{user}")
}

fn ask_inner(pipe_name: &str, request: &str) -> AskOutcome {
    // daemon 可能正在启动或忙于上一单：约 2s 内重试连接，仍失败按「连不上」处理
    let mut last_err = String::new();
    for attempt in 0..5 {
        match OpenOptions::new().read(true).write(true).open(pipe_name) {
            Ok(mut f) => {
                let sent = f
                    .write_all(request.as_bytes())
                    .and_then(|()| f.write_all(b"\n"))
                    .and_then(|()| f.flush());
                if let Err(e) = sent {
                    return AskOutcome::Unavailable(format!("写入 ask 管道失败：{e}"));
                }
                let mut line = String::new();
                return match BufReader::new(f).read_line(&mut line) {
                    Ok(0) => AskOutcome::Unavailable("守护进程未回复即断开".to_string()),
                    Ok(_) => parse_reply(&line),
                    Err(e) => AskOutcome::Unavailable(format!("读取 ask 回复失败：{e}")),
                };
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt < 4 {
                    thread::sleep(Duration::from_millis(400));
                }
            }
        }
    }
    AskOutcome::Unavailable(format!("无法连接 ask 管道 {pipe_name}：{last_err}"))
}

fn parse_reply(line: &str) -> AskOutcome {
    let trimmed = line.trim();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        let preview: String = trimmed.chars().take(80).collect();
        return AskOutcome::Unavailable(format!("ask 回复不是合法 JSON：{preview}"));
    };
    match v.get("decision").and_then(|d| d.as_str()) {
        Some("allow") => AskOutcome::Allow,
        Some("deny") => {
            let reason = v
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("用户拒绝")
                .to_string();
            AskOutcome::Deny(reason)
        }
        _ => AskOutcome::Unavailable("ask 回复缺 decision 字段或取值非法".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reply_allow_and_deny() {
        assert!(matches!(
            parse_reply(r#"{"decision":"allow"}"#),
            AskOutcome::Allow
        ));
        match parse_reply(r#"{"decision":"deny","reason":"太危险"}"#) {
            AskOutcome::Deny(r) => assert_eq!(r, "太危险"),
            _ => panic!("应为 Deny"),
        }
        // deny 无 reason 用默认文案
        assert!(matches!(
            parse_reply(r#"{"decision":"deny"}"#),
            AskOutcome::Deny(_)
        ));
    }

    #[test]
    fn parse_reply_garbage_is_unavailable() {
        for bad in [
            "not json",
            r#"{"decision":"maybe"}"#,
            r#"{"foo":1}"#,
            "[1,2]",
            "",
        ] {
            assert!(
                matches!(parse_reply(bad), AskOutcome::Unavailable(_)),
                "应不可用: {bad}"
            );
        }
    }

    #[test]
    fn unreachable_pipe_is_unavailable_fast() {
        // 随机不存在的管道名：约 2s 重试后必须 Unavailable（fail-safe，不挂死）
        let name = format!(r"\\.\pipe\KCG.test.no-daemon-{}", std::process::id());
        let start = std::time::Instant::now();
        let outcome = ask_inner(&name, "{}");
        assert!(matches!(outcome, AskOutcome::Unavailable(_)));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "连不上不应挂死: {:?}",
            start.elapsed()
        );
    }
}
