//! ask 管道服务端集成测试：起真实命名管道，模拟 hook 客户端按契约发 JSON 行，断言回复。
//! 覆盖：allow / deny / 非法 JSON / 缺字段 / 55s 超时自动 deny（缩短注入）/ 串行排队。
#![cfg(windows)]

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use guard_daemon::ask_pipe::{self, AskReply, AskRequest, PipeEvent, Server};

fn test_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\KCG.test.ask.{}-{}", std::process::id(), tag)
}

/// 模拟 hook 客户端：连接（约 2s 重试，同 hook 侧范式）→ 发一行 → 读一行回复
fn client_roundtrip(pipe: &str, request: &str) -> String {
    let mut last_err = String::new();
    for attempt in 0..5 {
        match OpenOptions::new().read(true).write(true).open(pipe) {
            Ok(mut f) => {
                f.write_all(request.as_bytes()).unwrap();
                f.write_all(b"\n").unwrap();
                f.flush().unwrap();
                let mut line = String::new();
                BufReader::new(f).read_line(&mut line).unwrap();
                return line;
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt < 4 {
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    panic!("连不上测试管道 {pipe}: {last_err}");
}

fn spawn_client(pipe: &str, request: &str) -> JoinHandle<String> {
    let pipe = pipe.to_string();
    let request = request.to_string();
    thread::spawn(move || client_roundtrip(&pipe, &request))
}

/// 等一单 Ask 事件，返回请求与回复通道
fn expect_ask(server: &Server) -> (AskRequest, Sender<AskReply>) {
    match server.events().recv_timeout(Duration::from_secs(5)) {
        Ok(PipeEvent::Ask { request, reply_tx }) => (request, reply_tx),
        Ok(PipeEvent::Idle) => panic!("期望 Ask 事件却收到 Idle"),
        Err(e) => panic!("等 Ask 事件超时/通道断开: {e}"),
    }
}

fn expect_idle(server: &Server) {
    match server.events().recv_timeout(Duration::from_secs(5)) {
        Ok(PipeEvent::Idle) => {}
        Ok(PipeEvent::Ask { .. }) => panic!("期望 Idle 事件却收到 Ask"),
        Err(e) => panic!("等 Idle 事件超时/通道断开: {e}"),
    }
}

fn reply_json(line: &str) -> serde_json::Value {
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("回复不是合法 JSON: {line} ({e})"))
}

const VALID_REQ: &str =
    r#"{"rule":"git-force-push","tool":"Bash","command":"git push --force","session_id":"s-1"}"#;

#[test]
fn allow_roundtrip() {
    let pipe = test_pipe_name("allow");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();
    let client = spawn_client(&pipe, VALID_REQ);

    let (req, reply_tx) = expect_ask(&server);
    assert_eq!(req.rule, "git-force-push");
    assert_eq!(req.tool, "Bash");
    assert_eq!(req.command, "git push --force");
    assert_eq!(req.session_id, "s-1");
    reply_tx.send(AskReply::Allow).unwrap();

    let reply = reply_json(&client.join().unwrap());
    assert_eq!(reply["decision"].as_str().unwrap(), "allow");
    assert!(reply.get("reason").is_none());
    expect_idle(&server);
    server.shutdown();
}

#[test]
fn deny_roundtrip_with_chinese_reason() {
    let pipe = test_pipe_name("deny");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();
    let client = spawn_client(&pipe, VALID_REQ);

    let (_req, reply_tx) = expect_ask(&server);
    reply_tx
        .send(AskReply::Deny("用户拒绝：太危险".to_string()))
        .unwrap();

    let reply = reply_json(&client.join().unwrap());
    assert_eq!(reply["decision"].as_str().unwrap(), "deny");
    assert_eq!(reply["reason"].as_str().unwrap(), "用户拒绝：太危险");
    expect_idle(&server);
    server.shutdown();
}

#[test]
fn invalid_json_denied_without_popup() {
    let pipe = test_pipe_name("garbage");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();
    let client = spawn_client(&pipe, "this is not json");

    // 非法请求不弹窗：只收到完结事件，回复按 deny
    expect_idle(&server);
    let reply = reply_json(&client.join().unwrap());
    assert_eq!(reply["decision"].as_str().unwrap(), "deny");
    server.shutdown();
}

#[test]
fn missing_fields_denied_without_popup() {
    let pipe = test_pipe_name("missing");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();
    let client = spawn_client(&pipe, r#"{"rule":"git-force-push"}"#);

    expect_idle(&server);
    let reply = reply_json(&client.join().unwrap());
    assert_eq!(reply["decision"].as_str().unwrap(), "deny");
    server.shutdown();
}

#[test]
fn session_id_optional() {
    let pipe = test_pipe_name("nosid");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();
    let client = spawn_client(
        &pipe,
        r#"{"rule":"git-force-push","tool":"Bash","command":"git push -f"}"#,
    );

    let (req, reply_tx) = expect_ask(&server);
    assert_eq!(req.session_id, "");
    reply_tx.send(AskReply::Allow).unwrap();
    assert_eq!(reply_json(&client.join().unwrap())["decision"], "allow");
    expect_idle(&server);
    server.shutdown();
}

#[test]
fn ask_timeout_auto_deny() {
    let pipe = test_pipe_name("timeout");
    // 注入缩短的超时测 55s 自动 deny 路径（生产值 55s 由 daemon.rs 注入）
    let server = ask_pipe::start(&pipe, Duration::from_millis(300)).unwrap();
    let started = Instant::now();
    let client = spawn_client(&pipe, VALID_REQ);

    // 收到 Ask 但故意不回复
    let (_req, _reply_tx) = expect_ask(&server);

    let reply = reply_json(&client.join().unwrap());
    let elapsed = started.elapsed();
    assert_eq!(reply["decision"].as_str().unwrap(), "deny");
    assert!(
        reply["reason"].as_str().unwrap().contains("自动拒绝"),
        "got: {reply}"
    );
    assert!(elapsed >= Duration::from_millis(280), "太快: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "太慢: {elapsed:?}");
    expect_idle(&server);
    server.shutdown();
}

#[test]
fn sequential_clients_are_served_in_order() {
    let pipe = test_pipe_name("queue");
    let server = ask_pipe::start(&pipe, Duration::from_secs(5)).unwrap();

    for i in 0..3 {
        let req = format!(
            r#"{{"rule":"git-force-push","tool":"Bash","command":"git push --force #{}", "session_id":""}}"#,
            i
        );
        let client = spawn_client(&pipe, &req);
        let (got, reply_tx) = expect_ask(&server);
        assert!(
            got.command.ends_with(&format!("#{i}")),
            "got: {}",
            got.command
        );
        reply_tx.send(AskReply::Allow).unwrap();
        assert_eq!(reply_json(&client.join().unwrap())["decision"], "allow");
        expect_idle(&server);
    }
    server.shutdown();
}

#[test]
fn default_pipe_name_follows_contract() {
    let name = ask_pipe::default_pipe_name();
    assert!(
        name.starts_with(r"\\.\pipe\KimiCodeGuard.ask."),
        "got: {name}"
    );
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
    assert!(name.ends_with(&user), "got: {name}");
}
