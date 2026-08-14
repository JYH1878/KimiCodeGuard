//! 事件上报客户端（M3 审计轨 A）。契约（GOAL.md 设计定案，与 daemon 侧 events_pipe.rs 对应）：
//! - 管道默认 `\\.\pipe\KimiCodeGuard.events.<用户名>`（`KCG_EVENTS_PIPE` 仅供测试覆盖）。
//! - fire-and-forget：写一行事件 JSON 即断开，不等回复。
//! - 事件 JSON：`{event, ts, session_id, cwd, tool_name?, decision?, reason?, payload}`，
//!   payload = hook 原始 stdin 全文，ts = Unix 毫秒。
//! - 连不上管道（管道忙才重试，总预算 200ms；管道不存在立即失败）→ 追加写 spool：
//!   默认 `%LOCALAPPDATA%\KimiCodeGuard\spool\events.jsonl`（`KCG_EVENTS_SPOOL` 仅供测试覆盖），
//!   目录不存在要重建。daemon 启动时回收 spool 入库。
//! - 热路径纪律（不变量 4/6）：绝不 panic；daemon 不在时零等待（ERROR_FILE_NOT_FOUND 直接落 spool）。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 连接总预算（仅 ERROR_PIPE_BUSY 时重试；daemon 未运行是即时失败不占用预算）
const CONNECT_BUDGET: Duration = Duration::from_millis(200);
/// 管道忙时的重试间隔
const RETRY_INTERVAL: Duration = Duration::from_millis(20);
/// Windows ERROR_PIPE_BUSY（所有管道实例都在忙，值得等）
const ERROR_PIPE_BUSY: i32 = 231;

/// 一条待上报事件（字段与 daemon 侧 parse_event 对应）
pub struct Event<'a> {
    /// SessionStart / SessionEnd / SessionHeartbeat / PreToolUse
    pub event: &'a str,
    pub session_id: &'a str,
    pub cwd: &'a str,
    pub tool_name: Option<&'a str>,
    /// allow / deny / ask_allow / ask_deny（仅 PreToolUse 有）
    pub decision: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// hook 原始 stdin 全文
    pub payload: &'a str,
}

/// 上报一条事件。返回 true = 经管道送达；false = 已落 spool 兜底。本函数总返回，永 panic。
pub fn report(ev: &Event) -> bool {
    let line = build_line(ev);
    if send_to_pipe(&line) {
        return true;
    }
    write_spool(&line);
    false
}

/// Unix 毫秒时间戳（系统钟异常时为 0，不 panic）
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_line(ev: &Event) -> String {
    serde_json::json!({
        "event": ev.event,
        "ts": now_millis(),
        "session_id": ev.session_id,
        "cwd": ev.cwd,
        "tool_name": ev.tool_name,
        "decision": ev.decision,
        "reason": ev.reason,
        "payload": ev.payload,
    })
    .to_string()
}

fn default_pipe_name() -> String {
    let user = std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    format!(r"\\.\pipe\KimiCodeGuard.events.{user}")
}

fn pipe_name() -> String {
    std::env::var("KCG_EVENTS_PIPE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_pipe_name)
}

fn spool_path() -> PathBuf {
    if let Some(p) = std::env::var("KCG_EVENTS_SPOOL")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(p);
    }
    std::env::var("LOCALAPPDATA")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("KimiCodeGuard")
        .join("spool")
        .join("events.jsonl")
}

/// 写一行到事件管道。管道忙（ERROR_PIPE_BUSY）在预算内重试；其余错误立即失败。
fn send_to_pipe(line: &str) -> bool {
    let pipe = pipe_name();
    let deadline = Instant::now() + CONNECT_BUDGET;
    loop {
        match OpenOptions::new().write(true).open(&pipe) {
            Ok(mut f) => {
                let mut data = Vec::with_capacity(line.len() + 1);
                data.extend_from_slice(line.as_bytes());
                data.push(b'\n');
                return f.write_all(&data).and_then(|()| f.flush()).is_ok();
            }
            Err(e) => {
                let busy = e.raw_os_error() == Some(ERROR_PIPE_BUSY);
                if busy && Instant::now() < deadline {
                    std::thread::sleep(RETRY_INTERVAL);
                    continue;
                }
                return false;
            }
        }
    }
}

/// 追加写 spool（目录不存在要重建）。任何失败都静默——上报绝不能拖垮热路径。
fn write_spool(line: &str) {
    let path = spool_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let _ = f.write_all(line.as_bytes());
    let _ = f.write_all(b"\n");
}
