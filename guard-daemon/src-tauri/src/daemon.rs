//! ask 弹窗调度：管道服务端 ↔ Tauri 窗口的粘合层。
//!
//! 数据流：ask_pipe worker 发 PipeEvent::Ask（附 reply_tx）→ 这里存起 reply_tx、
//! 给 ask 窗口发 `ask-request` 事件并弹窗 → 前端点按钮调 `ask_respond` 命令 →
//! 回复经 reply_tx 回到 worker 写给 hook。55s 无人点：worker 超时自动 deny，
//! 随后发 PipeEvent::Idle，这里清状态关窗（用户迟到的点击会因通道已断被忽略）。
//! 全路径不 panic：锁中毒取 into_inner，窗口/通道错误只记日志。

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, State};

use guard_daemon::ask_pipe::{self, AskReply, PipeEvent};

/// 弹窗等人工确认的时长：55s（比 hook 侧 60s 超时早 5s，D2 fail-safe 留余量）
const ASK_TIMEOUT_DEFAULT: Duration = Duration::from_secs(55);

/// 当前待回复的 ask（worker 串行 ⇒ 最多一单在途）
pub type PendingStore = Arc<Mutex<Option<Sender<AskReply>>>>;

/// 启动管道服务端 + 调度线程。返回是否在监听（托盘状态用）。失败不阻断启动。
pub fn start_pipe_server(app: &AppHandle, pending: PendingStore) -> bool {
    let timeout = std::env::var("KCG_DAEMON_ASK_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(Duration::from_millis)
        .unwrap_or(ASK_TIMEOUT_DEFAULT);
    let pipe_name = ask_pipe::default_pipe_name();
    let server = match ask_pipe::start(&pipe_name, timeout) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("ask 管道监听启动失败：{e}（ask 规则将一律被 hook 保险式拒绝）");
            return false;
        }
    };

    let app = app.clone();
    thread::Builder::new()
        .name("kcg-ask-dispatcher".to_string())
        .spawn(move || {
            // Server 在此线程持有：dispatcher 退出即 drop（置 shutdown 标志）
            let server = server;
            for event in server.events() {
                match event {
                    PipeEvent::Ask { request, reply_tx } => {
                        on_ask(&app, &pending, request, reply_tx);
                    }
                    PipeEvent::Idle => {
                        // 上一单完结（已回复或超时）：清待复状态、关窗（已关则 no-op）
                        *pending.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        if let Some(w) = app.get_webview_window("ask") {
                            let _ = w.hide();
                        }
                    }
                }
            }
            tracing::warn!("ask 事件通道已关闭，dispatcher 退出");
        })
        .map(|_handle| true) // JoinHandle drop 即 detach，线程继续跑
        .unwrap_or_else(|e| {
            tracing::error!("创建 ask 调度线程失败：{e}");
            false
        })
}

fn on_ask(
    app: &AppHandle,
    pending: &PendingStore,
    request: ask_pipe::AskRequest,
    reply_tx: Sender<AskReply>,
) {
    let Some(window) = app.get_webview_window("ask") else {
        // 窗口不存在（极端情况）：立即 deny，不挂住 hook
        tracing::error!("ask 窗口不可用，按 deny 回复");
        let _ = reply_tx.send(AskReply::Deny("弹窗窗口不可用".to_string()));
        return;
    };
    *pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(reply_tx);
    if let Err(e) = app.emit_to("ask", "ask-request", &request) {
        tracing::error!("投递 ask 请求到窗口失败：{e}，按 deny 回复");
        let tx = pending.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(tx) = tx {
            let _ = tx.send(AskReply::Deny("弹窗投递失败".to_string()));
        }
        return;
    }
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

/// 前端按钮回调：decision = "allow" / "deny"。请求已超时完结时回复会被丢弃（记日志）。
#[tauri::command]
pub fn ask_respond(
    decision: &str,
    reason: Option<String>,
    pending: State<'_, PendingStore>,
    app: AppHandle,
) {
    let reply = if decision == "allow" {
        AskReply::Allow
    } else {
        AskReply::Deny(
            reason
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "用户拒绝".to_string()),
        )
    };
    let tx = pending.lock().unwrap_or_else(|e| e.into_inner()).take();
    match tx {
        Some(tx) => {
            let allow = matches!(reply, AskReply::Allow);
            tracing::info!(allow, "ask 人工确认完成");
            let _ = tx.send(reply);
        }
        None => tracing::warn!("人工回复到达时该请求已完结（超时），忽略"),
    }
    if let Some(w) = app.get_webview_window("ask") {
        let _ = w.hide();
    }
}
