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
use guard_daemon::{audit, events_pipe, protect, sessions};

use crate::tray;

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

// ---------- M3：事件管道 + 会话跟踪（空载自退） ----------

/// 会话跟踪巡检间隔
const TRACK_TICK: Duration = Duration::from_secs(15);

/// 启动事件管道服务端 + 会话跟踪线程。成功返回回溯任务提交口（Some），失败 None。
/// 失败不阻断启动（只降级审计）。
///
/// 数据流：events_pipe worker 落库后把事件克隆经 sink 发过来 → 跟踪线程喂 SessionTracker
/// （Start 加 / End 删 / Heartbeat 刷新 / 24h 僵死清除）→ 每 TICK 巡检一次，
/// 空载持续 idle_timeout（生产 5 分钟，`KCG_IDLE_EXIT_MS` 可注入）→ app.exit(0) 自退。
///
/// M4（审计轨 B）：启动后自动提交一次 wire 回溯任务（增量幂等——首跑大导入安装前
/// 历史，之后每次启动只扫新增行；回复只记日志）。手动重扫走托盘「回溯历史会话」。
pub fn start_events_server(app: &AppHandle) -> Option<Sender<events_pipe::WorkItem>> {
    let pipe_name = events_pipe::default_pipe_name();
    let db_path = audit::default_db_path();
    let spool_path = events_pipe::default_spool_path();
    let (sink_tx, sink_rx) = std::sync::mpsc::channel();
    let server = match events_pipe::start(&pipe_name, &db_path, &spool_path, Some(sink_tx)) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("events 管道监听启动失败：{e}（事件将只能走 spool，待下次启动回收）");
            return None;
        }
    };
    let backfill_tx = server.backfill_sender();

    let idle_timeout = std::env::var("KCG_IDLE_EXIT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(Duration::from_millis)
        .unwrap_or(sessions::IDLE_EXIT_AFTER);
    let zombie_after = std::env::var("KCG_ZOMBIE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(Duration::from_millis)
        .unwrap_or(sessions::ZOMBIE_AFTER);

    let app = app.clone();
    let spawned = thread::Builder::new()
        .name("kcg-session-tracker".to_string())
        .spawn(move || {
            // Server 在此线程持有：线程退出即 drop（置 shutdown 标志）；不调用其方法
            let _server = server;
            let mut tracker = sessions::SessionTracker::new();
            loop {
                match sink_rx.recv_timeout(TRACK_TICK) {
                    Ok(ev) => tracker.on_event(&ev.event, &ev.session_id, ev.ts),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::error!("events sink 通道断开（worker 已退出），跟踪线程结束");
                        return;
                    }
                }
                let now = guard_daemon_now_millis();
                if tracker.should_exit(now, idle_timeout, zombie_after) {
                    tracing::info!(
                        "无活跃会话持续 {idle_timeout:?}，daemon 空载自退（事件管道随进程关闭）"
                    );
                    app.exit(0);
                    return;
                }
            }
        })
        .map(|_handle| true) // JoinHandle drop 即 detach，线程继续跑
        .unwrap_or_else(|e| {
            tracing::error!("创建会话跟踪线程失败：{e}");
            false
        });
    if !spawned {
        return None;
    }

    // 启动自动回溯：独立线程等回复，不阻塞 setup；失败只记日志
    let auto_tx = backfill_tx.clone();
    let root = guard_daemon::wire::default_sessions_root();
    let _ = thread::Builder::new()
        .name("kcg-auto-backfill".to_string())
        .spawn(move || {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if auto_tx
                .send(events_pipe::WorkItem::Backfill(events_pipe::BackfillJob {
                    root,
                    reply: reply_tx,
                }))
                .is_err()
            {
                tracing::error!("自动回溯任务提交失败（worker 通道已断）");
                return;
            }
            match reply_rx.recv() {
                Ok(s) => tracing::info!(
                    "启动自动回溯完成：{} 个文件，新导入 {} 条，重复跳过 {} 条",
                    s.files,
                    s.imported,
                    s.dup_skipped
                ),
                Err(_) => tracing::error!("自动回溯回复通道断开"),
            }
        });

    Some(backfill_tx)
}

/// 当前 Unix 毫秒（系统钟异常时为 0；0 会让所有会话立即僵死，属安全方向的降级）
fn guard_daemon_now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------- M5：自保护巡检 v1 ----------

/// 启动时先同步算一次初始状态（托盘初始图标/文本用），随后巡逻线程每周期复查。
/// config 路径解析失败（无 KIMI_CODE_HOME/USERPROFILE/HOME）也收敛为 ConfigMissing，
/// 不 panic——防护巡检与 ask 防护互不牵连。
pub fn initial_protect_status() -> (protect::ProtectStatus, Option<std::path::PathBuf>) {
    let config = protect::config_path();
    let status = match &config {
        Some(c) => protect::check(c),
        None => protect::ProtectStatus::ConfigMissing,
    };
    (status, config)
}

/// 自保护巡检线程：启动即查一次，之后每 interval 复查。状态变化时更新托盘
/// （显红「防护失效」/ 恢复回绿）。interval 生产 5 分钟，`KCG_PROTECT_INTERVAL_MS`
/// 仅供测试注入（>0 才生效）。全路径不 panic：IO/解析失败只产生状态枚举 + 日志。
pub fn start_protect_patrol(
    app: &AppHandle,
    initial: (protect::ProtectStatus, Option<std::path::PathBuf>),
) {
    let interval = std::env::var("KCG_PROTECT_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(Duration::from_millis)
        .unwrap_or(protect::PROTECT_INTERVAL);
    let app = app.clone();
    let spawned = thread::Builder::new()
        .name("kcg-protect-patrol".to_string())
        .spawn(move || {
            let mut last = Some(initial);
            loop {
                // 复查：任何错误收敛为状态枚举（ConfigMissing/HookExeMissing…），不 panic
                let fresh = initial_protect_status();
                if last.as_ref() != Some(&fresh) {
                    tracing::info!(
                        status = fresh.0.code(),
                        "自保护巡检状态变化：{}",
                        fresh.0.detail(
                            fresh
                                .1
                                .as_deref()
                                .unwrap_or_else(|| std::path::Path::new("<未知>"))
                        )
                    );
                    tray::update_protect(&app, fresh.0.clone(), fresh.1.clone());
                }
                last = Some(fresh);
                thread::sleep(interval);
            }
        })
        .map(|_handle| true) // JoinHandle drop 即 detach，线程继续跑
        .unwrap_or_else(|e| {
            tracing::error!("创建自保护巡检线程失败：{e}");
            false
        });
    if !spawned {
        tracing::error!("自保护巡检未启动（托盘仍显示初始状态，不会自动刷新）");
    }
}
