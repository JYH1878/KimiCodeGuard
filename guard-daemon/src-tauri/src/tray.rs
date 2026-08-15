//! 托盘图标：常驻。菜单：状态（禁用态文本）、一键修复（防护失效时可用）、校验审计链、
//! 导出审计 JSONL、回溯历史会话、打开审计面板（M6）、开机自启（默认关）、退出。
//! 图标为 KimiCodeBar 占位图标（不设计新图标）；自保护巡检异常时换红图标 + 状态显红。
//! 消息框用 windows-sys MessageBoxW（不为几个弹窗引 tauri-plugin-dialog）。

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};
use tauri_plugin_autostart::ManagerExt;

use guard_daemon::audit;
use guard_daemon::events_pipe::{BackfillJob, WorkItem};
use guard_daemon::protect::{self, ProtectStatus};
use guard_daemon::wire;

pub const TRAY_ID: &str = "main-tray";

/// 占位托盘图标（编译期嵌入，来自 KimiCodeBar 素材）
const ICON_NORMAL: &[u8] = include_bytes!("../icons/tray-normal.png");
/// 防护失效红图标（自保护巡检异常态，M5 新增）
const ICON_RED: &[u8] = include_bytes!("../icons/tray-red.png");

/// 托盘自保护 UI 句柄（App 管理态）：巡检线程经 update_protect 更新文本/图标/修复菜单。
/// tauri 的 MenuItem 包装有 unsafe Send/Sync（muda 内部 Rc 由 tauri 背书），
/// 跨线程只经 run_on_main_thread 触达 UI，Windows 上菜单修改始终发生在主线程。
pub struct ProtectUi {
    status_item: MenuItem<tauri::Wry>,
    repair_item: MenuItem<tauri::Wry>,
    /// 防护健康时状态行显示的文本（管道监听态，setup 时定死）
    healthy_text: String,
}

pub fn setup(
    app: &AppHandle,
    listening: bool,
    events_listening: bool,
    backfill_tx: Option<Sender<WorkItem>>,
    initial: &(ProtectStatus, Option<PathBuf>),
) -> tauri::Result<()> {
    let pipe_text = match (listening, events_listening) {
        (true, true) => "状态：管道监听中",
        (true, false) => "状态：事件管道未监听",
        (false, true) => "状态：ask 管道未监听",
        (false, false) => "状态：管道未监听",
    };
    let (initial_status, initial_config) = initial;
    let healthy = initial_status.is_healthy();
    let status_text = if healthy {
        pipe_text.to_string()
    } else {
        format!(
            "状态：防护失效——{}",
            initial_status.detail(initial_config.as_deref().unwrap_or(Path::new("<未知>")))
        )
    };
    let status = MenuItem::with_id(app, "status", status_text, false, None::<&str>)?;
    let repair = MenuItem::with_id(app, "protect-repair", "一键修复", !healthy, None::<&str>)?;
    let verify = MenuItem::with_id(app, "verify-audit", "校验审计链", true, None::<&str>)?;
    let export = MenuItem::with_id(app, "export-audit", "导出审计 JSONL", true, None::<&str>)?;
    let backfill = MenuItem::with_id(app, "backfill-history", "回溯历史会话", true, None::<&str>)?;
    // M6：审计面板（托盘常开入口；关闭只隐藏，见 main.rs CloseRequested 拦截）
    let open_panel = MenuItem::with_id(app, "open-panel", "打开审计面板", true, None::<&str>)?;
    // 开机自启：勾选态以系统真实状态为准（默认关，M3 拍板）
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "开机自启",
        true,
        autostart_on,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &repair,
            &verify,
            &export,
            &backfill,
            &open_panel,
            &autostart,
            &quit,
        ],
    )?;

    app.manage(ProtectUi {
        status_item: status,
        repair_item: repair,
        healthy_text: pipe_text.to_string(),
    });

    let autostart_in_handler = autostart.clone();
    TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("KimiCodeGuard")
        .icon(tauri::image::Image::from_bytes(if healthy {
            ICON_NORMAL
        } else {
            ICON_RED
        })?)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "quit" => app.exit(0),
            "protect-repair" => {
                let app = app.clone();
                let _ = std::thread::Builder::new()
                    .name("kcg-tray-repair".to_string())
                    .spawn(move || repair_protect(&app));
            }
            "verify-audit" => verify_audit(),
            "export-audit" => export_audit(),
            "backfill-history" => backfill_history(&backfill_tx),
            "open-panel" => crate::panel::open_panel(app),
            "autostart" => {
                let launch = app.autolaunch();
                let was = launch.is_enabled().unwrap_or(false);
                let result = if was {
                    launch.disable()
                } else {
                    launch.enable()
                };
                match result {
                    Ok(()) => tracing::info!("开机自启已切换：{}", !was),
                    Err(e) => tracing::error!("切换开机自启失败：{e}"),
                }
                // 勾选态一律回读系统真实状态（失败时不会显示成假勾选）
                let _ = autostart_in_handler.set_checked(launch.is_enabled().unwrap_or(false));
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// 自保护巡检线程回调：更新状态文本/图标/修复菜单（主线程执行，菜单修改线程安全）。
/// 失败只记日志——托盘 UI 更新失败不影响防护本体。
pub fn update_protect(app: &AppHandle, status: ProtectStatus, config: Option<PathBuf>) {
    let app = app.clone();
    let caller = app.clone();
    let _ = caller.run_on_main_thread(move || {
        let Some(ui) = app.try_state::<ProtectUi>() else {
            tracing::warn!("托盘 ProtectUi 未初始化，忽略自保护状态更新");
            return;
        };
        let healthy = status.is_healthy();
        let text = if healthy {
            ui.healthy_text.clone()
        } else {
            format!(
                "状态：防护失效——{}",
                status.detail(config.as_deref().unwrap_or(Path::new("<未知>")))
            )
        };
        if let Err(e) = ui.status_item.set_text(text) {
            tracing::error!("更新托盘状态文本失败：{e}");
        }
        if let Err(e) = ui.repair_item.set_enabled(!healthy) {
            tracing::error!("更新一键修复菜单可用态失败：{e}");
        }
        let icon_bytes: &[u8] = if healthy { ICON_NORMAL } else { ICON_RED };
        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            match tauri::image::Image::from_bytes(icon_bytes) {
                Ok(img) => {
                    if let Err(e) = tray.set_icon(Some(img)) {
                        tracing::error!("更新托盘图标失败：{e}");
                    }
                }
                Err(e) => tracing::error!("解析托盘图标失败：{e}"),
            }
        }
    });
}

/// 「一键修复」：spawn daemon 同目录 guard-hook.exe install（原子注入 + 回读校验），
/// 成功后复查回绿。失败不 panic，只弹中文消息框 + 日志。
fn repair_protect(app: &AppHandle) {
    let daemon_exe = std::env::current_exe().unwrap_or_default();
    let config = match protect::config_path() {
        Some(c) => c,
        None => {
            message_box(
                "KimiCodeGuard 一键修复",
                "无法确定 Kimi Code 配置路径（KIMI_CODE_HOME / USERPROFILE 缺失）。",
                Icon::Error,
            );
            return;
        }
    };
    match protect::repair(&daemon_exe, &config) {
        protect::RepairOutcome::Ok => {
            let fresh = protect::check(&config);
            update_protect(app, fresh.clone(), Some(config.clone()));
            if fresh.is_healthy() {
                message_box(
                    "KimiCodeGuard 一键修复",
                    "修复成功，防护已恢复。",
                    Icon::Info,
                );
            } else {
                message_box(
                    "KimiCodeGuard 一键修复",
                    &format!("修复命令已执行，但复查仍未通过：{}", fresh.detail(&config)),
                    Icon::Error,
                );
            }
        }
        protect::RepairOutcome::NonZero(code) => message_box(
            "KimiCodeGuard 一键修复",
            &format!("修复失败：install 退出码 {code}（详见日志）。"),
            Icon::Error,
        ),
        protect::RepairOutcome::SpawnFailed(e) => message_box(
            "KimiCodeGuard 一键修复",
            &format!("修复失败：{e}"),
            Icon::Error,
        ),
    }
}

/// 「回溯历史会话」（M4 审计轨 B）：提交回溯任务 → 另起线程等回复 → 中文摘要消息框。
/// 增量幂等：重复扫只导入新行。回复超时 300s（首扫大库留足余量）。
fn backfill_history(backfill_tx: &Option<Sender<WorkItem>>) {
    let Some(tx) = backfill_tx else {
        message_box(
            "KimiCodeGuard 历史回溯",
            "事件管道未监听，无法回溯（daemon 启动时降级，详见日志）。",
            Icon::Error,
        );
        return;
    };
    let tx = tx.clone();
    let _ = std::thread::Builder::new()
        .name("kcg-tray-backfill".to_string())
        .spawn(move || {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx
                .send(WorkItem::Backfill(BackfillJob {
                    root: wire::default_sessions_root(),
                    reply: reply_tx,
                }))
                .is_err()
            {
                message_box(
                    "KimiCodeGuard 历史回溯",
                    "回溯任务提交失败（daemon 内部通道已断），请重启托盘。",
                    Icon::Error,
                );
                return;
            }
            match reply_rx.recv_timeout(Duration::from_secs(300)) {
                Ok(s) if s.db_ok => {
                    let mut body = format!(
                        "回溯完成：扫描 {} 个会话文件，新导入 {} 条，重复跳过 {} 条，损坏行 {} 条。",
                        s.files, s.imported, s.dup_skipped, s.bad_lines
                    );
                    if s.torn_files > 0 {
                        body += &format!("{} 个文件正在写入中，末行留待下次补扫。", s.torn_files);
                    }
                    body += "\n\n审计链校验与导出可正常覆盖回溯数据。";
                    message_box("KimiCodeGuard 历史回溯", &body, Icon::Info);
                }
                Ok(_) => message_box(
                    "KimiCodeGuard 历史回溯",
                    "审计库不可用，回溯未执行（详见日志）。",
                    Icon::Error,
                ),
                Err(_) => message_box(
                    "KimiCodeGuard 历史回溯",
                    "回溯超时（300 秒无回复），请查看日志。",
                    Icon::Error,
                ),
            }
        });
}

/// 「校验审计链」：全量重算 hash 链，结果弹中文消息框（绿=通过，红=被篡改/读库失败）。
fn verify_audit() {
    let db_path = audit::default_db_path();
    if !db_path.exists() {
        message_box(
            "KimiCodeGuard 审计链校验",
            "尚无审计数据（audit.db 不存在）。",
            Icon::Info,
        );
        return;
    }
    let result = audit::AuditDb::open(&db_path)
        .map_err(|e| audit::VerifyError::Db(e.to_string()))
        .and_then(|db| db.verify_chain());
    match result {
        Ok(n) => message_box(
            "KimiCodeGuard 审计链校验",
            &format!("校验通过：共 {n} 行事件，哈希链完整，未发现篡改。"),
            Icon::Info,
        ),
        Err(e) => message_box(
            "KimiCodeGuard 审计链校验",
            &format!("校验失败：{e}\n\n审计记录可能已被篡改，请导出留证并排查。"),
            Icon::Error,
        ),
    }
}

/// 「导出审计 JSONL」：写 `Documents\KimiCodeGuard-audit-<本地时间戳>.jsonl` 后打开所在目录。
fn export_audit() {
    let db_path = audit::default_db_path();
    if !db_path.exists() {
        message_box(
            "KimiCodeGuard 审计导出",
            "尚无审计数据（audit.db 不存在）。",
            Icon::Info,
        );
        return;
    }
    let outcome = (|| -> Result<(PathBuf, u64), String> {
        let db = audit::AuditDb::open(&db_path).map_err(|e| e.to_string())?;
        let dir = documents_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let file = dir.join(format!("KimiCodeGuard-audit-{}.jsonl", local_timestamp()));
        let f = std::fs::File::create(&file).map_err(|e| e.to_string())?;
        let n = db
            .dump_jsonl(std::io::BufWriter::new(f))
            .map_err(|e| e.to_string())?;
        Ok((file, n))
    })();
    match outcome {
        Ok((file, n)) => {
            tracing::info!("审计已导出 {} 行至 {}", n, file.display());
            // explorer /select 高亮导出文件；detached 不等待
            let _ = std::process::Command::new("explorer")
                .arg(format!(r#"/select,"{}""#, file.display()))
                .spawn();
        }
        Err(e) => message_box(
            "KimiCodeGuard 审计导出",
            &format!("导出失败：{e}"),
            Icon::Error,
        ),
    }
}

/// Documents 目录：%USERPROFILE%\Documents；USERPROFILE 缺失时退到 daemon 数据目录
fn documents_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|p| PathBuf::from(p).join("Documents"))
        .unwrap_or_else(audit::data_dir)
}

/// 本地时间戳 yyyyMMdd-HHmmss（文件名用；Windows 走 GetLocalTime，免引时间库）
#[cfg(windows)]
fn local_timestamp() -> String {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: 传入有效栈上缓冲；SYSTEMTIME 全字段 POD，调用后已初始化
    let st = unsafe {
        let mut st = std::mem::MaybeUninit::<SYSTEMTIME>::uninit();
        GetLocalTime(st.as_mut_ptr());
        st.assume_init()
    };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

#[cfg(not(windows))]
fn local_timestamp() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{millis}")
}

enum Icon {
    Info,
    Error,
}

/// 中文消息框（Windows 原生 MessageBoxW；非 Windows 退化为日志）
#[cfg(windows)]
fn message_box(title: &str, body: &str, icon: Icon) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_SYSTEMMODAL,
    };
    let style = match icon {
        Icon::Info => MB_OK | MB_ICONINFORMATION,
        Icon::Error => MB_OK | MB_ICONERROR,
    } | MB_SYSTEMMODAL; // 置顶：托盘菜单触发的反馈不该被其它窗口埋掉
    let t: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let b: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: 两个宽串均以 0 结尾；无 owner 窗口（托盘无窗口句柄可给）
    unsafe {
        MessageBoxW(std::ptr::null_mut(), b.as_ptr(), t.as_ptr(), style);
    }
}

#[cfg(not(windows))]
fn message_box(title: &str, body: &str, _icon: Icon) {
    tracing::info!("{title}：{body}");
}
