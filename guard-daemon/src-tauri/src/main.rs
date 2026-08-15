#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod logging;
mod panel;
mod tray;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        // 单实例：第二个实例启动只记日志后退出（两个 listener 抢同一管道没有意义）
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            tracing::warn!("KimiCodeGuard 已在运行，第二个实例退出");
        }))
        // 开机自启（托盘勾选项，默认关；Windows 上 MacosLauncher 参数不用）
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(daemon::PendingStore::default())
        .invoke_handler(tauri::generate_handler![
            daemon::ask_respond,
            panel::panel_query,
            panel::panel_stats,
            panel::panel_row
        ])
        .setup(|app| {
            // 日志必须最先初始化；失败退回 stderr，不 panic
            logging::init();
            tracing::info!("KimiCodeGuard daemon 启动 v{}", env!("CARGO_PKG_VERSION"));

            // ask 管道服务端 + 调度线程（失败只降级：托盘显示「未监听」，hook 侧 fail-safe deny）
            let listening = daemon::start_pipe_server(
                app.handle(),
                app.state::<daemon::PendingStore>().inner().clone(),
            );
            // M3：事件管道服务端（审计轨 A 落库 + spool 回收）+ 会话跟踪（空载自退）
            // M4：返回回溯任务提交口（轨 B），随启动自动回溯一次并传给托盘菜单
            let backfill_tx = daemon::start_events_server(app.handle());
            // M5：自保护巡检 v1——启动同步算一次初始状态给托盘（图标/文本/修复菜单），
            // 之后巡逻线程每 5 分钟复查并更新托盘（KCG_PROTECT_INTERVAL_MS 仅供测试）
            let protect_initial = daemon::initial_protect_status();
            tray::setup(
                app.handle(),
                listening,
                backfill_tx.is_some(),
                backfill_tx,
                &protect_initial,
            )?;
            daemon::start_protect_patrol(app.handle(), protect_initial);

            // ask 窗口点关闭只隐藏不销毁（hook 还在等回复时，超时逻辑照常兜底）
            if let Some(ask_window) = app.get_webview_window("ask") {
                let window = ask_window.clone();
                ask_window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                });
            }

            // 面板窗口点关闭只隐藏不销毁（照 ask 窗口模式；托盘可再开，退出走托盘「退出」）
            if let Some(panel_window) = app.get_webview_window("panel") {
                let window = panel_window.clone();
                panel_window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                });
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running KimiCodeGuard daemon");
}
