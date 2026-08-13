#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod logging;
mod tray;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        // 单实例：第二个实例启动只记日志后退出（两个 listener 抢同一管道没有意义）
        .plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            tracing::warn!("KimiCodeGuard 已在运行，第二个实例退出");
        }))
        .manage(daemon::PendingStore::default())
        .invoke_handler(tauri::generate_handler![daemon::ask_respond])
        .setup(|app| {
            // 日志必须最先初始化；失败退回 stderr，不 panic
            logging::init();
            tracing::info!("KimiCodeGuard daemon 启动 v{}", env!("CARGO_PKG_VERSION"));

            // ask 管道服务端 + 调度线程（失败只降级：托盘显示「未监听」，hook 侧 fail-safe deny）
            let listening = daemon::start_pipe_server(
                app.handle(),
                app.state::<daemon::PendingStore>().inner().clone(),
            );
            tray::setup(app.handle(), listening)?;

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

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running KimiCodeGuard daemon");
}
