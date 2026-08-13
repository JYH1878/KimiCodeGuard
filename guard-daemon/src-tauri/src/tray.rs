//! 托盘图标：常驻，菜单两项——状态（禁用态文本，显示管道是否在监听）、退出。
//! 图标为 KimiCodeBar 占位图标（M2 不设计新图标）。

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle,
};

pub const TRAY_ID: &str = "main-tray";

/// 占位托盘图标（编译期嵌入，来自 KimiCodeBar 素材）
const ICON_NORMAL: &[u8] = include_bytes!("../icons/tray-normal.png");

pub fn setup(app: &AppHandle, listening: bool) -> tauri::Result<()> {
    let status_text = if listening {
        "状态：管道监听中"
    } else {
        "状态：管道未监听"
    };
    let status = MenuItem::with_id(app, "status", status_text, false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("KimiCodeGuard")
        .icon(tauri::image::Image::from_bytes(ICON_NORMAL)?)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| {
            if event.id().as_ref() == "quit" {
                app.exit(0);
            }
        })
        .build(app)?;

    Ok(())
}
