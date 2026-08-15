//! M6 审计面板（daemon 侧粘合层）：三个只读查询命令 + 托盘开窗。
//!
//! - 命令全部薄壳透传 `guard_daemon::panel_query`，不重复写 SQL；
//! - 每次调用现开只读连接（busy_timeout 2s），与写者 worker 并发安全；
//! - 审计库不存在 → 返回中文错误，前端显示「尚无审计数据」；
//! - 开窗只 show/unminimize/set_focus；关闭只隐藏（CloseRequested 拦截在 main.rs，
//!   与 ask 窗口同模式）。

use tauri::{AppHandle, Manager};

use guard_daemon::audit;
use guard_daemon::panel_query::{
    self, EventFilter, PanelEvent, PanelStats, QueryPage, StatsBounds,
};

/// 只读连接 + 查询（每次现开现关，不长期持有句柄）
fn with_ro<T>(f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>) -> Result<T, String> {
    let conn = panel_query::open_readonly(&audit::default_db_path()).map_err(|e| e.to_string())?;
    f(&conn).map_err(|e| e.to_string())
}

/// 事件流查询：筛选 + 游标分页（id < cursor 倒序）。
#[tauri::command]
pub fn panel_query(filter: EventFilter, limit: u32) -> Result<QueryPage, String> {
    with_ro(|conn| panel_query::query_events(conn, &filter, limit))
}

/// 统计：decision 分布（今日 + 总计）、事件分布、工具 Top10、近 N 天每日计数。
/// 「今日 / 每日」边界 ts 由前端按本地时区算好传入（项目无时间库）。
#[tauri::command]
pub fn panel_stats(today_start_ts: i64, day_starts_ts: Vec<i64>) -> Result<PanelStats, String> {
    let bounds = StatsBounds {
        today_start_ts,
        day_starts_ts,
    };
    with_ro(|conn| panel_query::query_stats(conn, &bounds))
}

/// 详情：返回 payload 全文（id 不存在 → null）。
#[tauri::command]
pub fn panel_row(id: i64) -> Result<Option<PanelEvent>, String> {
    with_ro(|conn| panel_query::panel_row(conn, id))
}

/// 托盘「打开审计面板」：已开则聚焦，未开则 show。全路径不 panic。
pub fn open_panel(app: &AppHandle) {
    match app.get_webview_window("panel") {
        Some(w) => {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
        None => tracing::error!("panel 窗口不存在（tauri.conf.json 未配置 label=panel？）"),
    }
}
