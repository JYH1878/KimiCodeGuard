//! 审计面板查询层（M6）：audit.db 只读访问，与写者 worker 并发安全。
//!
//! - 所有连接 `open_readonly` + busy_timeout 2s：写者 worker 并发写时等锁，不报错；
//! - 本模块只有 SELECT，不暴露任何写路径（硬边界：不动 events 表结构 / hash 链 /
//!   任何写路径）；
//! - 「今日 / 每日」边界 ts 由前端按本地时区算好本地午夜传入，Rust 不碰时区
//!   （项目无时间库）；
//! - 列表 payload 截断 500 字符（详情走 `panel_row` 取全文）。

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};

/// 列表 payload 截断长度（字符）
pub const PAYLOAD_TRUNCATE_CHARS: usize = 500;
/// 单页上限（前端每页 100，留余量）
pub const MAX_PAGE_SIZE: u32 = 200;
/// 只读连接等写锁的时长（写者 worker 并发时等锁不报错）
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(2000);

/// 打开只读连接。库文件不存在时按错误返回（面板显示「尚无审计数据」），
/// 绝不因面板查询创建 / 改动 audit.db。
pub fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    Ok(conn)
}

/// 事件流筛选（缺省 None = 不过滤；tauri 命令参数，前端发 camelCase 键）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct EventFilter {
    /// 事件名精确匹配
    pub event: Option<String>,
    /// decision 精确匹配（deny / ask_allow / ask_deny / allow）
    pub decision: Option<String>,
    /// tool_name 精确匹配
    pub tool_name: Option<String>,
    /// 关键字：LIKE 匹配 payload 与 reason（% _ \ 转义）
    pub keyword: Option<String>,
    /// ts >= 此值（含，Unix 毫秒）
    pub ts_from: Option<i64>,
    /// ts <= 此值（含，Unix 毫秒）
    pub ts_to: Option<i64>,
    /// 游标：id < cursor 倒序取下一页
    pub cursor: Option<i64>,
}

/// 面板展示的一行事件（列表 payload 截断 500 字符）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PanelEvent {
    pub id: i64,
    pub ts: i64,
    pub event: String,
    pub session_id: String,
    pub cwd: String,
    pub tool_name: Option<String>,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub payload: String,
    /// payload 是否被截断（截断才为 true）
    pub payload_truncated: bool,
}

/// 一页结果：rows 倒序（新在前），total = 符合筛选的总行数（非本页行数）
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QueryPage {
    pub rows: Vec<PanelEvent>,
    pub total: i64,
}

/// 事件流查询：筛选 + 游标分页（id < cursor 倒序），limit 上限 200。
pub fn query_events(
    conn: &Connection,
    filter: &EventFilter,
    limit: u32,
) -> rusqlite::Result<QueryPage> {
    let limit = limit.clamp(1, MAX_PAGE_SIZE);
    let (where_sql, params) = build_where(filter);
    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM events{where_sql}");
        conn.query_row(
            &sql,
            params_from_iter(params.iter().map(|p| p.as_ref())),
            |r| r.get(0),
        )?
    };
    let sql = format!(
        "SELECT id, ts, event, session_id, cwd, tool_name, decision, reason, payload
         FROM events{where_sql} ORDER BY id DESC LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(params.iter().map(|p| p.as_ref())), |row| {
            map_row(row, true)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(QueryPage { rows, total })
}

/// 详情查询：返回 payload 全文（无截断）。id 不存在返回 None。
pub fn panel_row(conn: &Connection, id: i64) -> rusqlite::Result<Option<PanelEvent>> {
    conn.query_row(
        "SELECT id, ts, event, session_id, cwd, tool_name, decision, reason, payload
         FROM events WHERE id = ?1",
        params![id],
        |row| map_row(row, false),
    )
    .optional()
}

/// 统计筛选参数：「今日」与「近 N 天」的每日边界由前端算好本地午夜 ts 传入
/// （升序，最后一项为今日起点）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct StatsBounds {
    /// 今日起点（本地午夜，Unix 毫秒，含）
    pub today_start_ts: i64,
    /// 近 N 天每日起点（升序，含；最后一项应为今日起点）
    pub day_starts_ts: Vec<i64>,
}

/// 各 decision 计数（PreToolUse 专属；NULL decision 不计入）
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DecisionCounts {
    pub deny: i64,
    pub ask_allow: i64,
    pub ask_deny: i64,
    pub allow: i64,
}

/// 名称 + 计数（事件分布 / 工具 TopN）
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct NameCount {
    pub name: String,
    pub count: i64,
}

/// 面板统计：decision 分布（今日 + 总计）、事件分布、工具 Top10、近 N 天每日计数
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PanelStats {
    pub today: DecisionCounts,
    pub total: DecisionCounts,
    /// 事件总行数
    pub total_rows: i64,
    /// 事件名分布（按计数降序）
    pub events: Vec<NameCount>,
    /// tool_name Top10（按计数降序）
    pub tools: Vec<NameCount>,
    /// 与 bounds.day_starts_ts 一一对应；最后一项 = 今日
    pub daily: Vec<i64>,
}

/// 面板统计查询。
pub fn query_stats(conn: &Connection, bounds: &StatsBounds) -> rusqlite::Result<PanelStats> {
    let total_rows = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
    let mut stats = PanelStats {
        total_rows,
        ..Default::default()
    };

    // decision 分布：今日（ts >= 今日起点）与总计；NULL decision（生命周期事件）不计
    stats.today = decision_counts(conn, Some(bounds.today_start_ts))?;
    stats.total = decision_counts(conn, None)?;

    // 事件名分布（按计数降序）
    let mut stmt = conn.prepare(
        "SELECT event, COUNT(*) AS c FROM events
         GROUP BY event ORDER BY c DESC, event ASC",
    )?;
    stats.events = stmt
        .query_map([], |row| {
            Ok(NameCount {
                name: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    // 工具 Top10（只算 PreToolUse 等有 tool_name 的行）
    let mut stmt = conn.prepare(
        "SELECT tool_name, COUNT(*) AS c FROM events
         WHERE tool_name IS NOT NULL AND tool_name <> ''
         GROUP BY tool_name ORDER BY c DESC, tool_name ASC LIMIT 10",
    )?;
    stats.tools = stmt
        .query_map([], |row| {
            Ok(NameCount {
                name: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    // 近 N 天每日计数：第 i 天 = [day[i], day[i+1])，最后一天 = [day[n-1], +∞)
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM events WHERE ts >= ?1 AND ts < ?2")?;
    let n = bounds.day_starts_ts.len();
    let mut daily = Vec::with_capacity(n);
    for i in 0..n {
        let from = bounds.day_starts_ts[i];
        let to = bounds.day_starts_ts.get(i + 1).copied().unwrap_or(i64::MAX);
        daily.push(stmt.query_row(params![from, to], |r| r.get(0))?);
    }
    stats.daily = daily;
    Ok(stats)
}

/// 按 decision 分组计数（deny / ask_allow / ask_deny / allow；其余值忽略）。
/// `since_ts` = Some 时只统计 ts >= 该值的行（今日口径）。
fn decision_counts(conn: &Connection, since_ts: Option<i64>) -> rusqlite::Result<DecisionCounts> {
    let sql = match since_ts {
        Some(_) => "SELECT decision, COUNT(*) FROM events WHERE ts >= ?1 GROUP BY decision",
        None => "SELECT decision, COUNT(*) FROM events GROUP BY decision",
    };
    let mut stmt = conn.prepare(sql)?;
    let map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<(Option<String>, i64)> {
        Ok((row.get(0)?, row.get(1)?))
    };
    let mut counts = DecisionCounts::default();
    let rows = match since_ts {
        Some(ts) => stmt
            .query_map(params![ts], map)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => stmt
            .query_map([], map)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    for (decision, count) in rows {
        match decision.as_deref() {
            Some("deny") => counts.deny = count,
            Some("ask_allow") => counts.ask_allow = count,
            Some("ask_deny") => counts.ask_deny = count,
            Some("allow") => counts.allow = count,
            _ => {} // NULL / 未知值不计
        }
    }
    Ok(counts)
}

/// 构造 WHERE 子句与参数（编号参数 ?n，与 params_from_iter 兼容）。
/// 关键字 LIKE 用反斜杠转义 % _ \（ESCAPE '\'），payload 与 reason 复用同一参数。
fn build_where(filter: &EventFilter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    /// 参数入列并返回其编号（?n）
    fn push_param(
        params: &mut Vec<Box<dyn rusqlite::ToSql>>,
        v: impl rusqlite::ToSql + 'static,
    ) -> usize {
        params.push(Box::new(v));
        params.len()
    }
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(v) = &filter.event {
        clauses.push(format!("event = ?{}", push_param(&mut params, v.clone())));
    }
    if let Some(v) = &filter.decision {
        clauses.push(format!(
            "decision = ?{}",
            push_param(&mut params, v.clone())
        ));
    }
    if let Some(v) = &filter.tool_name {
        clauses.push(format!(
            "tool_name = ?{}",
            push_param(&mut params, v.clone())
        ));
    }
    if let Some(v) = &filter.keyword {
        let pat = format!("%{}%", escape_like(v));
        let n = push_param(&mut params, pat);
        clauses.push(format!(
            "(payload LIKE ?{n} ESCAPE '\\' OR reason LIKE ?{n} ESCAPE '\\')"
        ));
    }
    if let Some(v) = filter.ts_from {
        clauses.push(format!("ts >= ?{}", push_param(&mut params, v)));
    }
    if let Some(v) = filter.ts_to {
        clauses.push(format!("ts <= ?{}", push_param(&mut params, v)));
    }
    if let Some(v) = filter.cursor {
        clauses.push(format!("id < ?{}", push_param(&mut params, v)));
    }
    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    (sql, params)
}

/// LIKE 关键字转义（转义符 = 反斜杠；% _ \ 三个特殊字符）
fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// 行 → PanelEvent（truncate = 列表截断 500 字符，详情全文）
fn map_row(row: &rusqlite::Row<'_>, truncate: bool) -> rusqlite::Result<PanelEvent> {
    let payload: String = row.get(8)?;
    let (payload, payload_truncated) =
        if truncate && payload.chars().count() > PAYLOAD_TRUNCATE_CHARS {
            (payload.chars().take(PAYLOAD_TRUNCATE_CHARS).collect(), true)
        } else {
            (payload, false)
        };
    Ok(PanelEvent {
        id: row.get(0)?,
        ts: row.get(1)?,
        event: row.get(2)?,
        session_id: row.get(3)?,
        cwd: row.get(4)?,
        tool_name: row.get(5)?,
        decision: row.get(6)?,
        reason: row.get(7)?,
        payload,
        payload_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditDb, AuditEvent};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// 用完即删的临时目录（测试自清理）
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("kcg-panel-test-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("建临时目录");
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const T: i64 = 1_760_000_000_000; // 基准时间戳（毫秒）
    const DAY_MS: i64 = 86_400_000;

    fn ev(
        ts: i64,
        event: &str,
        tool: Option<&str>,
        decision: Option<&str>,
        payload: &str,
    ) -> AuditEvent {
        AuditEvent {
            ts,
            event: event.to_string(),
            session_id: "sess-x".to_string(),
            cwd: "D:/work".to_string(),
            tool_name: tool.map(str::to_string),
            decision: decision.map(str::to_string),
            reason: decision.map(|d| format!("规则-{d}")),
            payload: payload.to_string(),
        }
    }

    fn tool_ev(ts: i64, tool: &str, decision: &str) -> AuditEvent {
        ev(
            ts,
            "PreToolUse",
            Some(tool),
            Some(decision),
            &format!("{{\"tool_name\":\"{tool}\"}}"),
        )
    }

    /// 建库 + 追加 rows，返回 db 路径
    fn seed(dir: &TempDir, rows: &[AuditEvent]) -> PathBuf {
        let path = dir.0.join("audit.db");
        let db = AuditDb::open(&path).expect("开库");
        for r in rows {
            db.append(r).expect("追加");
        }
        path
    }

    /// 建空库后开只读连接，返回 (路径, 连接)
    fn open_ro(dir: &TempDir) -> (PathBuf, Connection) {
        let path = dir.0.join("audit.db");
        AuditDb::open(&path).expect("建库");
        let conn = open_readonly(&path).expect("只读开库");
        (path, conn)
    }

    /// seed + 开只读连接
    fn seeded_ro(dir: &TempDir, rows: &[AuditEvent]) -> Connection {
        let path = seed(dir, rows);
        open_readonly(&path).expect("只读开库")
    }

    // —— 只读连接契约 ——
    #[test]
    fn open_readonly_rejects_writes_and_sets_busy_timeout() {
        let dir = TempDir::new("ro");
        let (_, conn) = open_ro(&dir);
        // 写路径必须被拒（硬边界：面板绝不写 audit.db）
        assert!(
            conn.execute("INSERT INTO backfill_seen(key) VALUES ('x')", [])
                .is_err(),
            "只读连接必须拒绝写"
        );
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("读 busy_timeout");
        assert_eq!(busy, 2000, "写者并发时等锁 2s 不报错");
        // 库不存在 → 错误（面板据此显示「尚无审计数据」，绝不建库）
        assert!(open_readonly(&dir.0.join("no-such.db")).is_err());
    }

    // —— 基础查询：倒序 + total ——
    #[test]
    fn query_returns_newest_first_with_total() {
        let dir = TempDir::new("basic");
        let conn = seeded_ro(
            &dir,
            &[
                ev(T, "SessionStart", None, None, "{}"),
                tool_ev(T + 1, "Bash", "deny"),
                tool_ev(T + 2, "Read", "allow"),
                tool_ev(T + 3, "Bash", "ask_allow"),
                ev(T + 4, "SessionEnd", None, None, "{}"),
            ],
        );
        let page = query_events(&conn, &EventFilter::default(), 100).expect("查询");
        let ids: Vec<i64> = page.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [5, 4, 3, 2, 1], "必须按 id 倒序（新在前）");
        assert_eq!(page.total, 5);
    }

    // —— 游标分页 ——
    #[test]
    fn cursor_pagination_walks_all_pages() {
        let dir = TempDir::new("paging");
        let rows: Vec<AuditEvent> = (0..25).map(|i| tool_ev(T + i, "Bash", "deny")).collect();
        let conn = seeded_ro(&dir, &rows);
        let p1 = query_events(&conn, &EventFilter::default(), 10).expect("第 1 页");
        assert_eq!(p1.rows.len(), 10);
        assert_eq!(p1.rows[0].id, 25);
        assert_eq!(p1.rows[9].id, 16);
        assert_eq!(p1.total, 25, "每页 total 都是全量计数");

        let f2 = EventFilter {
            cursor: Some(16),
            ..Default::default()
        };
        let p2 = query_events(&conn, &f2, 10).expect("第 2 页");
        assert_eq!(p2.rows[0].id, 15);
        assert_eq!(p2.rows[9].id, 6);

        let f3 = EventFilter {
            cursor: Some(6),
            ..Default::default()
        };
        let p3 = query_events(&conn, &f3, 10).expect("第 3 页");
        let ids: Vec<i64> = p3.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [5, 4, 3, 2, 1], "末页不足一页");
        // 三页无重叠无遗漏
        let all: std::collections::BTreeSet<i64> = p1
            .rows
            .iter()
            .chain(p2.rows.iter())
            .chain(p3.rows.iter())
            .map(|r| r.id)
            .collect();
        assert_eq!(all.len(), 25);
    }

    // —— limit 上限 200 ——
    #[test]
    fn limit_capped_at_200() {
        let dir = TempDir::new("cap");
        let rows: Vec<AuditEvent> = (0..205).map(|i| tool_ev(T + i, "Bash", "deny")).collect();
        let conn = seeded_ro(&dir, &rows);
        let page = query_events(&conn, &EventFilter::default(), 1000).expect("查询");
        assert_eq!(page.rows.len(), 200, "limit 超上限必须截到 200");
        assert_eq!(page.total, 205, "total 不受 limit 影响");
        let page0 = query_events(&conn, &EventFilter::default(), 0).expect("limit 0");
        assert_eq!(page0.rows.len(), 1, "limit 0 按 1 处理");
    }

    // —— decision 筛选 ——
    #[test]
    fn decision_filter_exact_match() {
        let dir = TempDir::new("decision");
        let conn = seeded_ro(
            &dir,
            &[
                tool_ev(T + 1, "Bash", "deny"),
                tool_ev(T + 2, "Bash", "deny"),
                tool_ev(T + 3, "Read", "allow"),
                tool_ev(T + 4, "Bash", "ask_allow"),
                tool_ev(T + 5, "Bash", "ask_deny"),
                ev(T + 6, "SessionStart", None, None, "{}"),
            ],
        );
        let f = EventFilter {
            decision: Some("deny".to_string()),
            ..Default::default()
        };
        let page = query_events(&conn, &f, 100).expect("查询");
        let ids: Vec<i64> = page.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [2, 1], "只有 decision=deny 的行");
        assert_eq!(page.total, 2);
    }

    // —— event / tool_name 筛选 ——
    #[test]
    fn event_and_tool_filters() {
        let dir = TempDir::new("eventtool");
        let conn = seeded_ro(
            &dir,
            &[
                ev(T, "SessionStart", None, None, "{}"),
                ev(T + 1, "SessionStart", None, None, "{}"),
                tool_ev(T + 2, "Bash", "deny"),
                tool_ev(T + 3, "Read", "allow"),
                ev(T + 4, "SessionEnd", None, None, "{}"),
            ],
        );
        let fe = EventFilter {
            event: Some("SessionStart".to_string()),
            ..Default::default()
        };
        let page = query_events(&conn, &fe, 100).expect("event 筛选");
        assert_eq!(page.total, 2);
        assert!(page.rows.iter().all(|r| r.event == "SessionStart"));

        let ft = EventFilter {
            tool_name: Some("Bash".to_string()),
            ..Default::default()
        };
        let page = query_events(&conn, &ft, 100).expect("tool 筛选");
        assert_eq!(page.total, 1);
        assert_eq!(page.rows[0].tool_name.as_deref(), Some("Bash"));
    }

    // —— 关键字：payload 与 reason 双匹配 + LIKE 转义 ——
    #[test]
    fn keyword_matches_payload_or_reason_with_like_escape() {
        let dir = TempDir::new("keyword");
        let mut r1 = tool_ev(T + 1, "Bash", "deny");
        r1.payload = "普通命令 aXb 100%done".to_string();
        r1.reason = Some("规则 rm-force".to_string());
        let mut r2 = tool_ev(T + 2, "Bash", "deny");
        r2.payload = "特殊命令 a%b special".to_string();
        let mut r3 = tool_ev(T + 3, "Bash", "deny");
        r3.payload = "普通命令".to_string();
        r3.reason = Some("命中 rm-force 规则".to_string());
        let conn = seeded_ro(&dir, &[r1, r2, r3]);

        // "%" 必须按字面转义：不带转义 "a%b" 会误匹配 r1 的 "aXb"
        let f = EventFilter {
            keyword: Some("a%b".to_string()),
            ..Default::default()
        };
        let page = query_events(&conn, &f, 100).expect("转义查询");
        let ids: Vec<i64> = page.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [2], "LIKE 特殊字符必须转义，只命中字面 a%b");

        // reason 也要能命中
        let f = EventFilter {
            keyword: Some("rm-force".to_string()),
            ..Default::default()
        };
        let page = query_events(&conn, &f, 100).expect("reason 查询");
        assert_eq!(page.total, 2, "reason 含 rm-force 的行命中（r1/r3）");
    }

    // —— ts 起止（含边界）——
    #[test]
    fn ts_range_inclusive() {
        let dir = TempDir::new("tsrange");
        let conn = seeded_ro(
            &dir,
            &[
                tool_ev(T + 1000, "Bash", "deny"),
                tool_ev(T + 2000, "Bash", "deny"),
                tool_ev(T + 3000, "Bash", "deny"),
                tool_ev(T + 4000, "Bash", "deny"),
            ],
        );
        let f = EventFilter {
            ts_from: Some(T + 2000),
            ts_to: Some(T + 3000),
            ..Default::default()
        };
        let page = query_events(&conn, &f, 100).expect("区间查询");
        let ids: Vec<i64> = page.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [3, 2], "起止均为闭区间");
        let f = EventFilter {
            ts_from: Some(T + 2500),
            ..Default::default()
        };
        let page = query_events(&conn, &f, 100).expect("仅下限");
        assert_eq!(page.total, 2);
    }

    // —— payload 截断 500 字符 ——
    #[test]
    fn payload_truncated_at_500_chars() {
        let dir = TempDir::new("trunc");
        let long: String = "长".repeat(600);
        let short: String = "短".repeat(100);
        let mut a = tool_ev(T + 1, "Bash", "deny");
        a.payload = long.clone();
        let mut b = tool_ev(T + 2, "Bash", "deny");
        b.payload = short.clone();
        let conn = seeded_ro(&dir, &[a, b]);
        let page = query_events(&conn, &EventFilter::default(), 100).expect("查询");
        assert_eq!(page.rows.len(), 2);
        let (short_row, long_row) = (&page.rows[0], &page.rows[1]); // 倒序：id2(短) 在前
        assert_eq!(short_row.payload, short, "≤500 不截断");
        assert!(!short_row.payload_truncated);
        assert_eq!(long_row.payload.chars().count(), 500, ">500 截到 500 字符");
        assert!(long_row.payload_truncated);
        assert!(long_row.payload.starts_with("长长长"));
    }

    // —— panel_row：全文 + 不存在 None ——
    #[test]
    fn panel_row_returns_full_payload() {
        let dir = TempDir::new("row");
        let mut a = tool_ev(T + 1, "Bash", "deny");
        a.payload = "x".repeat(600);
        let conn = seeded_ro(&dir, &[a]);
        let row = panel_row(&conn, 1).expect("查详情").expect("存在");
        assert_eq!(row.payload.len(), 600, "详情必须返回全文");
        assert!(!row.payload_truncated);
        assert_eq!(row.decision.as_deref(), Some("deny"));
        assert!(panel_row(&conn, 999).expect("查详情").is_none());
    }

    // —— 统计：今日/总计 decision、每日计数、事件分布、工具 Top10 ——
    #[test]
    fn stats_decision_daily_events_tools() {
        let dir = TempDir::new("stats");
        let conn = seeded_ro(
            &dir,
            &[
                tool_ev(T + 1000, "Bash", "deny"),
                tool_ev(T + 2000, "Read", "allow"),
                ev(T + 3000, "SessionStart", None, None, "{}"),
                tool_ev(T - DAY_MS + 500, "Bash", "ask_allow"),
                tool_ev(T - 2 * DAY_MS + 500, "Grep", "deny"),
            ],
        );
        let bounds = StatsBounds {
            today_start_ts: T,
            day_starts_ts: vec![T - 2 * DAY_MS, T - DAY_MS, T],
        };
        let s = query_stats(&conn, &bounds).expect("统计");
        assert_eq!(s.total_rows, 5);
        assert_eq!(
            s.today,
            DecisionCounts {
                deny: 1,
                allow: 1,
                ..Default::default()
            },
            "今日：deny 1 + allow 1（SessionStart 无 decision 不计）"
        );
        assert_eq!(
            s.total,
            DecisionCounts {
                deny: 2,
                ask_allow: 1,
                allow: 1,
                ..Default::default()
            }
        );
        assert_eq!(s.daily, vec![1, 1, 3], "近 3 天每日计数（含所有事件类型）");
        assert_eq!(s.events.len(), 2);
        assert_eq!(s.events[0].name, "PreToolUse");
        assert_eq!(s.events[0].count, 4, "事件分布按计数降序");
        assert_eq!(s.events[1].name, "SessionStart");
        assert_eq!(s.tools[0].name, "Bash");
        assert_eq!(s.tools[0].count, 2, "工具 Top 按计数降序");
        let tool_names: Vec<&str> = s.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tool_names, ["Bash", "Grep", "Read"], "并列按名称升序");
    }

    // —— 统计：空库 / 空每日边界 ——
    #[test]
    fn stats_empty_db_is_zeroed() {
        let dir = TempDir::new("statsempty");
        let (_, conn) = open_ro(&dir);
        let bounds = StatsBounds {
            today_start_ts: T,
            day_starts_ts: vec![],
        };
        let s = query_stats(&conn, &bounds).expect("空库统计");
        assert_eq!(
            s,
            PanelStats {
                total_rows: 0,
                ..Default::default()
            },
            "空库全零，不报错"
        );
    }
}
