//! 审计轨 A：SQLite append-only + hash chain（AGENTS.md D7，GOAL.md 设计定案）。
//!
//! - 库文件默认 `%LOCALAPPDATA%\KimiCodeGuard\audit.db`。
//! - 表 `events(id, ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash, hash)`。
//! - `hash = sha256(prev_hash + 行规范串)`；行规范串 = `(id, ts, event, session_id, cwd,
//!   tool_name, decision, reason, payload)` 的 JSON 数组串（JSON 转义保证字段边界无歧义）；
//!   首行 `prev_hash` = 64 个 `'0'`。
//! - 应用层只 INSERT：本模块不暴露任何 UPDATE/DELETE 入口；
//!   `verify_chain()` 全量重算逐行校验，任何篡改（改字段/改 hash/删行）都会在首个断裂行报错。
//! - 写路径由 daemon 的串行 worker 独占（同一时刻只有一个 append 调用者），
//!   `id = MAX(id)+1` 自取因此无竞态。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

/// 创世行的 prev_hash（64 个 '0'）
const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 一条审计事件（与 hook 上报的事件 JSON 字段一一对应）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Unix 毫秒时间戳（hook 侧生成）
    pub ts: i64,
    /// 事件名：SessionStart / SessionEnd / SessionHeartbeat / PreToolUse
    pub event: String,
    pub session_id: String,
    pub cwd: String,
    pub tool_name: Option<String>,
    /// deny / ask_allow / ask_deny / allow（仅 PreToolUse 有）
    pub decision: Option<String>,
    pub reason: Option<String>,
    /// hook 原始 stdin 全文
    pub payload: String,
}

/// 默认库路径：`%LOCALAPPDATA%\KimiCodeGuard\audit.db`（LOCALAPPDATA 缺失时退到临时目录）
pub fn default_db_path() -> PathBuf {
    data_dir().join("audit.db")
}

/// daemon 数据目录：`%LOCALAPPDATA%\KimiCodeGuard`
pub fn data_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("KimiCodeGuard")
}

/// append-only 审计库。写连接独占式持有，只暴露 INSERT。
pub struct AuditDb {
    conn: Connection,
}

impl AuditDb {
    /// 打开（不存在则建库建表）。父目录不存在会创建。
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY,
                ts         INTEGER NOT NULL,
                event      TEXT NOT NULL,
                session_id TEXT NOT NULL,
                cwd        TEXT NOT NULL,
                tool_name  TEXT,
                decision   TEXT,
                reason     TEXT,
                payload    TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                hash       TEXT NOT NULL
            );
            -- 审计轨 B（M4）：行级去重键（sha256(path:line:raw)，跨重扫/协议迁移重写幂等）
            CREATE TABLE IF NOT EXISTS backfill_seen (
                key        TEXT PRIMARY KEY
            );
            -- 审计轨 B：文件级增量游标（已消费行数；缩短=协议迁移重写，调用方归零重扫）
            CREATE TABLE IF NOT EXISTS backfill_files (
                path       TEXT PRIMARY KEY,
                lines      INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    /// 追加一行，返回新行 id。链上前一行 hash 取自当前最大 id 行（无行 = 创世 prev_hash）。
    pub fn append(&self, e: &AuditEvent) -> rusqlite::Result<i64> {
        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let id: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM events", [], |r| {
                    r.get(0)
                })?;
        let hash = row_hash(&prev_hash, &canonical_string(id, e));
        self.conn.execute(
            "INSERT INTO events
                (id, ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                e.ts,
                e.event,
                e.session_id,
                e.cwd,
                e.tool_name,
                e.decision,
                e.reason,
                e.payload,
                prev_hash,
                hash
            ],
        )?;
        Ok(id)
    }

    /// 文件级增量游标：该 wire.jsonl 已消费到第几行（无记录 = 0）
    pub fn backfill_cursor(&self, file_key: &str) -> rusqlite::Result<u64> {
        Ok(self
            .conn
            .query_row(
                "SELECT lines FROM backfill_files WHERE path = ?1",
                params![file_key],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|v| v.max(0) as u64)
            .unwrap_or(0))
    }

    /// 审计轨 B 批量导入（单事务）。`items` = `(去重键, 事件)`；逐条
    /// `INSERT OR IGNORE backfill_seen`，新键才 append 进链——重扫/协议迁移重写
    /// 后重跑天然幂等。最后把文件游标更新为 `new_cursor`。
    /// 写者仍是 events worker 单线程，起点 id/prev_hash 只查一次无竞态。
    pub fn append_backfill(
        &self,
        file_key: &str,
        items: &[(String, AuditEvent)],
        new_cursor: u64,
    ) -> rusqlite::Result<BackfillStats> {
        let tx = self.conn.unchecked_transaction()?;
        let mut prev_hash: String = tx
            .query_row(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let mut id: i64 =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
        let mut stats = BackfillStats::default();
        for (key, e) in items {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO backfill_seen(key) VALUES (?1)",
                params![key],
            )?;
            if inserted == 0 {
                stats.dup_skipped += 1;
                continue;
            }
            id += 1;
            let hash = row_hash(&prev_hash, &canonical_string(id, e));
            tx.execute(
                "INSERT INTO events
                    (id, ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    id,
                    e.ts,
                    e.event,
                    e.session_id,
                    e.cwd,
                    e.tool_name,
                    e.decision,
                    e.reason,
                    e.payload,
                    prev_hash,
                    hash
                ],
            )?;
            prev_hash = hash;
            stats.imported += 1;
        }
        tx.execute(
            "INSERT OR REPLACE INTO backfill_files(path, lines) VALUES (?1, ?2)",
            params![file_key, new_cursor as i64],
        )?;
        tx.commit()?;
        Ok(stats)
    }

    /// 全量重算校验链。Ok(n) = 校验了 n 行全绿；Err 指明首个断裂行。
    pub fn verify_chain(&self) -> Result<u64, VerifyError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash, hash
             FROM events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredRow {
                id: row.get(0)?,
                event: AuditEvent {
                    ts: row.get(1)?,
                    event: row.get(2)?,
                    session_id: row.get(3)?,
                    cwd: row.get(4)?,
                    tool_name: row.get(5)?,
                    decision: row.get(6)?,
                    reason: row.get(7)?,
                    payload: row.get(8)?,
                },
                prev_hash: row.get(9)?,
                hash: row.get(10)?,
            })
        })?;
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0u64;
        for row in rows {
            let row = row?;
            if row.prev_hash != prev {
                return Err(VerifyError::PrevHashMismatch { id: row.id });
            }
            let expect = row_hash(&prev, &canonical_string(row.id, &row.event));
            if expect != row.hash {
                return Err(VerifyError::HashMismatch { id: row.id });
            }
            prev = row.hash;
            count += 1;
        }
        Ok(count)
    }

    /// 当前行数（测试与托盘状态用）
    pub fn count(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
    }

    /// 导出全量为 JSONL（每行 = 一行事件的完整字段，含 hash 链）。
    /// 只读操作；写端负责落文件。
    pub fn dump_jsonl(&self, mut out: impl std::io::Write) -> rusqlite::Result<u64> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash, hash
             FROM events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "ts": row.get::<_, i64>(1)?,
                "event": row.get::<_, String>(2)?,
                "session_id": row.get::<_, String>(3)?,
                "cwd": row.get::<_, String>(4)?,
                "tool_name": row.get::<_, Option<String>>(5)?,
                "decision": row.get::<_, Option<String>>(6)?,
                "reason": row.get::<_, Option<String>>(7)?,
                "payload": row.get::<_, String>(8)?,
                "prev_hash": row.get::<_, String>(9)?,
                "hash": row.get::<_, String>(10)?,
            }))
        })?;
        let mut n = 0u64;
        for row in rows {
            let v = row?;
            let line = serde_json::to_string(&v).unwrap_or_default();
            if writeln!(out, "{line}").is_err() {
                break; // 写失败（磁盘满等）：已写部分保持合法 JSONL，行数返回实际写出数
            }
            n += 1;
        }
        Ok(n)
    }
}

/// 回溯批量导入统计
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackfillStats {
    /// 新导入行数
    pub imported: u64,
    /// 去重跳过行数（重扫/迁移重写的重复行）
    pub dup_skipped: u64,
}

/// 链校验失败（id = 首个断裂行）
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// 该行的 prev_hash 与上一行 hash 不符（含删行/插行/改 prev_hash）
    PrevHashMismatch { id: i64 },
    /// 该行内容与自身 hash 不符（改字段/改 hash）
    HashMismatch { id: i64 },
    /// 读库本身失败
    Db(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::PrevHashMismatch { id } => {
                write!(f, "第 {id} 行与上一行的链式哈希衔接断裂")
            }
            VerifyError::HashMismatch { id } => write!(f, "第 {id} 行内容与哈希不符（已被篡改）"),
            VerifyError::Db(msg) => write!(f, "读取审计库失败：{msg}"),
        }
    }
}

impl From<rusqlite::Error> for VerifyError {
    fn from(e: rusqlite::Error) -> Self {
        VerifyError::Db(e.to_string())
    }
}

struct StoredRow {
    id: i64,
    event: AuditEvent,
    prev_hash: String,
    hash: String,
}

/// 行规范串：固定字段顺序的 JSON 数组（serde_json 序列化基础类型不会失败，
/// unwrap_or_default 只是防御；即便失败各端算法一致，校验语义不变）。
fn canonical_string(id: i64, e: &AuditEvent) -> String {
    serde_json::to_string(&serde_json::json!([
        id,
        e.ts,
        e.event,
        e.session_id,
        e.cwd,
        e.tool_name,
        e.decision,
        e.reason,
        e.payload
    ]))
    .unwrap_or_default()
}

/// hash = sha256(prev_hash + 行规范串) 的小写十六进制
fn row_hash(prev_hash: &str, canonical: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// 用完即删的临时目录（GOAL 任务 6 精神：测试自清理）
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("kcg-audit-test-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("建临时目录");
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_event(tag: &str) -> AuditEvent {
        AuditEvent {
            ts: 1_760_000_000_000,
            event: "PreToolUse".to_string(),
            session_id: format!("sess-{tag}"),
            cwd: "D:/work".to_string(),
            tool_name: Some("Bash".to_string()),
            decision: Some("deny".to_string()),
            reason: Some("规则 rm-force".to_string()),
            payload: format!("{{\"tool_name\":\"Bash\",\"tag\":\"{tag}\"}}"),
        }
    }

    fn lifecycle_event(tag: &str) -> AuditEvent {
        AuditEvent {
            ts: 1_760_000_001_000,
            event: "SessionStart".to_string(),
            session_id: format!("sess-{tag}"),
            cwd: "D:/work".to_string(),
            tool_name: None,
            decision: None,
            reason: None,
            payload: "{}".to_string(),
        }
    }

    // —— 任务 0 冒烟：rusqlite bundled 最小读写 ——
    #[test]
    fn rusqlite_bundled_smoke() {
        let dir = TempDir::new("smoke");
        let conn = Connection::open(dir.0.join("smoke.db")).expect("开库");
        conn.execute("CREATE TABLE t (v TEXT)", []).expect("建表");
        conn.execute("INSERT INTO t (v) VALUES ('你好')", [])
            .expect("写");
        let v: String = conn
            .query_row("SELECT v FROM t", [], |r| r.get(0))
            .expect("读");
        assert_eq!(v, "你好");
    }

    // —— 任务 1：写入回读 ——
    #[test]
    fn append_and_read_back() {
        let dir = TempDir::new("rw");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        let id1 = db.append(&lifecycle_event("a")).expect("append 1");
        let id2 = db.append(&sample_event("b")).expect("append 2");
        assert_eq!((id1, id2), (1, 2));
        assert_eq!(db.count().expect("count"), 2);

        let (prev1, hash1): (String, String) = db
            .conn
            .query_row("SELECT prev_hash, hash FROM events WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("读行 1");
        assert_eq!(prev1, GENESIS_PREV_HASH, "首行 prev_hash 必须是 64 个 0");
        assert_eq!(hash1.len(), 64);

        let row2 = db
            .conn
            .query_row(
                "SELECT ts, event, session_id, cwd, tool_name, decision, reason, payload, prev_hash
                 FROM events WHERE id = 2",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                },
            )
            .expect("读行 2");
        let e = sample_event("b");
        assert_eq!(
            row2,
            (
                e.ts,
                e.event,
                e.session_id,
                e.cwd,
                e.tool_name,
                e.decision,
                e.reason,
                e.payload,
                hash1
            ),
            "第二行字段必须原样回读，prev_hash 必须等于首行 hash"
        );
    }

    // —— 任务 1：链校验绿 ——
    #[test]
    fn verify_chain_ok() {
        let dir = TempDir::new("ok");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        assert_eq!(db.verify_chain(), Ok(0), "空库校验应绿（0 行）");
        db.append(&lifecycle_event("a")).expect("a");
        db.append(&sample_event("b")).expect("b");
        db.append(&sample_event("c")).expect("c");
        assert_eq!(db.verify_chain(), Ok(3));
    }

    // —— 任务 1：SQL UPDATE 篡改一行 → verify 必红 ——
    #[test]
    fn tamper_update_breaks_chain() {
        let dir = TempDir::new("tamper");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        db.append(&lifecycle_event("a")).expect("a");
        db.append(&sample_event("b")).expect("b");
        db.append(&sample_event("c")).expect("c");
        assert_eq!(db.verify_chain(), Ok(3));

        db.conn
            .execute("UPDATE events SET payload = 'tampered' WHERE id = 2", [])
            .expect("篡改");
        assert_eq!(
            db.verify_chain(),
            Err(VerifyError::HashMismatch { id: 2 }),
            "改第 2 行内容后必须在第 2 行报红"
        );
    }

    // —— 任务 1 补充：篡改 hash 字段本身 / 删行，同样必红 ——
    #[test]
    fn tamper_hash_field_breaks_chain() {
        let dir = TempDir::new("tamperhash");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        db.append(&sample_event("a")).expect("a");
        db.append(&sample_event("b")).expect("b");
        db.conn
            .execute(
                "UPDATE events SET hash = printf('%.64c', 'f') WHERE id = 1",
                [],
            )
            .expect("篡改 hash");
        assert_eq!(db.verify_chain(), Err(VerifyError::HashMismatch { id: 1 }));
    }

    #[test]
    fn delete_row_breaks_chain() {
        let dir = TempDir::new("del");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        for tag in ["a", "b", "c"] {
            db.append(&sample_event(tag)).expect(tag);
        }
        db.conn
            .execute("DELETE FROM events WHERE id = 2", [])
            .expect("删行");
        assert_eq!(
            db.verify_chain(),
            Err(VerifyError::PrevHashMismatch { id: 3 }),
            "删第 2 行后第 3 行的 prev_hash 衔接必须报红"
        );
    }

    // —— dump_jsonl：导出行数与内容 ——
    #[test]
    fn dump_jsonl_roundtrip() {
        let dir = TempDir::new("dump");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        db.append(&lifecycle_event("a")).expect("a");
        db.append(&sample_event("b")).expect("b");
        let mut buf: Vec<u8> = Vec::new();
        let n = db.dump_jsonl(&mut buf).expect("导出");
        assert_eq!(n, 2);
        let text = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v: serde_json::Value = serde_json::from_str(lines[1]).expect("行 2 是合法 JSON");
        assert_eq!(v["event"], "PreToolUse");
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["hash"].as_str().expect("hash 串").len(), 64);
    }

    // —— 任务 2（M4）：回溯批量导入 ——

    /// 构造一条 wire 回溯事件 + 去重键
    fn backfill_item(file: &str, line: u64, tag: &str) -> (String, AuditEvent) {
        (
            format!("key-{file}-{line}-{tag}"),
            AuditEvent {
                ts: 1_780_000_000_000 + line as i64,
                event: "wire.tool_call".to_string(),
                session_id: format!("sess-{file}"),
                cwd: "D:/work".to_string(),
                tool_name: Some("Bash".to_string()),
                decision: None,
                reason: Some(format!("wire 回溯：{file}:{line}")),
                payload: format!("{{\"type\":\"context.append_loop_event\",\"tag\":\"{tag}\"}}"),
            },
        )
    }

    #[test]
    fn backfill_import_and_chain_green() {
        let dir = TempDir::new("bf-basic");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        assert_eq!(db.backfill_cursor("f1").expect("游标"), 0, "无记录 = 0");
        let items: Vec<_> = (1..=3).map(|l| backfill_item("f1", l, "x")).collect();
        let stats = db.append_backfill("f1", &items, 3).expect("导入");
        assert_eq!(
            stats,
            BackfillStats {
                imported: 3,
                dup_skipped: 0
            }
        );
        assert_eq!(db.count().expect("count"), 3);
        assert_eq!(db.verify_chain(), Ok(3));
        assert_eq!(db.backfill_cursor("f1").expect("游标"), 3);
        // 事件名与 provenance 抽查
        let (ev, reason): (String, Option<String>) = db
            .conn
            .query_row("SELECT event, reason FROM events WHERE id = 2", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("读行 2");
        assert_eq!(ev, "wire.tool_call");
        assert_eq!(reason.as_deref(), Some("wire 回溯：f1:2"));
    }

    #[test]
    fn backfill_reimport_is_zero_new() {
        let dir = TempDir::new("bf-idem");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        let items: Vec<_> = (1..=3).map(|l| backfill_item("f1", l, "x")).collect();
        db.append_backfill("f1", &items, 3).expect("首导");
        let stats = db.append_backfill("f1", &items, 3).expect("重导");
        assert_eq!(
            stats,
            BackfillStats {
                imported: 0,
                dup_skipped: 3
            },
            "同文件同内容重扫必须 0 新增"
        );
        assert_eq!(db.count().expect("count"), 3);
        assert_eq!(db.verify_chain(), Ok(3));
    }

    #[test]
    fn tamper_backfilled_row_breaks_chain() {
        let dir = TempDir::new("bf-tamper");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        let items: Vec<_> = (1..=2).map(|l| backfill_item("f1", l, "x")).collect();
        db.append_backfill("f1", &items, 2).expect("导入");
        db.conn
            .execute("UPDATE events SET payload = 'forged' WHERE id = 1", [])
            .expect("篡改");
        assert_eq!(
            db.verify_chain(),
            Err(VerifyError::HashMismatch { id: 1 }),
            "回溯导入行同样受链保护"
        );
    }

    #[test]
    fn backfill_mixed_with_live_append() {
        let dir = TempDir::new("bf-mixed");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        db.append(&sample_event("live-1")).expect("实时 1");
        let items: Vec<_> = (1..=2).map(|l| backfill_item("f1", l, "x")).collect();
        db.append_backfill("f1", &items, 2).expect("回溯");
        db.append(&sample_event("live-2")).expect("实时 2");
        assert_eq!(db.count().expect("count"), 4);
        assert_eq!(db.verify_chain(), Ok(4), "实时与回溯混插后链仍绿");
        // 再次回溯不破坏实时行
        let stats = db.append_backfill("f1", &items, 2).expect("重回溯");
        assert_eq!(stats.imported, 0);
        assert_eq!(db.verify_chain(), Ok(4));
    }

    #[test]
    fn backfill_shrink_rescan_dedups_unchanged_lines() {
        let dir = TempDir::new("bf-shrink");
        let db = AuditDb::open(&dir.0.join("audit.db")).expect("开库");
        let v1: Vec<_> = (1..=3).map(|l| backfill_item("f1", l, "old")).collect();
        db.append_backfill("f1", &v1, 3).expect("首导");
        // 协议迁移整文件重写：行 1/2 内容变（新键），行 3 不变（键不变）；游标归零重扫
        let v2: Vec<(String, AuditEvent)> = vec![
            backfill_item("f1", 1, "migrated"),
            backfill_item("f1", 2, "migrated"),
            backfill_item("f1", 3, "old"),
        ];
        let stats = db.append_backfill("f1", &v2, 3).expect("迁移后重扫");
        assert_eq!(
            stats,
            BackfillStats {
                imported: 2,
                dup_skipped: 1
            },
            "未变行去重、变化行作为新行导入"
        );
        assert_eq!(db.count().expect("count"), 5);
        assert_eq!(db.verify_chain(), Ok(5));
    }
}
