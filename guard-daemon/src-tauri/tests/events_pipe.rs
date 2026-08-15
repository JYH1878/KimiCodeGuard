//! 事件管道服务端集成测试：起真实命名管道，模拟 hook 客户端 fire-and-forget 发事件行。
//! 覆盖：三连发入库有序 / 非法 JSON 丢弃不崩 / 启动回收 spool 后删文件 / 管道名契约 / sink 转发。
#![cfg(windows)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use guard_daemon::audit::AuditDb;
use guard_daemon::events_pipe;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 用完即删的临时目录（测试自清理）
struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("kcg-events-test-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).expect("建临时目录");
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\KCG.test.events.{}-{}", std::process::id(), tag)
}

/// 模拟 hook 客户端：fire-and-forget——连接（约 2s 重试）→ 写一行 → 立即断开不等回复
fn client_fire(pipe: &str, line: &str) {
    let mut last_err = String::new();
    for attempt in 0..5 {
        match OpenOptions::new().write(true).open(pipe) {
            Ok(mut f) => {
                f.write_all(line.as_bytes()).unwrap();
                f.write_all(b"\n").unwrap();
                f.flush().unwrap();
                return; // drop 即断开
            }
            Err(e) => {
                last_err = e.to_string();
                if attempt < 4 {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    panic!("连不上测试管道 {pipe}: {last_err}");
}

fn event_line(tag: &str) -> String {
    serde_json::json!({
        "event": "PreToolUse",
        "ts": 1_760_000_000_000i64,
        "session_id": format!("sess-{tag}"),
        "cwd": "D:/work",
        "tool_name": "Bash",
        "decision": "deny",
        "reason": "规则 rm-force",
        "payload": format!("{{\"tag\":\"{tag}\"}}"),
    })
    .to_string()
}

/// 轮询等 db 行数到达 n（worker 异步入库）
fn wait_count(db_path: &std::path::Path, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let db = AuditDb::open(db_path).expect("开库");
        let c = db.count().expect("count");
        if c >= n {
            return;
        }
        if Instant::now() >= deadline {
            let mut buf: Vec<u8> = Vec::new();
            let _ = db.dump_jsonl(&mut buf);
            let text = String::from_utf8(buf).unwrap_or_default();
            let sess: Vec<String> = text
                .lines()
                .filter_map(|l| {
                    serde_json::from_str::<serde_json::Value>(l)
                        .ok()
                        .and_then(|v| {
                            v.get("session_id")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string())
                        })
                })
                .collect();
            panic!("等 {n} 行超时（当前 {c} 行）；已入库 session_id: {sess:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn three_sends_land_in_order() {
    let dir = TempDir::new("order");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let pipe = test_pipe_name("order");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    client_fire(&pipe, &event_line("a"));
    client_fire(&pipe, &event_line("b"));
    client_fire(&pipe, &event_line("c"));

    wait_count(&db_path, 3);
    server.shutdown();

    let db = AuditDb::open(&db_path).expect("回读开库");
    assert_eq!(db.verify_chain().expect("链校验"), 3);
    let mut buf: Vec<u8> = Vec::new();
    db.dump_jsonl(&mut buf).expect("导出");
    let text = String::from_utf8(buf).expect("utf8");
    let tags: Vec<String> = text
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("合法 JSON 行");
            v["session_id"]
                .as_str()
                .expect("session_id 串")
                .trim_start_matches("sess-")
                .to_string()
        })
        .collect();
    assert_eq!(tags, ["a", "b", "c"], "三连发必须按发送顺序入库");
}

#[test]
fn invalid_json_dropped_without_crash() {
    let dir = TempDir::new("garbage");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let pipe = test_pipe_name("garbage");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    client_fire(&pipe, "this is not json");
    client_fire(&pipe, &event_line("ok1"));
    wait_count(&db_path, 1);

    // 服务没崩：再发一条合法事件仍能入库
    client_fire(&pipe, &event_line("ok2"));
    wait_count(&db_path, 2);
    server.shutdown();

    let db = AuditDb::open(&db_path).expect("回读开库");
    assert_eq!(db.verify_chain().expect("链校验"), 2);
}

#[test]
fn spool_recovered_and_deleted_on_start() {
    let dir = TempDir::new("spool");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    std::fs::create_dir_all(spool.parent().unwrap()).expect("建 spool 目录");
    let body = format!(
        "{}\n{}\n{}\n",
        event_line("s1"),
        "not-json-line",
        event_line("s2")
    );
    std::fs::write(&spool, body).expect("写 spool");

    let pipe = test_pipe_name("spool");
    // start 返回即代表 worker 已完成「开库 + spool 回收」
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    assert!(!spool.exists(), "回收后 spool 文件必须删除");
    let db = AuditDb::open(&db_path).expect("开库");
    assert_eq!(db.count().expect("count"), 2, "非法行丢弃，两条合法行入库");
    assert_eq!(db.verify_chain().expect("链校验"), 2);
    server.shutdown();
}

#[test]
fn sink_receives_parsed_events() {
    let dir = TempDir::new("sink");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let pipe = test_pipe_name("sink");
    let (tx, rx) = mpsc::channel();
    let server = events_pipe::start(&pipe, &db_path, &spool, Some(tx)).expect("启动");

    client_fire(&pipe, &event_line("live"));
    let ev = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("sink 应收到事件");
    assert_eq!(ev.id, Some(1), "sink 负载必须带入库行 id（面板游标分页用）");
    assert_eq!(ev.event.event, "PreToolUse");
    assert_eq!(ev.event.session_id, "sess-live");
    wait_count(&db_path, 1);
    server.shutdown();
}

#[test]
fn pipe_name_contract() {
    let name = events_pipe::default_pipe_name();
    assert!(
        name.starts_with(r"\\.\pipe\KimiCodeGuard.events."),
        "事件管道名契约：{name}"
    );
}

#[test]
fn spool_path_contract() {
    let p = events_pipe::default_spool_path();
    assert!(p.ends_with("events.jsonl"), "spool 文件名：{p:?}");
    assert!(
        p.to_string_lossy().contains("KimiCodeGuard"),
        "spool 目录：{p:?}"
    );
}

// ---------- M4：wire 回溯（审计轨 B） ----------

use guard_daemon::events_pipe::{BackfillJob, WorkItem};

/// 把 fixtures/wire/<name> 摆进临时 sessions 树，返回 (root, wire 文件路径)
fn stage_wire_fixture(dir: &TempDir, name: &str, session: &str) -> (PathBuf, PathBuf) {
    let root = dir.0.join("sessions");
    let agent_dir = root.join("wd_t").join(session).join("agents").join("main");
    std::fs::create_dir_all(&agent_dir).expect("建 agents 目录");
    let dst = agent_dir.join("wire.jsonl");
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures")
        .join("wire")
        .join(name);
    std::fs::copy(src, &dst).expect("复制 wire 样本");
    (root, dst)
}

fn submit_backfill(
    server: &events_pipe::Server,
    root: PathBuf,
) -> mpsc::Receiver<events_pipe::BackfillSummary> {
    let (reply_tx, reply_rx) = mpsc::channel();
    server
        .backfill_sender()
        .send(WorkItem::Backfill(BackfillJob {
            root,
            reply: reply_tx,
        }))
        .expect("提交回溯任务");
    reply_rx
}

#[test]
fn backfill_imports_wire_fixture() {
    let dir = TempDir::new("bf");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let (root, _wire) = stage_wire_fixture(&dir, "v2-main-01.jsonl", "session_bf");
    let pipe = test_pipe_name("bf");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    let rx = submit_backfill(&server, root);
    let summary = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("等回溯回复");
    assert!(summary.db_ok);
    assert_eq!(summary.files, 1);
    assert_eq!(summary.imported, 8, "v2 样本应导入 8 条");
    assert_eq!(summary.torn_files, 1, "样本末行撕裂");
    server.shutdown();

    let db = AuditDb::open(&db_path).expect("回读开库");
    assert_eq!(db.count().expect("count"), 8);
    assert_eq!(db.verify_chain().expect("链校验"), 8);
    let wire_file = _wire.display().to_string();
    assert_eq!(
        db.backfill_cursor(&wire_file).expect("游标"),
        18,
        "19 行撕裂 1 行，游标 18"
    );
    // 事件名抽查：导出含 wire.* 命名空间
    let mut buf: Vec<u8> = Vec::new();
    db.dump_jsonl(&mut buf).expect("导出");
    let text = String::from_utf8(buf).expect("utf8");
    assert!(text.contains("\"wire.session_start\""));
    assert!(text.contains("\"wire.user_prompt\""));
    assert!(text.contains("\"wire.tool_call\""));
    assert!(text.contains("\"wire.permission\""));
}

#[test]
fn backfill_rerun_is_zero_new() {
    let dir = TempDir::new("bf2");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let (root, _w) = stage_wire_fixture(&dir, "v2-main-01.jsonl", "session_bf2");
    let pipe = test_pipe_name("bf2");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    let first = submit_backfill(&server, root.clone())
        .recv_timeout(Duration::from_secs(10))
        .expect("首扫回复");
    assert_eq!(first.imported, 8);
    let second = submit_backfill(&server, root)
        .recv_timeout(Duration::from_secs(10))
        .expect("重扫回复");
    assert_eq!(second.imported, 0, "增量重扫必须 0 新增");
    server.shutdown();

    let db = AuditDb::open(&db_path).expect("回读开库");
    assert_eq!(db.count().expect("count"), 8);
    assert_eq!(db.verify_chain().expect("链校验"), 8);
}

#[test]
fn backfill_db_unavailable_replies_db_not_ok() {
    let dir = TempDir::new("bf3");
    // 用文件挡住目录路径：AuditDb::open 必失败
    let blocker = dir.0.join("blocker");
    std::fs::write(&blocker, "not a dir").expect("写挡路文件");
    let db_path = blocker.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let (root, _w) = stage_wire_fixture(&dir, "subagent-01.jsonl", "session_bf3");
    let pipe = test_pipe_name("bf3");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    let summary = submit_backfill(&server, root)
        .recv_timeout(Duration::from_secs(10))
        .expect("回溯回复");
    assert!(!summary.db_ok, "库不可用必须 db_ok=false");
    assert_eq!(summary.imported, 0);

    // 服务没崩：管道事件照常受理（只丢弃+日志），shutdown 正常
    client_fire(&pipe, &event_line("still-alive"));
    std::thread::sleep(Duration::from_millis(300));
    server.shutdown();
}

#[test]
fn events_served_after_backfill() {
    let dir = TempDir::new("bf4");
    let db_path = dir.0.join("audit.db");
    let spool = dir.0.join("spool").join("events.jsonl");
    let (root, _w) = stage_wire_fixture(&dir, "v1-main-01.jsonl", "session_bf4");
    let pipe = test_pipe_name("bf4");
    let server = events_pipe::start(&pipe, &db_path, &spool, None).expect("启动");

    let summary = submit_backfill(&server, root)
        .recv_timeout(Duration::from_secs(10))
        .expect("回溯回复");
    assert_eq!(summary.imported, 4, "v1 样本应导入 4 条");

    // 回溯后管道实时事件照常入库，且与回溯行同链
    client_fire(&pipe, &event_line("after"));
    wait_count(&db_path, 5);
    server.shutdown();

    let db = AuditDb::open(&db_path).expect("回读开库");
    assert_eq!(db.verify_chain().expect("链校验"), 5, "回溯+实时混插链绿");
}
