//! 真机反向验证专用（GOAL 反向验证 #1）：对真实 audit.db 做 SQL 篡改与还原。
//! 默认全忽略，手动跑（在 guard-daemon/src-tauri 下）：
//!   cargo test --test audit_real -- --ignored --nocapture
//! 流程：
//!   1. tamper_first_row —— 改首行 payload（原值备份到 audit.kcg-tamper-backup.json），自检链必红；
//!      此时点托盘「校验审计链」必须报红（人工/截图确认）。
//!   2. restore_first_row —— 还原首行并删备份，自检链回绿；托盘校验亦应回绿。
//!
//! 库路径默认 %LOCALAPPDATA%\KimiCodeGuard\audit.db，KCG_AUDIT_DB 可覆盖。
#![cfg(windows)]

use std::path::PathBuf;

use guard_daemon::audit;
use rusqlite::Connection;

fn db_path() -> PathBuf {
    std::env::var("KCG_AUDIT_DB")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(audit::default_db_path)
}

fn backup_path() -> PathBuf {
    let mut p = db_path();
    p.set_extension("kcg-tamper-backup.json");
    p
}

#[test]
#[ignore = "真机反向验证：篡改首行（改完请人工点托盘校验确认报红）"]
fn tamper_first_row() {
    let path = db_path();
    assert!(path.exists(), "audit.db 不存在：{}", path.display());
    let conn = Connection::open(&path).expect("开库");
    let payload: String = conn
        .query_row(
            "SELECT payload FROM events ORDER BY id ASC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("库里至少要有一行（先跑 E2E 造数据）");
    std::fs::write(
        backup_path(),
        serde_json::json!({"payload": payload}).to_string(),
    )
    .expect("写备份");
    conn.execute(
        "UPDATE events SET payload = 'KCG-TAMPERED-BY-TEST' WHERE id = (SELECT MIN(id) FROM events)",
        [],
    )
    .expect("篡改");
    drop(conn);

    let db = audit::AuditDb::open(&path).expect("重开库");
    assert!(db.verify_chain().is_err(), "篡改后链校验必须红");
    println!("已篡改首行：请点托盘「校验审计链」确认报红，然后跑 restore_first_row 还原");
}

#[test]
#[ignore = "真机反向验证：还原首行"]
fn restore_first_row() {
    let backup = std::fs::read_to_string(backup_path()).expect("先跑 tamper_first_row");
    let v: serde_json::Value = serde_json::from_str(&backup).expect("备份是合法 JSON");
    let payload = v["payload"].as_str().expect("备份含 payload").to_string();

    let path = db_path();
    let conn = Connection::open(&path).expect("开库");
    conn.execute(
        "UPDATE events SET payload = ?1 WHERE id = (SELECT MIN(id) FROM events)",
        [payload],
    )
    .expect("还原");
    drop(conn);
    std::fs::remove_file(backup_path()).expect("删备份");

    let db = audit::AuditDb::open(&path).expect("重开库");
    assert!(db.verify_chain().is_ok(), "还原后链校验必须绿");
    println!("已还原：链校验回绿");
}
