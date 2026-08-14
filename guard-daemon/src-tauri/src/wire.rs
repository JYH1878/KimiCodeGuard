//! 审计轨道 B：wire.jsonl 回溯解析（AGENTS.md D7，M4）。
//!
//! 解析 `~/.kimi-code/sessions/<wd>/<sid>/agents/<agent>/wire.jsonl`，把安装前的
//! 安全相关历史事件提取为可入 audit.db 的 `AuditEvent`（event 用 `wire.*` 命名空间，
//! 与轨 A 实时事件区分）。协议事实（2026-08-14 按 0.36.0 源码 wire-manifest +
//! 本机 128 个真实文件核对）：
//!
//! - 信封：每行 `{type, time?, ...payload}`；`time` = epoch 毫秒，旧数据可能秒级
//!   （官方导出扫描器口径：`>1e12` 按 ms，`≤1e12` 按 s×1000 归一）。
//! - 导入集（安全相关）：`metadata`→`wire.session_start`（ts=created_at）；
//!   `turn.prompt` 且 `origin.kind=="user"`→`wire.user_prompt`；
//!   `context.append_loop_event` 内 `event.type=="tool.call"`→`wire.tool_call`；
//!   `permission.record_approval_result`→`wire.permission`（decision 原样）。
//! - `context.append_message` 是用户 prompt 的重放副本，必须跳过（双计陷阱）。
//! - 容错：坏行跳过不计入已消费行数；撕裂末行（无 \n 结尾且 JSON 非法）留待下次；
//!   未知 type 静默跳过；可导入记录缺 ts 跳过。
//! - session/agent 标识只在路径里；cwd 用文件内最后一个 `config.update.cwd` 回填。
//! - 导入行 payload = 原始行全文（取证保真），reason = 回溯来源「相对路径:行号」。

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::audit::AuditEvent;

/// 导入事件名（audit.db 的 event 列）
pub const EV_SESSION_START: &str = "wire.session_start";
pub const EV_USER_PROMPT: &str = "wire.user_prompt";
pub const EV_TOOL_CALL: &str = "wire.tool_call";
pub const EV_PERMISSION: &str = "wire.permission";

/// 单文件上限（numbat 同口径）：超过即跳过，防极端文件拖垮回溯
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// sessions 根目录：`KCG_WIRE_ROOT`（仅测试覆盖）> `$KIMI_CODE_HOME/sessions`
/// > `~/.kimi-code/sessions`（KIMI_CODE_HOME 是官方整体覆盖，D4）。
pub fn default_sessions_root() -> PathBuf {
    if let Ok(p) = std::env::var("KCG_WIRE_ROOT") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(home) = std::env::var("KIMI_CODE_HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join("sessions");
        }
    }
    let home = std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join(".kimi-code").join("sessions")
}

/// 从 wire.jsonl 路径取 (session_id, agent_id)。严格形状：
/// `…/<wd>/<sid>/agents/<agent>/wire.jsonl`（agents 段字面匹配，形状不符 → None）。
pub fn parse_wire_path(path: &Path) -> Option<(String, String)> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.eq_ignore_ascii_case("wire.jsonl") {
        return None;
    }
    let agent_dir = path.parent()?;
    let agents_dir = agent_dir.parent()?;
    if agents_dir.file_name()?.to_str()? != "agents" {
        return None;
    }
    let sid_dir = agents_dir.parent()?;
    let session_id = sid_dir.file_name()?.to_str()?.to_string();
    let agent_id = agent_dir.file_name()?.to_str()?.to_string();
    if session_id.is_empty() || agent_id.is_empty() {
        return None;
    }
    Some((session_id, agent_id))
}

/// 遍历 `<root>/<wd>/<sid>/agents/<agent>/wire.jsonl`，返回排序后的文件清单。
/// 根不存在或中间层缺失都按空处理（回溯是锦上添花，不许崩）。
pub fn discover(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(wds) = std::fs::read_dir(root) else {
        return out;
    };
    for wd in wds.flatten() {
        let Ok(sids) = std::fs::read_dir(wd.path()) else {
            continue;
        };
        for sid in sids.flatten() {
            let agents = sid.path().join("agents");
            let Ok(agent_dirs) = std::fs::read_dir(&agents) else {
                continue;
            };
            for agent in agent_dirs.flatten() {
                let candidate = agent.path().join("wire.jsonl");
                if candidate.is_file() {
                    out.push(candidate);
                }
            }
        }
    }
    out.sort();
    out
}

/// 单行提取结果
#[derive(Debug, PartialEq, Eq)]
pub enum Extract {
    /// 合法行但不在导入集（含可导入记录缺 ts 的降级）
    Skip,
    /// 非法 JSON / 非对象 / 缺 type 判别字段
    Bad,
    /// 命中导入集
    Event(ExtractedEvent),
}

/// 一条命中导入集的记录（AuditEvent 的半成品，缺 session_id/cwd/reason/payload 语境）
#[derive(Debug, PartialEq, Eq)]
pub struct ExtractedEvent {
    /// 归一后的 Unix 毫秒
    pub ts: i64,
    /// `wire.*` 事件名
    pub event: &'static str,
    pub tool_name: Option<String>,
    pub decision: Option<String>,
}

/// time 归一：`>1e12` 视为毫秒原样，`0 < t ≤ 1e12` 视为秒×1000，其余（缺/0/负）→ None
fn normalize_ts(t: Option<i64>) -> Option<i64> {
    const MS_THRESHOLD: i64 = 1_000_000_000_000;
    match t {
        Some(t) if t > MS_THRESHOLD => Some(t),
        Some(t) if t > 0 => Some(t * 1000),
        _ => None,
    }
}

/// 提取一行（trim 后）。映射表见模块头注释。
pub fn extract(line: &str) -> Extract {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
        return Extract::Bad;
    };
    let Some(obj) = v.as_object() else {
        return Extract::Bad;
    };
    let Some(ty) = obj.get("type").and_then(|t| t.as_str()) else {
        return Extract::Bad;
    };
    let time = || obj.get("time").and_then(|t| t.as_i64());
    match ty {
        "metadata" => match normalize_ts(obj.get("created_at").and_then(|t| t.as_i64())) {
            Some(ts) => Extract::Event(ExtractedEvent {
                ts,
                event: EV_SESSION_START,
                tool_name: None,
                decision: None,
            }),
            None => Extract::Skip,
        },
        "turn.prompt" => {
            let kind = obj
                .get("origin")
                .and_then(|o| o.get("kind"))
                .and_then(|k| k.as_str());
            if kind != Some("user") {
                return Extract::Skip; // injection/task 等注入来源不是用户亲口输入
            }
            match normalize_ts(time()) {
                Some(ts) => Extract::Event(ExtractedEvent {
                    ts,
                    event: EV_USER_PROMPT,
                    tool_name: None,
                    decision: None,
                }),
                None => Extract::Skip,
            }
        }
        "context.append_loop_event" => {
            let Some(ev) = obj.get("event").and_then(|e| e.as_object()) else {
                return Extract::Skip;
            };
            match ev.get("type").and_then(|t| t.as_str()) {
                Some("tool.call") => {
                    let Some(name) = ev.get("name").and_then(|n| n.as_str()) else {
                        return Extract::Skip; // 可导入但缺工具名：降级跳过（D5）
                    };
                    match normalize_ts(time()) {
                        Some(ts) => Extract::Event(ExtractedEvent {
                            ts,
                            event: EV_TOOL_CALL,
                            tool_name: Some(name.to_string()),
                            decision: None,
                        }),
                        None => Extract::Skip,
                    }
                }
                _ => Extract::Skip, // step.*/content.part/tool.result 等一律不导入
            }
        }
        "permission.record_approval_result" => {
            let Some(decision) = obj
                .get("result")
                .and_then(|r| r.get("decision"))
                .and_then(|d| d.as_str())
            else {
                return Extract::Skip;
            };
            match normalize_ts(time()) {
                Some(ts) => Extract::Event(ExtractedEvent {
                    ts,
                    event: EV_PERMISSION,
                    tool_name: obj
                        .get("toolName")
                        .and_then(|n| n.as_str())
                        .map(str::to_string),
                    decision: Some(decision.to_string()),
                }),
                None => Extract::Skip,
            }
        }
        _ => Extract::Skip, // 未知/ bookkeeping 类型静默跳过（含 append_message 重放副本）
    }
}

/// 一条待导入记录：行号 + 去重键 + 完整 AuditEvent
#[derive(Debug)]
pub struct BackfillItem {
    /// 1-based 行号
    pub line_no: u64,
    /// sha256(`<path>:<line_no>:<raw_line>`) 十六进制（跨重扫/迁移重写去重）
    pub key: String,
    pub event: AuditEvent,
}

/// 单文件扫描产出
#[derive(Debug, Default)]
pub struct FileScan {
    pub items: Vec<BackfillItem>,
    /// 已消费行数（含 skip/bad 行，不含撕裂末行）——调用方存为下次起点游标
    pub lines_consumed: u64,
    /// 非法 JSON 行数（不含撕裂末行）
    pub bad_lines: u64,
    /// 末行撕裂（无 \n 结尾且 JSON 非法）：未消费，下次重读
    pub torn: bool,
    /// 文件超过上限被跳过
    pub oversized: bool,
}

/// 扫描单个 wire.jsonl。`from_line`（1-based）之前的行只维护 cwd 语境不产出
/// （增量重扫时 cwd 回填仍正确）；`root` 用于 reason 里的相对路径 provenance。
/// 全程不 panic：文件打不开/形状非法 → 空 FileScan。
pub fn scan_file(path: &Path, root: &Path, from_line: u64) -> FileScan {
    let mut scan = FileScan::default();
    let Some((session_id, _agent_id)) = parse_wire_path(path) else {
        return scan;
    };
    let Ok(meta) = std::fs::metadata(path) else {
        return scan;
    };
    if meta.len() > MAX_FILE_BYTES {
        scan.oversized = true;
        return scan;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return scan;
    };
    // 末字节不是 \n ⇒ 最后一行可能是写入中的撕裂行（检查完把游标退回文件头）
    let ends_with_newline = {
        let mut f = &file;
        let mut buf = [0u8; 1];
        let ends = meta.len() == 0
            || (f.seek(SeekFrom::End(-1)).is_ok()
                && f.read_exact(&mut buf).is_ok()
                && buf[0] == b'\n');
        let _ = f.seek(SeekFrom::Start(0));
        ends
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/");
    let path_key = path.display().to_string();

    let mut cwd = String::new();
    let mut last_outcome_bad = false;
    let reader = BufReader::new(file);
    for (idx, line) in reader.lines().enumerate() {
        let line_no = (idx as u64) + 1;
        let Ok(raw) = line else {
            scan.bad_lines += 1;
            last_outcome_bad = true;
            continue;
        };
        let raw = raw.trim_end_matches('\r');
        if raw.trim().is_empty() {
            last_outcome_bad = false;
            continue; // 空行不计消费也不计数（官方读取器同：空行跳过）
        }
        // cwd 语境：无论是否在导入区间都要跟踪（增量重扫回填正确性）
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
            if v.get("type").and_then(|t| t.as_str()) == Some("config.update") {
                if let Some(c) = v.get("cwd").and_then(|c| c.as_str()) {
                    cwd = c.to_string();
                }
            }
        }
        scan.lines_consumed = line_no;
        last_outcome_bad = false;
        if line_no < from_line {
            continue;
        }
        match extract(raw) {
            Extract::Skip => {}
            Extract::Bad => {
                scan.bad_lines += 1;
                last_outcome_bad = true;
            }
            Extract::Event(e) => {
                let key = sha256_hex(&format!("{path_key}:{line_no}:{raw}"));
                scan.items.push(BackfillItem {
                    line_no,
                    key,
                    event: AuditEvent {
                        ts: e.ts,
                        event: e.event.to_string(),
                        session_id: session_id.clone(),
                        cwd: cwd.clone(),
                        tool_name: e.tool_name,
                        decision: e.decision,
                        reason: Some(format!("wire 回溯：{rel}:{line_no}")),
                        payload: raw.to_string(),
                    },
                });
            }
        }
    }
    // 撕裂末行：无 \n 结尾且 JSON 非法 ⇒ 不算消费，下次文件长全后重读
    if !ends_with_newline && last_outcome_bad {
        scan.torn = true;
        scan.bad_lines -= 1;
        scan.lines_consumed -= 1;
        scan.items.retain(|it| it.line_no <= scan.lines_consumed);
    }
    scan
}

/// sha256 小写十六进制（去重键用；与 audit.rs 的链式 hash 无关）
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
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

    /// 用完即删的临时目录（与 audit.rs 测试同范式）
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir()
                .join(format!("kcg-wire-test-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).expect("建临时目录");
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures")
            .join("wire")
            .join(name)
    }

    // —— extract：导入集映射 ——
    #[test]
    fn metadata_maps_to_session_start() {
        let e =
            extract(r#"{"type":"metadata","protocol_version":"1.5","created_at":1785000000000}"#);
        assert_eq!(
            e,
            Extract::Event(ExtractedEvent {
                ts: 1785000000000,
                event: EV_SESSION_START,
                tool_name: None,
                decision: None,
            })
        );
    }

    #[test]
    fn user_prompt_maps_but_injection_skips() {
        let user = extract(
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"hi"}],"origin":{"kind":"user"},"time":1785000001000}"#,
        );
        assert!(matches!(
            &user,
            Extract::Event(ExtractedEvent {
                event: EV_USER_PROMPT,
                ts: 1785000001000,
                ..
            })
        ));
        for origin in ["injection", "task", "hook"] {
            let line = format!(
                r#"{{"type":"turn.prompt","input":[{{"type":"text","text":"x"}}],"origin":{{"kind":"{origin}"}},"time":1785000001000}}"#
            );
            assert_eq!(extract(&line), Extract::Skip, "origin={origin} 必须跳过");
        }
        // origin 缺失也跳过
        assert_eq!(
            extract(r#"{"type":"turn.prompt","input":[],"time":1785000001000}"#),
            Extract::Skip
        );
    }

    #[test]
    fn append_message_is_replay_and_skips() {
        // 与 turn.prompt 同内容的重放副本：双计陷阱，必须跳过
        let e = extract(
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"hi"}],"toolCalls":[]},"time":1785000001000}"#,
        );
        assert_eq!(e, Extract::Skip);
    }

    #[test]
    fn tool_call_maps_with_name() {
        let e = extract(
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"c1","name":"Bash","args":{"command":"ls"}},"time":1785000002000}"#,
        );
        assert_eq!(
            e,
            Extract::Event(ExtractedEvent {
                ts: 1785000002000,
                event: EV_TOOL_CALL,
                tool_name: Some("Bash".to_string()),
                decision: None,
            })
        );
    }

    #[test]
    fn tool_call_missing_name_or_time_skips() {
        assert_eq!(
            extract(
                r#"{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"c1"},"time":1785000002000}"#
            ),
            Extract::Skip,
            "缺 name 降级跳过"
        );
        assert_eq!(
            extract(
                r#"{"type":"context.append_loop_event","event":{"type":"tool.call","name":"Bash","args":{}}}"#
            ),
            Extract::Skip,
            "缺 time 降级跳过"
        );
    }

    #[test]
    fn other_loop_events_skip() {
        for ev in [
            r#"{"type":"step.begin","uuid":"u1"}"#,
            r#"{"type":"content.part","part":{"type":"think","think":"x"}}"#,
            r#"{"type":"tool.result","toolCallId":"c1","result":{"output":"o"}}"#,
            r#"{"type":"step.end","uuid":"u1"}"#,
        ] {
            let line = format!(
                r#"{{"type":"context.append_loop_event","event":{ev},"time":1785000002000}}"#
            );
            assert_eq!(extract(&line), Extract::Skip, "{ev} 必须跳过");
        }
    }

    #[test]
    fn permission_result_maps_decision() {
        for decision in ["approved", "rejected", "cancelled"] {
            let line = format!(
                r#"{{"type":"permission.record_approval_result","toolCallId":"c1","toolName":"Bash","result":{{"decision":"{decision}"}},"time":1785000005000}}"#
            );
            assert_eq!(
                extract(&line),
                Extract::Event(ExtractedEvent {
                    ts: 1785000005000,
                    event: EV_PERMISSION,
                    tool_name: Some("Bash".to_string()),
                    decision: Some(decision.to_string()),
                })
            );
        }
        // 缺 result.decision → 跳过
        assert_eq!(
            extract(
                r#"{"type":"permission.record_approval_result","toolCallId":"c1","time":1785000005000}"#
            ),
            Extract::Skip
        );
    }

    #[test]
    fn bookkeeping_and_unknown_types_skip() {
        for line in [
            r#"{"type":"usage.record","model":"kimi-k2","usage":{"output":5},"time":1785000006000}"#,
            r#"{"type":"llm.request","kind":"loop","model":"kimi-k2","time":1785000001000}"#,
            r#"{"type":"future.unknown_operation","whatever":{},"time":1785000007000}"#,
            r#"{"type":"micro_compaction.apply","cutoff":42,"time":1785000002000}"#,
            r#"{"type":"config.update","profileName":"agent","time":1785000000001}"#,
        ] {
            assert_eq!(extract(line), Extract::Skip, "{line}");
        }
    }

    #[test]
    fn bad_lines_are_bad() {
        assert_eq!(extract("{not json"), Extract::Bad);
        assert_eq!(extract("[1,2,3]"), Extract::Bad, "非对象");
        assert_eq!(extract(r#"{"foo":1}"#), Extract::Bad, "缺 type");
        assert_eq!(extract(""), Extract::Bad);
    }

    #[test]
    fn ts_seconds_normalized_to_ms() {
        let e = extract(
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","name":"Read","args":{}},"time":1784000100}"#,
        );
        assert_eq!(
            e,
            Extract::Event(ExtractedEvent {
                ts: 1784000100000,
                event: EV_TOOL_CALL,
                tool_name: Some("Read".to_string()),
                decision: None,
            }),
            "秒级 time 必须 ×1000"
        );
    }

    #[test]
    fn metadata_without_created_at_skips() {
        assert_eq!(
            extract(r#"{"type":"metadata","protocol_version":"1.5"}"#),
            Extract::Skip
        );
    }

    // —— parse_wire_path ——
    #[test]
    fn wire_path_shapes() {
        let (sid, agent) = parse_wire_path(Path::new(
            r"C:\Users\x\.kimi-code\sessions\wd_a_1\session_abc\agents\main\wire.jsonl",
        ))
        .expect("main 形状");
        assert_eq!((sid.as_str(), agent.as_str()), ("session_abc", "main"));
        let (sid, agent) = parse_wire_path(Path::new(
            "/home/x/.kimi-code/sessions/wd_b_2/session_def/agents/agent-0/wire.jsonl",
        ))
        .expect("子 agent 形状");
        assert_eq!((sid.as_str(), agent.as_str()), ("session_def", "agent-0"));
        assert!(
            parse_wire_path(Path::new(r"C:\x\sessions\wd\sid\agents\main\other.jsonl")).is_none(),
            "文件名不符"
        );
        assert!(
            parse_wire_path(Path::new(r"C:\x\sessions\wd\sid\wire.jsonl")).is_none(),
            "缺 agents 段"
        );
        assert!(
            parse_wire_path(Path::new("wire.jsonl")).is_none(),
            "裸文件名无语境"
        );
    }

    // —— discover ——
    #[test]
    fn discover_walks_three_levels() {
        let dir = TempDir::new("discover");
        let root = dir.0.join("sessions");
        let p1 = root.join("wd_a/session_1/agents/main");
        let p2 = root.join("wd_a/session_1/agents/agent-0");
        let p3 = root.join("wd_b/session_2/agents/main");
        std::fs::create_dir_all(&p1).expect("d1");
        std::fs::create_dir_all(&p2).expect("d2");
        std::fs::create_dir_all(&p3).expect("d3");
        std::fs::write(p1.join("wire.jsonl"), "{}").expect("w1");
        std::fs::write(p2.join("wire.jsonl"), "{}").expect("w2");
        std::fs::write(p3.join("wire.jsonl"), "{}").expect("w3");
        // 干扰项：非 wire 文件、session_index.jsonl、agents 之外的散落文件
        std::fs::write(p1.join("blobs"), "x").expect("w4");
        std::fs::write(root.join("wd_a/session_1/session_index.jsonl"), "{}").expect("w5");
        let found = discover(&root);
        assert_eq!(found.len(), 3, "只收 agents/*/wire.jsonl：{found:?}");
        assert!(
            discover(&root.join("不存在")).is_empty(),
            "根不存在按空处理"
        );
    }

    // —— scan_file（对 fixtures） ——
    #[test]
    fn scan_v2_fixture_counts_and_content() {
        let f = fixture("v2-main-01.jsonl");
        // 伪造成 sessions 树形状（scan_file 需要从路径取 session_id）
        let dir = TempDir::new("scanv2");
        let root = dir.0.join("sessions");
        let agent_dir = root.join("wd_t/session_v2/agents/main");
        std::fs::create_dir_all(&agent_dir).expect("建目录");
        let dst = agent_dir.join("wire.jsonl");
        std::fs::copy(&f, &dst).expect("复制样本");

        let scan = scan_file(&dst, &root, 1);
        assert!(scan.torn, "样本末行是撕裂行");
        assert_eq!(scan.bad_lines, 0, "撕裂行不计 bad");
        assert_eq!(scan.lines_consumed, 18, "19 行文件撕裂 1 行消费 18");
        assert_eq!(
            scan.items.len(),
            8,
            "metadata1+prompt2+tool.call3+permission2"
        );
        let events: Vec<&str> = scan.items.iter().map(|i| i.event.event.as_str()).collect();
        assert_eq!(
            events,
            [
                EV_SESSION_START,
                EV_USER_PROMPT,
                EV_TOOL_CALL,
                EV_TOOL_CALL,
                EV_TOOL_CALL,
                EV_PERMISSION,
                EV_PERMISSION,
                EV_USER_PROMPT
            ]
        );
        // 字段抽查
        assert_eq!(scan.items[0].event.ts, 1785000000000);
        assert!(scan.items[0].event.payload.contains("protocol_version"));
        assert_eq!(scan.items[2].event.tool_name.as_deref(), Some("Bash"));
        assert_eq!(
            scan.items[2].event.cwd, "D:/work/demo",
            "config.update 回填"
        );
        assert_eq!(scan.items[6].event.decision.as_deref(), Some("rejected"));
        assert!(
            scan.items[2]
                .event
                .reason
                .as_deref()
                .expect("reason")
                .ends_with(":9"),
            "provenance 带行号：{:?}",
            scan.items[2].event.reason
        );
        // 去重键稳定
        let again = scan_file(&dst, &root, 1);
        assert_eq!(scan.items[2].key, again.items[2].key);
    }

    #[test]
    fn scan_v1_fixture_seconds_ts_and_bad_line() {
        let f = fixture("v1-main-01.jsonl");
        let dir = TempDir::new("scanv1");
        let root = dir.0.join("sessions");
        let agent_dir = root.join("wd_t/session_v1/agents/main");
        std::fs::create_dir_all(&agent_dir).expect("建目录");
        let dst = agent_dir.join("wire.jsonl");
        std::fs::copy(&f, &dst).expect("复制样本");

        let scan = scan_file(&dst, &root, 1);
        assert!(!scan.torn, "v1 样本有换行结尾");
        assert_eq!(scan.bad_lines, 1, "中部坏行计数");
        assert_eq!(scan.items.len(), 4, "metadata1+prompt1+tool.call2");
        assert_eq!(scan.items[2].event.ts, 1784000100000, "秒级归一");
        assert_eq!(
            scan.items[0].event.cwd, "",
            "无 cwd 的 config.update → 空串"
        );
        assert_eq!(scan.items[0].event.session_id, "session_v1");
    }

    #[test]
    fn scan_resume_keeps_cwd_context() {
        let f = fixture("v2-main-01.jsonl");
        let dir = TempDir::new("resume");
        let root = dir.0.join("sessions");
        let agent_dir = root.join("wd_t/session_r/agents/main");
        std::fs::create_dir_all(&agent_dir).expect("建目录");
        let dst = agent_dir.join("wire.jsonl");
        std::fs::copy(&f, &dst).expect("复制样本");

        let scan = scan_file(&dst, &root, 14);
        assert!(
            scan.items.iter().all(|i| i.line_no >= 14),
            "只产出 from_line 之后"
        );
        assert_eq!(
            scan.items.len(),
            2,
            "14 行后：permission(rejected)+prompt（未知类型跳过）"
        );
        assert_eq!(
            scan.items[1].event.cwd, "D:/work/demo",
            "续扫也要回填第 2 行的 cwd"
        );
        assert_eq!(scan.lines_consumed, 18);
    }

    #[test]
    fn scan_torn_line_recovers_after_completion() {
        // 先写半行（无 \n），扫描应 torn 且不消费；补全后再扫应导入
        let dir = TempDir::new("torn");
        let root = dir.0.join("sessions");
        let agent_dir = root.join("wd_t/session_t/agents/main");
        std::fs::create_dir_all(&agent_dir).expect("建目录");
        let dst = agent_dir.join("wire.jsonl");
        let part1 =
            "{\"type\":\"metadata\",\"protocol_version\":\"1.5\",\"created_at\":1785000000000}\n";
        let half = "{\"type\":\"context.append_loop_event\",\"event\":{\"type\":\"tool.cal";
        std::fs::write(&dst, format!("{part1}{half}")).expect("写半行");
        let scan1 = scan_file(&dst, &root, 1);
        assert!(scan1.torn && scan1.lines_consumed == 1 && scan1.items.len() == 1);

        let full = "{\"type\":\"context.append_loop_event\",\"event\":{\"type\":\"tool.call\",\"toolCallId\":\"c\",\"name\":\"Bash\",\"args\":{}},\"time\":1785000009000}\n";
        std::fs::write(&dst, format!("{part1}{full}")).expect("补全");
        let scan2 = scan_file(&dst, &root, scan1.lines_consumed + 1);
        assert!(!scan2.torn);
        assert_eq!(scan2.items.len(), 1);
        assert_eq!(scan2.items[0].event.tool_name.as_deref(), Some("Bash"));
    }
}
