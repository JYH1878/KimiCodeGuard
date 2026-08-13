//! fixtures 回归门禁：真实采集的 payload 必须足量、合法、覆盖面够，
//! 且每条都能被解析器解析出工具名与关键字段（M1 扩展）。

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use guard_hook::payload::Payload;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}

fn fixture_entries() -> Vec<PathBuf> {
    let dir = fixtures_dir();
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("fixtures 目录不可读 {}: {e}（先跑采集）", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();
    entries
}

#[test]
fn fixtures_are_sufficient_and_valid() {
    let entries = fixture_entries();
    assert!(
        entries.len() >= 10,
        "fixtures 至少需要 10 条真实 payload，当前 {} 条",
        entries.len()
    );

    let mut tools = HashSet::new();
    for path in &entries {
        let raw =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("{} 读取失败: {e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{} 不是合法 JSON: {e}", path.display()));
        assert_eq!(
            v.get("hook_event_name").and_then(|x| x.as_str()),
            Some("PreToolUse"),
            "{} 的 hook_event_name 必须是 PreToolUse",
            path.display()
        );
        let tool = v
            .get("tool_name")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("{} 缺 tool_name", path.display()));
        assert!(!tool.is_empty(), "{} 的 tool_name 为空", path.display());
        tools.insert(tool.to_string());
    }

    assert!(
        tools.len() >= 4,
        "fixtures 至少覆盖 4 种工具，当前 {:?}",
        tools
    );
}

/// M1：14 条真实 payload 必须全部解析成功，且工具名与关键字段可取。
#[test]
fn all_fixtures_parse_with_tool_and_key_fields() {
    let entries = fixture_entries();
    assert_eq!(entries.len(), 14, "fixtures 当前应为 14 条（M0 采集量）");

    for path in &entries {
        let raw = fs::read(path).unwrap_or_else(|e| panic!("{} 读取失败: {e}", path.display()));
        let p = Payload::parse(&raw)
            .unwrap_or_else(|| panic!("{} 解析失败（真实 payload 必须可解析）", path.display()));
        let fname = path.file_name().unwrap().to_string_lossy().to_string();

        // 公共字段齐全（fixtures 均为完整采集，不应触发缺失降级）
        assert!(
            p.notes.is_empty(),
            "{fname} 不应有字段缺失 note: {:?}",
            p.notes
        );
        for (name, val) in [
            ("hook_event_name", &p.hook_event_name),
            ("session_id", &p.session_id),
            ("cwd", &p.cwd),
            ("tool_name", &p.tool_name),
            ("tool_call_id", &p.tool_call_id),
        ] {
            assert!(val.is_some(), "{fname} 缺 {name}");
        }

        // 工具名与按工具取关键字段
        let tool = p.tool_name.as_deref().unwrap();
        match tool {
            "Bash" => assert!(
                p.bash_command().is_some_and(|c| !c.is_empty()),
                "{fname} Bash 缺 command"
            ),
            "Read" | "Write" | "Edit" => assert!(
                p.file_path().is_some_and(|s| !s.is_empty()),
                "{fname} {tool} 缺 path"
            ),
            "Glob" | "Grep" | "FetchURL" | "WebSearch" => {
                assert!(p.bash_command().is_none() && p.file_path().is_none());
            }
            other => panic!("{fname} 出现未知工具 {other}（更新解析器认知）"),
        }

        // v1/v2 引擎字段差异（HANDOFF §二）：v2 多 client_type
        if fname.starts_with("v2-") {
            assert_eq!(
                p.client_type.as_deref(),
                Some("kimi_code_cli"),
                "{fname} v2 应带 client_type"
            );
        } else {
            assert!(p.client_type.is_none(), "{fname} v1 不应有 client_type");
        }
        // 本批 fixtures 均为 headless 采集：无 session_title
        assert!(
            p.session_title.is_none(),
            "{fname} headless 不应有 session_title"
        );
    }
}
