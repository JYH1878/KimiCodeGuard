//! fixtures 回归门禁：真实采集的 payload 必须足量、合法、覆盖面够。

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}

#[test]
fn fixtures_are_sufficient_and_valid() {
    let dir = fixtures_dir();
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("fixtures 目录不可读 {}: {e}（先跑采集）", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort();

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
