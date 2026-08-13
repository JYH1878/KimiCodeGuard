//! guard-hook 事件 payload 解析（M1）。
//!
//! 字段以 fixtures/ 14 条真实采集为准（D6），缺字段容错降级不崩溃（D5）。
//! 公共字段：hook_event_name / session_id / cwd / tool_name / tool_input / tool_call_id；
//! v2 引擎多 client_type；交互会话可能多 session_title（headless 没有）。

use serde_json::Value;

/// 解析后的 PreToolUse payload。字段缺失用 None 表达，不拒绝整条。
pub struct Payload {
    pub raw: Value,
    pub hook_event_name: Option<String>,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub tool_call_id: Option<String>,
    /// v2 引擎特有（v1 无此字段）。
    pub client_type: Option<String>,
    /// 交互会话可能有，headless 没有。
    pub session_title: Option<String>,
    /// 解析期发现的字段缺失，供 hook 入口写 stderr（不变量 5）。
    pub notes: Vec<String>,
}

impl Payload {
    /// 整条 JSON 非法（或非对象）→ None，调用方按放行处理（exit 0 打 {}）。
    pub fn parse(bytes: &[u8]) -> Option<Payload> {
        let raw: Value = serde_json::from_slice(bytes).ok()?;
        if !raw.is_object() {
            return None;
        }
        let get_str = |key: &str| raw.get(key).and_then(|v| v.as_str()).map(str::to_string);

        let mut notes = Vec::new();
        let mut field = |key: &str| {
            let v = get_str(key);
            if v.is_none() {
                notes.push(format!("guard-hook: payload 缺字段 {key}，相关规则已跳过"));
            }
            v
        };

        let hook_event_name = field("hook_event_name");
        let session_id = field("session_id");
        let cwd = field("cwd");
        let tool_name = field("tool_name");
        let tool_call_id = field("tool_call_id");
        let tool_input = raw.get("tool_input").cloned();
        if tool_input.is_none() {
            notes.push("guard-hook: payload 缺字段 tool_input，相关规则已跳过".to_string());
        }
        let client_type = get_str("client_type");
        let session_title = get_str("session_title");

        Some(Payload {
            raw,
            hook_event_name,
            session_id,
            cwd,
            tool_name,
            tool_input,
            tool_call_id,
            client_type,
            session_title,
            notes,
        })
    }

    /// Bash 工具的命令文本。非 Bash 或缺 command → None。
    pub fn bash_command(&self) -> Option<&str> {
        if self.tool_name.as_deref() != Some("Bash") {
            return None;
        }
        self.tool_input.as_ref()?.get("command")?.as_str()
    }

    /// Read/Write/Edit 工具的目标路径。其他工具或缺 path → None。
    pub fn file_path(&self) -> Option<&str> {
        match self.tool_name.as_deref() {
            Some("Read") | Some("Write") | Some("Edit") => {}
            _ => return None,
        }
        self.tool_input.as_ref()?.get("path")?.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_returns_none() {
        assert!(Payload::parse(b"not json").is_none());
        assert!(Payload::parse(b"").is_none());
        assert!(Payload::parse(b"[1,2,3]").is_none()); // 非对象
        assert!(Payload::parse(b"\"str\"").is_none());
    }

    #[test]
    fn v1_bash_full_fields() {
        let p = Payload::parse(
            br#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"D:/p",
                 "tool_name":"Bash","tool_input":{"command":"echo hi"},
                 "tool_call_id":"t1"}"#,
        )
        .expect("合法 payload 必须解析成功");
        assert_eq!(p.tool_name.as_deref(), Some("Bash"));
        assert_eq!(p.bash_command(), Some("echo hi"));
        assert_eq!(p.file_path(), None); // Bash 无 path
        assert_eq!(p.client_type, None);
        assert!(p.notes.is_empty(), "字段齐全不应有 note: {:?}", p.notes);
    }

    #[test]
    fn v2_extra_fields() {
        let p = Payload::parse(
            br#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"D:\\p",
                 "client_type":"kimi_code_cli","tool_name":"Read",
                 "tool_input":{"path":"a.txt"},"tool_call_id":"t1","session_title":"demo"}"#,
        )
        .expect("合法 payload 必须解析成功");
        assert_eq!(p.client_type.as_deref(), Some("kimi_code_cli"));
        assert_eq!(p.session_title.as_deref(), Some("demo"));
        assert_eq!(p.file_path(), Some("a.txt"));
        assert_eq!(p.bash_command(), None); // Read 无 command
    }

    #[test]
    fn missing_single_field_is_noted_not_rejected() {
        let p = Payload::parse(
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        )
        .expect("缺字段不拒绝整条");
        assert_eq!(p.session_id, None);
        assert_eq!(p.bash_command(), Some("ls")); // 不依赖 session_id 的规则仍可用
        assert!(p.notes.iter().any(|n| n.contains("session_id")));
        assert!(p.notes.iter().any(|n| n.contains("cwd")));
    }

    #[test]
    fn bash_without_command_returns_none() {
        let p = Payload::parse(
            br#"{"hook_event_name":"PreToolUse","session_id":"s","cwd":"/x",
                 "tool_name":"Bash","tool_input":{},"tool_call_id":"t"}"#,
        )
        .expect("解析成功");
        assert_eq!(p.bash_command(), None);
    }
}
