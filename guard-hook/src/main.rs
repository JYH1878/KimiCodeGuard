//! guard-hook：KimiCodeGuard 的 PreToolUse hook 与 config 注入器。
//!
//! 子命令：
//! - `hook [--dump-dir <目录>]`  stdin 解析 → 规则判定：放行打 {} exit 0；deny 中文原因 exit 2；
//!   ask 走命名管道问 daemon，超时/连不上/拒绝一律 exit 2（D1/D2）。任何内部异常收敛为 exit 0 打 {}
//! - `install --config <路径> [--dump-dir <目录>]`  原子注入 hook 标记块（不给 --dump-dir 则 command 不带落盘参数）
//! - `uninstall --config <路径>`  原子移除标记块
//! - `sanitize --dump-dir <目录> --out-dir <目录>`  原始 payload 脱敏入库
//!
//! 热路径纪律（AGENTS.md 不变量 4）：禁止 unwrap/expect/panic，一切内部错误收敛为放行或按策略 exit 2。

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_hook::payload::Payload;
use guard_hook::pipe::{self, AskOutcome};
use guard_hook::rules::{evaluate, Decision};

const BEGIN_MARK: &str = "# BEGIN KimiCodeGuard";
const END_MARK: &str = "# END KimiCodeGuard";
const BACKUP_SUFFIX: &str = ".kcg-bak";
const TMP_SUFFIX: &str = ".kcg-tmp";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        usage();
        return ExitCode::from(2);
    };
    match cmd {
        "hook" => run_hook(&args[1..]),
        "install" => run_install(&args[1..]),
        "uninstall" => run_uninstall(&args[1..]),
        "sanitize" => run_sanitize(&args[1..]),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!(
        "guard-hook <hook|install|uninstall|sanitize>\n\
         \x20 hook [--dump-dir <目录>]\n\
         \x20 install --config <路径> [--dump-dir <目录>]\n\
         \x20 uninstall --config <路径>\n\
         \x20 sanitize --dump-dir <目录> --out-dir <目录>"
    );
}

/// 取 `--name <值>` 或 `--name=<值>` 形式的参数值。
fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(rest) = a.strip_prefix(name).and_then(|s| s.strip_prefix('=')) {
            return Some(rest.to_string());
        }
    }
    None
}

// ---------- hook ----------

fn run_hook(args: &[String]) -> ExitCode {
    let mut buf = Vec::new();
    // 读取失败也照常放行：hook 崩溃 = fail-open，但我们主动做到 exit 0。
    let _ = io::stdin().read_to_end(&mut buf);
    if let Some(dir) = flag_value(args, "--dump-dir") {
        let _ = dump_payload(Path::new(&dir), &buf);
    }

    // 整条 JSON 非法 → 放行（D5 防御性解析）
    let Some(payload) = Payload::parse(&buf) else {
        return allow();
    };
    // 缺字段降级：规则已跳过，stderr 记一行（不变量 5）
    for note in &payload.notes {
        eprintln!("{note}");
    }

    match evaluate(&payload) {
        Decision::Allow => allow(),
        Decision::Deny { rule, reason } => {
            eprintln!("KimiCodeGuard 已拦截（规则 {rule}）：{reason}");
            ExitCode::from(2)
        }
        Decision::Ask { rule, question } => {
            let tool = payload.tool_name.as_deref().unwrap_or("unknown");
            let detail = payload
                .bash_command()
                .or_else(|| payload.file_path())
                .unwrap_or("");
            eprintln!("KimiCodeGuard 需人工确认（规则 {rule}）：{question}");
            match pipe::ask(rule, tool, detail, payload.session_id.as_deref()) {
                AskOutcome::Allow => allow(),
                AskOutcome::Deny(reason) => {
                    eprintln!("KimiCodeGuard：已拒绝（规则 {rule}）：{reason}");
                    ExitCode::from(2)
                }
                // D2 fail-safe：超时 / 连不上 / 回复非法 → 主动 exit 2，绝不默认放行
                AskOutcome::Unavailable(why) => {
                    eprintln!(
                        "KimiCodeGuard：无法取得人工确认（{why}），按安全策略拦截（规则 {rule}）"
                    );
                    ExitCode::from(2)
                }
            }
        }
    }
}

/// 放行：stdout 打 {} 并 exit 0（M0 行为不变）。
fn allow() -> ExitCode {
    print!("{{}}");
    let _ = io::stdout().flush();
    ExitCode::SUCCESS
}

fn dump_payload(dir: &Path, buf: &[u8]) -> io::Result<()> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = format!("{}-{}.json", millis, std::process::id());
    fs::write(dir.join(name), buf)
}

// ---------- 标记块 ----------

/// 生成注入块文本（不含前导换行）。字段严格限定 event/command/timeout。
/// timeout = 75：hook 官方默认 30s、超时即放行（fail-open，HANDOFF 五.4）；
/// ask 弹窗要等用户 60s，必须留足余量。
/// dump_dir 为 None 时 command 就是 `"<exe>" hook`（日常防护不落盘 payload）。
fn render_block(exe: &Path, dump_dir: Option<&str>) -> String {
    let command = match dump_dir {
        Some(dir) => format!("\"{}\" hook --dump-dir \"{}\"", exe.display(), dir),
        None => format!("\"{}\" hook", exe.display()),
    };
    format!(
        "{}\n[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"{}\"\ntimeout = 75\n{}\n",
        BEGIN_MARK,
        toml_basic_escape(&command),
        END_MARK
    )
}

/// TOML 基本字符串转义（反斜杠与双引号）。
fn toml_basic_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 删除内容中的标记块。删除范围：BEGIN 行（含我们注入时补的前导换行）到 END 行（含行尾换行）。
fn remove_block(content: &str) -> String {
    let Some(begin_pos) = content.find(BEGIN_MARK) else {
        return content.to_string();
    };
    // 对齐到 BEGIN 所在行行首
    let line_start = content[..begin_pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    // 连同 install 补入的前导换行一起删
    let rm_start = if line_start > 0 && content.as_bytes()[line_start - 1] == b'\n' {
        line_start - 1
    } else {
        line_start
    };
    let rm_end = match content[begin_pos..].find(END_MARK) {
        Some(rel) => {
            let end = begin_pos + rel + END_MARK.len();
            if content.as_bytes().get(end) == Some(&b'\n') {
                end + 1
            } else {
                end
            }
        }
        // 只有 BEGIN 没有 END（残缺块）：删到文件尾
        None => content.len(),
    };
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..rm_start]);
    out.push_str(&content[rm_end..]);
    out
}

/// 在原内容末尾追加标记块。非空内容统一补一个前导换行，保证 uninstall 可逐字节还原。
fn append_block(content: &str, block: &str) -> String {
    let mut out = String::with_capacity(content.len() + block.len() + 1);
    out.push_str(content);
    if !content.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    out
}

// ---------- 原子写 ----------

/// 同目录 tmp + fsync + rename（参考 numbat install.go 范式）。
/// 任何一步失败都不触碰原文件。
fn atomic_write(path: &Path, content: &[u8]) -> io::Result<()> {
    let tmp = PathBuf::from(format!("{}{}", path.display(), TMP_SUFFIX));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn backup_path(config: &Path) -> PathBuf {
    PathBuf::from(format!("{}{}", config.display(), BACKUP_SUFFIX))
}

// ---------- install / uninstall ----------

fn run_install(args: &[String]) -> ExitCode {
    let Some(config) = flag_value(args, "--config") else {
        eprintln!("install 需要 --config（--dump-dir 可选）");
        return ExitCode::from(2);
    };
    let dump_dir = flag_value(args, "--dump-dir");
    let config = PathBuf::from(config);
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("无法定位当前 exe：{e}");
            return ExitCode::FAILURE;
        }
    };

    let original = match fs::read_to_string(&config) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("读取 config 失败：{e}");
            return ExitCode::FAILURE;
        }
    };

    // 备份：已存在则不覆盖（保留最初的原版）
    let bak = backup_path(&config);
    if let Some(c) = &original {
        if !bak.exists() {
            if let Err(e) = fs::write(&bak, c) {
                eprintln!("备份失败：{e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let base = original.as_deref().unwrap_or("");
    let new_content = append_block(
        &remove_block(base),
        &render_block(&exe, dump_dir.as_deref()),
    );

    if let Err(e) = atomic_write(&config, new_content.as_bytes()) {
        eprintln!("写入 config 失败（原文件未动）：{e}");
        return ExitCode::FAILURE;
    }

    // 回读校验
    let ok = fs::read_to_string(&config)
        .map(|c| c == new_content && c.contains(BEGIN_MARK) && c.contains(END_MARK))
        .unwrap_or(false);
    if !ok {
        eprintln!("回读校验失败，恢复备份");
        let restored = if let Some(c) = &original {
            atomic_write(&config, c.as_bytes())
        } else {
            fs::remove_file(&config).map_err(|e| io::Error::new(e.kind(), e.to_string()))
        };
        if let Err(e) = restored {
            eprintln!("恢复备份也失败：{e}（备份在 {}）", bak.display());
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_uninstall(args: &[String]) -> ExitCode {
    let Some(config) = flag_value(args, "--config") else {
        eprintln!("uninstall 需要 --config");
        return ExitCode::from(2);
    };
    let config = PathBuf::from(config);
    let content = match fs::read_to_string(&config) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("读取 config 失败：{e}");
            return ExitCode::FAILURE;
        }
    };
    let new_content = remove_block(&content);
    if new_content == content {
        return ExitCode::SUCCESS; // 没有标记块，无需写入
    }
    if let Err(e) = atomic_write(&config, new_content.as_bytes()) {
        eprintln!("写入 config 失败（原文件未动）：{e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

// ---------- sanitize ----------

fn run_sanitize(args: &[String]) -> ExitCode {
    let (Some(dump_dir), Some(out_dir)) = (
        flag_value(args, "--dump-dir"),
        flag_value(args, "--out-dir"),
    ) else {
        eprintln!("sanitize 需要 --dump-dir 与 --out-dir");
        return ExitCode::from(2);
    };
    let dump_dir = PathBuf::from(dump_dir);
    let out_dir = PathBuf::from(out_dir);
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("创建输出目录失败：{e}");
        return ExitCode::FAILURE;
    }

    let mut files: Vec<PathBuf> = match fs::read_dir(&dump_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
            .collect(),
        Err(e) => {
            eprintln!("读取 dump 目录失败：{e}");
            return ExitCode::FAILURE;
        }
    };
    files.sort();

    let home = home_variants();
    let mut counters: HashMap<(String, String), u32> = HashMap::new();
    let mut written = 0u32;
    for f in &files {
        let Ok(raw) = fs::read_to_string(f) else {
            continue; // 单条损坏不拖垮整批
        };
        let (engine, tool) = detect_engine_tool(&raw);
        let seq = counters.entry((engine.clone(), tool.clone())).or_insert(0);
        *seq += 1;
        let name = format!("{}-{}-{:02}.json", engine, tool.to_ascii_lowercase(), *seq);
        let clean = redact(&raw, &home);
        if fs::write(out_dir.join(&name), clean).is_ok() {
            written += 1;
        }
    }
    println!("sanitize 完成：{written} 条写入 {}", out_dir.display());
    ExitCode::SUCCESS
}

/// 从 payload 判断引擎与工具名。v2 引擎多 client_type/session_title 字段。
/// 解析失败一律降级为 unknown，不崩溃。
fn detect_engine_tool(raw: &str) -> (String, String) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return ("unknown".into(), "unknown".into());
    };
    let tool = v
        .get("tool_name")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string();
    let engine = if v.get("client_type").is_some() || v.get("session_title").is_some() {
        "v2"
    } else {
        "v1"
    };
    (engine.into(), tool)
}

/// 当前用户 home 目录的各种写法（原样 / 正斜杠 / JSON 转义反斜杠 / cygwin）。
fn home_variants() -> Vec<String> {
    let home = env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| env::var("HOME").ok().filter(|s| !s.is_empty()));
    let Some(home) = home else { return Vec::new() };
    let mut variants = vec![
        home.clone(),
        home.replace('\\', "/"),
        home.replace('\\', "\\\\"),
    ];
    // cygwin 形式：C:\Users\x -> /c/Users/x
    let bytes = home.as_bytes();
    if bytes.len() > 3 && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        variants.push(format!("/{}{}", drive, home[2..].replace('\\', "/")));
    }
    variants
}

/// 脱敏：home 路径 -> <HOME>；密钥形态 -> <REDACTED>。
/// 模式字面量分段拼接，避免源码本身命中敏感串扫描。
fn redact(text: &str, home: &[String]) -> String {
    let mut s = text.to_string();
    for v in home {
        if !v.is_empty() {
            s = s.replace(v.as_str(), "<HOME>");
        }
    }
    // 密钥形态：前缀 + 足够长的 token 才脱敏（模式串分段拼接，避免源码命中敏感串扫描）
    let prefixes: [(String, usize); 4] = [
        (["s", "k-"].concat(), 8),
        (["B", "earer "].concat(), 8),
        (["AK", "IA"].concat(), 16),
        (["x", "oxb-"].concat(), 8),
    ];
    for (p, min_len) in &prefixes {
        s = redact_prefixed_token(&s, p, *min_len);
    }
    s
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '=')
}

fn redact_prefixed_token(text: &str, prefix: &str, min_len: usize) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(prefix) {
        let after = &rest[i + prefix.len()..];
        let token_len = after.chars().take_while(|c| is_token_char(*c)).count();
        if token_len >= min_len {
            out.push_str(&rest[..i]);
            out.push_str("<REDACTED>");
            let byte_len: usize = after.chars().take(token_len).map(char::len_utf8).sum();
            rest = &after[byte_len..];
        } else {
            // 不够长不像密钥，原样保留，继续往后找
            out.push_str(&rest[..i + prefix.len()]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_block_noop_without_markers() {
        let src = "model = \"k\"\n";
        assert_eq!(remove_block(src), src);
    }

    #[test]
    fn remove_block_only_block() {
        let block = render_block(Path::new("C:/x/guard-hook.exe"), Some("D:/d"));
        assert_eq!(remove_block(&block), "");
    }

    #[test]
    fn append_then_remove_restores_without_trailing_newline() {
        let src = "model = \"k\""; // 无行尾换行
        let block = render_block(Path::new("C:/x/guard-hook.exe"), Some("D:/d"));
        let injected = append_block(src, &block);
        assert_eq!(remove_block(&injected), src);
    }

    #[test]
    fn append_then_remove_restores_with_trailing_newline() {
        let src = "model = \"k\"\n";
        let block = render_block(Path::new("C:/x/guard-hook.exe"), Some("D:/d"));
        let injected = append_block(src, &block);
        assert_eq!(remove_block(&injected), src);
    }

    #[test]
    fn double_inject_is_idempotent() {
        let src = "model = \"k\"\n";
        let block = render_block(Path::new("C:/x/guard-hook.exe"), Some("D:/d"));
        let once = append_block(&remove_block(src), &block);
        let twice = append_block(&remove_block(&once), &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn block_escapes_backslashes_and_quotes() {
        let block = render_block(Path::new("C:\\a b\\guard-hook.exe"), Some("D:\\d d"));
        assert!(block.contains(
            "command = \"\\\"C:\\\\a b\\\\guard-hook.exe\\\" hook --dump-dir \\\"D:\\\\d d\\\"\""
        ));
        assert!(block.contains("event = \"PreToolUse\""));
        assert!(block.contains("timeout = 75"));
        assert!(block.starts_with(BEGIN_MARK));
        assert!(block.ends_with(&format!("{}\n", END_MARK)));
    }

    #[test]
    fn block_without_dump_dir_is_plain_hook_command() {
        let block = render_block(Path::new("C:\\a b\\guard-hook.exe"), None);
        assert!(block.contains("command = \"\\\"C:\\\\a b\\\\guard-hook.exe\\\" hook\""));
        assert!(!block.contains("dump-dir"));
        assert!(block.contains("event = \"PreToolUse\""));
        assert!(block.contains("timeout = 75"));
    }

    #[test]
    fn redact_home_variants() {
        let home = vec![
            "C:\\Users\\tester".to_string(),
            "C:/Users/tester".to_string(),
            "C:\\\\Users\\\\tester".to_string(), // JSON 转义形态
        ];
        let raw = r#"{"cwd":"C:\\Users\\tester\\proj"}"#;
        let out = redact(raw, &home);
        assert!(out.contains("<HOME>"), "got: {out}");
        assert!(!out.contains("tester"));
    }

    #[test]
    fn redact_secret_shapes() {
        let fake_sk = format!("{}k-{}", "s", "abcdefghijklmnop");
        let fake_bearer = format!("{}earer {}", "B", "tokentokentoken");
        let fake_akia = format!("{}{}", "AK", "IAIOSFODNN7EXAMPLE");
        let raw = format!("a={fake_sk} b={fake_bearer} c={fake_akia} d=short");
        let out = redact(&raw, &[]);
        assert_eq!(out.matches("<REDACTED>").count(), 3, "got: {out}");
        assert!(out.contains("d=short"));
    }

    #[test]
    fn detect_engine_tool_tolerant() {
        assert_eq!(
            detect_engine_tool(r#"{"tool_name":"Bash","hook_event_name":"PreToolUse"}"#),
            ("v1".to_string(), "Bash".to_string())
        );
        assert_eq!(
            detect_engine_tool(r#"{"tool_name":"Read","client_type":"cli"}"#),
            ("v2".to_string(), "Read".to_string())
        );
        assert_eq!(
            detect_engine_tool("not json"),
            ("unknown".to_string(), "unknown".to_string())
        );
    }
}
