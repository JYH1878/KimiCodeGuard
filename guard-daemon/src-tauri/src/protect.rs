//! 自保护巡检 v1（M5 任务 3）：daemon 启动时 + 周期检查防护是否完好。
//!
//! 两项检查（任一缺失 = 防护失效 → 托盘显红「防护失效」+ 菜单「一键修复」）：
//! 1. `~/.kimi-code/config.toml` 含注入块（marker 块优先；marker 被剥时退到裸块检测，
//!    见 extract_hook_exe_orphan——2026-08-15 实测 Kimi Code 重写 config 会丢注释）；
//! 2. 注入块里 PreToolUse hook 的 command 中的 hook exe 路径存在。
//!
//! 一键修复 = spawn daemon 自身同目录的 `guard-hook.exe install --config <config> --daemon-path <daemon exe>`
//! （安装目录布局下两者同处 $INSTDIR；install 原子注入 + 回读校验，见 guard-hook main.rs）。
//!
//! 边界（docs/THREAT_MODEL.md）：巡检只**发现**不**阻止**——恶意用户手改 config 不在
//! v0.1 威胁模型内；hook 二进制自校验不做（M5 拍板）。一切 IO/解析失败收敛为状态枚举，
//! 绝不 panic：daemon 崩溃 = 弹窗/审计全降级，违反不变量 4 的精神。

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

/// 生产巡检间隔：5 分钟（`KCG_PROTECT_INTERVAL_MS` 仅供测试注入）
pub const PROTECT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// 与 guard-hook install 共用的注入 marker（字符串必须与 guard-hook main.rs 一致）
pub const BEGIN_MARK: &str = "# BEGIN KimiCodeGuard";
pub const END_MARK: &str = "# END KimiCodeGuard";

/// daemon 同目录下的 hook 修复器文件名（NSIS 安装布局：两 exe 同处 $INSTDIR）
pub const HOOK_EXE_NAME: &str = "guard-hook.exe";

/// 防护状态（纯数据，UI 层据此显红/修复）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectStatus {
    /// 两项检查全过
    Healthy,
    /// config.toml 不存在（读失败视同缺失，安全方向）
    ConfigMissing,
    /// config 存在但没有完整注入块（marker 缺失或块内没有 PreToolUse command）
    MarkerMissing,
    /// 注入块在，但 command 指向的 hook exe 路径不存在
    HookExeMissing { path: String },
}

impl ProtectStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// 托盘事件用的短状态码（前端/i18n 不参与，中文详情走 detail）
    pub fn code(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::ConfigMissing => "config_missing",
            Self::MarkerMissing => "marker_missing",
            Self::HookExeMissing { .. } => "hook_exe_missing",
        }
    }

    /// 中文详情（托盘 tooltip / 修复结果消息框用）
    pub fn detail(&self, config: &Path) -> String {
        match self {
            Self::Healthy => "防护生效".to_string(),
            Self::ConfigMissing => format!("配置文件不存在：{}", config.display()),
            Self::MarkerMissing => format!(
                "{} 中未找到 KimiCodeGuard 注入块（marker 缺失或块不完整）",
                config.display()
            ),
            Self::HookExeMissing { path } => format!("hook 程序不存在：{path}"),
        }
    }

    /// 发往托盘的 Tauri 事件负载
    pub fn to_event(&self, config: &Path) -> ProtectEvent {
        ProtectEvent {
            status: self.code().to_string(),
            detail: self.detail(config),
        }
    }
}

/// `protect-status` Tauri 事件负载（托盘监听更新状态文本/图标/修复菜单）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtectEvent {
    pub status: String,
    pub detail: String,
}

/// Kimi Code 配置文件路径：`KIMI_CODE_HOME` 整体覆盖优先（沙箱隔离用），
/// 否则 `%USERPROFILE%\.kimi-code\config.toml`（USERPROFILE 缺失退 HOME）。
/// 与 D4「运行时只读 ~/.kimi-code（KIMI_CODE_HOME 可整体覆盖）」一致。
pub fn config_path() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("KIMI_CODE_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(home).join("config.toml"));
    }
    let profile = std::env::var_os("USERPROFILE")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var_os("HOME").filter(|s| !s.is_empty()))?;
    Some(
        PathBuf::from(profile)
            .join(".kimi-code")
            .join("config.toml"),
    )
}

/// 巡检两项检查。任何 IO 错误收敛为对应状态，不 panic。
/// marker 块优先；marker 缺失时退到裸块检测（防误报红）。
pub fn check(config: &Path) -> ProtectStatus {
    let content = match std::fs::read_to_string(config) {
        Ok(c) => c,
        Err(_) => return ProtectStatus::ConfigMissing,
    };
    let hook = extract_hook_exe(&content).or_else(|| extract_hook_exe_orphan(&content));
    let Some(hook) = hook else {
        return ProtectStatus::MarkerMissing;
    };
    if Path::new(&hook).is_file() {
        ProtectStatus::Healthy
    } else {
        ProtectStatus::HookExeMissing { path: hook }
    }
}

/// 裸块检测：全文（不依赖 marker）找引用 guard-hook.exe 的 PreToolUse hook，
/// 返回其 exe 路径。背景（2026-08-15 实测）：Kimi Code 重写 config.toml 会丢弃注释，
/// marker 被剥后注入的 hooks 段以裸块形态留存——裸块同样是有效防护，只认 marker
/// 会误报红。第三方 PreToolUse hook（command 不含 guard-hook.exe）不算。
pub fn extract_hook_exe_orphan(content: &str) -> Option<String> {
    let mut event: Option<String> = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            event = None; // 任何新表头都重置事件上下文
            continue;
        }
        if let Some(v) = line.strip_prefix("event") {
            event = v.split_once('=').and_then(|(_, v)| unquote(v.trim()));
            continue;
        }
        if let Some(v) = line.strip_prefix("command") {
            if event.as_deref() == Some("PreToolUse") {
                let Some((_, raw)) = v.split_once('=') else {
                    continue;
                };
                let Some(cmd) = unquote(raw.trim()) else {
                    continue;
                };
                if cmd.contains(HOOK_EXE_NAME) {
                    return first_quoted_token(&cmd);
                }
            }
        }
    }
    None
}

/// 从 config 内容里提取注入块 PreToolUse command 指向的 hook exe 路径。
/// 只认我们注入的 marker 块；解析失败返回 None（视同 MarkerMissing，安全方向）。
pub fn extract_hook_exe(content: &str) -> Option<String> {
    let begin = content.find(BEGIN_MARK)?;
    let block_end_rel = content[begin..]
        .find(END_MARK)
        .unwrap_or(content.len() - begin);
    let block = &content[begin..begin + block_end_rel];

    let mut event: Option<String> = None;
    for line in block.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[[hooks]]") {
            if rest.trim().is_empty() {
                event = None; // 进入新 hook 段，重置事件
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("event") {
            event = v.split_once('=').and_then(|(_, v)| unquote(v.trim()));
            continue;
        }
        if let Some(v) = line.strip_prefix("command") {
            if event.as_deref() == Some("PreToolUse") {
                let raw = v.split_once('=').map(|(_, v)| v.trim())?;
                let cmd = unquote(raw)?;
                return first_quoted_token(&cmd);
            }
        }
    }
    None
}

/// TOML 基本字符串的粗解析：剥掉首尾引号并反转义 `\\` / `\"`（其余转义原样保留）。
/// 我们注入的 command 只会产生这两种转义（guard-hook render_block/toml_basic_escape）。
fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        Some(toml_basic_unescape(&s[1..s.len() - 1]))
    } else {
        None
    }
}

/// TOML 基本字符串反转义：`\\`→`\`，`\"`→`"`；其余字符原样（不解释 \n/\u，防御性）。
fn toml_basic_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// 提取命令串的第一个 token：`"C:\a b\x.exe" hook ...` → `C:\a b\x.exe`；
/// 不带引号时退化为按空白切分（对第三方 hook 的宽容解析，只会误报红不会误报绿）。
fn first_quoted_token(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    if let Some(rest) = cmd.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    let token = cmd.split_whitespace().next()?;
    (!token.is_empty()).then(|| token.to_string())
}

/// 修复器 exe：daemon 自身同目录的 guard-hook.exe（NSIS 布局两 exe 同处 $INSTDIR）。
pub fn hook_exe_next_to(daemon_exe: &Path) -> PathBuf {
    daemon_exe
        .parent()
        .map(|p| p.join(HOOK_EXE_NAME))
        .unwrap_or_else(|| PathBuf::from(HOOK_EXE_NAME))
}

/// 修复命令行参数：`install --config <config> --daemon-path <daemon exe>`。
/// install 内部用 current_exe 定位 hook 自身（guard-hook main.rs），故无需传 hook 路径。
pub fn repair_args(daemon_exe: &Path, config: &Path) -> Vec<OsString> {
    vec![
        OsString::from("install"),
        OsString::from("--config"),
        config.as_os_str().to_os_string(),
        OsString::from("--daemon-path"),
        daemon_exe.as_os_str().to_os_string(),
    ]
}

/// 修复结果（失败不 panic，UI 据此给中文反馈）
#[derive(Debug, PartialEq, Eq)]
pub enum RepairOutcome {
    /// 修复子进程 exit 0
    Ok,
    /// 修复子进程非零退出（install 失败：写配置失败/回读校验失败等）
    NonZero(i32),
    /// 找不到修复器或 spawn 失败（含原因）
    SpawnFailed(String),
}

/// 一键修复：spawn 自身同目录 guard-hook.exe install（真实 OS spawn）。
pub fn repair(daemon_exe: &Path, config: &Path) -> RepairOutcome {
    repair_with(daemon_exe, config, |hook, args| {
        std::process::Command::new(hook)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    })
}

/// 修复的注入版：spawn 闭包可换（单测注入假 spawner，不碰真进程）。
pub fn repair_with(
    daemon_exe: &Path,
    config: &Path,
    spawn: impl FnOnce(&Path, &[OsString]) -> io::Result<ExitStatus>,
) -> RepairOutcome {
    let hook_exe = hook_exe_next_to(daemon_exe);
    if !hook_exe.is_file() {
        return RepairOutcome::SpawnFailed(format!(
            "未找到修复器 {}（需与 daemon 位于同一目录）",
            hook_exe.display()
        ));
    }
    let args = repair_args(daemon_exe, config);
    match spawn(&hook_exe, &args) {
        Ok(st) if st.success() => RepairOutcome::Ok,
        Ok(st) => RepairOutcome::NonZero(st.code().unwrap_or(-1)),
        Err(e) => RepairOutcome::SpawnFailed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 环境变量测试互斥（set_var 全局生效，避免并行测试互相污染）
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// 与 guard-hook render_block 同构的测试注入块（路径含空格与反斜杠，覆盖转义）
    fn test_block(exe: &Path) -> String {
        let e = exe
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!(
            "# BEGIN KimiCodeGuard\n\
             [[hooks]]\nevent = \"PreToolUse\"\ncommand = \"\\\"{e}\\\" hook\"\ntimeout = 75\n\
             [[hooks]]\nevent = \"SessionStart\"\ncommand = \"\\\"{e}\\\" lifecycle --event SessionStart --daemon-path \\\"C:\\\\dev\\\\guard-daemon.exe\\\"\"\ntimeout = 5\n\
             [[hooks]]\nevent = \"SessionEnd\"\ncommand = \"\\\"{e}\\\" lifecycle --event SessionEnd\"\ntimeout = 5\n\
             # END KimiCodeGuard\n"
        )
    }

    /// TempDir 守卫：Drop 整树删除（guard-hook 测试同款纪律，防 TEMP 残留）
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "kcg-protect-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Windows ExitStatus 构造（std 无公开构造器；from_raw 是稳定通道唯一途径）
    fn exit_status(code: u32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code)
    }

    fn ok_status() -> ExitStatus {
        exit_status(0)
    }

    fn code2_status() -> ExitStatus {
        exit_status(2)
    }

    // ---------- config_path ----------

    #[test]
    fn config_path_prefers_kimi_code_home() {
        let _lock = ENV_LOCK.lock().unwrap();
        let sandbox = TempDir::new("home");
        std::env::set_var("KIMI_CODE_HOME", sandbox.path());
        assert_eq!(config_path(), Some(sandbox.path().join("config.toml")));
        std::env::remove_var("KIMI_CODE_HOME");
    }

    #[test]
    fn config_path_falls_back_to_userprofile() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("KIMI_CODE_HOME");
        let profile = std::env::var_os("USERPROFILE").expect("Windows 必有 USERPROFILE");
        let expected = PathBuf::from(profile)
            .join(".kimi-code")
            .join("config.toml");
        assert_eq!(config_path(), Some(expected));
    }

    // ---------- check 两项检查 ----------

    #[test]
    fn healthy_when_marker_and_hook_exe_exist() {
        let dir = TempDir::new("healthy");
        let hook = dir.path().join("guard-hook.exe");
        std::fs::write(&hook, b"fake").unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, test_block(&hook)).unwrap();
        assert_eq!(check(&config), ProtectStatus::Healthy);
    }

    #[test]
    fn config_missing_reports_config_missing() {
        let dir = TempDir::new("cfg-missing");
        assert_eq!(
            check(&dir.path().join("config.toml")),
            ProtectStatus::ConfigMissing
        );
    }

    #[test]
    fn marker_missing_reports_marker_missing() {
        let dir = TempDir::new("marker-missing");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "model = \"kimi\"\n").unwrap();
        assert_eq!(check(&config), ProtectStatus::MarkerMissing);
    }

    #[test]
    fn hook_exe_missing_reports_path() {
        let dir = TempDir::new("exe-missing");
        let config = dir.path().join("config.toml");
        let hook = dir.path().join("gone").join("guard-hook.exe");
        std::fs::write(&config, test_block(&hook)).unwrap();
        assert_eq!(
            check(&config),
            ProtectStatus::HookExeMissing {
                path: hook.display().to_string()
            }
        );
    }

    #[test]
    fn broken_block_without_command_counts_as_marker_missing() {
        let dir = TempDir::new("broken-block");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "# BEGIN KimiCodeGuard\n# END KimiCodeGuard\n").unwrap();
        assert_eq!(check(&config), ProtectStatus::MarkerMissing);
    }

    // ---------- 裸块容错（2026-08-15 实测：Kimi 重写 config 丢注释，marker 被剥） ----------

    /// 与真机裸块同构：marker 被剥后的注入段（无 BEGIN/END 注释）
    fn orphan_block(exe: &Path) -> String {
        let e = exe.display().to_string().replace('\\', "\\\\");
        format!(
            "model = \"kimi\"\n\n[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"\\\"{e}\\\" hook\"\ntimeout = 75\n"
        )
    }

    #[test]
    fn orphan_block_healthy_when_exe_exists() {
        let dir = TempDir::new("orphan-healthy");
        let hook = dir.path().join("guard-hook.exe");
        std::fs::write(&hook, b"fake").unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, orphan_block(&hook)).unwrap();
        assert_eq!(check(&config), ProtectStatus::Healthy);
    }

    #[test]
    fn orphan_block_exe_missing_is_reported() {
        let dir = TempDir::new("orphan-exe-missing");
        let config = dir.path().join("config.toml");
        let hook = dir.path().join("gone").join("guard-hook.exe");
        std::fs::write(&config, orphan_block(&hook)).unwrap();
        assert_eq!(
            check(&config),
            ProtectStatus::HookExeMissing {
                path: hook.display().to_string()
            }
        );
    }

    #[test]
    fn third_party_pretool_hook_does_not_count() {
        let dir = TempDir::new("third-party");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"\\\"C:\\\\tools\\\\other.exe\\\" run\"\n",
        )
        .unwrap();
        assert_eq!(check(&config), ProtectStatus::MarkerMissing);
    }

    #[test]
    fn marker_wins_over_orphan() {
        let dir = TempDir::new("marker-wins");
        let marker_hook = dir.path().join("guard-hook.exe");
        std::fs::write(&marker_hook, b"fake").unwrap();
        let orphan_hook = dir.path().join("gone").join("guard-hook.exe");
        let config = dir.path().join("config.toml");
        let content = format!("{}{}", test_block(&marker_hook), orphan_block(&orphan_hook));
        std::fs::write(&config, content).unwrap();
        // marker 块指向存在的 exe → 绿（不受裸块坏路径影响）
        assert_eq!(check(&config), ProtectStatus::Healthy);
    }

    // ---------- extract_hook_exe 解析 ----------

    #[test]
    fn extract_handles_toml_escapes_in_path() {
        let dir = TempDir::new("extract");
        let hook = dir.path().join("a b").join("guard-hook.exe");
        let block = test_block(&hook);
        let extracted = extract_hook_exe(&block).expect("应解析出路径");
        assert_eq!(Path::new(&extracted), hook);
    }

    #[test]
    fn extract_none_without_marker() {
        assert_eq!(extract_hook_exe("model = \"kimi\"\n"), None);
    }

    #[test]
    fn extract_picks_pretool_not_lifecycle() {
        let dir = TempDir::new("extract-order");
        let hook = dir.path().join("guard-hook.exe");
        // SessionStart 的 command 在前也必须是 PreToolUse 的 exe 胜出
        let block = test_block(&hook);
        let extracted = extract_hook_exe(&block).unwrap();
        assert_eq!(Path::new(&extracted), hook);
    }

    #[test]
    fn first_quoted_token_handles_unquoted_fallback() {
        assert_eq!(
            first_quoted_token("C:\\tools\\x.exe --flag"),
            Some("C:\\tools\\x.exe".to_string())
        );
        assert_eq!(
            first_quoted_token("\"C:\\a b\\x.exe\" hook"),
            Some("C:\\a b\\x.exe".to_string())
        );
        assert_eq!(first_quoted_token(""), None);
    }

    // ---------- 修复 ----------

    #[test]
    fn repair_args_are_exact() {
        let args = repair_args(
            Path::new("C:\\app\\guard-daemon.exe"),
            Path::new("C:\\Users\\x\\.kimi-code\\config.toml"),
        );
        assert_eq!(
            args,
            vec![
                OsString::from("install"),
                OsString::from("--config"),
                OsString::from("C:\\Users\\x\\.kimi-code\\config.toml"),
                OsString::from("--daemon-path"),
                OsString::from("C:\\app\\guard-daemon.exe"),
            ]
        );
    }

    #[test]
    fn repair_success_turns_red_back_to_green() {
        let dir = TempDir::new("repair-green");
        let daemon = dir.path().join("guard-daemon.exe");
        let hook = dir.path().join("guard-hook.exe");
        let config = dir.path().join("config.toml");
        // 起始红：marker 缺失
        std::fs::write(&config, "model = \"kimi\"\n").unwrap();
        assert_eq!(check(&config), ProtectStatus::MarkerMissing);
        // 修复器必须已存在于 daemon 同目录（repair 前置检查；NSIS 布局下恒成立）
        std::fs::write(&hook, b"fake").unwrap();

        // 假 spawner：模拟 guard-hook install 的效果（写块 + exit 0）
        let outcome = repair_with(&daemon, &config, |_hook_path, args| {
            assert_eq!(args[0], OsString::from("install"));
            assert_eq!(args[1], OsString::from("--config"));
            assert_eq!(args[3], OsString::from("--daemon-path"));
            std::fs::write(&config, test_block(&hook)).unwrap();
            Ok(ok_status())
        });
        assert_eq!(outcome, RepairOutcome::Ok);
        // 修复后回绿
        assert_eq!(check(&config), ProtectStatus::Healthy);
    }

    #[test]
    fn repair_without_hook_exe_fails_without_panic() {
        let dir = TempDir::new("repair-nohook");
        let daemon = dir.path().join("guard-daemon.exe");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "x = 1\n").unwrap();
        let outcome = repair_with(&daemon, &config, |_, _| {
            panic!("spawner 不应被调用");
        });
        assert!(matches!(outcome, RepairOutcome::SpawnFailed(_)));
    }

    #[test]
    fn repair_spawn_error_becomes_spawn_failed() {
        let dir = TempDir::new("repair-spawnerr");
        let daemon = dir.path().join("guard-daemon.exe");
        let hook = dir.path().join("guard-hook.exe");
        std::fs::write(&hook, b"fake").unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "x = 1\n").unwrap();
        let outcome = repair_with(&daemon, &config, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "模拟 spawn 失败",
            ))
        });
        assert_eq!(
            outcome,
            RepairOutcome::SpawnFailed("模拟 spawn 失败".to_string())
        );
    }

    #[test]
    fn repair_nonzero_exit_is_reported() {
        let dir = TempDir::new("repair-nonzero");
        let daemon = dir.path().join("guard-daemon.exe");
        let hook = dir.path().join("guard-hook.exe");
        std::fs::write(&hook, b"fake").unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "x = 1\n").unwrap();
        let outcome = repair_with(&daemon, &config, |_, _| Ok(code2_status()));
        assert_eq!(outcome, RepairOutcome::NonZero(2));
    }

    #[test]
    fn protect_event_round_trips_status_code() {
        let ev = ProtectStatus::HookExeMissing {
            path: "C:\\x\\hook.exe".to_string(),
        }
        .to_event(Path::new("C:\\cfg"));
        assert_eq!(ev.status, "hook_exe_missing");
        assert!(ev.detail.contains("C:\\x\\hook.exe"));
        let json = serde_json::to_string(&ev).unwrap();
        let back: ProtectEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "hook_exe_missing");
    }
}
