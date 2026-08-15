//! 规则判定核心（M7）：rm-force / cred-files / git-force-push / self-protect /
//! git-destroy / shell-obfuscation 六条。
//!
//! `evaluate` 对外是纯函数：环境依赖（fs::canonicalize、USERPROFILE、受保护路径集、
//! git 工作区探测）在入口处注入（`Env`），规则逻辑本身不碰 IO，好测。
//! 热路径禁止 unwrap/expect/panic（不变量 4）。
//!
//! 探测类依赖注入纪律（M7）：受保护路径集与 git 状态探测照 canon/home 方式注入
//! `evaluate_with`，单测不碰真机路径与真 git；allow 热路径不新增 IO（有单测断言）。

use crate::payload::Payload;
use std::fs;

/// 判定结果。
pub enum Decision {
    Allow,
    Deny {
        rule: &'static str,
        reason: String,
    },
    Ask {
        rule: &'static str,
        question: String,
    },
}

impl Decision {
    /// 判定类别，供测试与日志断言。
    pub fn kind(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny { .. } => "deny",
            Decision::Ask { .. } => "ask",
        }
    }
}

/// 注入的探测依赖。`evaluate` 用真实环境构建；单测用假值（机器无关）。
pub struct Env<'a> {
    /// 路径 canonicalize（存在时返回展开 8.3 短名与 junction 后的真实路径）。
    pub canon: &'a dyn Fn(&str) -> Option<String>,
    /// 用户 home 目录（~ 展开与 .ssh/.aws 判定用），通常是 USERPROFILE。
    pub home: Option<&'a str>,
    /// self-protect 受保护路径集（正斜杠绝对路径；比较时统一小写）。
    pub protected: &'a [String],
    /// git 工作区探测：payload cwd 跑 `git status --porcelain`，返回「是否脏」。
    /// git 缺失 / 非仓库 / 超时 / 出错 → 一律 true（按有变更处理，拦截方向）。
    pub git_dirty: &'a dyn Fn(&str) -> bool,
}

/// 顶层入口：注入真实环境（fs::canonicalize、USERPROFILE、受保护路径集、git 探测）。
pub fn evaluate(p: &Payload) -> Decision {
    let protected = real_protected_paths();
    let home = real_home();
    let env = Env {
        canon: &fs_canonicalize,
        home: home.as_deref(),
        protected: &protected,
        git_dirty: &git_status_dirty,
    };
    evaluate_with(p, &env)
}

/// 可注入环境依赖的判定核心。
pub fn evaluate_with(p: &Payload, env: &Env) -> Decision {
    evaluate_rules(p, env, 0)
}

/// 规则链 + shell-obfuscation 剥壳。obfuscation_depth 上限 2（嵌套最多 2 层）。
fn evaluate_rules(p: &Payload, env: &Env, obfuscation_depth: u8) -> Decision {
    if let Some(d) = rule_rm_force(p) {
        return d;
    }
    if let Some(d) = rule_cred_files(p, env.canon, env.home) {
        return d;
    }
    if let Some(d) = rule_git_force_push(p) {
        return d;
    }
    if let Some(d) = rule_self_protect(p, env) {
        return d;
    }
    if let Some(d) = rule_git_destroy(p, env) {
        return d;
    }
    if obfuscation_depth < 2 {
        if let Some(d) = rule_shell_obfuscation(p, env, obfuscation_depth) {
            return d;
        }
    }
    Decision::Allow
}

/// 剥 Windows canonicalize/current_exe 的 `\\?\` 前缀。
fn strip_verbatim(s: &str) -> &str {
    s.strip_prefix(r"\\?\").unwrap_or(s)
}

/// 真实文件系统的 canonicalize（剥 Windows `\\?\` 前缀），供 evaluate 与测试 harness 复用。
pub fn fs_canonicalize(path: &str) -> Option<String> {
    let p = fs::canonicalize(path).ok()?;
    let s = p.to_string_lossy().into_owned();
    Some(strip_verbatim(&s).to_string())
}

fn real_home() -> Option<String> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
}

/// 真实受保护路径集（self-protect）：
/// ① config.toml（KIMI_CODE_HOME 覆盖优先，否则 ~/.kimi-code/config.toml）
/// ② 当前 hook exe ③ 同目录 daemon exe（KimiCodeGuard.exe 与 guard-daemon.exe 两个名字都算）
/// ④ audit.db（%LOCALAPPDATA%\KimiCodeGuard\audit.db）。
/// 全部规范为正斜杠绝对路径；文件已存在时 canonicalize 展开 8.3/junction。
/// 任何一步失败只丢对应条目，不崩溃（不变量 4）。
fn real_protected_paths() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |path: String| {
        let norm = path.replace('\\', "/");
        let final_path = fs_canonicalize(&norm).unwrap_or(norm);
        // canonicalize 返回反斜杠形态，必须换回正斜杠再入库（与目标规范化口径一致）
        out.push(final_path.replace('\\', "/"));
    };

    // ① config.toml：KIMI_CODE_HOME 整体覆盖 ~/.kimi-code（D4）
    let kim_home = std::env::var("KIMI_CODE_HOME")
        .ok()
        .filter(|s| !s.is_empty());
    let home = real_home();
    if let Some(kh) = kim_home {
        push(format!("{}/config.toml", kh.trim_end_matches('/')));
    } else if let Some(h) = &home {
        push(format!(
            "{}/.kimi-code/config.toml",
            h.trim_end_matches('/')
        ));
    }

    // ②③ 当前 hook exe + 同目录 daemon exe（两个名字都算）
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy().into_owned();
        let s = strip_verbatim(&s).to_string();
        push(s.clone());
        if let Some(dir) = std::path::Path::new(&s).parent() {
            for name in ["KimiCodeGuard.exe", "guard-daemon.exe"] {
                push(format!(
                    "{}/{}",
                    dir.to_string_lossy().replace('\\', "/"),
                    name
                ));
            }
        }
    }

    // ④ audit.db
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        if !appdata.is_empty() {
            push(format!(
                "{}/KimiCodeGuard/audit.db",
                appdata.trim_end_matches('/').replace('\\', "/")
            ));
        }
    }
    out
}

/// 真实 git 工作区探测：cwd 跑 `git status --porcelain`（300ms 超时）。
/// git 缺失 / 非仓库 / 超时 / 读取失败 → 一律 true（按有变更处理，拦截方向）。
pub fn git_status_dirty(cwd: &str) -> bool {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let child = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return true;
    };
    let deadline = Instant::now() + Duration::from_millis(300);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut s = String::new();
                let _ = child
                    .stdout
                    .take()
                    .and_then(|mut o| o.read_to_string(&mut s).ok());
                if !status.success() {
                    return true;
                }
                return !s.trim().is_empty();
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return true,
        }
    }
}

fn deny(rule: &'static str, reason: &str) -> Decision {
    Decision::Deny {
        rule,
        reason: reason.to_string(),
    }
}

// ---------- 命令链切分与 token 化 ----------

/// 按链式分隔符（&& / || / ; / | / & / 换行）把命令切段，跟踪单双引号（引号内不切）。
fn split_chain(cmd: &str) -> Vec<String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let (mut in_s, mut in_d) = (false, false);
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_d => {
                in_s = !in_s;
                cur.push(c);
            }
            '"' if !in_s => {
                in_d = !in_d;
                cur.push(c);
            }
            '\n' | ';' if !in_s && !in_d => push_seg(&mut segs, &mut cur),
            '&' if !in_s && !in_d => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                }
                push_seg(&mut segs, &mut cur);
            }
            '|' if !in_s && !in_d => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                }
                push_seg(&mut segs, &mut cur);
            }
            _ => cur.push(c),
        }
    }
    push_seg(&mut segs, &mut cur);
    segs
}

fn push_seg(segs: &mut Vec<String>, cur: &mut String) {
    if !cur.trim().is_empty() {
        segs.push(std::mem::take(cur));
    } else {
        cur.clear();
    }
}

/// 空白切分 + 去单双引号。不做一般性反斜杠转义（避免毁掉 Windows 路径 C:\x），
/// `\rm` 形态由 basename 切段自然处理（反斜杠被当路径分隔符切掉）。
fn tokenize(seg: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let (mut in_s, mut in_d, mut has) = (false, false, false);
    for c in seg.chars() {
        match c {
            '\'' if !in_d => {
                in_s = !in_s;
                has = true;
            }
            '"' if !in_s => {
                in_d = !in_d;
                has = true;
            }
            c if c.is_whitespace() && !in_s && !in_d => {
                if has {
                    toks.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            _ => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        toks.push(cur);
    }
    toks
}

/// 跳过段首前缀（sudo 及其选项、环境变量赋值），返回命令名 token 下标。
fn skip_prefix(toks: &[String]) -> usize {
    let mut i = 0;
    while let Some(t) = toks.get(i) {
        if t == "sudo" {
            i += 1;
            // sudo 选项：无参直接跳；带参的多跳一个
            while let Some(o) = toks.get(i) {
                if !o.starts_with('-') || o.as_str() == "-" {
                    break;
                }
                i += 1;
                if matches!(o.as_str(), "-u" | "-g" | "-h" | "-p" | "-C" | "-T" | "-U") {
                    i += 1;
                }
            }
        } else if is_env_assign(t) {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// FOO=bar 形态的环境变量前缀赋值。
fn is_env_assign(t: &str) -> bool {
    let Some((k, _)) = t.split_once('=') else {
        return false;
    };
    !k.is_empty()
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && k.chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
}

/// 路径形态命令名取最后一段（/bin/rm → rm，\rm → rm，C:\tools\git.exe → git.exe）。
fn basename(t: &str) -> &str {
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

/// 命令名小写并去 .exe 后缀。
fn cmd_stem(t: &str) -> String {
    let lower = basename(t).to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

// ---------- 规则 1：rm-force（Deny） ----------

fn rule_rm_force(p: &Payload) -> Option<Decision> {
    let cmd = p.bash_command()?;
    for seg in split_chain(cmd) {
        let toks = tokenize(&seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        let stem = cmd_stem(name);
        let args = &toks[i + 1..];
        let hit = match stem.as_str() {
            "rm" => has_unix_recurse_force(args),
            // cmd 内建命令不区分大小写；/s = 递归
            "del" => has_dos_flag(args, 's'),
            "rd" | "rmdir" => has_dos_flag(args, 's'),
            "remove-item" => has_pwsh_recurse_force(args),
            _ => false,
        };
        if hit {
            return Some(deny(
                "rm-force",
                "递归强制删除命令（rm -rf / del /s / Remove-Item -Recurse -Force 形态）",
            ));
        }
    }
    None
}

/// rm 的递归+强制：-r/-R/--recursive 与 -f/--force 同时出现，支持 -rf 合并与任意排列；
/// `--` 之后是操作数不再解析。
fn has_unix_recurse_force(args: &[String]) -> bool {
    let (mut rec, mut force, mut operand) = (false, false, false);
    for a in args {
        if operand {
            continue;
        }
        if a == "--" {
            operand = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            match long.split('=').next().unwrap_or(long) {
                "recursive" => rec = true,
                "force" => force = true,
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            for c in a[1..].chars() {
                match c {
                    'r' | 'R' => rec = true,
                    'f' => force = true,
                    _ => {}
                }
            }
        }
    }
    rec && force
}

/// cmd 开关形态："/" + 纯字母（可合并如 /s/q 写作 /sq），含目标字母即中；
/// Unix 形态绝对路径（/ 后含非字母）不算开关。
fn has_dos_flag(args: &[String], flag: char) -> bool {
    args.iter().any(|a| {
        let Some(rest) = a.strip_prefix('/') else {
            return false;
        };
        !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_alphabetic())
            && rest.chars().any(|c| c.eq_ignore_ascii_case(&flag))
    })
}

/// PowerShell 唯一前缀缩写：-r/-re/.../-recurse → -Recurse，-f/-fo/... → -Force。
/// 已知误伤面：-Filter 会被前缀匹配当成 -Force（方向是拦截侧，可接受）。
fn has_pwsh_recurse_force(args: &[String]) -> bool {
    let (mut rec, mut force) = (false, false);
    for a in args {
        let Some(rest) = a.strip_prefix('-') else {
            continue;
        };
        let key = rest
            .split(['=', ':'])
            .next()
            .unwrap_or(rest)
            .to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        if "recurse".starts_with(&key) {
            rec = true;
        }
        if "force".starts_with(&key) {
            force = true;
        }
    }
    rec && force
}

// ---------- 规则 2：cred-files（Deny） ----------

fn rule_cred_files(
    p: &Payload,
    canon: &dyn Fn(&str) -> Option<String>,
    home: Option<&str>,
) -> Option<Decision> {
    let raw_path = p.file_path()?;
    let norm = normalize_path(raw_path, p.cwd.as_deref(), home)?;
    if is_credential_path(&norm, home) {
        return Some(deny(
            "cred-files",
            "目标路径指向凭据文件（.env / 私钥 / 证书 / ~/.ssh 或 ~/.aws 内文件）",
        ));
    }
    // 文件存在时 canonicalize 兜底：展开 8.3 短名与 junction 后再判一次
    if let Some(real) = canon(&norm) {
        let real = real.replace('\\', "/");
        if !real.eq_ignore_ascii_case(&norm) && is_credential_path(&real, home) {
            return Some(deny(
                "cred-files",
                "目标路径经真实位置解析后指向凭据文件（8.3 短名或 junction 形态）",
            ));
        }
    }
    None
}

/// 字符串层规范化（不碰 IO）：~ 展开、统一正斜杠、相对路径拼 cwd、去 . 与 ..。
/// 无法确定绝对位置（相对路径且无 cwd）→ None，调用方跳过本规则。
fn normalize_path(raw: &str, cwd: Option<&str>, home: Option<&str>) -> Option<String> {
    let mut s = raw.trim().replace('\\', "/");
    if s.is_empty() {
        return None;
    }
    // ~ 展开成 home
    if s == "~" {
        s = home?.replace('\\', "/");
    } else if let Some(rest) = s.strip_prefix("~/") {
        s = format!(
            "{}/{}",
            home?.trim_end_matches('/').replace('\\', "/"),
            rest
        );
    }
    // 相对路径拼 cwd
    if !is_absolute_path(&s) {
        let cwd = cwd?.trim_end_matches('/').replace('\\', "/");
        if cwd.is_empty() {
            return None;
        }
        s = format!("{cwd}/{s}");
    }
    // 逐段去 . 与 ..
    let mut parts: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // 不能越过根（盘符段或首段）
                if parts.len() > usize::from(is_drive_seg(parts.first())) {
                    parts.pop();
                }
            }
            _ => parts.push(seg),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

fn is_drive_seg(seg: Option<&&str>) -> bool {
    seg.map(|s| s.len() == 2 && s.ends_with(':'))
        .unwrap_or(false)
}

/// 绝对路径：盘符（C:/）、POSIX 根（/x）、UNC（//server/...）。
fn is_absolute_path(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()) || s.starts_with('/')
}

/// 凭据名单判定。norm 为正斜杠规范化路径，比较统一小写（Windows 不区分大小写）。
fn is_credential_path(norm: &str, home: Option<&str>) -> bool {
    let lower = norm.to_ascii_lowercase();
    if let Some(h) = home {
        let h = h.replace('\\', "/");
        let h = h.trim_end_matches('/').to_ascii_lowercase();
        if !h.is_empty()
            && (lower.starts_with(&format!("{h}/.ssh/"))
                || lower.starts_with(&format!("{h}/.aws/")))
        {
            return true;
        }
    }
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // 豁免必须先于 .env.* 通配
    if matches!(base, ".env.example" | ".env.sample" | ".env.template") {
        return false;
    }
    if matches!(
        base,
        ".env" | ".git-credentials" | ".netrc" | "id_rsa" | "id_ed25519" | "id_ecdsa"
    ) {
        return true;
    }
    if base.starts_with(".env.") {
        return true;
    }
    if let Some((_, ext)) = base.rsplit_once('.') {
        if matches!(ext, "pem" | "key" | "pfx" | "p12") {
            return true;
        }
    }
    false
}

// ---------- 规则 3：git-force-push（Ask） ----------

/// git 全局选项解析：返回 (子命令, 剩余 token 切片)。
fn git_subcommand(toks: &[String], i: usize) -> Option<(&str, &[String])> {
    let mut j = i + 1;
    loop {
        let t = toks.get(j)?;
        match t.as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--exec-path" => j += 2,
            s if s.starts_with("--") && s.contains('=') => j += 1,
            s if s.starts_with('-') && s.len() > 1 => j += 1,
            s => return Some((s, &toks[j + 1..])),
        }
    }
}

fn rule_git_force_push(p: &Payload) -> Option<Decision> {
    let cmd = p.bash_command()?;
    for seg in split_chain(cmd) {
        let toks = tokenize(&seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        if cmd_stem(name) != "git" {
            continue;
        }
        let Some((sub, rest)) = git_subcommand(&toks, i) else {
            continue;
        };
        if sub != "push" {
            continue;
        }
        // --delete 不拦（git-destroy 地界）；带 force 家族才 Ask
        let force = rest.iter().any(|a| {
            a == "--force"
                || a.starts_with("--force-with-lease")
                || (a.starts_with('-') && !a.starts_with("--") && a[1..].chars().any(|c| c == 'f'))
        });
        if force {
            return Some(Decision::Ask {
                rule: "git-force-push",
                question:
                    "git push 携带 --force / -f / --force-with-lease，可能覆盖远端历史，是否允许？"
                        .to_string(),
            });
        }
    }
    None
}

// ---------- 规则 4：self-protect（Deny） ----------

const SELF_PROTECT_REASON: &str = "目标路径受 KimiCodeGuard 保护，请手动修改或用托盘一键修复";

fn rule_self_protect(p: &Payload, env: &Env) -> Option<Decision> {
    if env.protected.is_empty() {
        return None;
    }
    // Write/Edit 工具 file_path 命中 → 拦（读不拦，Read 无 write_path）
    if matches!(p.tool_name.as_deref(), Some("Write") | Some("Edit")) {
        if let Some(path) = p.write_path() {
            if self_protect_hit(path, p.cwd.as_deref(), env) {
                return Some(deny("self-protect", SELF_PROTECT_REASON));
            }
        }
    }
    let cmd = p.bash_command()?;
    for seg in split_chain(cmd) {
        let toks = tokenize(&seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        let stem = cmd_stem(name);
        let args = &toks[i + 1..];
        match stem.as_str() {
            // cp/mv/copy/move/rename：目标 = 最后一个操作数
            "cp" | "mv" | "copy" | "move" | "rename" => {
                if let Some(target) = last_operand(args) {
                    if self_protect_hit(target, p.cwd.as_deref(), env) {
                        return Some(deny("self-protect", SELF_PROTECT_REASON));
                    }
                }
            }
            // tee：每个操作数都是写出目标
            "tee" => {
                for t in operands(args) {
                    if self_protect_hit(t, p.cwd.as_deref(), env) {
                        return Some(deny("self-protect", SELF_PROTECT_REASON));
                    }
                }
            }
            // del/rm：每个操作数都是删除目标（rm -rf 已由 rm-force 先行拦截）
            "del" | "rm" => {
                for t in operands(args) {
                    if self_protect_hit(t, p.cwd.as_deref(), env) {
                        return Some(deny("self-protect", SELF_PROTECT_REASON));
                    }
                }
            }
            // sed -i：编辑的目标文件
            "sed" if has_inplace_flag(args) => {
                for t in sed_targets(args) {
                    if self_protect_hit(t, p.cwd.as_deref(), env) {
                        return Some(deny("self-protect", SELF_PROTECT_REASON));
                    }
                }
            }
            _ => {}
        }
        // 重定向（>、>>、1>、2>、&> 等）：写出目标
        if let Some(target) = redirect_target(&toks) {
            if self_protect_hit(target, p.cwd.as_deref(), env) {
                return Some(deny("self-protect", SELF_PROTECT_REASON));
            }
        }
    }
    None
}

/// 目标路径是否命中受保护集：字符串层规范化（~ 展开/统一斜杠/相对拼 cwd）后
/// 与保护集逐一小写比较；文件存在时 canonicalize 兜底（8.3 短名与 junction）。
fn self_protect_hit(raw: &str, cwd: Option<&str>, env: &Env) -> bool {
    let Some(norm) = normalize_path(raw, cwd, env.home) else {
        return false;
    };
    if hits_protected(&norm, env.protected) {
        return true;
    }
    if let Some(real) = (env.canon)(&norm) {
        let real = real.replace('\\', "/");
        if !real.eq_ignore_ascii_case(&norm) && hits_protected(&real, env.protected) {
            return true;
        }
    }
    false
}

/// 规范化路径（正斜杠）与受保护集逐一小写比较（Windows 不区分大小写）。
fn hits_protected(norm: &str, protected: &[String]) -> bool {
    let lower = norm.to_ascii_lowercase();
    protected.iter().any(|p| p.to_ascii_lowercase() == lower)
}

/// 取所有操作数（跳过选项形态的 token；`--` 之后全算操作数）。
fn operands(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut after_dd = false;
    for a in args {
        if after_dd {
            out.push(a.as_str());
            continue;
        }
        if a == "--" {
            after_dd = true;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            continue;
        }
        out.push(a.as_str());
    }
    out
}

/// 最后一个操作数（cp/mv 的目标）。
fn last_operand(args: &[String]) -> Option<&str> {
    operands(args).pop()
}

/// 重定向目标抽取：token 形态 > / >>（目标在下一 token）、>file / >>file（附着）、
/// 2> / 1>> / &> / 2>>file（数字或 & 前缀，可内联）。
fn redirect_target(toks: &[String]) -> Option<&str> {
    for (idx, t) in toks.iter().enumerate() {
        let s = t.as_str();
        if s == ">" || s == ">>" {
            return toks.get(idx + 1).map(String::as_str);
        }
        if s.starts_with('>') && s.len() > 1 {
            let rest = &s[1..];
            let rest = rest.strip_prefix('>').unwrap_or(rest);
            if !rest.is_empty() {
                return Some(rest);
            }
        }
        // 纯数字/& 前缀后跟 > / >>：2>、1>>、&>、2>>file
        let lead_len = s
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '&')
            .count();
        if lead_len > 0 && lead_len < s.len() {
            let rest = &s[lead_len..];
            let op_len = if rest.starts_with(">>") {
                2
            } else if rest.starts_with('>') {
                1
            } else {
                0
            };
            if op_len > 0 {
                let inline = &rest[op_len..];
                if !inline.is_empty() {
                    return Some(inline);
                }
                return toks.get(idx + 1).map(String::as_str);
            }
        }
    }
    None
}

/// sed -i / --in-place（含 -i.bak 附着后缀形态）。
fn has_inplace_flag(args: &[String]) -> bool {
    args.iter()
        .any(|a| a == "-i" || a == "--in-place" || (a.starts_with("-i") && a.len() > 2))
}

/// sed -i 的编辑目标：-i 后可能紧邻后缀参数（.bak 等），统一从第 2 个操作数起算
/// （-i.bak 附着形态同构：操作数 = [script, files...]）。脚本参数被一起检查无害
/// （只有恰等于受保护路径的字符串才会误中，方向是拦截侧）。
fn sed_targets(args: &[String]) -> Vec<&str> {
    let ops = operands(args);
    if ops.is_empty() {
        return Vec::new();
    }
    ops[1..].to_vec()
}

// ---------- 规则 5：git-destroy（Ask 家族，无 deny） ----------

const GIT_DESTROY_HISTORY_Q: &str = "git 销毁性操作，可能永久删除提交历史或远端引用，是否允许？";
const GIT_DESTROY_DIRTY_Q: &str = "工作区有未提交改动将永久丢失，是否允许？";

fn rule_git_destroy(p: &Payload, env: &Env) -> Option<Decision> {
    let cmd = p.bash_command()?;
    for seg in split_chain(cmd) {
        let toks = tokenize(&seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        if cmd_stem(name) != "git" {
            continue;
        }
        let Some((sub, rest)) = git_subcommand(&toks, i) else {
            continue;
        };
        // 历史/远端销毁（无需探测，一律 ask）
        if git_history_destroy(sub, rest) {
            return Some(Decision::Ask {
                rule: "git-destroy",
                question: GIT_DESTROY_HISTORY_Q.to_string(),
            });
        }
        // 工作区销毁：探测仓库状态，有变更才 ask（干净直接放行）
        if git_workspace_destroy(sub, rest) {
            let cwd = p.cwd.as_deref().unwrap_or("");
            if (env.git_dirty)(cwd) {
                return Some(Decision::Ask {
                    rule: "git-destroy",
                    question: GIT_DESTROY_DIRTY_Q.to_string(),
                });
            }
            // 干净 → 本规则放行，继续后续规则
        }
    }
    None
}

/// 历史/远端销毁形态（无需探测仓库状态）。
fn git_history_destroy(sub: &str, rest: &[String]) -> bool {
    match sub {
        "push" => rest
            .iter()
            .any(|a| a == "--delete" || (a.starts_with(':') && a.len() > 1)),
        "branch" => rest.iter().any(|a| {
            a == "-D"
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && a.len() > 1
                    && a[1..].chars().any(|c| c == 'D'))
        }),
        "tag" => rest.iter().any(|a| a == "-d" || a == "--delete"),
        "reflog" => rest.first().map(|s| s.as_str()) == Some("expire"),
        "gc" => rest
            .iter()
            .any(|a| a == "--prune" || a.starts_with("--prune=")),
        "filter-branch" | "filter-repo" => true,
        "update-ref" => rest.iter().any(|a| a == "-d" || a == "--delete"),
        "stash" => matches!(
            rest.first().map(String::as_str),
            Some("drop") | Some("clear")
        ),
        _ => false,
    }
}

/// 工作区销毁形态（需探测仓库状态：有变更才 ask）。
fn git_workspace_destroy(sub: &str, rest: &[String]) -> bool {
    match sub {
        "reset" => rest.iter().any(|a| a == "--hard"),
        "clean" => !has_short_flag(rest, 'n') && has_short_flag(rest, 'f'),
        // 仅 checkout -- <路径> 形态：-- 之后还有操作数
        "checkout" => rest
            .iter()
            .position(|a| a == "--")
            .map(|pos| rest.len() > pos + 1)
            .unwrap_or(false),
        // --staged 只动索引不毁工作区；默认 / --worktree 形态 + 有操作数才探测
        "restore" => !rest.iter().any(|a| a == "--staged") && !operands(rest).is_empty(),
        _ => false,
    }
}

/// 单短横合并旗标（-fd）或独立（-f -d）中含目标字母。
fn has_short_flag(args: &[String], flag: char) -> bool {
    args.iter().any(|a| {
        a.starts_with('-')
            && !a.starts_with("--")
            && a.len() > 1
            && a[1..].chars().any(|c| c.eq_ignore_ascii_case(&flag))
    })
}

// ---------- 规则 6：shell-obfuscation（剥壳重判；不透明编码 ask） ----------

const OBFUS_PEEL_NOTE: &str = "（经 shell 包装解出）";
const OBFUS_DECODE_NOTE: &str = "（经编码解码还原）";
const OBFUS_OPAQUE_Q: &str = "执行不透明编码内容，无法审查，是否允许？";
/// 解码输入上限（防内存放大）。
const DECODE_INPUT_CAP: usize = 64 * 1024;

fn rule_shell_obfuscation(p: &Payload, env: &Env, depth: u8) -> Option<Decision> {
    let cmd = p.bash_command()?;
    let segs = split_chain(cmd);
    // ① 包装器剥壳：bash/sh -c、cmd /c、powershell -Command 的内层重判
    for seg in &segs {
        if let Some(inner) = peel_wrapper(seg) {
            if let Some(d) = rejudge_command(p, env, &inner, depth + 1) {
                return Some(annotate(d, OBFUS_PEEL_NOTE));
            }
        }
    }
    // ② 编码执行：powershell -enc / base64 管道进解释器
    if let Some(d) = encoded_execution(p, env, &segs, depth) {
        return Some(d);
    }
    None
}

/// 剥一层包装器：bash/sh/zsh/dash -c <cmd>、cmd /c <cmd>、powershell -Command/-c <cmd>。
fn peel_wrapper(seg: &str) -> Option<String> {
    let toks = tokenize(seg);
    let i = skip_prefix(&toks);
    let name = cmd_stem(toks.get(i)?);
    let args = &toks[i + 1..];
    match name.as_str() {
        "bash" | "sh" | "zsh" | "dash" => c_flag_command(args),
        "cmd" => {
            let pos = args.iter().position(|a| a.eq_ignore_ascii_case("/c"))?;
            let inner = args[pos + 1..].join(" ");
            if inner.trim().is_empty() {
                None
            } else {
                Some(inner)
            }
        }
        "powershell" | "pwsh" => powershell_command(args),
        _ => None,
    }
}

/// bash/sh 的 -c（含合并形态 -lc）：取下一个 token 为内层命令。
fn c_flag_command(args: &[String]) -> Option<String> {
    for (idx, a) in args.iter().enumerate() {
        if a.starts_with('-')
            && !a.starts_with("--")
            && a.len() > 1
            && a[1..].chars().any(|c| c == 'c')
        {
            let inner = args.get(idx + 1)?;
            if inner.trim().is_empty() {
                return None;
            }
            return Some(inner.clone());
        }
    }
    None
}

/// powershell -Command/-c（唯一前缀缩写）的明文内层命令。
/// -EncodedCommand 前缀不在此处剥（走编码分支）。
fn powershell_command(args: &[String]) -> Option<String> {
    for (idx, a) in args.iter().enumerate() {
        let Some(stripped) = a.strip_prefix('-') else {
            continue;
        };
        let flag = stripped.to_ascii_lowercase();
        if flag.is_empty() || !"command".starts_with(&flag) {
            continue;
        }
        let inner = args.get(idx + 1)?;
        if inner.trim().is_empty() {
            return None;
        }
        return Some(inner.clone());
    }
    None
}

/// 编码执行：powershell -enc/-EncodedCommand、base64 -d/certutil -decode 管道进解释器。
/// 能干净解码 → 先解码再重判；解不出或解码后没命中 → ask（不透明）。
fn encoded_execution(p: &Payload, env: &Env, segs: &[String], depth: u8) -> Option<Decision> {
    // a) powershell -EncodedCommand / -enc / -e（值像 base64 才认）
    for seg in segs {
        let toks = tokenize(seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        if !matches!(cmd_stem(name).as_str(), "powershell" | "pwsh") {
            continue;
        }
        if let Some(b64) = powershell_encoded_value(&toks[i + 1..]) {
            if let Some(d) = decode_and_rejudge(p, env, &b64, depth) {
                return Some(d);
            }
            return Some(Decision::Ask {
                rule: "shell-obfuscation",
                question: OBFUS_OPAQUE_Q.to_string(),
            });
        }
    }
    // b) 解码器管道进解释器：base64 -d / certutil -decode 后跟 bash/sh/cmd/powershell
    for (idx, seg) in segs.iter().enumerate() {
        if !is_decoder_segment(seg) {
            continue;
        }
        let has_interpreter = segs[idx + 1..].iter().any(|s| is_interpreter_segment(s));
        if !has_interpreter {
            continue;
        }
        let candidate = decode_input_candidate(segs, idx);
        if let Some(d) = decode_and_rejudge(p, env, &candidate, depth) {
            return Some(d);
        }
        return Some(Decision::Ask {
            rule: "shell-obfuscation",
            question: OBFUS_OPAQUE_Q.to_string(),
        });
    }
    None
}

/// -EncodedCommand / -enc 明确形态，或 -e（值长得像 base64 才认——
/// -e 是 -EncodedCommand 与 -ExecutionPolicy 的共同前缀，避免误吃策略参数）。
fn powershell_encoded_value(args: &[String]) -> Option<String> {
    for (idx, a) in args.iter().enumerate() {
        let Some(stripped) = a.strip_prefix('-') else {
            continue;
        };
        let flag = stripped.to_ascii_lowercase();
        if flag.is_empty() || !"encodedcommand".starts_with(&flag) {
            continue;
        }
        let v = args.get(idx + 1)?;
        if v.is_empty() {
            return None;
        }
        if flag == "e" && !looks_like_base64(v) {
            continue;
        }
        return Some(v.clone());
    }
    None
}

/// 解码器段：base64 -d/--decode/-D、certutil -decode。
fn is_decoder_segment(seg: &str) -> bool {
    let toks = tokenize(seg);
    let i = skip_prefix(&toks);
    let Some(name) = toks.get(i) else {
        return false;
    };
    let stem = cmd_stem(name);
    if stem == "base64" {
        toks[i + 1..]
            .iter()
            .any(|a| a == "-d" || a == "--decode" || a == "-D")
    } else if stem == "certutil" {
        toks[i + 1..]
            .iter()
            .any(|a| a.eq_ignore_ascii_case("-decode"))
    } else {
        false
    }
}

/// 解释器段：bash/sh/zsh/dash/cmd/powershell/pwsh（编码内容管道进去执行）。
fn is_interpreter_segment(seg: &str) -> bool {
    let toks = tokenize(seg);
    let i = skip_prefix(&toks);
    let Some(name) = toks.get(i) else {
        return false;
    };
    matches!(
        cmd_stem(name).as_str(),
        "bash" | "sh" | "zsh" | "dash" | "cmd" | "powershell" | "pwsh"
    )
}

/// 解码器段的候选输入：解码器自身 <<< herestring，否则紧前段的全部参数拼接。
fn decode_input_candidate(segs: &[String], idx: usize) -> String {
    let toks = tokenize(&segs[idx]);
    if let Some(pos) = toks.iter().position(|t| t == "<<<") {
        if let Some(v) = toks.get(pos + 1) {
            return v.clone();
        }
    }
    if idx == 0 {
        return String::new();
    }
    let prev = tokenize(&segs[idx - 1]);
    let i = skip_prefix(&prev);
    if i < prev.len() {
        prev[i + 1..].join(" ")
    } else {
        String::new()
    }
}

/// 解码 → 文本 → 重判。解码失败或解码后未命中任何规则 → None（调用方按不透明 ask）。
fn decode_and_rejudge(p: &Payload, env: &Env, b64_text: &str, depth: u8) -> Option<Decision> {
    if b64_text.len() > DECODE_INPUT_CAP {
        return None;
    }
    let bytes = decode_base64(b64_text)?;
    let text = bytes_to_text(&bytes)?;
    let d = rejudge_command(p, env, &text, depth + 1)?;
    Some(annotate(d, OBFUS_DECODE_NOTE))
}

/// 把内层命令文本放回原 payload 的 tool_input.command，重跑整条规则链。
/// 构造出的 JSON 一定合法，但防御性起见 parse 失败按 None（放行）处理。
fn rejudge_command(p: &Payload, env: &Env, cmd_text: &str, depth: u8) -> Option<Decision> {
    let mut raw = p.raw.clone();
    let ti = raw.get_mut("tool_input")?.as_object_mut()?;
    ti.insert(
        "command".into(),
        serde_json::Value::String(cmd_text.to_string()),
    );
    let bytes = serde_json::to_vec(&raw).ok()?;
    let inner = Payload::parse(&bytes)?;
    match evaluate_rules(&inner, env, depth) {
        Decision::Allow => None,
        d => Some(d),
    }
}

/// 判定附加说明（嵌套剥壳不重复加注）。
fn annotate(d: Decision, note: &str) -> Decision {
    match d {
        Decision::Deny { rule, reason } => Decision::Deny {
            rule,
            reason: if reason.ends_with(note) {
                reason
            } else {
                format!("{reason}{note}")
            },
        },
        Decision::Ask { rule, question } => Decision::Ask {
            rule,
            question: if question.ends_with(note) {
                question
            } else {
                format!("{question}{note}")
            },
        },
        Decision::Allow => Decision::Allow,
    }
}

/// 手写 base64 解码（标准 + URL-safe 字母表，容忍空白；上限由调用方保证）。
/// 非法字符 / 长度错位 → None。
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut pad = 0;
    let mut nchars = 0;
    for c in text.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == '=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return None; // '=' 后还有非空白字符
        }
        let v = base64_value(c)?;
        nchars += 1;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    let total = nchars + pad;
    if total % 4 == 1 || pad > 2 {
        return None;
    }
    Some(out)
}

fn base64_value(c: char) -> Option<u32> {
    match c {
        'A'..='Z' => Some((c as u32) - ('A' as u32)),
        'a'..='z' => Some((c as u32) - ('a' as u32) + 26),
        '0'..='9' => Some((c as u32) - ('0' as u32) + 52),
        '+' | '-' => Some(62),
        '/' | '_' => Some(63),
        _ => None,
    }
}

/// 解码字节 → 文本：优先 UTF-8；否则 UTF-16LE/BE。要求「像文本」（控制字符占比低）。
fn bytes_to_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() > DECODE_INPUT_CAP {
        return None;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        if looks_like_text(s) {
            return Some(s.to_string());
        }
    }
    if bytes.len().is_multiple_of(2) {
        let le: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&le) {
            if looks_like_text(&s) {
                return Some(s);
            }
        }
        let be: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&be) {
            if looks_like_text(&s) {
                return Some(s);
            }
        }
    }
    None
}

/// 控制字符（\t\r\n 除外）占比 < 5% 且非空 → 像文本。
fn looks_like_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bad = s
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\t' | '\r' | '\n'))
        .count();
    bad * 20 < s.chars().count()
}

/// 值是否「长得像 base64」：长度 ≥4 且为 4 的倍数，字符全在字母表（含空白与 =）。
fn looks_like_base64(s: &str) -> bool {
    let mut nchars = 0;
    let mut pad = 0;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == '=' {
            pad += 1;
            continue;
        }
        if base64_value(c).is_none() {
            return false;
        }
        nchars += 1;
    }
    nchars >= 4 && (nchars + pad) % 4 == 0 && pad <= 2
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn bash(cmd: &str) -> Payload {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":"D:/proj","tool_name":"Bash","tool_input":{{"command":{}}},"tool_call_id":"t"}}"#,
            serde_json::to_string(cmd).unwrap()
        );
        Payload::parse(json.as_bytes()).unwrap()
    }

    fn bash_in(cmd: &str, cwd: &str) -> Payload {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":{},"tool_name":"Bash","tool_input":{{"command":{}}},"tool_call_id":"t"}}"#,
            serde_json::to_string(cwd).unwrap(),
            serde_json::to_string(cmd).unwrap()
        );
        Payload::parse(json.as_bytes()).unwrap()
    }

    fn tool_payload(tool: &str, path: &str, cwd: &str) -> Payload {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":{},"tool_name":{},"tool_input":{{"path":{}}},"tool_call_id":"t"}}"#,
            serde_json::to_string(cwd).unwrap(),
            serde_json::to_string(tool).unwrap(),
            serde_json::to_string(path).unwrap()
        );
        Payload::parse(json.as_bytes()).unwrap()
    }

    fn read_tool(path: &str, cwd: &str) -> Payload {
        tool_payload("Read", path, cwd)
    }

    fn no_canon(_: &str) -> Option<String> {
        None
    }

    /// 默认测试环境：无 canon、假 home、空保护集、仓库干净。
    fn test_env<'a>(canon: &'a dyn Fn(&str) -> Option<String>, home: &'a str) -> Env<'a> {
        Env {
            canon,
            home: Some(home),
            protected: &[],
            git_dirty: &|_| false,
        }
    }

    /// self-protect 假保护集（机器无关）。
    fn fake_protected() -> Vec<String> {
        [
            "C:/Users/tester/.kimi-code/config.toml",
            "C:/tools/guard-hook.exe",
            "C:/tools/KimiCodeGuard.exe",
            "C:/tools/guard-daemon.exe",
            "C:/Users/tester/AppData/Local/KimiCodeGuard/audit.db",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn eval_bash(cmd: &str) -> Decision {
        evaluate_with(&bash(cmd), &test_env(&no_canon, "C:/Users/tester"))
    }

    fn eval_protect(p: &Payload, canon: &dyn Fn(&str) -> Option<String>) -> Decision {
        let protected = fake_protected();
        let env = Env {
            canon,
            home: Some("C:/Users/tester"),
            protected: &protected,
            git_dirty: &|_| false,
        };
        evaluate_with(p, &env)
    }

    fn eval_git(cmd: &str, dirty: bool) -> Decision {
        let env = Env {
            canon: &no_canon,
            home: Some("C:/Users/tester"),
            protected: &[],
            git_dirty: &|_| dirty,
        };
        evaluate_with(&bash(cmd), &env)
    }

    // ---- rm-force ----

    #[test]
    fn rm_force_flag_permutations() {
        for c in [
            "rm -rf /tmp/x",
            "rm -fr /tmp/x",
            "rm -r -f /tmp/x",
            "rm -f -r /tmp/x",
            "rm --recursive --force /tmp/x",
            "rm --force --recursive /tmp/x",
            "rm -Rf /tmp/x",
            "\\rm -rf ~",
            "sudo rm -rf /",
            "sudo -n rm -rf /tmp/x",
            "/bin/rm -rf /tmp/x",
            "FOO=1 rm -rf /tmp/x",
            "echo ok && rm -rf build",
            "echo ok; rm -rf build",
            "ls | rm -rf build",
            "echo a\nrm -rf b",
        ] {
            assert_eq!(eval_bash(c).kind(), "deny", "应拦截: {c}");
        }
    }

    #[test]
    fn rm_without_recurse_or_force_allowed() {
        for c in [
            "rm file.txt",
            "rm -f file.txt",
            "rm -r dir",
            "rm -i file.txt",
            "rmdir empty_dir",
            "echo \"rm -rf /\"",
            "git rm -r --cached dir",
        ] {
            assert_eq!(eval_bash(c).kind(), "allow", "应放行: {c}");
        }
    }

    #[test]
    fn windows_delete_variants() {
        for c in [
            "del /s /q folder",
            "DEL /S folder",
            "rd /s /q folder",
            "RMDIR /S folder",
            "Remove-Item -Recurse -Force ./build",
            "remove-item -recurse -force ./build",
            "Remove-Item -r -fo ./build",
        ] {
            assert_eq!(eval_bash(c).kind(), "deny", "应拦截: {c}");
        }
        for c in [
            "del file.txt",
            "del /q file.txt",
            "rd emptydir",
            "Remove-Item ./file.txt",
            "Remove-Item -Recurse ./dir",
        ] {
            assert_eq!(eval_bash(c).kind(), "allow", "应放行: {c}");
        }
    }

    // ---- cred-files ----

    #[test]
    fn credential_files_denied() {
        let home = "C:/Users/tester";
        for (path, cwd) in [
            (".env", "D:/proj"),
            (".env.production", "D:/proj"),
            ("id_rsa", "D:/proj"),
            ("id_ed25519", "D:/proj"),
            ("server.pem", "D:/proj"),
            ("app.key", "D:/proj"),
            ("cert.pfx", "D:/proj"),
            ("store.p12", "D:/proj"),
            (".git-credentials", "D:/proj"),
            (".netrc", "D:/proj"),
            ("~/.ssh/id_rsa", "D:/proj"),
            ("~/.aws/credentials", "D:/proj"),
            ("C:/Users/tester/.ssh/config", "D:/proj"),
            ("../../Users/tester/.ssh/id_rsa", "C:/Users/tester/proj/sub"),
            ("./sub/../.env", "D:/proj"),
        ] {
            let env = test_env(&no_canon, home);
            let d = evaluate_with(&read_tool(path, cwd), &env);
            assert_eq!(d.kind(), "deny", "应拦截: {path} (cwd={cwd})");
        }
    }

    #[test]
    fn lookalike_files_allowed() {
        let home = "C:/Users/tester";
        for (path, cwd) in [
            (".env.example", "D:/proj"),
            (".env.sample", "D:/proj"),
            (".env.template", "D:/proj"),
            ("id_rsa.pub", "D:/proj"),
            ("production.env", "D:/proj"),
            ("notes.pem.txt", "D:/proj"),
            ("C:/Users/tester/.config/app.json", "D:/proj"),
            ("src/main.rs", "D:/proj"),
        ] {
            let env = test_env(&no_canon, home);
            let d = evaluate_with(&read_tool(path, cwd), &env);
            assert_eq!(d.kind(), "allow", "应放行: {path}");
        }
    }

    #[test]
    fn mixed_slashes_and_tilde_normalized() {
        let home = "C:\\Users\\tester";
        // 混合斜杠 + ~ + 反斜杠 home
        let p = read_tool("~\\.ssh\\id_rsa", "D:/proj");
        assert_eq!(evaluate_with(&p, &test_env(&no_canon, home)).kind(), "deny");
        let p = read_tool("C:\\Users/tester\\.aws\\credentials", "D:/proj");
        assert_eq!(evaluate_with(&p, &test_env(&no_canon, home)).kind(), "deny");
    }

    #[test]
    fn relative_path_without_cwd_skips_rule() {
        let json = br#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","tool_input":{"path":".env"},"tool_call_id":"t"}"#;
        let p = Payload::parse(json).unwrap();
        assert_eq!(p.cwd, None);
        // 缺 cwd → 相对路径无法定位 → 规则跳过（放行，缺失已由 parse 记 note）
        assert_eq!(
            evaluate_with(&p, &test_env(&no_canon, "C:/Users/tester")).kind(),
            "allow"
        );
    }

    #[test]
    fn canonicalize_fallback_catches_junction() {
        // 字符串层无害（temp 下 keys.txt），canon 后落入 home/.ssh
        let canon = |_: &str| Some("C:/Users/tester/.ssh/keys.txt".to_string());
        let p = read_tool("keys.txt", "D:/temp/link");
        assert_eq!(
            evaluate_with(&p, &test_env(&canon, "C:/Users/tester")).kind(),
            "deny"
        );
    }

    // ---- git-force-push ----

    #[test]
    fn git_force_push_asked() {
        for c in [
            "git push --force",
            "git push -f origin main",
            "git push -uf origin main",
            "git push -fu origin main",
            "git push --force-with-lease",
            "git push --force-with-lease=main:abc123",
            "git -C /repo push --force",
            "git --git-dir=/r/.git push -f",
            "cd x && git push -f",
            "sudo git push --force",
        ] {
            assert_eq!(eval_bash(c).kind(), "ask", "应询问: {c}");
        }
    }

    #[test]
    fn git_normal_push_allowed() {
        for c in [
            "git push origin main",
            "git push -u origin main",
            "git pull --force",
            "git fetch --force",
            "git config push.forcePush true",
            "git commit -m \"push --force\"",
        ] {
            assert_eq!(eval_bash(c).kind(), "allow", "应放行: {c}");
        }
    }

    // ---- self-protect ----

    #[test]
    fn protect_write_edit_tools_denied() {
        for (tool, path) in [
            ("Write", "C:/Users/tester/.kimi-code/config.toml"),
            ("Write", "~/.kimi-code/config.toml"),
            ("Edit", "C:/tools/guard-hook.exe"),
            ("Write", "C:/tools/KimiCodeGuard.exe"),
            ("Edit", "C:/tools/guard-daemon.exe"),
            (
                "Write",
                "C:/Users/tester/AppData/Local/KimiCodeGuard/audit.db",
            ),
            ("Write", "audit.db"), // cwd 在数据目录内的相对路径
        ] {
            let cwd = if path == "audit.db" {
                "C:/Users/tester/AppData/Local/KimiCodeGuard"
            } else {
                "D:/proj"
            };
            let p = tool_payload(tool, path, cwd);
            assert_eq!(
                eval_protect(&p, &no_canon).kind(),
                "deny",
                "{tool} {path} 应拦截"
            );
        }
    }

    #[test]
    fn protect_read_allowed() {
        let p = read_tool("~/.kimi-code/config.toml", "D:/proj");
        assert_eq!(eval_protect(&p, &no_canon).kind(), "allow", "读不拦");
    }

    #[test]
    fn protect_bash_cp_mv_copy_move_rename_denied() {
        for c in [
            "cp a.exe C:/tools/guard-hook.exe",
            "mv /tmp/x ~/.kimi-code/config.toml",
            "copy b.exe C:/tools/KimiCodeGuard.exe",
            "move c.exe C:/tools/guard-daemon.exe",
            "rename d.bin C:/Users/tester/AppData/Local/KimiCodeGuard/audit.db",
        ] {
            let d = eval_protect(&bash(c), &no_canon);
            assert_eq!(d.kind(), "deny", "应拦截: {c}");
        }
    }

    #[test]
    fn protect_bash_tee_denied() {
        for c in [
            "echo x | tee C:/tools/guard-hook.exe",
            "tee -a C:/Users/tester/.kimi-code/config.toml",
        ] {
            let d = eval_protect(&bash(c), &no_canon);
            assert_eq!(d.kind(), "deny", "应拦截: {c}");
        }
    }

    #[test]
    fn protect_bash_redirect_denied() {
        for c in [
            "echo x > C:/Users/tester/.kimi-code/config.toml",
            "echo x >> C:/tools/guard-hook.exe",
            "echo x 2> C:/tools/guard-daemon.exe",
            "echo x 1>> C:/tools/KimiCodeGuard.exe",
            "echo x &> C:/Users/tester/AppData/Local/KimiCodeGuard/audit.db",
            "echo x >C:/tools/guard-hook.exe",
            "echo x 2>>C:/tools/guard-daemon.exe",
        ] {
            let d = eval_protect(&bash(c), &no_canon);
            assert_eq!(d.kind(), "deny", "应拦截: {c}");
        }
        // 相对路径重定向在数据目录 cwd 下命中
        let d = eval_protect(
            &bash_in(
                "echo x > audit.db",
                "C:/Users/tester/AppData/Local/KimiCodeGuard",
            ),
            &no_canon,
        );
        assert_eq!(d.kind(), "deny");
    }

    #[test]
    fn protect_bash_rm_del_sed_denied() {
        for c in [
            "rm C:/tools/guard-hook.exe",
            "rm -f C:/tools/guard-daemon.exe",
            "del C:/tools/KimiCodeGuard.exe",
            "del /q C:/Users/tester/AppData/Local/KimiCodeGuard/audit.db",
            "sed -i 's/a/b/' C:/Users/tester/.kimi-code/config.toml",
            "sed -i.bak 's/a/b/' C:/tools/guard-hook.exe",
            "sed --in-place 's/a/b/' C:/tools/guard-daemon.exe",
        ] {
            let d = eval_protect(&bash(c), &no_canon);
            assert_eq!(d.kind(), "deny", "应拦截: {c}");
        }
    }

    #[test]
    fn protect_allow_cases() {
        for c in [
            "cat C:/Users/tester/.kimi-code/config.toml",   // 读不拦
            "cp C:/tools/guard-hook.exe C:/tmp/backup.exe", // 源命中目标不命中
            "echo \"x > y\"",                               // 引号内不是重定向
            "echo x > C:/tmp/out.txt",                      // 非保护路径
            "touch C:/Users/tester/.kimi-code/config.toml", // touch 不在合同内
        ] {
            let d = eval_protect(&bash(c), &no_canon);
            assert_eq!(d.kind(), "allow", "应放行: {c}");
        }
        let p = tool_payload(
            "Write",
            "C:/Users/tester/.kimi-code/settings.json",
            "D:/proj",
        );
        assert_eq!(eval_protect(&p, &no_canon).kind(), "allow");
        let p = tool_payload(
            "Write",
            "C:/Users/tester/.kimi-code/config.toml.bak",
            "D:/proj",
        );
        assert_eq!(eval_protect(&p, &no_canon).kind(), "allow");
        let p = tool_payload("Write", "C:/Users/tester/.kimi-code", "D:/proj");
        assert_eq!(
            eval_protect(&p, &no_canon).kind(),
            "allow",
            "父目录不在保护合同内"
        );
    }

    #[test]
    fn protect_canonicalize_fallback_catches_junction() {
        // 字符串层无害（D:/proj/guard-hook.exe），canon 后落入受保护 exe
        let canon = |_: &str| Some("C:/tools/guard-hook.exe".to_string());
        let p = tool_payload("Write", "guard-hook.exe", "D:/proj");
        let d = eval_protect(&p, &canon);
        assert_eq!(d.kind(), "deny", "canon 兜底应拦截 8.3/junction 形态");
    }

    #[test]
    fn protect_empty_set_allows_all() {
        // 保护集为空（如环境探测全部失败）→ 本规则完全跳过，不误拦
        let p = tool_payload("Write", "C:/Users/tester/.kimi-code/config.toml", "D:/proj");
        assert_eq!(
            evaluate_with(&p, &test_env(&no_canon, "C:/Users/tester")).kind(),
            "allow"
        );
    }

    #[test]
    fn real_protected_paths_use_forward_slashes() {
        // canonicalize 返回反斜杠形态——防回归：入库前必须换回正斜杠（与目标规范化口径一致）
        for p in real_protected_paths() {
            assert!(!p.contains('\\'), "保护路径应为正斜杠: {p}");
            assert!(p.len() > 3, "保护路径不应为空/过短: {p:?}");
        }
    }

    // ---- git-destroy ----

    #[test]
    fn gd_history_forms_always_ask_without_probe() {
        let calls = Cell::new(0u32);
        let probe = |_: &str| {
            calls.set(calls.get() + 1);
            true
        };
        let env = Env {
            canon: &no_canon,
            home: Some("C:/Users/tester"),
            protected: &[],
            git_dirty: &probe,
        };
        for c in [
            "git push origin --delete old-branch",
            "git push origin :refs/heads/x",
            "git branch -D feature/x",
            "git tag -d v1.0",
            "git reflog expire --expire=now --all",
            "git gc --prune=now",
            "git gc --prune",
            "git filter-branch --force HEAD",
            "git filter-repo --path secrets",
            "git update-ref -d refs/heads/x",
            "git stash drop stash@{0}",
            "git stash clear",
        ] {
            let d = evaluate_with(&bash(c), &env);
            assert_eq!(d.kind(), "ask", "应询问: {c}");
            assert_eq!(calls.get(), 0, "{c} 是历史/远端销毁形态，不应探测仓库");
        }
    }

    #[test]
    fn gd_workspace_dirty_asks() {
        for c in [
            "git reset --hard HEAD~1",
            "git clean -f",
            "git clean -fd",
            "git clean -xdf",
            "git checkout -- src/main.rs",
            "git restore src/main.rs",
            "git restore --worktree a.txt",
            "git -C /r reset --hard",
        ] {
            let d = eval_git(c, true);
            assert_eq!(d.kind(), "ask", "脏仓库应询问: {c}");
        }
    }

    #[test]
    fn gd_workspace_clean_allows() {
        for c in [
            "git reset --hard HEAD~1",
            "git clean -f",
            "git checkout -- src/main.rs",
            "git restore a.txt",
        ] {
            let d = eval_git(c, false);
            assert_eq!(d.kind(), "allow", "干净仓库应放行: {c}");
        }
    }

    #[test]
    fn gd_allow_forms() {
        for c in [
            "git clean -n",
            "git clean -n -f",
            "git clean -d",
            "git reset --soft HEAD~1",
            "git reset HEAD~1",
            "git reset --mixed HEAD~1",
            "git checkout main",
            "git checkout -b new",
            "git restore --staged src/main.rs",
            "git branch -d merged",
            "git gc",
            "git reflog show",
            "git stash list",
            "git stash pop",
            "git tag v2.0",
        ] {
            assert_eq!(eval_git(c, true).kind(), "allow", "应放行: {c}");
        }
    }

    #[test]
    fn gd_probe_called_exactly_once_for_workspace() {
        let calls = Cell::new(0u32);
        let probe = |_: &str| {
            calls.set(calls.get() + 1);
            false
        };
        let env = Env {
            canon: &no_canon,
            home: Some("C:/Users/tester"),
            protected: &[],
            git_dirty: &probe,
        };
        let d = evaluate_with(&bash("git reset --hard HEAD~1"), &env);
        assert_eq!(d.kind(), "allow");
        assert_eq!(calls.get(), 1, "工作区销毁形态应恰好探测一次");
    }

    // ---- shell-obfuscation ----

    #[test]
    fn obfus_wrapper_denies() {
        for c in [
            "bash -c \"rm -rf /tmp/x\"",
            "sh -c 'rm -rf /tmp/x'",
            "zsh -c \"rm -rf /tmp/x\"",
            "cmd /c \"del /s C:\\temp\\x\"",
            "powershell -Command \"Remove-Item -Recurse -Force C:/tmp/x\"",
            "powershell -c \"Remove-Item -Recurse -Force C:/tmp/x\"",
            "pwsh -Command \"Remove-Item -Recurse -Force C:/tmp/x\"",
            "bash -lc \"rm -rf /tmp/x\"",
            "FOO=1 bash -c \"rm -rf /tmp/x\"",
            "bash -c \"sh -c 'rm -rf /tmp/x'\"", // 嵌套 2 层
        ] {
            assert_eq!(eval_bash(c).kind(), "deny", "应拦截: {c}");
        }
    }

    #[test]
    fn obfus_wrapper_inner_self_protect_denied() {
        let d = eval_protect(
            &bash("bash -c \"echo x > C:/Users/tester/.kimi-code/config.toml\""),
            &no_canon,
        );
        assert_eq!(d.kind(), "deny");
        if let Decision::Deny { rule, reason } = d {
            assert_eq!(rule, "self-protect");
            assert!(
                reason.ends_with(OBFUS_PEEL_NOTE),
                "reason 应注明剥壳: {reason}"
            );
        } else {
            panic!("应为 Deny");
        }
    }

    #[test]
    fn obfus_wrapper_ask_annotated() {
        let d = eval_bash("bash -c \"git push --force\"");
        assert_eq!(d.kind(), "ask");
        if let Decision::Ask { rule, question } = d {
            assert_eq!(rule, "git-force-push", "内层命中谁走谁的判定");
            assert!(
                question.ends_with(OBFUS_PEEL_NOTE),
                "question 应注明剥壳: {question}"
            );
        } else {
            panic!("应为 Ask");
        }
    }

    #[test]
    fn obfus_wrapper_benign_allows() {
        for c in [
            "bash -c \"echo hello\"",
            "bash -c \"ls -la\"",
            "sh -c 'pwd'",
            "cmd /c dir",
            "powershell -Command \"Get-Location\"",
            "bash --noprofile -c \"echo x\"",
            "powershell -ExecutionPolicy Bypass -Command \"Get-Location\"",
        ] {
            assert_eq!(eval_bash(c).kind(), "allow", "应放行: {c}");
        }
    }

    #[test]
    fn obfus_encoded_pipe_denies() {
        // base64("rm -rf /tmp/bx")
        let d = eval_bash("echo cm0gLXJmIC90bXAvYng= | base64 -d | bash");
        assert_eq!(d.kind(), "deny");
        if let Decision::Deny { reason, .. } = d {
            assert!(
                reason.ends_with(OBFUS_DECODE_NOTE),
                "reason 应注明解码还原: {reason}"
            );
        } else {
            panic!("应为 Deny");
        }
    }

    #[test]
    fn obfus_powershell_enc_denies() {
        // UTF-16LE base64("Remove-Item -Recurse -Force C:/tmp/x")
        let b64 = encode_utf16le_b64("Remove-Item -Recurse -Force C:/tmp/x");
        let d = eval_bash(&format!("powershell -enc {b64}"));
        assert_eq!(d.kind(), "deny", "powershell -enc 解码后应拦");
        let d = eval_bash(&format!("powershell -EncodedCommand {b64}"));
        assert_eq!(d.kind(), "deny");
    }

    #[test]
    fn obfus_encoded_asks() {
        // base64("git push --force")：解码命中 git-force-push → 问
        let d = eval_bash("echo Z2l0IHB1c2ggLS1mb3JjZQ== | base64 -d | bash");
        assert_eq!(d.kind(), "ask");
        // base64("echo hi")：解码干净但没命中 → 不透明 ask
        let d = eval_bash("echo ZWNobyBoaQ== | base64 -d | bash");
        assert_eq!(d.kind(), "ask");
        if let Decision::Ask { rule, .. } = d {
            assert_eq!(rule, "shell-obfuscation");
        } else {
            panic!("应为 Ask");
        }
        // 解不出 → 不透明 ask
        let d = eval_bash("echo not-base64-!!! | base64 -d | bash");
        assert_eq!(d.kind(), "ask");
        // certutil -decode 管道进解释器（输入不可读）→ 不透明 ask
        let d = eval_bash("echo Zm9v | certutil -decode - - | cmd");
        assert_eq!(d.kind(), "ask");
        // powershell -enc 垃圾 → 不透明 ask
        let d = eval_bash("powershell -enc !!!");
        assert_eq!(d.kind(), "ask");
    }

    #[test]
    fn obfus_ps_dash_e_heuristic() {
        // -e 跟 base64 值 → 编码执行（UTF-16LE b64 "rm -rf /tmp/e"）
        let b64 = encode_utf16le_b64("rm -rf /tmp/e");
        assert_eq!(eval_bash(&format!("powershell -e {b64}")).kind(), "deny");
        // -e 跟策略值（-ExecutionPolicy）→ 不误判
        assert_eq!(
            eval_bash("powershell -e Bypass -Command Get-Location").kind(),
            "allow"
        );
    }

    #[test]
    fn obfus_no_interpreter_or_cap_allows_ask() {
        // 解码器后没有解释器 → 不拦（只写 stdout/文件）
        assert_eq!(eval_bash("echo cm0gLXJmIC8= | base64 -d").kind(), "allow");
        assert_eq!(
            eval_bash("echo cm0gLXJmIC8= | base64 -d > out.txt").kind(),
            "allow"
        );
        // 解码输入超 64KB 上限 → 按解不出处理 → ask
        let big = "A".repeat(70 * 1024);
        let d = eval_bash(&format!("echo {big} | base64 -d | bash"));
        assert_eq!(d.kind(), "ask");
    }

    #[test]
    fn obfus_three_layers_caps_at_two() {
        // 3 层嵌套超出「嵌套最多 2 层」上限 → 不再剥壳 → 放行（合同约定）
        let c = "bash -c \"bash -c 'bash -c \\\"rm -rf /tmp/x\\\"'\"";
        assert_eq!(eval_bash(c).kind(), "allow");
    }

    #[test]
    fn allow_hot_path_never_probes_git() {
        // M7 合同：allow 热路径不新增 IO——非 destroy 命令不得触发 git 探测
        let calls = Cell::new(0u32);
        let probe = |_: &str| {
            calls.set(calls.get() + 1);
            true
        };
        let env = Env {
            canon: &no_canon,
            home: Some("C:/Users/tester"),
            protected: &[],
            git_dirty: &probe,
        };
        for c in [
            "ls -la",
            "echo hi",
            "git status",
            "git push origin main",
            "npm test",
            "rm file.txt",
            "bash -c \"ls\"",
            "cat file.txt",
        ] {
            let d = evaluate_with(&bash(c), &env);
            assert_eq!(d.kind(), "allow", "{c}");
        }
        assert_eq!(calls.get(), 0, "非 git-destroy 命令不应调用 git 探测");
    }

    /// 测试助手：UTF-16LE base64（PowerShell -EncodedCommand 编码形态）。
    fn encode_utf16le_b64(s: &str) -> String {
        let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        // 手写 base64 编码（测试侧，避开引入依赖）
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
            out.push(ALPHA[(n >> 18) as usize & 63] as char);
            out.push(ALPHA[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHA[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHA[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    // ---- 切分与 token 化 ----

    #[test]
    fn chain_split_respects_quotes() {
        let segs = split_chain("echo \"a;b\" && rm -rf x");
        assert_eq!(segs.len(), 2);
        assert!(segs[0].contains("\"a;b\""));
        let segs = split_chain("echo 'a|b' | cat");
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn tokenize_strips_quotes() {
        assert_eq!(tokenize("\"rm\" -rf /"), vec!["rm", "-rf", "/"]);
        assert_eq!(tokenize("'git' push"), vec!["git", "push"]);
    }

    // ---- base64 解码 ----

    #[test]
    fn decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("cm0gLXJmIC8=").unwrap(), b"rm -rf /");
        assert_eq!(decode_base64("cm0gLXJmIC8").unwrap(), b"rm -rf /"); // 无 pad
        assert_eq!(decode_base64("cm0g\nLXJm\nIC8=").unwrap(), b"rm -rf /"); // 容忍空白
        assert_eq!(decode_base64("ZWNobyBoaQ==").unwrap(), b"echo hi");
        assert_eq!(decode_base64("-_-_").unwrap(), b"\xfb\xff\xbf"); // URL-safe
        assert!(decode_base64("!!!").is_none());
        assert!(decode_base64("Z").is_none()); // 长度错位（%4==1）
        assert!(decode_base64("Zg===").is_none()); // pad 过多
        assert!(decode_base64("Zg== x").is_none()); // pad 后有内容
                                                    // 缺 pad 宽松容忍（拦截方向：能解就解）
        assert_eq!(decode_base64("Zg=").unwrap(), b"f");
    }

    #[test]
    fn bytes_to_text_prefers_utf8_then_utf16() {
        assert_eq!(bytes_to_text(b"echo hi").unwrap(), "echo hi");
        // UTF-16LE（无 BOM）"rm -rf"
        let mut le = Vec::new();
        for u in "rm -rf".encode_utf16() {
            le.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(bytes_to_text(&le).unwrap(), "rm -rf");
        // 全零字节：UTF-8/UTF-16 均含 NUL 控制字符 → None
        assert!(bytes_to_text(&[0x00, 0x00, 0x00, 0x00]).is_none());
        // 空 → None
        assert!(bytes_to_text(b"").is_none());
    }
}
