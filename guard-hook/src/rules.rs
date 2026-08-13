//! 规则判定核心（M1，D9）：rm-force / cred-files / git-force-push 三条。
//!
//! `evaluate` 对外是纯函数：环境依赖（fs::canonicalize、USERPROFILE）在入口处注入，
//! 规则逻辑本身不碰 IO，好测。热路径禁止 unwrap/expect/panic（不变量 4）。
//!
//! 已知缺口（v0.2 地界，见 AGENTS.md D9）：base64/变量拼接等 shell 混淆不拦，
//! 由 v0.2 的 shell-obfuscation 规则覆盖；`git push --delete` 不拦（v0.2 git-destroy）。

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

/// 顶层入口：注入真实环境（fs::canonicalize、USERPROFILE）。
pub fn evaluate(p: &Payload) -> Decision {
    evaluate_with(p, &fs_canonicalize, real_home().as_deref())
}

/// 可注入环境依赖的判定核心。
///
/// - `canon`：路径 canonicalize（存在时返回展开 8.3 短名与 junction 后的真实路径）。
/// - `home`：用户 home 目录（~ 展开与 .ssh/.aws 判定用），通常是 USERPROFILE。
pub fn evaluate_with(
    p: &Payload,
    canon: &dyn Fn(&str) -> Option<String>,
    home: Option<&str>,
) -> Decision {
    if let Some(d) = rule_rm_force(p) {
        return d;
    }
    if let Some(d) = rule_cred_files(p, canon, home) {
        return d;
    }
    if let Some(d) = rule_git_force_push(p) {
        return d;
    }
    Decision::Allow
}

/// 真实文件系统的 canonicalize（剥 Windows `\\?\` 前缀），供 evaluate 与测试 harness 复用。
pub fn fs_canonicalize(path: &str) -> Option<String> {
    let p = fs::canonicalize(path).ok()?;
    let s = p.to_string_lossy().into_owned();
    // Windows canonicalize 返回 \\?\ 前缀，剥掉以便后续统一比较
    Some(s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s))
}

fn real_home() -> Option<String> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
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

fn rule_git_force_push(p: &Payload) -> Option<Decision> {
    let cmd = p.bash_command()?;
    for seg in split_chain(cmd) {
        let toks = tokenize(&seg);
        let i = skip_prefix(&toks);
        let Some(name) = toks.get(i) else { continue };
        if cmd_stem(name) != "git" {
            continue;
        }
        // git 全局选项：带参消费下一个，无参/--x=y 跳过；第一个非选项 token 是子命令
        let mut j = i + 1;
        let sub = loop {
            let Some(t) = toks.get(j) else { break None };
            match t.as_str() {
                "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--exec-path" => j += 2,
                s if s.starts_with("--") && s.contains('=') => j += 1,
                s if s.starts_with('-') && s.len() > 1 => j += 1,
                s => break Some(s),
            }
        };
        if sub != Some("push") {
            continue;
        }
        // --delete 不拦（v0.2 git-destroy 地界）；带 force 家族才 Ask
        let force = toks[j + 1..].iter().any(|a| {
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

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn bash(cmd: &str) -> Payload {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":"D:/proj","tool_name":"Bash","tool_input":{{"command":{}}},"tool_call_id":"t"}}"#,
            serde_json::to_string(cmd).unwrap()
        );
        Payload::parse(json.as_bytes()).unwrap()
    }

    fn read_tool(path: &str, cwd: &str) -> Payload {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":{},"tool_name":"Read","tool_input":{{"path":{}}},"tool_call_id":"t"}}"#,
            serde_json::to_string(cwd).unwrap(),
            serde_json::to_string(path).unwrap()
        );
        Payload::parse(json.as_bytes()).unwrap()
    }

    fn no_canon(_: &str) -> Option<String> {
        None
    }

    fn eval_bash(cmd: &str) -> Decision {
        evaluate_with(&bash(cmd), &no_canon, Some("C:/Users/tester"))
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
        let home = Some("C:/Users/tester");
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
            let d = evaluate_with(&read_tool(path, cwd), &no_canon, home);
            assert_eq!(d.kind(), "deny", "应拦截: {path} (cwd={cwd})");
        }
    }

    #[test]
    fn lookalike_files_allowed() {
        let home = Some("C:/Users/tester");
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
            let d = evaluate_with(&read_tool(path, cwd), &no_canon, home);
            assert_eq!(d.kind(), "allow", "应放行: {path}");
        }
    }

    #[test]
    fn mixed_slashes_and_tilde_normalized() {
        let home = Some("C:\\Users\\tester");
        // 混合斜杠 + ~ + 反斜杠 home
        let p = read_tool("~\\.ssh\\id_rsa", "D:/proj");
        assert_eq!(evaluate_with(&p, &no_canon, home).kind(), "deny");
        let p = read_tool("C:\\Users/tester\\.aws\\credentials", "D:/proj");
        assert_eq!(evaluate_with(&p, &no_canon, home).kind(), "deny");
    }

    #[test]
    fn relative_path_without_cwd_skips_rule() {
        let json = br#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","tool_input":{"path":".env"},"tool_call_id":"t"}"#;
        let p = Payload::parse(json).unwrap();
        assert_eq!(p.cwd, None);
        // 缺 cwd → 相对路径无法定位 → 规则跳过（放行，缺失已由 parse 记 note）
        assert_eq!(
            evaluate_with(&p, &no_canon, Some("C:/Users/tester")).kind(),
            "allow"
        );
    }

    #[test]
    fn canonicalize_fallback_catches_junction() {
        // 字符串层无害（temp 下 keys.txt），canon 后落入 home/.ssh
        let canon = |_: &str| Some("C:/Users/tester/.ssh/keys.txt".to_string());
        let p = read_tool("keys.txt", "D:/temp/link");
        assert_eq!(
            evaluate_with(&p, &canon, Some("C:/Users/tester")).kind(),
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
            "git push --delete origin old-branch",
            "git pull --force",
            "git fetch --force",
            "git config push.forcePush true",
            "git commit -m \"push --force\"",
        ] {
            assert_eq!(eval_bash(c).kind(), "allow", "应放行: {c}");
        }
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
}
