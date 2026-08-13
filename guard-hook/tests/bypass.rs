//! 绕过对抗集 harness（M1）。
//!
//! - corpus：仓库根 tests/bypass/*.json，每条 {name, payload, expect: deny|ask|allow}。
//!   文件坏、缺字段、expect 非法、name 与文件名不一致 → 测试失败，绝不跳过。
//! - 全量过 evaluate_with 断言判定类别；home 注入固定假值 C:/Users/tester（机器无关）。
//! - 每规则抽 ≥2 条用真实 exe 端到端喂 stdin 断言退出码（deny→2 / allow→0 / ask 三组）。
//! - 8.3 短名与 junction：在 TEMP / home 建真实文件验证 canonicalize 兜底。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use guard_hook::payload::Payload;
use guard_hook::rules::{evaluate, evaluate_with, fs_canonicalize};

const FAKE_HOME: &str = "C:/Users/tester";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("kcg-bypass-{}-{}-{}", tag, std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------- corpus 加载 ----------

struct Case {
    name: String,
    payload: serde_json::Value,
    expect: String,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("bypass")
}

fn load_corpus() -> Vec<Case> {
    let dir = corpus_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus 目录不可读 {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "corpus 为空：{}", dir.display());
    files
        .iter()
        .map(|f| {
            let raw =
                fs::read_to_string(f).unwrap_or_else(|e| panic!("{} 读取失败: {e}", f.display()));
            let v: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{} 不是合法 JSON: {e}", f.display()));
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("{} 缺 name 字段", f.display()))
                .to_string();
            let payload = v
                .get("payload")
                .cloned()
                .unwrap_or_else(|| panic!("{} 缺 payload 字段", f.display()));
            let expect = v
                .get("expect")
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("{} 缺 expect 字段", f.display()))
                .to_string();
            assert!(
                matches!(expect.as_str(), "deny" | "ask" | "allow"),
                "{} expect 取值非法: {expect}（只许 deny|ask|allow）",
                f.display()
            );
            assert!(payload.is_object(), "{} payload 必须是对象", f.display());
            let stem = f.file_stem().unwrap().to_string_lossy().to_string();
            assert_eq!(name, stem, "{} name 与文件名不一致", f.display());
            Case {
                name,
                payload,
                expect,
            }
        })
        .collect()
}

fn find_case(name: &str) -> Case {
    load_corpus()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("corpus 缺用例 {name}"))
}

// ---------- corpus 全量断言 ----------

#[test]
fn corpus_matches_expectations() {
    let cases = load_corpus();
    assert!(
        cases.len() >= 30,
        "bypass corpus 至少 30 条，当前 {} 条",
        cases.len()
    );
    for c in &cases {
        let bytes = serde_json::to_vec(&c.payload).unwrap();
        let p = Payload::parse(&bytes)
            .unwrap_or_else(|| panic!("{} 的 payload 无法被解析器解析", c.name));
        let d = evaluate_with(&p, &fs_canonicalize, Some(FAKE_HOME));
        assert_eq!(
            d.kind(),
            c.expect,
            "用例 {} 期望 {} 实得 {}",
            c.name,
            c.expect,
            d.kind()
        );
    }
}

#[test]
fn corpus_covers_block_and_pass_per_rule() {
    let cases = load_corpus();
    let count = |prefix: &str, expect: &str| {
        cases
            .iter()
            .filter(|c| c.name.starts_with(prefix) && c.expect == expect)
            .count()
    };
    assert!(
        count("rm-", "deny") >= 2 && count("rm-", "allow") >= 2,
        "rm-force 需各 ≥2 条拦与放"
    );
    assert!(
        count("cred-", "deny") >= 2 && count("cred-", "allow") >= 2,
        "cred-files 需各 ≥2 条拦与放"
    );
    assert!(
        count("git-", "ask") >= 2 && count("git-", "allow") >= 2,
        "git-force-push 需各 ≥2 条问与放"
    );
}

// ---------- 端到端（真实 exe 喂 stdin） ----------

fn run_hook(payload: &serde_json::Value, envs: &[(&str, String)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_guard-hook"));
    cmd.arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(payload).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn e2e_deny_exits_2() {
    for name in [
        "rm-deny-01-rf-basic",
        "rm-deny-08-chain-and",
        "cred-deny-01-env-relative",
        "cred-deny-02-env-production",
    ] {
        let out = run_hook(&find_case(name).payload, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name} 应 exit 2，stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("KimiCodeGuard 已拦截"),
            "{name} stderr 应含中文拦截原因"
        );
    }
}

#[test]
fn e2e_allow_exits_0() {
    for name in [
        "rm-allow-01-force-only",
        "git-allow-01-normal-push",
        "cred-allow-01-env-example",
    ] {
        let out = run_hook(&find_case(name).payload, &[]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{name} 应 exit 0，stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "{}",
            "{name} stdout 应为 {{}}"
        );
    }
}

// ---------- ask 三组（假 daemon） ----------

fn unique_pipe_name() -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(r"\\.\pipe\KCG.test.{}.{}", std::process::id(), n)
}

#[test]
fn e2e_ask_no_daemon_exits_2() {
    for name in ["git-ask-01-force", "git-ask-04-force-with-lease"] {
        let pipe = unique_pipe_name(); // 不存在daemon监听
        let out = run_hook(
            &find_case(name).payload,
            &[
                ("KCG_ASK_PIPE", pipe),
                ("KCG_ASK_TIMEOUT_MS", "5000".to_string()),
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name} 无 daemon 应 fail-safe exit 2，stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(windows)]
#[test]
fn e2e_ask_fake_daemon_allow_exits_0() {
    let pipe = unique_pipe_name();
    let daemon = fake_daemon::serve_once(&pipe, Some(r#"{"decision":"allow"}"#));
    let out = run_hook(
        &find_case("git-ask-01-force").payload,
        &[
            ("KCG_ASK_PIPE", pipe),
            ("KCG_ASK_TIMEOUT_MS", "10000".to_string()),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "daemon 回 allow 应 exit 0，stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "{}");
    assert!(daemon.join().unwrap(), "假 daemon 应完成一单服务");
}

#[cfg(windows)]
#[test]
fn e2e_ask_fake_daemon_deny_exits_2() {
    let pipe = unique_pipe_name();
    let daemon = fake_daemon::serve_once(&pipe, Some(r#"{"decision":"deny","reason":"测试拒绝"}"#));
    let out = run_hook(
        &find_case("git-ask-02-f").payload,
        &[
            ("KCG_ASK_PIPE", pipe),
            ("KCG_ASK_TIMEOUT_MS", "10000".to_string()),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "daemon 回 deny 应 exit 2，stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(daemon.join().unwrap(), "假 daemon 应完成一单服务");
}

#[cfg(windows)]
#[test]
fn e2e_ask_daemon_silent_times_out_exits_2() {
    let pipe = unique_pipe_name();
    // daemon 连入后不回话：hold 30s；客户端 600ms 超时必须先 exit 2（D2 fail-safe）
    let _daemon = fake_daemon::serve_once(&pipe, None);
    let start = std::time::Instant::now();
    let out = run_hook(
        &find_case("git-ask-03-uf-combined").payload,
        &[
            ("KCG_ASK_PIPE", pipe),
            ("KCG_ASK_TIMEOUT_MS", "600".to_string()),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "超时应 exit 2，stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "超时不应挂死：{:?}",
        start.elapsed()
    );
    // 不 join daemon：它仍在 hold，随测试进程退出被回收
}

#[cfg(windows)]
mod fake_daemon {
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    /// 起一次性假 daemon：接一单，读完请求行，按 reply 回复（None = 沉默 hold 30s 后挂断）。
    /// 返回的 JoinHandle 在成功服务一单后得到 true；超时用例不应 join（线程仍在 hold）。
    pub fn serve_once(pipe_name: &str, reply: Option<&'static str>) -> JoinHandle<bool> {
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        thread::spawn(move || unsafe {
            let h = CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            );
            if h == INVALID_HANDLE_VALUE {
                return false;
            }
            let ok = serve(h, reply);
            CloseHandle(h);
            ok
        })
    }

    unsafe fn serve(h: HANDLE, reply: Option<&str>) -> bool {
        if ConnectNamedPipe(h, std::ptr::null_mut()) == 0 {
            return false;
        }
        // 读完请求行（到 \n）
        let mut buf = [0u8; 1024];
        loop {
            let mut n = 0u32;
            if ReadFile(
                h,
                buf.as_mut_ptr() as _,
                buf.len() as u32,
                &mut n,
                std::ptr::null_mut(),
            ) == 0
                || n == 0
            {
                break;
            }
            if buf[..n as usize].contains(&b'\n') {
                break;
            }
        }
        match reply {
            Some(r) => {
                let data = format!("{r}\n");
                let mut written = 0u32;
                if WriteFile(
                    h,
                    data.as_ptr() as _,
                    data.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                ) == 0
                {
                    return false;
                }
                FlushFileBuffers(h);
            }
            None => thread::sleep(Duration::from_secs(30)), // 沉默：触发客户端超时
        }
        DisconnectNamedPipe(h);
        true
    }
}

// ---------- 8.3 短名与 junction（canonicalize 兜底专项） ----------

#[cfg(windows)]
fn get_short_path_name(path: &Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u16; 4096];
    let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf16(&buf).ok()
}

fn read_payload_with(path: &str) -> Payload {
    let json = format!(
        r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":"D:/proj","tool_name":"Read","tool_input":{{"path":{}}},"tool_call_id":"t"}}"#,
        serde_json::to_string(path).unwrap()
    );
    Payload::parse(json.as_bytes()).unwrap()
}

#[cfg(windows)]
#[test]
fn short_name_83_still_denied() {
    let dir = temp_dir("83");
    let long = dir.join(".env.production");
    fs::write(&long, "SECRET=x").unwrap();
    let long_str = long.to_string_lossy().to_string();
    let short = get_short_path_name(&long).expect("GetShortPathNameW 不应失败");
    if short.eq_ignore_ascii_case(&long_str) {
        // 本卷禁用 8.3 命名：无短名可测，验证 canonicalize 自洽即可（非跳过，是环境适配断言）
        assert_eq!(
            fs_canonicalize(&long_str).map(|s| s.to_ascii_lowercase()),
            fs_canonicalize(&short).map(|s| s.to_ascii_lowercase())
        );
        return;
    }
    // 短名形态（如 ENV~1.PRO）字符串层不命中名单，canonicalize 展开后必须命中
    let d = evaluate_with(
        &read_payload_with(&short),
        &fs_canonicalize,
        Some(FAKE_HOME),
    );
    assert_eq!(
        d.kind(),
        "deny",
        "8.3 短名 {short} 应被 canonicalize 兜底拦截"
    );
}

/// 退出时尽量清理（文件删不了就删目录， junction 用 remove_dir）。
struct Cleanup(Vec<PathBuf>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
            let _ = fs::remove_dir(p);
        }
    }
}

#[cfg(windows)]
#[test]
fn junction_into_ssh_dir_still_denied() {
    let home = std::env::var("USERPROFILE").expect("需要 USERPROFILE");
    let ssh = Path::new(&home).join(".ssh");
    let created_ssh = !ssh.exists();
    if created_ssh {
        fs::create_dir_all(&ssh).unwrap();
    }
    let canary_name = format!("kcg-junction-canary-{}", std::process::id());
    let canary = ssh.join(&canary_name);
    fs::write(&canary, "kcg").unwrap();
    let link = temp_dir("junc").join("link");
    let st = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&link)
        .arg(&ssh)
        .status()
        .unwrap();
    assert!(st.success(), "mklink /J 失败");
    let _cleanup = Cleanup(if created_ssh {
        vec![link.clone(), canary.clone(), ssh.clone()]
    } else {
        vec![link.clone(), canary.clone()]
    });

    // 字符串层：basename 是 canary 名、路径在 TEMP 下——不命中名单；
    // canonicalize 后落在真实 home 的 .ssh 内 → 必须 deny。
    let via_link = format!(
        "{}/{}",
        link.to_string_lossy().replace('\\', "/"),
        canary_name
    );
    let d = evaluate(&read_payload_with(&via_link));
    assert_eq!(
        d.kind(),
        "deny",
        "经 junction {via_link} 应被 canonicalize 兜底拦截"
    );
}
