//! ask 命名管道服务端（M2 核心）。契约照 guard-hook/src/pipe.rs 头部注释，一字不改：
//! - 管道名 `\\.\pipe\KimiCodeGuard.ask.<USERNAME 环境变量，缺省 default>`
//! - 请求一条 JSON 行：rule / tool / command / session_id
//! - 回复一条 JSON 行：`{"decision":"allow"}` 或 `{"decision":"deny","reason":"..."}`
//!
//! hook 侧 60s 超时/连不上/回复非法自己 exit 2，daemon 不兜这个底。
//!
//! 行为（M2 任务书）：
//! - 启动即监听；合法请求经事件通道交给 UI 层弹窗，worker 串行处理 ⇒ 一次只弹一个；
//! - 等回复超过 ask_timeout（生产 55s，比 hook 的 60s 早 5s）自动按 deny 回复；
//! - 请求 JSON 非法 / 缺字段 → 立即按 deny 回复、记日志、不弹窗；
//! - 永不 panic：每步错误都收敛为日志 + 关闭该连接。
//!
//! 线程结构：
//! - listener：循环创建管道实例 → ConnectNamedPipe 等连接 → 连接塞进通道后立刻
//!   创建下一实例（多个并发客户端在通道里排队，worker 一次取一个）。
//! - worker：串行处理连接：读一行（read_timeout 兜底防静默客户端）→ 解析 →
//!   合法则发 PipeEvent::Ask 并等 UI 回复（ask_timeout 超时自动 deny）→ 写回复 →
//!   发 PipeEvent::Idle 通知 UI 关窗清状态。
//!
//! 读超时用「读线程 + recv_timeout」实现（与 hook 侧同范式）；超时后读线程持有的
//! 克隆句柄最多滞留到客户端断开（客户端即 hook，读到 deny 就退出）。

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// 单条连接的读超时：hook 连上会立刻写请求，超过即按异常客户端处理
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 管道读/写缓冲区（行协议，read_line 自动拼段，这里只是 chunk 大小）
const PIPE_BUF: u32 = 8192;

/// 一次 ask 请求（契约字段：rule / tool / command / session_id）
#[derive(Debug, Clone, serde::Serialize)]
pub struct AskRequest {
    pub rule: String,
    pub tool: String,
    pub command: String,
    pub session_id: String,
}

/// UI 层的回复
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskReply {
    Allow,
    Deny(String),
}

impl AskReply {
    fn to_json_line(&self) -> String {
        match self {
            AskReply::Allow => serde_json::json!({"decision":"allow"}).to_string(),
            AskReply::Deny(reason) => {
                serde_json::json!({"decision":"deny","reason":reason}).to_string()
            }
        }
    }
}

/// daemon 事件：Ask = 新请求待人工确认（附回复通道）；Idle = 上一单已完结（回复或超时）
pub enum PipeEvent {
    Ask {
        request: AskRequest,
        reply_tx: Sender<AskReply>,
    },
    Idle,
}

/// 运行中的服务端。drop 不关线程，显式调 `shutdown`。
pub struct Server {
    events: Receiver<PipeEvent>,
    shutdown: ArcBool,
    pipe_name: String,
    listener: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
}

type ArcBool = std::sync::Arc<AtomicBool>;

impl Server {
    /// 事件通道（Ask/Idle 交替到达，worker 串行保证严格交替）
    pub fn events(&self) -> &Receiver<PipeEvent> {
        &self.events
    }

    /// 停止监听并回收线程：先置标志，再以客户端身份碰一下管道把 listener
    /// 从 ConnectNamedPipe 里唤醒；worker 随连接通道关闭退出（若正在处理一单，
    /// 最多等到该单读超时/回复超时）。
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.pipe_name);
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// 默认管道名：`\\.\pipe\KimiCodeGuard.ask.<USERNAME|default>`（与 hook 侧一致）
pub fn default_pipe_name() -> String {
    let user = std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    format!(r"\\.\pipe\KimiCodeGuard.ask.{user}")
}

/// 启动服务端。首个管道实例创建成功才返回 Ok（托盘据此显示「监听中/未监听」）。
pub fn start(pipe_name: &str, ask_timeout: Duration) -> io::Result<Server> {
    let (conn_tx, conn_rx) = mpsc::channel::<File>();
    let (event_tx, event_rx) = mpsc::channel::<PipeEvent>();
    let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
    let shutdown: ArcBool = std::sync::Arc::new(AtomicBool::new(false));

    let listener = {
        let pipe_name = pipe_name.to_string();
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("kcg-pipe-listener".to_string())
            .spawn(move || listener_loop(&pipe_name, &conn_tx, &ready_tx, &shutdown))
            .map_err(|e| io::Error::other(format!("创建 listener 线程失败：{e}")))?
    };

    // 等 listener 报首个实例的创建结果（创建是即时系统调用，不会久等；
    // 线程若异常退出，channel 断开 recv 立即返回 Err）
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = listener.join();
            return Err(e);
        }
        Err(_) => {
            let _ = listener.join();
            return Err(io::Error::other(
                "listener 线程异常退出（未报告管道创建结果）",
            ));
        }
    }

    let worker = {
        let shutdown = shutdown.clone();
        thread::Builder::new()
            .name("kcg-pipe-worker".to_string())
            .spawn(move || worker_loop(&conn_rx, &event_tx, ask_timeout, &shutdown))
            .map_err(|e| io::Error::other(format!("创建 worker 线程失败：{e}")))?
    };

    Ok(Server {
        events: event_rx,
        shutdown,
        pipe_name: pipe_name.to_string(),
        listener: Some(listener),
        worker: Some(worker),
    })
}

/// listener：创建实例 → 等连接 → 交连接 → 立刻建下一实例。任何单步失败只记日志继续；
/// 首个实例的创建结果通过 ready_tx 同步给 start。
fn listener_loop(
    pipe_name: &str,
    conn_tx: &Sender<File>,
    ready_tx: &Sender<io::Result<()>>,
    shutdown: &ArcBool,
) {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut first = true;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        // SAFETY: wide 是以 0 结尾的 UTF-16 串；返回句柄随后校验。
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF,
                PIPE_BUF,
                0,
                std::ptr::null(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            if first {
                let _ = ready_tx.send(Err(err));
                return;
            }
            tracing::warn!("创建管道实例失败：{err}（1s 后重试）");
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        if first {
            first = false;
            if ready_tx.send(Ok(())).is_err() {
                // SAFETY: 句柄有效且未被接管
                unsafe { CloseHandle(handle) };
                return;
            }
            tracing::info!("ask 管道监听中：{pipe_name}");
        }

        // SAFETY: 句柄有效；阻塞等客户端连接。ERROR_PIPE_CONNECTED = 客户端在
        // Create 与 Connect 之间已连上，按成功处理。
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        let ok = connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !ok {
            let err = io::Error::last_os_error();
            tracing::warn!("等待管道连接失败：{err}");
            // SAFETY: 句柄有效且未被接管
            unsafe { CloseHandle(handle) };
            continue;
        }
        if shutdown.load(Ordering::SeqCst) {
            // SAFETY: 句柄有效且未被接管
            unsafe { CloseHandle(handle) };
            return;
        }
        // SAFETY: 连接已建立，句柄独占移交给 File，由 worker 用完关闭
        let file = unsafe { File::from_raw_handle(handle as _) };
        if conn_tx.send(file).is_err() {
            return; // worker 已退出（只会发生在 shutdown 流程中）
        }
    }
}

/// worker：串行处理连接（一次一个 = 一次只弹一个窗）。
fn worker_loop(
    conn_rx: &Receiver<File>,
    event_tx: &Sender<PipeEvent>,
    ask_timeout: Duration,
    shutdown: &ArcBool,
) {
    while let Ok(mut file) = conn_rx.recv() {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        serve_one(&mut file, event_tx, ask_timeout);
        let _ = event_tx.send(PipeEvent::Idle);
        // SAFETY: 句柄仍有效（File 尚未 drop）；断开后 drop 即关闭
        unsafe { DisconnectNamedPipe(file_as_raw(&file)) };
    }
}

/// 处理单条连接：读一行 → 解析 → 弹窗等回复/立即 deny → 写回复。全路径不 panic。
fn serve_one(file: &mut File, event_tx: &Sender<PipeEvent>, ask_timeout: Duration) {
    let Some(read_result) = read_line_with_timeout(file, READ_TIMEOUT) else {
        tracing::warn!("读取 ask 请求超时（{READ_TIMEOUT:?}），按 deny 回复");
        write_reply(file, &AskReply::Deny("请求读取超时".to_string()));
        return;
    };
    let line = match read_result {
        Ok(line) => line,
        Err(e) => {
            tracing::warn!("读取 ask 请求失败：{e}，按 deny 回复");
            write_reply(file, &AskReply::Deny("请求读取失败".to_string()));
            return;
        }
    };
    let Some(request) = parse_request(&line) else {
        let preview: String = line.trim().chars().take(120).collect();
        tracing::warn!("ask 请求非法（不弹窗，按 deny 回复）：{preview}");
        write_reply(file, &AskReply::Deny("请求格式非法".to_string()));
        return;
    };
    tracing::info!(rule = %request.rule, tool = %request.tool, "收到 ask 请求，等待人工确认");

    let (reply_tx, reply_rx) = mpsc::channel();
    if event_tx.send(PipeEvent::Ask { request, reply_tx }).is_err() {
        // UI 层已消失：fail-safe deny，不挂住 hook
        write_reply(file, &AskReply::Deny("守护进程弹窗服务不可用".to_string()));
        return;
    }
    let reply = match reply_rx.recv_timeout(ask_timeout) {
        Ok(reply) => reply,
        Err(_) => {
            tracing::warn!("ask 弹窗 {ask_timeout:?} 无人响应，自动按 deny 回复");
            AskReply::Deny(format!("{} 秒无人确认，自动拒绝", ask_timeout.as_secs()))
        }
    };
    write_reply(file, &reply);
}

/// 写一条回复 JSON 行；失败只记日志（客户端可能已超时断开）。
fn write_reply(file: &mut File, reply: &AskReply) {
    let mut line = reply.to_json_line();
    line.push('\n');
    if let Err(e) = file.write_all(line.as_bytes()).and_then(|()| file.flush()) {
        tracing::warn!("写 ask 回复失败：{e}");
    }
}

/// 读一行，带超时（读线程 + recv_timeout 范式，与 hook 侧一致）。
/// None = 超时；超时后读线程持有的克隆句柄最多滞留到客户端断开。
fn read_line_with_timeout(file: &File, timeout: Duration) -> Option<io::Result<String>> {
    let mut clone = file.try_clone().ok()?;
    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("kcg-pipe-reader".to_string())
        .spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(&mut clone)
                .read_line(&mut line)
                .map(|_| line);
            let _ = tx.send(result);
        });
    spawned.ok()?;
    rx.recv_timeout(timeout).ok()
}

/// 解析请求 JSON 行：必须是对象且 rule/tool/command 为字符串（session_id 缺省 ""）。
/// 多余字段忽略（契约之外字段向前兼容）。
fn parse_request(line: &str) -> Option<AskRequest> {
    let v = serde_json::from_str::<serde_json::Value>(line.trim()).ok()?;
    let obj = v.as_object()?;
    let get = |key: &str| obj.get(key).and_then(|x| x.as_str()).map(str::to_string);
    Some(AskRequest {
        rule: get("rule")?,
        tool: get("tool")?,
        command: get("command")?,
        session_id: get("session_id").unwrap_or_default(),
    })
}

/// 取 File 底层句柄（DisconnectNamedPipe 用；不取得所有权）
fn file_as_raw(file: &File) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    file.as_raw_handle() as HANDLE
}
