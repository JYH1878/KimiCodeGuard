//! 事件管道服务端（M3 审计轨 A 入口）。契约（GOAL.md 设计定案，定死）：
//! - 管道名 `\\.\pipe\KimiCodeGuard.events.<USERNAME 环境变量，缺省 default>`
//! - fire-and-forget：客户端（hook）写一行事件 JSON 即断开，不等回复
//! - 事件 JSON：`{"event","ts","session_id","cwd","tool_name"?,"decision"?,"reason"?,"payload"}`
//!
//! 行为：
//! - listener + 串行 worker（结构仿 ask_pipe.rs）：worker 是 audit.db 唯一写者，
//!   收到事件即 append（audit.rs 的 MAX(id)+1 自取因此无竞态）；
//! - 非法 JSON / 缺关键字段（event/ts/payload）→ 记日志丢弃，不崩（D5）；
//! - worker 启动先回收 spool：逐行入库后删文件（入库失败的行重写回 spool 不丢数据）；
//! - 全程无 panic：每步错误收敛为日志；审计库打不开时继续收事件（只丢弃+日志），
//!   绝不拖垮 ask 防护。
//! - sink：每条解析成功的事件（含 spool 回收的）都会克隆一份发过去——
//!   会话跟踪（任务 4，空载自退）据此工作，与落库解耦。
//!
//! M4（审计轨 B）：worker 同时收 `WorkItem::Backfill` 回溯任务（wire.jsonl 增量
//! 幂等导入 audit.db，见 `run_backfill`）。单 worker 串行 ⇒ 「唯一写者」不变量
//! 覆盖回溯与实时两条写路径。

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_INBOUND;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::audit::{self, AuditDb, AuditEvent};
use crate::wire;

/// 单条连接的读超时：hook 连上会立刻写事件行，超过即按异常客户端处理
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 管道读缓冲区（行协议，read_line 自动拼段，这里只是 chunk 大小）
const PIPE_BUF: u32 = 8192;

/// 默认管道名：`\\.\pipe\KimiCodeGuard.events.<USERNAME|default>`（与 hook 侧一致）
pub fn default_pipe_name() -> String {
    let user = std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    format!(r"\\.\pipe\KimiCodeGuard.events.{user}")
}

/// 默认 spool 路径：`%LOCALAPPDATA%\KimiCodeGuard\spool\events.jsonl`（与 hook 侧一致）
pub fn default_spool_path() -> std::path::PathBuf {
    audit::data_dir().join("spool").join("events.jsonl")
}

/// 解析一行事件 JSON。event / ts / payload 缺失或类型不对 → None（调用方记日志丢弃）；
/// 其余字段缺省容错（D5）。多余字段忽略（向前兼容）。
pub fn parse_event(line: &str) -> Option<AuditEvent> {
    let v = serde_json::from_str::<serde_json::Value>(line.trim()).ok()?;
    let obj = v.as_object()?;
    let get = |key: &str| obj.get(key).and_then(|x| x.as_str()).map(str::to_string);
    Some(AuditEvent {
        event: get("event")?,
        ts: obj.get("ts")?.as_i64()?,
        session_id: get("session_id").unwrap_or_default(),
        cwd: get("cwd").unwrap_or_default(),
        tool_name: get("tool_name"),
        decision: get("decision"),
        reason: get("reason"),
        payload: get("payload")?,
    })
}

/// 回收 spool：逐行解析入库，返回成功入库条数。
/// 文件不存在 = 正常（0 条）；非法行记日志丢弃；入库失败的行重写回 spool（不删文件）；
/// 全部成功则删除 spool 文件。
pub fn recover_spool(spool_path: &Path, db: &AuditDb, sink: Option<&Sender<AuditEvent>>) -> usize {
    let Ok(content) = std::fs::read_to_string(spool_path) else {
        return 0; // 不存在（或读失败按无处理）：没有可回收的
    };
    let mut kept = 0usize;
    let mut failed: Vec<&str> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_event(line) {
            Some(ev) => match db.append(&ev) {
                Ok(_) => {
                    kept += 1;
                    if let Some(s) = sink {
                        let _ = s.send(ev);
                    }
                }
                Err(e) => {
                    tracing::error!("spool 事件入库失败（保留该行待下次回收）：{e}");
                    failed.push(line);
                }
            },
            None => {
                let preview: String = line.trim().chars().take(120).collect();
                tracing::warn!("spool 含非法事件行，丢弃：{preview}");
            }
        }
    }
    if failed.is_empty() {
        if let Err(e) = std::fs::remove_file(spool_path) {
            tracing::warn!("删除 spool 文件失败：{e}");
        }
    } else {
        let mut body = failed.join("\n");
        body.push('\n');
        if let Err(e) = std::fs::write(spool_path, body) {
            tracing::error!("重写 spool 残余行失败：{e}");
        }
    }
    kept
}

/// worker 的工作项：管道连接（轨 A）或回溯任务（轨 B）。
/// 单通道串行 ⇒ worker 仍是 audit.db 唯一写者。
pub enum WorkItem {
    /// 一条已接管的管道连接
    Conn(File),
    /// wire.jsonl 回溯导入任务
    Backfill(BackfillJob),
}

/// 一次回溯任务：扫描 root 下的 wire.jsonl，增量幂等导入后回复汇总
pub struct BackfillJob {
    /// sessions 根目录
    pub root: PathBuf,
    /// 完成回复（只发一次；接收端断开只记日志）
    pub reply: Sender<BackfillSummary>,
}

/// 回溯汇总（托盘消息框 / 日志用）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackfillSummary {
    /// 发现的 wire.jsonl 文件数
    pub files: u64,
    /// 新导入行数
    pub imported: u64,
    /// 去重跳过行数
    pub dup_skipped: u64,
    /// 非法 JSON 行数
    pub bad_lines: u64,
    /// 末行撕裂（写入中）的文件数
    pub torn_files: u64,
    /// 超限跳过的文件数
    pub oversized_files: u64,
    /// false = 审计库不可用，什么也没导入
    pub db_ok: bool,
}

/// 运行中的事件管道服务端。drop 不关线程，显式调 `shutdown`。
pub struct Server {
    shutdown: ArcBool,
    pipe_name: String,
    /// worker 通道的发送端（listener 持克隆；shutdown 时先 join listener 再 drop 本端）
    work_tx: Option<Sender<WorkItem>>,
    listener: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
}

type ArcBool = std::sync::Arc<AtomicBool>;

impl Server {
    /// 回溯任务提交口（克隆即得，发送端 cheap）
    pub fn backfill_sender(&self) -> Sender<WorkItem> {
        self.work_tx
            .as_ref()
            .expect("Server 未 shutdown 前 work_tx 必在")
            .clone()
    }

    /// 停止监听并回收线程：置标志 → 碰管道唤醒 listener → join listener
    /// （其 work_tx 克隆随退出 drop）→ drop 本端 → 通道关闭 → worker 退出后 join。
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = OpenOptions::new().write(true).open(&self.pipe_name);
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
        drop(self.work_tx.take());
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

/// 启动事件管道服务端。返回时：首个管道实例已创建成功（否则 Err），
/// 且 worker 已完成「开库 + spool 回收」（审计库打不开不视为启动失败，只记 error）。
pub fn start(
    pipe_name: &str,
    db_path: &Path,
    spool_path: &Path,
    sink: Option<Sender<AuditEvent>>,
) -> io::Result<Server> {
    let (work_tx, work_rx) = mpsc::channel::<WorkItem>();
    let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
    let (worker_ready_tx, worker_ready_rx) = mpsc::channel::<()>();
    let shutdown: ArcBool = std::sync::Arc::new(AtomicBool::new(false));

    let listener = {
        let pipe_name = pipe_name.to_string();
        let shutdown = shutdown.clone();
        let conn_tx = work_tx.clone();
        thread::Builder::new()
            .name("kcg-events-listener".to_string())
            .spawn(move || listener_loop(&pipe_name, &conn_tx, &ready_tx, &shutdown))
            .map_err(|e| io::Error::other(format!("创建 events listener 线程失败：{e}")))?
    };

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = listener.join();
            return Err(e);
        }
        Err(_) => {
            let _ = listener.join();
            return Err(io::Error::other(
                "events listener 线程异常退出（未报告管道创建结果）",
            ));
        }
    }

    let worker = {
        let shutdown = shutdown.clone();
        let db_path = db_path.to_path_buf();
        let spool_path = spool_path.to_path_buf();
        thread::Builder::new()
            .name("kcg-events-worker".to_string())
            .spawn(move || {
                worker_loop(
                    &work_rx,
                    &db_path,
                    &spool_path,
                    sink,
                    &worker_ready_tx,
                    &shutdown,
                )
            })
            .map_err(|e| io::Error::other(format!("创建 events worker 线程失败：{e}")))?
    };

    // 等 worker 完成开库 + spool 回收（开库失败也会发信号，仅记日志）
    let _ = worker_ready_rx.recv();

    Ok(Server {
        shutdown,
        pipe_name: pipe_name.to_string(),
        work_tx: Some(work_tx),
        listener: Some(listener),
        worker: Some(worker),
    })
}

/// listener：创建实例 → 等连接 → 交连接 → 立刻建下一实例（与 ask_pipe 同范式，只入向）。
fn listener_loop(
    pipe_name: &str,
    conn_tx: &Sender<WorkItem>,
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
                PIPE_ACCESS_INBOUND,
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
            tracing::warn!("创建 events 管道实例失败：{err}（1s 后重试）");
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
            tracing::info!("events 管道监听中：{pipe_name}");
        }

        // SAFETY: 句柄有效；阻塞等客户端连接。ERROR_PIPE_CONNECTED = 客户端已连上，按成功处理。
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        let ok = connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !ok {
            let err = io::Error::last_os_error();
            tracing::warn!("等待 events 管道连接失败：{err}");
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
        if conn_tx.send(WorkItem::Conn(file)).is_err() {
            return; // worker 已退出（只会发生在 shutdown 流程中）
        }
    }
}

/// worker：audit.db 唯一写者。先开库 + 回收 spool（发就绪信号），再串行处理工作项：
/// 管道事件入库（轨 A）/ wire 回溯导入（轨 B）。大首扫期间管道事件在缓冲区排队不丢
/// （hook 侧 fire-and-forget 语义不变），回溯与实时事件因此不会交错写库。
fn worker_loop(
    work_rx: &Receiver<WorkItem>,
    db_path: &Path,
    spool_path: &Path,
    sink: Option<Sender<AuditEvent>>,
    ready_tx: &Sender<()>,
    shutdown: &ArcBool,
) {
    let db = match AuditDb::open(db_path) {
        Ok(db) => Some(db),
        Err(e) => {
            tracing::error!("审计库打开失败：{e}（事件将只记日志后丢弃，ask 防护不受影响）");
            None
        }
    };
    if let Some(db) = &db {
        let recovered = recover_spool(spool_path, db, sink.as_ref());
        if recovered > 0 {
            tracing::info!("启动回收 spool 事件 {recovered} 条入库");
        }
    }
    let _ = ready_tx.send(());

    while let Ok(item) = work_rx.recv() {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        match item {
            WorkItem::Conn(mut file) => {
                serve_one(&mut file, db.as_ref(), sink.as_ref());
                // SAFETY: 句柄仍有效（File 尚未 drop）；断开后 drop 即关闭
                unsafe { DisconnectNamedPipe(file_as_raw(&file)) };
            }
            WorkItem::Backfill(job) => {
                let summary = run_backfill(&job.root, db.as_ref());
                tracing::info!(
                    files = summary.files,
                    imported = summary.imported,
                    dup = summary.dup_skipped,
                    bad = summary.bad_lines,
                    torn = summary.torn_files,
                    db_ok = summary.db_ok,
                    "wire 回溯导入完成"
                );
                let _ = job.reply.send(summary);
            }
        }
    }
}

/// 回溯导入：遍历 root 下全部 wire.jsonl，按文件游标增量扫描 + 幂等批量入库。
/// 文件缩短（kimi 协议迁移整文件重写）→ 游标归零重扫，backfill_seen 行级去重兜底；
/// 行号位移导致的少量重复属已知良性偏差（宁多不缺）。
fn run_backfill(root: &Path, db: Option<&AuditDb>) -> BackfillSummary {
    let mut summary = BackfillSummary {
        db_ok: db.is_some(),
        ..BackfillSummary::default()
    };
    let Some(db) = db else {
        return summary;
    };
    for file in wire::discover(root) {
        summary.files += 1;
        let file_key = file.display().to_string();
        let stored = db.backfill_cursor(&file_key).unwrap_or(0);
        let mut scan = wire::scan_file(&file, root, stored + 1);
        if scan.lines_consumed < stored {
            tracing::info!(
                "wire 文件缩短（协议迁移重写？），游标 {stored} → 0 全量重扫：{}",
                file.display()
            );
            scan = wire::scan_file(&file, root, 1);
        }
        summary.bad_lines += scan.bad_lines;
        summary.torn_files += u64::from(scan.torn);
        summary.oversized_files += u64::from(scan.oversized);
        let items: Vec<(String, AuditEvent)> = scan
            .items
            .into_iter()
            .map(|it| (it.key, it.event))
            .collect();
        match db.append_backfill(&file_key, &items, scan.lines_consumed) {
            Ok(stats) => {
                summary.imported += stats.imported;
                summary.dup_skipped += stats.dup_skipped;
            }
            Err(e) => tracing::error!("回溯入库失败（{}）：{e}", file.display()),
        }
    }
    summary
}

/// 处理单条连接：读一行 → 解析 → 入库 + 转 sink。空行（shutdown 探针）静默跳过。
fn serve_one(file: &mut File, db: Option<&AuditDb>, sink: Option<&Sender<AuditEvent>>) {
    let Some(read_result) = read_line_with_timeout(file, READ_TIMEOUT) else {
        tracing::warn!("读取事件超时（{READ_TIMEOUT:?}），丢弃该连接");
        return;
    };
    let line = match read_result {
        Ok(line) => line,
        Err(e) => {
            tracing::warn!("读取事件失败：{e}，丢弃该连接");
            return;
        }
    };
    if line.trim().is_empty() {
        return; // shutdown 探针 / 客户端连上即断
    }
    let Some(event) = parse_event(&line) else {
        let preview: String = line.trim().chars().take(120).collect();
        tracing::warn!("事件 JSON 非法（丢弃）：{preview}");
        return;
    };
    if let Some(db) = db {
        if let Err(e) = db.append(&event) {
            tracing::error!(event = %event.event, "事件入库失败：{e}");
        }
    } else {
        tracing::warn!(event = %event.event, "审计库不可用，事件丢弃");
    }
    if let Some(sink) = sink {
        let _ = sink.send(event);
    }
}

/// 读一行，带超时（读线程 + recv_timeout 范式，与 ask_pipe 一致）。
fn read_line_with_timeout(file: &File, timeout: Duration) -> Option<io::Result<String>> {
    let mut clone = file.try_clone().ok()?;
    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("kcg-events-reader".to_string())
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

/// 取 File 底层句柄（DisconnectNamedPipe 用；不取得所有权）
fn file_as_raw(file: &File) -> windows_sys::Win32::Foundation::HANDLE {
    use std::os::windows::io::AsRawHandle;
    file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
}
