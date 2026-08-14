//! guard-daemon 核心库：ask 命名管道服务端 + 审计轨 A 落库 + 审计轨 B wire 回溯（可测试核心，不依赖 Tauri 运行时）。

#[cfg(windows)]
pub mod ask_pipe;
pub mod audit;
#[cfg(windows)]
pub mod events_pipe;
pub mod sessions;
pub mod wire;
