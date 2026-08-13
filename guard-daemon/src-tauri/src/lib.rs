//! guard-daemon 核心库：ask 命名管道服务端（可测试核心，不依赖 Tauri 运行时）。

#[cfg(windows)]
pub mod ask_pipe;
