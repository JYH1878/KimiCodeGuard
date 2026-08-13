//! guard-hook 核心库：payload 解析、规则判定、ask 管道客户端。
//!
//! 热路径纪律（AGENTS.md 不变量 4）：禁止 unwrap/expect/panic，
//! hook 崩溃 = 官方 fail-open = 静默放行（D1）。

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod payload;
pub mod pipe;
pub mod rules;
