# KimiCodeGuard

Kimi Code 的 Windows 安全卫士：托盘常驻，通过 PreToolUse hook 拦截危险操作（deny / ask 弹窗 / log），SQLite + hash chain + wire.jsonl 双轨审计。

> 开发守则与决策记录见 [AGENTS.md](AGENTS.md)。

## 当前状态

M0：仓库地基 + debug hook + 真实 hook payload 采集。

## 组成

- `guard-hook/` — Rust 单文件 exe：PreToolUse hook 薄 shim（stdin → 落盘 / 规则判定 → exit 0/2），内置 config 注入器。
- `guard-daemon/` — Tauri 2 托盘（规划中，M0 不开工）。
- `fixtures/` — 真实 hook payload（已脱敏），解析器与规则的唯一数据地基。
- `docs/` — 兼容矩阵（实测记录）；项目书、威胁模型待建。

## 构建

```bash
cargo build --release
```
