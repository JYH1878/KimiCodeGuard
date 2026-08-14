# KimiCodeGuard

Kimi Code 的 Windows 安全卫士：托盘常驻，通过 PreToolUse hook 拦截危险操作（deny / ask 弹窗 / log），SQLite + hash chain + wire.jsonl 双轨审计（审计层待后续里程碑）。

> 开发守则与决策记录见 [AGENTS.md](AGENTS.md)。

## 当前状态

- M1（2026-08-13 验收）：guard-hook —— PreToolUse 薄 shim，三条内置规则（`rm-force` deny / `cred-files` deny / `git-force-push` ask），57 条绕过对抗集。
- M2（2026-08-14 验收）：guard-daemon —— Tauri 2 托盘 + ask 弹窗服务端；真机防护已启用（`rm -rf` / 凭据文件直接拦，git 强制推送弹窗问人，55 秒无响应自动拒绝）。

## 组成

- `guard-hook/` — Rust 单文件 exe：PreToolUse hook 薄 shim（stdin → 规则判定 → exit 0/2），内置 config 原子注入器。
- `guard-daemon/` — Tauri 2 托盘（独立 workspace）：ask 命名管道服务端 + 弹窗 UI + 托盘菜单。
- `fixtures/` — 真实 hook payload（已脱敏），解析器与规则的唯一数据地基。
- `docs/` — 兼容矩阵（实测记录）；项目书、威胁模型待建。

## 构建与运行

```bash
cargo build --release                           # guard-hook → target/release/guard-hook.exe
cd guard-daemon && npm install && npm run build # 前端 → dist/
cd src-tauri && cargo build --release           # daemon → guard-daemon/src-tauri/target/release/guard-daemon.exe
```

启用防护：`target/release/guard-hook.exe install --config ~/.kimi-code/config.toml`（原子写入、自动备份，`uninstall` 可字节级还原）。ask 弹窗需要 guard-daemon 在运行；daemon 不在时 ask 规则按安全策略直接拒绝，deny 规则不受影响。
