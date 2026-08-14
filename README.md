# KimiCodeGuard

Kimi Code 的 Windows 安全卫士：托盘常驻，通过 PreToolUse hook 拦截危险操作（deny / ask 弹窗 / log），SQLite append-only + hash chain 审计落库（轨 A 已交付；轨 B wire.jsonl 回溯待后续里程碑）。

> 开发守则与决策记录（D1–D9）见 AGENTS.md —— 本地治理文件，不入库；公开版行为规范以 LICENSE 与本文档为准。

## 演示

危险命令直接被拦（Kimi Code 收到拒绝原因，不会执行）：

```
$ kimi -p "用 Bash 运行 rm -rf /tmp/demo"
KimiCodeGuard 已拦截（规则 rm-force）：递归强制删除命令（rm -rf / del /s / Remove-Item -Recurse -Force 形态）   ← hook exit 2
```

`git push --force` 这类操作弹窗问人：置顶中文弹窗显示完整命令与 55 秒倒计时，点「允许」放行、点「拒绝」或不点（超时）一律拦截。

每一次判定都进审计库（SQLite append-only + SHA-256 哈希链，改任何一条历史记录都会被「校验审计链」报红并定位行号）：

```json
{"ts":1786694872308,"event":"PreToolUse","session_id":"accept-m…","tool_name":"Bash","decision":"deny","reason":"规则 rm-force：递归强制删除命令…","hash":"7f1bf0b7ed0d24da…"}
```

托盘菜单随时可「导出审计 JSONL」拿到全量记录做复盘。

## 当前状态

- M1（2026-08-13 验收）：guard-hook —— PreToolUse 薄 shim，三条内置规则（`rm-force` deny / `cred-files` deny / `git-force-push` ask），57 条绕过对抗集。
- M2（2026-08-14 验收）：guard-daemon —— Tauri 2 托盘 + ask 弹窗服务端；真机防护已启用（`rm -rf` / 凭据文件直接拦，git 强制推送弹窗问人，55 秒无响应自动拒绝）。
- M3（2026-08-14 验收）：审计轨 A 落库 —— hook 事件上报 → 事件管道 → SQLite + hash chain（spool 兜底，daemon 不在时零丢失）；daemon 随 Kimi Code 会话自动启停（SessionStart 拉起、空载 5 分钟自退，可选开机自启）；托盘「校验审计链」（篡改报红定位行号）与「导出审计 JSONL」。

## 组成

- `guard-hook/` — Rust 单文件 exe：PreToolUse hook 薄 shim（stdin → 规则判定 → 事件上报 → exit 0/2），会话生命周期上报（lifecycle），内置 config 原子注入器。
- `guard-daemon/` — Tauri 2 托盘（独立 workspace）：ask 命名管道服务端 + 弹窗 UI、事件管道服务端 + SQLite/hash chain 审计库、会话跟踪启停调度、托盘菜单（状态 / 校验审计链 / 导出审计 JSONL / 开机自启 / 退出）。
- `fixtures/` — 真实 hook payload（已脱敏），解析器与规则的唯一数据地基。
- `docs/` — 兼容矩阵（实测记录）；项目书、威胁模型待建。

## 构建与运行

```bash
cargo build --release                           # guard-hook → target/release/guard-hook.exe
cd guard-daemon && npm install && npm run build # 前端 → dist/
cd src-tauri && cargo build --release           # daemon → guard-daemon/src-tauri/target/release/guard-daemon.exe
```

启用防护：`target/release/guard-hook.exe install --config ~/.kimi-code/config.toml --daemon-path <guard-daemon.exe 路径>`（原子写入、自动备份，`uninstall` 可字节级还原）。注入后每次 Kimi Code 会话启动会自动拉起 daemon；daemon 不在时 deny 规则照常拦截，ask 规则按安全策略直接拒绝，事件落 spool 待 daemon 拉起后回收。托盘「校验审计链」可随时全量重算哈希链，「导出审计 JSONL」落 `Documents\KimiCodeGuard-audit-<时间戳>.jsonl`。

