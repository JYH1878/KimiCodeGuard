# KimiCodeGuard

Kimi Code 的 Windows 安全卫士：托盘常驻，通过 PreToolUse hook 拦截危险操作（deny / ask 弹窗 / log），SQLite append-only + hash chain 审计落库（轨 A 实时事件 + 轨 B wire.jsonl 回溯安装前历史，均已交付）。

> 开发守则与决策记录（D1–D9）见 AGENTS.md —— 本地治理文件，不入库；公开版行为规范以 LICENSE 与本文档为准。

## 功能

- **危险命令拦截**：内置规则 deny 高危操作（`rm -rf`、凭据文件读写等），git 强制推送弹窗问人（55 秒无响应自动拒绝）；Kimi Code 双引擎（v1/v2）通吃。
- **双轨审计**：轨 A = hook 实时事件；轨 B = wire.jsonl 回溯安装前历史。统一进 SQLite 哈希链——改动任意一条历史记录，「校验审计链」立即报红并定位行号。
- **托盘常驻**：随 Kimi Code 会话自动启停、空载自退；校验审计链 / 导出审计 JSONL / 回溯历史会话 / 开机自启 一键直达。
- **fail-safe 设计**：hook 崩溃、daemon 掉线、弹窗超时一律按拒绝处理，绝不静默放行。

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

**回溯安装前历史（轨 B）**：daemon 首次启动自动扫描 `~/.kimi-code/sessions/**/wire.jsonl`，把安装之前的用户输入、工具调用、权限审批记录以 `wire.*` 事件幂等导入同一审计库（同一条哈希链保护，重复扫描零新增）；托盘「回溯历史会话」可随时手动重扫：

```json
{"ts":1785000002000,"event":"wire.tool_call","session_id":"session_…","tool_name":"Bash","reason":"wire 回溯：wd_…/session_…/agents/main/wire.jsonl:9","payload":"{\"type\":\"context.append_loop_event\",…}","hash":"…"}
```

## 隐私与数据

- 审计数据只存本地（`%LOCALAPPDATA%\KimiCodeGuard\audit.db`）；导出 JSONL 是你主动触发的动作。
- 回溯（轨 B）读取 Kimi Code 自己落盘的 `~/.kimi-code/sessions/**/wire.jsonl`，只提取安全相关事件（工具调用 / 用户输入 / 权限审批），不采集工具输出内容与模型思考。
- 仓库内 `fixtures/` 全部为脱敏或合成样本，不含任何真实会话内容。

## 当前状态

- M1（2026-08-13 验收）：guard-hook —— PreToolUse 薄 shim，三条内置规则（`rm-force` deny / `cred-files` deny / `git-force-push` ask），57 条绕过对抗集。
- M2（2026-08-14 验收）：guard-daemon —— Tauri 2 托盘 + ask 弹窗服务端；真机防护已启用（`rm -rf` / 凭据文件直接拦，git 强制推送弹窗问人，55 秒无响应自动拒绝）。
- M3（2026-08-14 验收）：审计轨 A 落库 —— hook 事件上报 → 事件管道 → SQLite + hash chain（spool 兜底，daemon 不在时零丢失）；daemon 随 Kimi Code 会话自动启停（SessionStart 拉起、空载 5 分钟自退，可选开机自启）；托盘「校验审计链」（篡改报红定位行号）与「导出审计 JSONL」。
- M4（2026-08-14 验收）：审计轨 B —— wire.jsonl 回溯解析（v1/v2 双引擎记录通吃，撕裂行/坏行/未来类型容错），安装前历史以 `wire.*` 事件幂等导入同一审计库（行级去重 + 文件游标增量）；daemon 启动自动回溯 + 托盘「回溯历史会话」手动重扫。

## 组成

- `guard-hook/` — Rust 单文件 exe：PreToolUse hook 薄 shim（stdin → 规则判定 → 事件上报 → exit 0/2），会话生命周期上报（lifecycle），内置 config 原子注入器。
- `guard-daemon/` — Tauri 2 托盘（独立 workspace）：ask 命名管道服务端 + 弹窗 UI、事件管道服务端 + SQLite/hash chain 审计库、wire.jsonl 回溯解析器（轨 B）、会话跟踪启停调度、托盘菜单（状态 / 校验审计链 / 导出审计 JSONL / 回溯历史会话 / 开机自启 / 退出）。
- `fixtures/` — 真实 hook payload（已脱敏）+ wire.jsonl 合成样本，解析器与规则的唯一数据地基。
- `docs/` — 兼容矩阵（实测记录）；项目书、威胁模型待建。

## 构建与运行

```bash
cargo build --release                           # guard-hook → target/release/guard-hook.exe
cd guard-daemon && npm install && npm run build # 前端 → dist/
cd src-tauri && cargo build --release           # daemon → guard-daemon/src-tauri/target/release/guard-daemon.exe
```

启用防护：`target/release/guard-hook.exe install --config ~/.kimi-code/config.toml --daemon-path <guard-daemon.exe 路径>`（原子写入、自动备份，`uninstall` 可字节级还原）。注入后每次 Kimi Code 会话启动会自动拉起 daemon；daemon 不在时 deny 规则照常拦截，ask 规则按安全策略直接拒绝，事件落 spool 待 daemon 拉起后回收。托盘「校验审计链」可随时全量重算哈希链，「导出审计 JSONL」落 `Documents\KimiCodeGuard-audit-<时间戳>.jsonl`。

卸载：`target/release/guard-hook.exe uninstall --config ~/.kimi-code/config.toml` 逐字节还原 config；如需连审计数据一并清除，删除 `%LOCALAPPDATA%\KimiCodeGuard\` 目录即可。

