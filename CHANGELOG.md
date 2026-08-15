# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-08-15

首个公开发布。给 Kimi Code CLI（Windows）装上安全门：托盘常驻，PreToolUse 拦截危险操作，
全程可取证审计。

### 拦截（M1–M2）

- guard-hook 单文件 exe（<3MB，冷启动 <50ms），PreToolUse 判定三态：放行 / 拒绝（`exit 2` + 中文原因）/ 弹窗确认。
- v0.1 内置三条规则：`rm-force` 拒绝（危险递归删除，含 `del /s`、`Remove-Item -Recurse -Force` 变体）、`cred-files` 拒绝（读取 `.env`、私钥、`~/.ssh`、`~/.aws` 等凭证文件）、`git-force-push` 弹窗确认。
- ask 弹窗：置顶中文窗口，等宽完整命令，55 秒无人确认自动拒绝（fail-safe）；hook 侧 60 秒超时主动 `exit 2`。
- 规范化抗绕过：8.3 短名、junction、UNC、命令链、`\rm`、大小写变体；57 条绕过对抗测试集。

### 审计（M3–M4）

- 轨 A 实时：hook 事件经命名管道上报，SQLite append-only + sha256 哈希链；daemon 不在时落 spool 兜底，拉起后自动回收。
- 轨 B 回溯：解析 `wire.jsonl` 重建**安装前**的会话历史（幂等增量、行级去重），与实时事件同库同链。
- 托盘菜单：校验审计链（篡改报红含行号）、导出审计 JSONL、回溯历史会话。
- daemon 随会话启停：SessionStart 拉起保活、空载 5 分钟自退、托盘「开机自启」（默认关）。

### 发布链路（M5）

- NSIS 安装器（当前用户免管理员，简体中文）：安装注入 hooks、卸载还原 config.toml（装前备份逐字节还原）；guard-hook.exe 随包分发；重装/修复自动去重「裸块」（Kimi 重写配置剥注释的实测场景）。
- 自保护巡检：daemon 启动时 + 每 5 分钟检查注入块与 hook 程序存在性，失效时托盘显红 + 「一键修复」。
- GitHub Actions CI 门禁：根与 daemon 双 workspace 的 fmt / clippy / 全量测试 + 前端 lint / build。
- 文档：`docs/THREAT_MODEL.md` 威胁模型、`docs/兼容矩阵.md` 四象限实测矩阵。

### 已知边界

- 安装器未签名，Windows SmartScreen 会提示，属预期（项目无代码签名证书）。
- v0.1 只拦三条规则；shell 混淆、`git push --delete` 等已知缺口滚动至 v0.2。
- 官方 fail-open 契约、二进制自校验、恶意用户手改配置不在防护范围内（见 THREAT_MODEL.md §4）。

[0.1.0]: https://github.com/JYH1878/KimiCodeGuard/releases/tag/v0.1.0
