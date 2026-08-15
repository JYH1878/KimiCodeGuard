# KimiCodeGuard 威胁模型（v0.1，2026-08-15）

> 配套文件：治理与决策记录见仓库根 `AGENTS.md`（D1–D9，本地治理文件）；工程细节见 `HANDOFF.md`。
> 本文只写威胁边界与对策对照，不重复功能说明。

## 1. 保护什么

1. **用户机器不被 AI agent 的危险命令毁掉**：`rm -rf`、读凭证文件、`git push --force` 这三类
   v0.1 规则覆盖的操作，在 Kimi Code 执行前被拦下（deny）或经人确认（ask 弹窗）。
2. **操作可取证**：每一次 hook 判定（放行/拒绝/人工确认）都进 `audit.db` 的
   append-only 哈希链；安装前的历史会话经 wire.jsonl 回溯入库。用户能校验链条完整性、
   能导出 JSONL 举证——「谁、何时、执行了什么、谁批的」。

## 2. 信任边界

| 组件 | 信任级别 | 约束 |
|---|---|---|
| Kimi Code 进程（v1/v2 引擎） | **半可信** | 它按协议调用 hook，但 hook 失败一律 fail-open 放行（官方契约，D1）；payload 字段随版本漂移，必须防御性解析（D5） |
| guard-hook（热路径） | 高 | 必须 panic-free（崩溃 = 官方 fail-open = 静默放行，D1/不变量 4）；单次处理 <100ms；内部错误收敛为按预置策略退出 |
| guard-daemon worker | 高 | `audit.db` **唯一写者**（事件管道与 wire 回溯共用单通道串行，events_pipe.rs WorkItem）；worker 之外无任何路径写库 |
| 用户本人 | 可信 | ask 弹窗的「允许」是最终裁决；审计库在用户自己的 `%LOCALAPPDATA%` 下，用户本来就能改自己的文件 |
| 本工具的二进制与配置注入块 | 半可信 | 可能被其他进程或用户手改——巡检只**发现**不**阻止**（见 §4） |

数据流边界：

- hook → daemon 走两条命名管道（`\\.\pipe\KimiCodeGuard.ask.<USERNAME>` /
  `…events.<USERNAME>`），按用户名隔离，同机其他用户的进程进不来；
  管道消息全部按「不可信输入」处理：非法 JSON / 缺字段 → deny + 记日志，不弹窗不崩溃。
- daemon 不在时事件落 spool（`%LOCALAPPDATA%\KimiCodeGuard\spool\`），拉起后回收；
  spool 本身可被本机进程篡改——它**不是**取证边界，取证边界以入库后的哈希链为准。

## 3. 威胁清单与对策

| # | 威胁 | 对策 | 依据 |
|---|---|---|---|
| T1 | hook 进程崩溃/超时 → 官方 fail-open 静默放行 | hook 按 panic-free 标准编写（热路径禁 unwrap/expect/panic!）；事件处理全路径错误收敛 | AGENTS.md D1、不变量 4；guard-hook `main.rs` |
| T2 | ask 弹窗挂死 → agent 无限等待 | hook 侧 60s 超时主动 `exit 2`；弹窗侧 55s 无人点自动 deny（早 5s 留余量） | D2、不变量 3；`pipe.rs` / `daemon.rs` |
| T3 | 「新版协议支持 ask/stdout 回喂」的误信导致设计返工 | deny-only 设计：阻断只走 `exit 2` + stderr，永不依赖 `permissionDecision: "ask"` | D1/D2（#1326/#2107/#2122 三源交叉） |
| T4 | config.toml 写入撕裂 → hooks 段静默丢失 | 注入一律 tmp + rename + 回读校验；禁止原地覆盖 | D3（#2070 教训）；guard-hook `install.rs` |
| T5 | v1 引擎严格 schema：注入不认识的 hook 事件名 → 整个 hooks 段被静默忽略 | 注入块只写双引擎交集事件（PreToolUse/SessionStart/SessionEnd），永不注入 v2 独有事件；`install.rs` 有反向断言 | D4 补记（2026-08-14 实测，HANDOFF 坑 16） |
| T6 | 依赖 `permission.rules` → v2 引擎根本不加载 | 防护只走 hooks 路径，永不依赖 permission.rules | D4（#2070） |
| T7 | payload 字段漂移/缺失 → 解析崩溃或误判 | 缺字段 → 该规则跳过 + 记日志，整条非法 → 放行；fixtures 真实 payload 回归是发版门禁 | D5/D6；`payload.rs` + `fixtures/` |
| T8 | 规则被路径花招绕过（8.3 短名、junction、UNC、命令链、反斜杠 `\rm`、大小写） | 规范化（~ 展开/斜杠统一/canonicalize 兜底）+ tests/bypass/ 对抗集 57 条，规则改动必须全绿 | 不变量门禁；`rules.rs` + `tests/bypass/` |
| T9 | 审计记录被事后篡改却无从发现 | append-only + sha256 哈希链（prev_hash 链接），托盘「校验审计链」报红含行号；导出 JSONL 供独立重算 | D7；`audit.rs` |
| T10 | 安装前的危险操作无记录 | 轨 B：wire.jsonl 回溯解析（幂等增量、行级去重、撕裂末行不消费），同一 audit.db 同一链 | D7；`wire.rs` |
| T11 | 防护被卸载/破坏后用户不知情 | 自保护巡检（`protect.rs`）：启动 + 每 5 分钟查注入块与 hook exe 存在性（marker 优先、裸块兜底——Kimi 重写 config 会剥注释，2026-08-15 实测），缺失 → 托盘显红 + 「一键修复」（重跑原子注入） | M5；`protect.rs` / `tray.rs` |
| T12 | daemon 崩溃/被杀 → ask 无响应 | hook 连不上管道 ~2s 内 fail-safe `exit 2`；事件落 spool 待回收；SessionStart 自动拉起 daemon | D2；`pipe.rs` / `report.rs` / `lifecycle` |
| T13 | NSIS 注入失败 → 装完无防护 | installer hooks 失败不阻塞但写 `installer.log`；daemon 巡检下一轮发现显红，用户点「一键修复」兜底 | M5 止损设计；`installer.nsis` + `protect.rs` |
| T14 | Kimi 重写 config.toml 剥掉注释 → marker 丢失 → install/修复重复注入同一事件双 hook | install 去重覆盖裸块（command 含 guard-hook.exe 的无 marker 段）；uninstall 不动裸块；NSIS 卸载优先还原装前备份，字节级一致 | 2026-08-15 实测（HANDOFF 坑 21）；`main.rs` remove_orphan_blocks / `installer.nsis` |

## 4. 明确不防什么（写实话）

1. **官方 fail-open 契约本身**：hook 进程没跑、被杀、超时上限被击穿时，Kimi Code 一律放行。
   这是官方协议行为，不在本工具能力范围内（D1 只保证我们自己不主动崩溃）。
2. **hook/daemon 二进制自校验**：不校验二进制签名/哈希。攻击者若能替换
   `%INSTDIR%` 下的 exe，已经拥有当前用户权限，可以做任何更糟的事——
   这超出 v0.1 威胁模型（防的是 agent 误操作，不是本机攻击者）。
3. **恶意用户手改 config.toml**：巡检（T11）只**发现** marker 丢失并显红，不阻止修改。
   用户改自己的配置文件是合法操作；本工具不与用户对打。
4. **绕过规则的语义攻击**：v0.1 只拦三条规则（rm-force / cred-files / git-force-push，D9）。
   shell 混淆（base64/变量拼接）、`git push --delete`、注册表/计划任务/管道执行等
   已知缺口属 v0.2 地界（`rules.rs` 注释逐条写明），当前**不拦**。
5. **审计链的物理删除**：用户可以整库删掉 audit.db（自己的文件）。哈希链防的是
   「篡改不可见」，不防「销毁」；删除后下一次写入从创世行重新起链。
6. **Kimi Code 进程内部的恶意行为**：模型若诱骗用户点「允许」，或在白名单工具里
   构造危险输入，本工具不介入内容层判断——拦截边界在 PreToolUse 的三条规则。
