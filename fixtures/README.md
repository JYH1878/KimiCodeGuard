# fixtures/ — 真实 hook payload（已脱敏）

KimiCodeGuard 解析器与规则的唯一数据地基（AGENTS.md D6）。全部是真实会话采集的
`PreToolUse` payload，不是手写样本。

- 采集日期：2026-08-13
- kimi 版本：0.34.0（`~/.kimi-code/bin/kimi`）
- 平台：Windows 11 + Git Bash
- 数量：14 条，覆盖 6 种工具 × 2 个引擎

## 采集方法（headless 象限）

1. 建沙箱 home：`%TEMP%\kcg-sandbox`，只从真实 home 复制三样：凭据目录、设备标识文件、`config.toml`（凭据绝不进本仓库）。
2. debug hook 注入沙箱 config：`guard-hook install --config <沙箱config> --dump-dir <沙箱dump>`。
3. 探针目录 `%TEMP%\kcg-probe` 放种子文件 `a.txt`，cd 进去逐条点名触发工具：

```bash
# 默认引擎（v2）：直接跑
KIMI_CODE_HOME=<沙箱> kimi -p "用 Bash 工具执行: echo hello-kcg-v2。只做这一件事。"
# legacy 引擎（v1）：加环境变量
KIMI_CODE_LEGACY_FLAG=1 KIMI_CODE_HOME=<沙箱> kimi -p "用 Read 工具读取 a.txt。只做这一件事。"
```

4. 脱敏入库：`guard-hook sanitize --dump-dir <沙箱dump> --out-dir fixtures/`。

## 文件清单

| 文件 | 引擎 | 工具 | 备注 |
|---|---|---|---|
| v1-bash-01.json | v1 (KIMI_CODE_LEGACY_FLAG=1) | Bash | `echo hello-kcg-v1` |
| v1-read-01.json | v1 | Read | 读 a.txt |
| v1-read-02.json | v1 | Read | Edit 会话内的先读后改 |
| v1-write-01.json | v1 | Write | 建 b1.txt |
| v1-edit-01.json | v1 | Edit | 改 b1.txt |
| v1-glob-01.json | v1 | Glob | 列 *.txt |
| v1-grep-01.json | v1 | Grep | 搜 a.txt 里的 hello |
| v2-bash-01.json | v2（0.34.0 默认） | Bash | `echo hello-kcg-v1` |
| v2-read-01.json | v2 | Read | 读 a.txt |
| v2-read-02.json | v2 | Read | Edit 会话内的先读后改 |
| v2-write-01.json | v2 | Write | 建 b2.txt |
| v2-edit-01.json | v2 | Edit | 改 b2.txt |
| v2-glob-01.json | v2 | Glob | 列 *.txt |
| v2-grep-01.json | v2 | Grep | 搜 a.txt 里的 hello |

## 实测字段结论（0.34.0 headless）

- 公共字段：`hook_event_name`、`session_id`、`cwd`、`tool_name`、`tool_input`、`tool_call_id`。
- v2 额外字段：`client_type`（本批恒为 `kimi_code_cli`）；`session_title` 本批未出现（headless 无标题），引擎探测以 `client_type`/`session_title` 任一存在为准。
- v1 的 `cwd` 用正斜杠，v2 用反斜杠（JSON 内为 `\\` 转义）——脱敏与解析两种形态都要处理。
- 本批未观察到 `mcp__*`、FetchURL、WebSearch 的 payload（沙箱未配置 mcp 服务），工具名集合见 AGENTS.md D5。

## 交互象限（TUI / web）人工补采步骤

M0 只自动化了 headless 象限。补采（人工，不自动化）：

1. TUI：沙箱 config 注入同上；`KIMI_CODE_HOME=<沙箱> kimi` 进交互界面，手动让它读文件、跑命令；结束后 dump 目录取 payload，sanitize 入库，文件名 `v{1,2}-<tool>-<序号>.json` 顺延。
2. web：`KIMI_CODE_HOME=<沙箱> kimi web`，浏览器里同样逐工具点名；v2 引擎路径，重点确认 `session_title` 字段是否出现。
3. 补采后更新本清单与 `docs/兼容矩阵.md`。

## 脱敏规则

- home 路径四种写法（原样 / 正斜杠 / JSON 转义反斜杠 / cygwin）→ `<HOME>`
- 密钥形态（常见 token 前缀 + 长串）→ `<REDACTED>`
- 其余原样保留（含 `session_id`、`tool_call_id`——随机值，无敏感性）

## wire/ — wire.jsonl 样本（审计轨道 B，2026-08-14 M4）

`wire/` 下是 `~/.kimi-code/sessions/<wd>/<sid>/agents/<agent>/wire.jsonl` 的**合成**
样本：schema 按 `参考/kimi-code-main` 0.36.0 `agent-core-v2/docs/wire-manifest.d.ts`
与本机 128 个真实文件的结构核对（protocol 1.4/1.5 各半，`config.update.cwd` 42/130
存在）构造，内容全为虚构数据，不含任何真实会话。

| 文件 | 形态 | 覆盖点 |
|---|---|---|
| v2-main-01.jsonl | protocol 1.5，主 agent | 全部导入类型（metadata/turn.prompt user/tool.call×3/permission×2）+ 跳过类型（injection origin、append_message 去重陷阱、content.part、tool.result、usage.record、llm.request、未知未来类型）+ 撕裂末行（无换行结尾的半行 JSON） |
| v1-main-01.jsonl | protocol 1.4，主 agent | v1 独有类型（micro_compaction.apply/context.update_token_count）、无 cwd 的 config.update、秒级 time（×1000 归一）、文件中部坏行 |
| subagent-01.jsonl | protocol 1.5，子 agent | 最小样本，配合 `agents/agent-0/` 路径形状测试 |

解析器（guard-daemon/src-tauri/src/wire.rs）只对这些样本开发；kimi 升版后按
真机文件重核结构再回归。
