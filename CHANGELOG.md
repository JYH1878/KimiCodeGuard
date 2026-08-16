# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.1] - 2026-08-16

热修：out-of-workspace 不再误报 `/dev/null` 重定向。

### 修复（M8.1）

- 误报现象：`2>/dev/null`、`> /dev/null`、`&> /dev/null`、`tee /dev/null` 这类丢弃输出的重定向，被 out-of-workspace 规则当成「工作区外写入」弹窗问人——daemon 不在时直接挡下命令，在时弹窗等 55 秒超时。这是 shell 最高频惯用法之一，v0.3.0 已带着它发版，必须热修重发。
- 修法：out-of-workspace 增加 POSIX 设备命名空间豁免——规范化后以 `/dev/` 开头且无盘符前缀的路径（`/dev/null`、`/dev/zero`、`/dev/std*`、`/dev/tty` 等）一律放行；带盘符的 `D:/dev/…` 是真实文件路径，绝不豁免。纯字符串判定，不进 Env、不做 IO。
- 两条 v0.3 规则的判定与 ask 逻辑不变，本批只加豁免。绕过对抗集 167 → 172 条（新增 5 条放行语料：`ls x 2>/dev/null`、`cat f > /dev/null`、`echo x &> /dev/null`、`tee /dev/null`、`cmd 2>&1` 对照）。

## [0.3.0] - 2026-08-15

规则扩展：内置规则 6 → 8，补上「远程内容直接灌入解释器」与「文件操作逃出工作区」两个高频缺口，并收掉 M7 验收实测放行的两个解码变体。

### 新增规则（M8）

- `pipe-exec` 弹窗确认：下载器（`curl` / `wget` / `iwr` / `Invoke-WebRequest` / `irm` / `Net.WebClient.Download*`）经管道或进程替换灌入解释器（`bash` / `sh` / `zsh` / `dash` / `python` / `node` / `cmd` / `powershell` / `pwsh` / `iex`）→ 问人（「远程内容经管灌入解释器，执行前无法审查」）。形态覆盖：`curl … | bash`、`bash <(curl …)`、`sh -c "$(curl …)"`、`iwr … | iex`。`||` / `&&` / `;` 分隔不算管道；下载后跨命令链执行（`curl -o f && bash f`）本批不覆盖（见 THREAT_MODEL 残余缺口）。
- `out-of-workspace` 弹窗确认：Write / Edit 工具的 `file_path` 与 Bash 写出目标（重定向 / `tee` / `cp` / `mv` / `copy` / `move` / `rename` / `del` / `rm` / `sed -i`）规范化后落在 cwd 子树外 → 问人（「工作区外文件操作」）。豁免系统临时目录（`%TEMP%` / `%TMP%`、`/tmp`、`/var/tmp`）与 `~/.kimi-code/`（Kimi Code 自身配置目录；config.toml 本体仍由 self-protect 拒绝）；读不触发；cwd 缺失跳过；canonicalize 兜底 junction / 8.3 逃逸。顺带修复 `normalize_path` 把 POSIX 根与 UNC 前缀坍缩的存量缺陷。
- `shell-obfuscation` 两个解码补丁：①`base64` 合并旗标——单横线、纯字母、含 `d`/`D` 的旗标簇按解码处理（`-di` / `-dw` / `-Di`）；②PowerShell `[Convert]::FromBase64String('…')` 字符串字面量——提取解码重判，解不出或没命中 → 问人（不透明），变量输入不误报。
- 绕过对抗集 121 → 167 条（pipe-exec 15、out-of-workspace 19、obfus 新 12），harness 收紧 schema 并给两条新规则加 ≥8 拦 + ≥5 放门禁断言；非 git-destroy 语料 git 探测仍必须为 0。

### 已知边界

- 下载后执行（`curl -o f && bash f`）跨命令链切段本批不覆盖；`registry-write` / `scheduled-task` / `git-dir-write` 滚入 v0.4。
- 详见 `docs/THREAT_MODEL.md` §4。

## [0.2.0] - 2026-08-15

规则扩展：内置规则 3 → 6，补上 shell 包装绕过与防护被拆台的缺口。

### 新增规则（M7）

- `self-protect` 拒绝：拦对四类受保护路径的写 / 删 / 改名——`config.toml`（`KIMI_CODE_HOME` 覆盖优先，否则 `~/.kimi-code/config.toml`）、当前 hook exe、同目录 daemon exe（`KimiCodeGuard.exe` 与 `guard-daemon.exe` 两个名字都算）、`audit.db`（`%LOCALAPPDATA%\KimiCodeGuard\`）。覆盖面：Write / Edit 工具路径命中；Bash 里重定向（`>`、`>>` 及数字前缀变体）、`tee`、`cp` / `mv` / `copy` / `move` / `rename` 目标、`del` / `rm` / `sed -i` 命中。**读不拦**。路径规范化复用凭据规则那套（`~` 展开 / 统一斜杠 / canonicalize 兜底 8.3 短名与 junction）。
- `shell-obfuscation` 剥壳重判：`bash -c` / `sh -c` / `cmd /c` / `powershell -Command` 的内层命令解出后对整条规则集重新判定（嵌套最多 2 层），内层命中谁走谁的判定（原因注明「经 shell 包装解出」）。编码执行：`base64 -d` / `certutil -decode` 管道进解释器、`powershell -enc` / `-EncodedCommand`——能干净解码就先解码再重判；解不出或没命中 → 弹窗问人（「执行不透明编码内容，无法审查」）。解码输入上限 64KB。
- `git-destroy` 弹窗确认（无拒绝，销毁操作都有合法场景）：①历史 / 远端销毁一律问人——`push --delete` 与 `push <remote> :ref`、`branch -D`、`tag -d`、`reflog expire`、`gc --prune`、`filter-branch` / `filter-repo`、`update-ref -d`、`stash drop` / `clear`。②工作区销毁看仓库状态——`reset --hard`、`clean` 带 `-f`、`checkout -- <路径>`、`restore [--worktree] <路径>` 在 payload 的 cwd 跑 `git status --porcelain`（300ms 超时；git 不存在 / 非仓库 / 超时一律按有变更处理）：有变更 → 问人（「有未提交改动将永久丢失」），无变更 → 放行。放行例：`clean -n`、`reset --soft/--mixed`、`checkout 分支名`、`restore --staged`。
- 绕过对抗集 57 → 121 条（每新规则 ≥8 拦 + ≥5 放）；allow 热路径不新增 IO（计数探测断言：非 git-destroy 语料探测调用数必须为 0）；git 探测真机 E2E 在 TEMP 建真实仓库验证。

### 审计面板（M6）

- 新增中文审计面板（托盘「打开审计面板」）：统计卡（今日拦截 / 弹窗确认 / 放行 / 事件总数）、14 天柱状图、高频工具 Top5、事件流表格（deny 红 / ask 黄 / allow 灰）、判定 / 事件 / 工具 / 关键字筛选、游标分页、点行展开完整 payload。
- 新事件实时上屏：daemon 落库后即推送面板，无需手动刷新。
- 面板对审计库为只读连接（含写拒单测），不影响哈希链与写入路径。

### 修复（M6）

- 修复事件管道偶发丢审计事件：fire-and-forget 客户端「连上即断」时，listener 误把 ERROR_NO_DATA 当失败关闭句柄，缓冲数据随之销毁。
- 修复审计面板自动刷新静默失效：capabilities 未列 panel 窗口导致前端事件监听无权限、无任何报错。

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

[0.3.0]: https://github.com/JYH1878/KimiCodeGuard/releases/tag/v0.3.0
[0.2.0]: https://github.com/JYH1878/KimiCodeGuard/releases/tag/v0.2.0
[0.1.0]: https://github.com/JYH1878/KimiCodeGuard/releases/tag/v0.1.0
