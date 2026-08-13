# PROGRESS.md — M0 进度记录

- [x] 0. 自测：cargo 1.97.1 / node 24.16.0 / kimi 0.34.0 可用；KIMI_CODE_HOME 指向 %TEMP%\kcg-sandbox 跑 `kimi -p "回复 ok"` 成功，会话落在沙箱 sessions/ 内。
- [x] 1. 仓库地基：git init、.gitignore、MIT LICENSE（JYH1878）、中文 README 骨架，已提交。
- [x] 2. guard-hook：workspace + 单 crate 单二进制，hook/install/uninstall/sanitize 四子命令；原子写 tmp+fsync+rename、回读校验、备份不覆盖；单测 9 + 集成 9 全绿；垃圾 stdin exit 0 stdout {} 实测通过。
- [x] 3. 沙箱采集：%TEMP%\kcg-sandbox 隔离 home，install 注入沙箱 config；kcg-probe 内 kimi -p 逐工具点名，默认(v2)与 KIMI_CODE_LEGACY_FLAG=1(v1) 双引擎各 6 工具，共 14 条真实 payload。
- [x] 4. 脱敏入库：sanitize 写 fixtures/（引擎-工具-序号命名），14 条；fixtures/README.md 记录版本/命令/清单/交互补采步骤；docs/兼容矩阵.md 建（headless 两格实测、交互未测）；沙箱与凭据副本已删。
- [x] 5. AGENTS.md 勘误：D1 事件数 v1=16/v2=20、§3 前端门禁改 npm、D4 路径关系改「运行时只读 ~/.kimi-code」、D5 并集按实测更新、证据索引加源码快照 0.36.0，均注明 2026-08-13 与源码证据。
