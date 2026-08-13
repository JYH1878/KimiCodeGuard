# PROGRESS.md — M0 进度记录

- [x] 0. 自测：cargo 1.97.1 / node 24.16.0 / kimi 0.34.0 可用；KIMI_CODE_HOME 指向 %TEMP%\kcg-sandbox 跑 `kimi -p "回复 ok"` 成功，会话落在沙箱 sessions/ 内。
- [x] 1. 仓库地基：git init、.gitignore、MIT LICENSE（JYH1878）、中文 README 骨架，已提交。
- [x] 2. guard-hook：workspace + 单 crate 单二进制，hook/install/uninstall/sanitize 四子命令；原子写 tmp+fsync+rename、回读校验、备份不覆盖；单测 9 + 集成 9 全绿；垃圾 stdin exit 0 stdout {} 实测通过。
