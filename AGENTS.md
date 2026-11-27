# AGENTS.md

VProxy（D:\project\rust\vs\vpn-parser）：桌面代理工作站。GUI + clap CLI + HTTP API（src/api）+ 多内核编译器（mihomo / sing-box / VP-Core / xray / meow）。lib 名为 `vproxy`（rlib/cdylib/staticlib），未发布 crates.io，仅 path/git 依赖。

## 硬规则：每次提交都要极致测试

pre-commit 钩子（core.hooksPath=scripts/githooks）机械强制。本地必须完整复现 CI（.github/workflows/ci.yml）每一步，全绿才允许 commit：

1. `cargo fmt --all -- --check`（本地加固，CI 未含 —— 曾因没跑 fmt 带进提交）
2. `cargo clippy --all-targets -- -D warnings`（本地加固）
3. `cargo check --no-default-features`（无头编译门，CI 同款）
4. `cargo test`（三内核自检依赖 data/kernels/，勿删）
5. 改了协议编译 / 内核更新 / 导出逻辑：另加 CLI 冒烟（parse / compile / export 各跑一次真实输入）+ `--headless` 启动后 `curl /api/health`
6. 改了 src/gui：提醒用户在 GUI 实际验证（代理启动/停止、更新内核）

白名单免测（钩子内置）：`*.md`、`*.txt`、`*.png`、`*.ico`、`.github/*`、`scoop/*`、`scripts/githooks/*`。`FORCE_FULL_GATE=1` 可无视白名单强制全门。

## 实测纪律（历史教训，违反过且付出过代价）

- loopback 测试 curl 必须 `--noproxy ""`：curl 对 127.0.0.1 默认绕过代理，不加就是直连，结果全假
- 起测试实例前先清点端口占用（`netstat -ano` / Get-CimInstance），杀净残留进程再跑 —— 残留实例曾反复污染测试结果
- 杀进程禁用过宽的 CommandLine 模糊匹配（曾误杀用户正在用的 mihomo，端口 17898）；按 netstat 的 PID 精确杀
- Windows 运行中 exe 不可删但可重命名（内核热更新的原理）；target 下 exe 被占用（OS error 32）时先停实例再 cargo run
- 本机 python/pip 损坏（SRE module mismatch），不要依赖 python 写参考实现
- clippy 的机器建议也会改错值：`rgb(0x12_13_16)` 被建议成 `0x1213_i16`（不同值）——`cargo clippy --fix` 之后必须逐文件 review diff，颜色/数值字面量重点核对
- mihomo 测试配置：hysteria2 监听器用 `users: {user: pass}` 映射（password 字段被忽略，404 是这个原因）；snell 监听器默认 version 4
- 手动替换 data/kernels 下的内核 exe 与 GUI 的安装记录会打架：GUI 再执行安装会按其记录的版本覆盖回来（本次 1.7.8 部署被用户随后的更新装回 1.7.7）——手动换内核后告知用户重启代理；**别和 GUI 安装流程并发操作同一文件**
- 更新检查依赖 api.github.com，限流/被掐时走离线缓存或兜底常量——兜底常量（VPCORE_TAG 等）随每次上游发版同步 bump，否则兜底会装回旧版
- cfg 平台专属代码（`#[cfg(target_os = "macos")]` / unix 块）不受 Windows 门禁编译覆盖——等价改写后必须全库 grep 同类构造点/调用点复核（ProxyChild 包 Box 改造就漏了 mac 测试辅助 1 处，mac CI 连挂 4 次）

## 打包纪律

- 本地 Windows 打包只生成安装版（`cargo build --release --bin vproxy` + `& "D:\software\InnoSetup6\ISCC.exe" installer/vproxy.iss`）及仅含 `*-setup.exe` 的 `dist/sha256-<version>.txt`
- **本地打包跳过便携版（不生成 `*-windows-x64-portable.zip`）**，除非用户明确要求；便携版由 CI（`.github/workflows/windows.yml`）按需产出

## 提交纪律

- 一个主题一个提交；提交前 `git diff --stat` 自查，不改无关文件
- 提交信息用中文 + conventional 前缀（feat/fix/chore，与 git log 历史一致）
- push 需用户明确要求；push 走 127.0.0.1:9980 代理
