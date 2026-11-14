# VProxy 架构与内核选路

> 本文描述**当前现状**，是架构与协议支持口径的唯一事实源。历史设计决策见根目录 `design.md` / `requirements.md` / `tasks.md`（仅作决策日志，不再维护为现状描述）。
>
> 更新约定：行为变更（新增协议、内核选路规则、编译器能力）时同步更新本文与两份 README 的协议矩阵。

## 1. 总览

VProxy 是 Rust + egui 的桌面代理工作站：采集订阅 → 解析节点 → 编译为各内核配置 → 驱动内核常驻运行 → 实测可用性与延迟。

配套内核仓库 **VP-Core**（`D:\project\rust\VP_Core`，独立发版）是纯 Rust 实现的全协议内核，VProxy 将其作为一等内核驱动，并承担其配置编译（VP-DSL）与节点解析的前置工作。

```
订阅源 / 分享链接
      │  src/parser（URI / Clash YAML / Base64 / 混合文本）
      ▼
节点库（data/subscriptions/*.db）
      │  src/proxy/compiler/<kernel>（按内核编译）
      ▼
Mihomo YAML │ sing-box JSON │ Xray JSON │ VP-Core DSL(.vp) │ Shoes / Meow 配置
      │
      ▼
内核常驻进程（src/proxy 进程管理 + src/system_proxy + TUN 提权）
```

## 2. 模块地图

| 模块 | 职责 |
| :--- | :--- |
| `src/parser` | 分享链接与订阅正文解析（URI scheme 见 §3）；Clash YAML、Base64、混合文本 |
| `src/export` | 节点 → Clash 代理 JSON / 分享链接（含各协议 URI 重建） |
| `src/kernel` | 内核资产管理、版本检测、更新器、**内核选路**（§5） |
| `src/proxy/compiler` | 每内核一个编译器：`mihomo` / `sing_box` / `xray` / `vp_core`（VP-DSL）/ `shoes` / `meow` |
| `src/proxy/ir` | 内核无关的编译中间层（RoutingPlan / OutboundKind / TransportSpec） |
| `src/proxy` | 进程生命周期、端口就绪检测、降级状态、系统代理会话 |
| `src/speedtest` | TCP 预筛 + 内核真实握手测速 + 可选吞吐探测 |
| `src/gui`、`src/api` | egui 界面（多语言、多主题）与本地 HTTP API（bearer 鉴权） |
| `src/db` | 主库 `vproxy.db` + 按源分片的 `data/subscriptions/*.db` |

## 3. 协议支持矩阵

解析与连接能力以代码为准：解析 scheme 注册在 `src/parser/common.rs`；各内核白名单在 `src/kernel/mod.rs` 的 `supports_proxy_protocol`。

**解析**：`ss` `ssr` `vmess` `vless` `trojan` `hysteria` `hysteria2/hy2` `tuic` `wireguard/wg` `socks5` `http(s)` `masque` `snell` `naive(+https/+quic)` `mieru` `ssh` `tailscale` `juicity` `shadowtls`，以及 Clash/Clash Meta YAML、Base64、混合文本。

| 内核 | 可运行协议 |
| :--- | :--- |
| VP-Core | `ss` `ssr` `vmess` `vless` `trojan` `snell` `hysteria2` `tuic` `juicity` `anytls` `mieru` `naive` `ssh` `brook` `wireguard` `masque` `http(s)` `socks5` |
| Mihomo | `ss` `ssr` `vmess` `vless` `trojan` `hysteria` `hysteria2` `tuic` `anytls` `snell` `mieru` `wireguard` `masque` `http(s)` `socks5` |
| sing-box | `ss` `vmess` `vless` `trojan` `hysteria2` `tuic` `anytls` `ssh` `wireguard` `http(s)` `socks5` |
| Xray | `ss` `vmess` `vless` `trojan` `http(s)` `socks5` |
| Shoes | `ss` `vmess` `vless` `trojan` `snell` `anytls` `naive` `wireguard` `http(s)` `socks5` |
| Meow | `ss` `vmess` `vless` `trojan` `hysteria2` `snell` `anytls` `http(s)` `socks5` |

备注：

- `tailscale` 目前只解析入库，尚无内核可运行，界面会标注。
- VP-Core 另有 Hysteria 1 原生出站，但自动选路优先交给 Mihomo。
- sing-box 自 1.12 移除了 juicity 出站，mihomo 从未支持过 juicity，故 juicity 只有 VP-Core 一条路。

## 4. 编译器要点

- **vp_core**：产出 VP-DSL（`.vp`）。类型白名单之外一律剔除并同步修剪 proxy-groups 引用；`raw` 网络归一为 `tcp`；重名 serde alias（`sni` / `skip-cert-verify` / `congestion-*`）归一，防止 VP-Core 解析 duplicate-field 报错；websocket 头补 UA、剥离 ECH。
- **sing_box**：SS+ShadowTLS 合并节点导出为 `shadowtls` endpoint + `detour`（sing-box 1.11+ 形态）。
- **mihomo**：SS+ShadowTLS 合并节点直通（`plugin: shadow-tls` 形态）。
- **xray**：仅系统代理模式参与，TUN 下自动跳过。

## 5. 内核选路规则（`src/kernel/mod.rs`）

自动选路（Auto 偏好）顺序：

1. **协议级偏好** `preferred_proxy_kernel`：
   `snell → Shoes`；`ssh → SingBox`；`naive → VP-Core`；`juicity → VP-Core`（专属）；`hysteria2/hy2/tuic/anytls/wireguard → SingBox`；其余落在白名单内的协议 → Mihomo。
2. 偏好内核未安装时按 `Mihomo ↔ SingBox` 回退，仍不可用再兜底 `VP-Core → Meow → Shoes → Xray`。
3. **传输层修正**：节点传输层为 `xhttp/splithttp` 时（仅 VP-Core 支持），无论上一步选中谁，均升级到 VP-Core（可用时），并在通知中说明。
4. **兼容性护栏**：Meow 排除 `xhttp/splithttp`、`grpc`、ECH、WireGuard/TUIC/SSR/MASQUE；VP-Core 仅排除 `mkcp/kcp`；命中时平滑回退并保留通知。
5. 手动点名内核时遵循同一套协议支持与兼容性检查；不支持则明确回退或报错，不静默丢弃。

## 6. VP-Core 原生栈速览

- **认证同源**：TUIC v5 与 Juicity 共用「TLS exporter token + uni 流认证」骨架（`vp-protocol/src/{tuic,juicity}.rs`），Juicity 用 `VER=0x00` 且保留认证流以承载 UnderlayAuth。
- **传输层**（vless/vmess/trojan 共用）：`ws`（含 0-RTT、v2ray-http-upgrade）、`grpc`、`h2`、`httpupgrade`（101 后裸流）、`xhttp/splithttp`（packet-up/stream-up/stream-one）、ShadowTLS v3 外层、REALITY、ECH。
- **QUIC 族**：Hysteria 1/2、TUIC v5、Juicity 共用 quinn 客户端基建（Happy Eyeballs、Token 导出、证书钉扎、PacketConn）。

## 7. 文档索引

| 文档 | 内容 |
| :--- | :--- |
| [README.md](../README.md) / [README.en.md](../README.en.md) | 项目功能、协议矩阵、安装打包 |
| [RELEASE_NOTES.md](../RELEASE_NOTES.md) | 版本发布记录 |
| [docs/openwrt.md](openwrt.md) | OpenWrt .ipk + LuCI 部署 |
| [docs/macos-tun.md](macos-tun.md) | macOS Mihomo TUN 提权服务 |
| `design.md` / `requirements.md` / `tasks.md`（根目录） | 历史设计决策日志与阶段清单（已交付，仅存档） |
| `docs/superpowers/` | 2026-07 阶段性 plans/specs 存档 |
