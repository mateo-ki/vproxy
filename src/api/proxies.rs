use crate::api::AppState;
use crate::models::Node;
use crate::proxy::ProxyState;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// 全局探针最大在途真实内核实例上限，防止突发大并发打爆系统端口/内存
static KERNEL_PROBE_SEMAPHORE: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(32));

/// `/proxies/:name/delay` 查询参数，严格对齐 Clash / Mihomo / Sing-box 标准
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProxyDelayQuery {
    /// 测速探测目标 URL，默认优先使用设置配置，兜底使用 Cloudflare / Google 204
    pub url: Option<String>,
    /// 超时时间（毫秒），默认 5000ms，自动夹紧在 200ms ~ 30000ms
    pub timeout: Option<u64>,
    /// 期望返回的状态码（默认 204 或 200）
    pub expected: Option<u16>,
    /// 探测模式：`auto`（默认智能多阶）、`real`（真实 HTTP 204 连接）、`tcp`（极致高并发 TCP Ping）
    pub mode: Option<String>,
}

/// 批量测速请求体（借鉴 v2rayN 批量机制与 FlClash 前端）
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BatchProxyDelayRequest {
    pub names: Vec<String>,
    pub url: Option<String>,
    pub timeout: Option<u64>,
    pub expected: Option<u16>,
    pub mode: Option<String>,
}

/// CORS 预检处理（方便本地 Yacd / Metacubexd / Clash Verge / FlClash 等直接跨域访问）
pub async fn cors_preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
            (
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type, *",
            ),
            (header::ACCESS_CONTROL_MAX_AGE, "86400"),
        ],
    )
        .into_response()
}

pub(crate) fn with_cors(res: Response) -> Response {
    let mut res = res;
    let headers = res.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization, Content-Type, *"),
    );
    res
}

/// 将内部协议标识转为标准 Clash 协议大写名称
pub fn clash_protocol_type(protocol: &str) -> &'static str {
    match protocol.to_ascii_lowercase().as_str() {
        "ss" | "shadowsocks" => "Shadowsocks",
        "ssr" | "shadowsocksr" => "ShadowsocksR",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "hysteria" | "hy" => "Hysteria",
        "hysteria2" | "hy2" => "Hysteria2",
        "tuic" => "Tuic",
        "wireguard" | "wg" => "WireGuard",
        "snell" => "Snell",
        "socks" | "socks5" => "Socks5",
        "http" | "https" => "Http",
        "ssh" => "SSH",
        "mieru" => "Mieru",
        "naive" | "naiveproxy" => "Naive",
        "tailscale" => "Tailscale",
        "shadowtls" => "ShadowTLS",
        "vpcore" => "VpCore",
        _ => "Unknown",
    }
}

/// `GET /proxies`：返回当前库中所有节点及虚拟策略组（完全兼容 Mihomo / Clash API）
pub async fn get_proxies(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let nodes = st
        .db
        .load_all_node_summaries()
        .await
        .map(|arc| arc.as_ref().clone())
        .unwrap_or_default();
    let mut map = serde_json::Map::new();

    // 1. 内置 DIRECT 策略
    map.insert(
        "DIRECT".into(),
        json!({
            "name": "DIRECT",
            "type": "Direct",
            "udp": true,
            "history": []
        }),
    );

    // 2. 内置 REJECT 策略
    map.insert(
        "REJECT".into(),
        json!({
            "name": "REJECT",
            "type": "Reject",
            "udp": true,
            "history": []
        }),
    );

    let active_node = st.proxy_manager.current_node().await;
    let active_name = active_node
        .as_ref()
        .map(|n| n.name.clone())
        .unwrap_or_else(|| "DIRECT".to_string());

    let all_names: Vec<String> = std::iter::once("DIRECT".to_string())
        .chain(nodes.iter().map(|n| n.name.clone()))
        .collect();

    // 3. GLOBAL 与 PROXY 选择组
    map.insert(
        "GLOBAL".into(),
        json!({
            "name": "GLOBAL",
            "type": "Selector",
            "now": active_name,
            "all": all_names,
            "history": []
        }),
    );

    map.insert(
        "PROXY".into(),
        json!({
            "name": "PROXY",
            "type": "Selector",
            "now": active_name,
            "all": all_names,
            "history": []
        }),
    );

    // 4. 用户节点列表
    for node in nodes {
        let mut history = Vec::new();
        if let Some(delay) = node.latency_ms {
            let time_str = node
                .latency_tested_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            history.push(json!({
                "time": time_str,
                "delay": delay
            }));
        }

        let proto_type = clash_protocol_type(&node.protocol);
        map.insert(
            node.name.clone(),
            json!({
                "id": node.id,
                "name": node.name,
                "type": proto_type,
                "server": node.server,
                "port": node.port,
                "udp": true,
                "xudp": true,
                "alive": node.latency_ok.unwrap_or(false),
                "history": history
            }),
        );
    }

    with_cors(Json(json!({ "proxies": map })).into_response())
}

/// `GET /proxies/{name}`：获取单节点信息
pub async fn get_proxy_detail(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let name = decoded.trim();

    if name.eq_ignore_ascii_case("DIRECT") {
        return with_cors(
            Json(json!({
                "name": "DIRECT",
                "type": "Direct",
                "udp": true,
                "history": []
            }))
            .into_response(),
        );
    }
    if name.eq_ignore_ascii_case("REJECT") {
        return with_cors(
            Json(json!({
                "name": "REJECT",
                "type": "Reject",
                "udp": true,
                "history": []
            }))
            .into_response(),
        );
    }

    let node = match st.db.find_node_by_name(name).await {
        Ok(Some(n)) => Some(n),
        _ => st.db.get_node(name).await.ok().flatten(),
    };

    let Some(node) = node else {
        return with_cors(
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "message": "proxy not found" })),
            )
                .into_response(),
        );
    };

    let mut history = Vec::new();
    if let Some(delay) = node.latency_ms {
        let time_str = node
            .latency_tested_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        history.push(json!({
            "time": time_str,
            "delay": delay
        }));
    }

    with_cors(
        Json(json!({
            "id": node.id,
            "name": node.name,
            "type": clash_protocol_type(&node.protocol),
            "server": node.server,
            "port": node.port,
            "udp": true,
            "xudp": true,
            "alive": node.latency_ok.unwrap_or(false),
            "history": history
        }))
        .into_response(),
    )
}

/// `GET /proxies/{name}/delay`：标准 Clash / Mihomo / Sing-box 高并发 RESTful 探针
pub async fn get_proxy_delay(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<ProxyDelayQuery>,
) -> impl IntoResponse {
    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let name = decoded.trim().to_string();

    match probe_proxy_delay_inner(&st, &name, query).await {
        Ok(delay) => with_cors(Json(json!({ "delay": delay })).into_response()),
        Err((code, msg)) => with_cors((code, Json(json!({ "message": msg }))).into_response()),
    }
}

/// `POST /proxies/delay`：高并发批量 RESTful 探针（限制最大并发窗口，避免突发耗尽系统句柄）
pub async fn batch_proxy_delay(
    State(st): State<Arc<AppState>>,
    Json(body): Json<BatchProxyDelayRequest>,
) -> impl IntoResponse {
    const MAX_BATCH_CONCURRENCY: usize = 64;
    let concurrency = Arc::new(tokio::sync::Semaphore::new(MAX_BATCH_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for name in body.names {
        let st = st.clone();
        let concurrency = concurrency.clone();
        let query = ProxyDelayQuery {
            url: body.url.clone(),
            timeout: body.timeout,
            expected: body.expected,
            mode: body.mode.clone(),
        };
        tasks.spawn(async move {
            let Ok(_permit) = concurrency.acquire_owned().await else {
                return (
                    name,
                    Err((StatusCode::SERVICE_UNAVAILABLE, "探针并发队列已关闭".into())),
                );
            };
            let res = probe_proxy_delay_inner(&st, &name, query).await;
            (name, res)
        });
    }

    let mut results = serde_json::Map::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok((name, outcome)) = res {
            match outcome {
                Ok(delay) => {
                    results.insert(name, json!({ "delay": delay }));
                }
                Err((_code, msg)) => {
                    results.insert(name, json!({ "message": msg }));
                }
            }
        }
    }

    with_cors(Json(json!({ "results": results })).into_response())
}

async fn probe_proxy_delay_inner(
    st: &AppState,
    name: &str,
    query: ProxyDelayQuery,
) -> Result<i64, (StatusCode, String)> {
    let timeout_ms = query.timeout.unwrap_or(5000).clamp(200, 30000);
    let timeout_dur = Duration::from_millis(timeout_ms);

    let settings = st.db.get_settings().await.unwrap_or_default();
    let test_url = query
        .url
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| {
            if !settings.speedtest_url.is_empty() {
                settings.speedtest_url.clone()
            } else {
                crate::proxy_probe::PROXY_CONNECTIVITY_TEST_URL.to_string()
            }
        });

    let mode = query
        .mode
        .as_deref()
        .unwrap_or(if settings.speedtest_tcp_ping_only {
            "tcp"
        } else {
            "auto"
        });

    // 1. 特殊策略处理
    if name.eq_ignore_ascii_case("DIRECT") {
        return probe_direct_target(&test_url, timeout_dur, query.expected.unwrap_or(204)).await;
    }
    if name.eq_ignore_ascii_case("REJECT") {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "proxy is REJECT".into()));
    }
    if name.eq_ignore_ascii_case("GLOBAL") || name.eq_ignore_ascii_case("PROXY") {
        if let Some(active_node) = st.proxy_manager.current_node().await {
            return probe_node_delay_multistage(st, &active_node, &test_url, timeout_dur, mode)
                .await;
        } else {
            return probe_direct_target(&test_url, timeout_dur, query.expected.unwrap_or(204))
                .await;
        }
    }

    // 2. 节点检索（优先按名称精确检索，次按 ID 匹配）
    let node = match st.db.find_node_by_name(name).await {
        Ok(Some(n)) => Some(n),
        _ => st.db.get_node(name).await.ok().flatten(),
    };

    let Some(node) = node else {
        return Err((StatusCode::NOT_FOUND, "proxy not found".into()));
    };

    // 3. 执行多阶高并发探活
    probe_node_delay_multistage(st, &node, &test_url, timeout_dur, mode).await
}

/// 直接探测目标直连延迟（DIRECT 策略）
async fn probe_direct_target(
    url: &str,
    timeout_dur: Duration,
    expected_status: u16,
) -> Result<i64, (StatusCode, String)> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout_dur)
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let started = std::time::Instant::now();
    match client.get(url).send().await {
        Ok(r) if r.status().is_success() || r.status().as_u16() == expected_status => {
            Ok(started.elapsed().as_millis().max(1) as i64)
        }
        Ok(r) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("HTTP {}", r.status()),
        )),
        Err(e) if e.is_timeout() => Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// 多阶高并发探针执行器（融合各家内核与客户端长处）：
/// 1. 若显式指定 tcp 或配置为 tcp_ping_only：走超轻量 TCP 握手 Ping（v2rayN Tcping 模型，万级 QPS，<30ms）
/// 2. 若代理引擎正在运行且已包含该节点：直接复用运行中控制器 /proxies/:name/delay（Mihomo / Singbox 原生热路径，0 开销）
/// 3. 若为 HTTP / SOCKS5 协议：纯 Rust 异步直连探针（0 额外进程，极速返回）
/// 4. 其余复杂代理协议（VMess / VLESS / Trojan / Hysteria2 等）：
///    - 先做快速 TCP 可达性预检（预筛死节点，无需启动内核，防止进程风暴）
///    - 通过信号量限制并发后，启动单节点探针执行真实 HTTP 204 探活（带暖连接与 Cloudflare 备用 URL 双保险）
///    - 若运行环境缺失二进制，自动优雅降级为 TCP 延迟保证可用性
async fn probe_node_delay_multistage(
    st: &AppState,
    node: &Node,
    test_url: &str,
    timeout_dur: Duration,
    mode: &str,
) -> Result<i64, (StatusCode, String)> {
    // 阶 1: 纯 TCP Ping
    if mode == "tcp" {
        return run_tcp_ping(st, node, timeout_dur).await;
    }

    // 阶 2: 运行中内核控制器热委托
    if st.proxy_manager.status().await.state == ProxyState::Running {
        let (ctrl_port, secret) = {
            let cfg = st.proxy_manager.config().await;
            (cfg.controller_port, cfg.controller_secret)
        };
        if ctrl_port > 0 {
            let encoded_name = utf8_percent_encode(&node.name, NON_ALPHANUMERIC).to_string();
            let target_encoded = utf8_percent_encode(test_url, NON_ALPHANUMERIC).to_string();
            let timeout_ms = timeout_dur.as_millis().clamp(500, 30000);
            let url = format!(
                "http://127.0.0.1:{ctrl_port}/proxies/{encoded_name}/delay?timeout={timeout_ms}&url={target_encoded}"
            );
            if let Ok(client) = reqwest::Client::builder()
                .no_proxy()
                .timeout(timeout_dur + Duration::from_millis(500))
                .build()
            {
                if let Ok(resp) = crate::proxy::with_controller_auth(client.get(&url), &secret)
                    .send()
                    .await
                {
                    if resp.status().is_success() {
                        if let Ok(val) = resp.json::<Value>().await {
                            if let Some(delay) = val.get("delay").and_then(|d| d.as_i64()) {
                                record_delay_async(st, &node.id, true, delay, "controller");
                                return Ok(delay);
                            }
                        }
                    } else if resp.status() == reqwest::StatusCode::GATEWAY_TIMEOUT {
                        record_delay_async(st, &node.id, false, 0, "controller");
                        return Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into()));
                    }
                }
            }
        }
    }

    // 阶 3: 无认证/非 TLS 的 HTTP / SOCKS 明文直通探活
    let proto = node.protocol.to_ascii_lowercase();
    if can_use_direct_proxy_probe(node) {
        return run_direct_proxy_probe(st, node, test_url, timeout_dur).await;
    }

    // 阶 4: 复杂协议（先 TCP 预检，再信号量受控内核探针）
    let is_udp_only = matches!(
        proto.as_str(),
        "wireguard" | "wg" | "tuic" | "hysteria2" | "hy2" | "hysteria" | "hy"
    );
    if !is_udp_only {
        let preflight_timeout = timeout_dur.min(Duration::from_millis(1500));
        if let Err(err) = check_tcp_reachability(&node.server, node.port, preflight_timeout).await {
            record_delay_async(st, &node.id, false, 0, "tcp_preflight");
            if err.contains("超时") || err.contains("Timeout") {
                return Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into()));
            } else {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, err));
            }
        }
    }

    run_kernel_proxy_probe(st, node, test_url, timeout_dur, mode).await
}

fn can_use_direct_proxy_probe(node: &Node) -> bool {
    let proto = node.protocol.to_ascii_lowercase();
    if proto != "http" && proto != "socks5" && proto != "socks" {
        return false;
    }
    let has_tls = node.config.get("tls").and_then(|v| v.as_bool()) == Some(true)
        || node
            .config
            .get("security")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("tls"));
    if has_tls {
        return false;
    }
    let has_auth = node
        .config
        .get("username")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
        || node
            .config
            .get("password")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
    !has_auth
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn run_direct_proxy_probe(
    st: &AppState,
    node: &Node,
    test_url: &str,
    timeout_dur: Duration,
) -> Result<i64, (StatusCode, String)> {
    let scheme = if node.protocol.eq_ignore_ascii_case("http") {
        "http"
    } else {
        "socks5h"
    };
    let host_port = format_host_port(&node.server, node.port);
    let proxy_url = format!("{scheme}://{host_port}");
    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout_dur)
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match crate::proxy_probe::probe_http_proxy_unified_delay(&client, Some(test_url)).await {
        Ok((delay_ms, _target)) => {
            record_delay_async(st, &node.id, true, delay_ms, "direct_proxy");
            Ok(delay_ms)
        }
        Err(err) => {
            record_delay_async(st, &node.id, false, 0, "direct_proxy");
            if crate::proxy_probe::is_connection_failure(&err) {
                Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, err))
            }
        }
    }
}

async fn run_kernel_proxy_probe(
    st: &AppState,
    node: &Node,
    test_url: &str,
    timeout_dur: Duration,
    mode: &str,
) -> Result<i64, (StatusCode, String)> {
    let _permit = KERNEL_PROBE_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "探针并发达到上限".into()))?;

    match crate::proxy_probe::spawn_single_node_probe_proxy(node).await {
        Ok(runner) => {
            let proxy_url = format!("http://127.0.0.1:{}", runner.mixed_port);
            let client = match reqwest::Proxy::all(&proxy_url) {
                Ok(proxy) => reqwest::Client::builder()
                    .proxy(proxy)
                    .timeout(timeout_dur)
                    .build()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
                Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            };

            let outcome =
                crate::proxy_probe::probe_http_proxy_unified_delay(&client, Some(test_url)).await;
            drop(runner);

            match outcome {
                Ok((delay_ms, _target)) => {
                    record_delay_async(st, &node.id, true, delay_ms, "mihomo_probe");
                    Ok(delay_ms)
                }
                Err(err) => {
                    record_delay_async(st, &node.id, false, 0, "mihomo_probe");
                    if crate::proxy_probe::is_connection_failure(&err) {
                        Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into()))
                    } else {
                        Err((StatusCode::INTERNAL_SERVER_ERROR, err))
                    }
                }
            }
        }
        Err(e) => {
            let err_text = e.to_string();
            // 仅在 auto 模式下且属于缺少内核可执行文件时允许降级为 TCP 握手；
            // real 模式或节点配置自身错误绝不静默伪装成连通成功
            if mode != "real" && err_text.contains("未找到") {
                tracing::warn!(node_id = %node.id, %e, "单节点探针内核未安装，auto 模式降级至 TCP Ping");
                run_tcp_ping(st, node, timeout_dur).await
            } else {
                tracing::warn!(node_id = %node.id, %e, "单节点探针内核启动失败");
                record_delay_async(st, &node.id, false, 0, "mihomo_probe");
                Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("探针启动失败: {e}"),
                ))
            }
        }
    }
}

async fn run_tcp_ping(
    st: &AppState,
    node: &Node,
    timeout_dur: Duration,
) -> Result<i64, (StatusCode, String)> {
    match check_tcp_reachability(&node.server, node.port, timeout_dur).await {
        Ok(ms) => {
            record_delay_async(st, &node.id, true, ms, "tcp_ping");
            Ok(ms)
        }
        Err(err) => {
            record_delay_async(st, &node.id, false, 0, "tcp_ping");
            if err.contains("超时") || err.contains("Timeout") {
                Err((StatusCode::GATEWAY_TIMEOUT, "Timeout".into()))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, err))
            }
        }
    }
}

async fn check_tcp_reachability(
    host: &str,
    port: u16,
    timeout_dur: Duration,
) -> Result<i64, String> {
    let addrs = match tokio::net::lookup_host((host, port)).await {
        Ok(iter) => iter.collect::<Vec<_>>(),
        Err(e) => return Err(format!("DNS 解析失败: {e}")),
    };
    let Some(&addr) = addrs.first() else {
        return Err("DNS 解析未返回有效地址".into());
    };
    let started = std::time::Instant::now();
    match tokio::time::timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Ok(started.elapsed().as_millis().max(1) as i64),
        Ok(Err(e)) => Err(format!("连接拒绝: {e}")),
        Err(_) => Err("连接超时".into()),
    }
}

fn record_delay_async(st: &AppState, node_id: &str, ok: bool, delay_ms: i64, kind: &'static str) {
    let db = st.db.clone();
    let id = node_id.to_string();
    tokio::spawn(async move {
        let latency = if ok { Some(delay_ms) } else { None };
        let _ = db
            .update_node_speed(&id, ok, latency, None, Some(kind), Some("delay_probe"))
            .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_clash_protocol_mappings() {
        assert_eq!(clash_protocol_type("ss"), "Shadowsocks");
        assert_eq!(clash_protocol_type("SHADOWSOCKS"), "Shadowsocks");
        assert_eq!(clash_protocol_type("vmess"), "Vmess");
        assert_eq!(clash_protocol_type("vless"), "Vless");
        assert_eq!(clash_protocol_type("trojan"), "Trojan");
        assert_eq!(clash_protocol_type("hysteria2"), "Hysteria2");
        assert_eq!(clash_protocol_type("hy2"), "Hysteria2");
        assert_eq!(clash_protocol_type("tuic"), "Tuic");
        assert_eq!(clash_protocol_type("wireguard"), "WireGuard");
        assert_eq!(clash_protocol_type("socks5"), "Socks5");
        assert_eq!(clash_protocol_type("http"), "Http");
        assert_eq!(clash_protocol_type("unknown-xyz"), "Unknown");
    }

    #[tokio::test]
    async fn test_cors_preflight_headers() {
        let resp = cors_preflight().await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            "GET, POST, OPTIONS"
        );
    }

    #[tokio::test]
    async fn test_tcp_reachability_measurement() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // 成功连接到监听端口
        let ms = check_tcp_reachability("127.0.0.1", port, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(ms > 0 && ms < 1000);

        drop(listener);

        // 端口关闭后连接应立即拒绝
        // 端口关闭后连接应立即拒绝或超时
        let err = check_tcp_reachability("127.0.0.1", port, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(
            err.contains("连接")
                || err.contains("超时")
                || err.contains("拒绝")
                || err.contains("10061")
        );
    }

    #[tokio::test]
    async fn test_direct_target_probe_success_and_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });

        let url = format!("http://127.0.0.1:{port}/generate_204");
        let delay = probe_direct_target(&url, Duration::from_secs(2), 204)
            .await
            .unwrap();
        assert!(delay > 0);

        // 超时测试
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = dead_listener.accept().await {
                tokio::time::sleep(Duration::from_millis(800)).await;
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
            }
        });

        let dead_url = format!("http://127.0.0.1:{dead_port}/timeout");
        let err = probe_direct_target(&dead_url, Duration::from_millis(200), 204)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(err.1, "Timeout");
    }

    #[test]
    fn test_direct_proxy_probe_eligibility_and_ipv6_formatting() {
        assert_eq!(format_host_port("1.2.3.4", 8080), "1.2.3.4:8080");
        assert_eq!(format_host_port("2001:db8::1", 1080), "[2001:db8::1]:1080");
        assert_eq!(
            format_host_port("[2001:db8::1]", 1080),
            "[2001:db8::1]:1080"
        );

        let now = chrono::Utc::now();
        let make_node = |protocol: &str, config: Value| Node {
            id: "id".into(),
            source_id: None,
            protocol: protocol.into(),
            name: "test".into(),
            server: "1.2.3.4".into(),
            port: 1080,
            raw: String::new(),
            config,
            country: None,
            latency_ms: None,
            latency_ok: None,
            download_kbps: None,
            latency_kernel: None,
            latency_test_kind: None,
            latency_tested_at: None,
            created_at: now,
            updated_at: now,
        };

        assert!(can_use_direct_proxy_probe(&make_node("http", json!({}))));
        assert!(can_use_direct_proxy_probe(&make_node("socks5", json!({}))));
        assert!(!can_use_direct_proxy_probe(&make_node(
            "http",
            json!({ "tls": true })
        )));
        assert!(!can_use_direct_proxy_probe(&make_node(
            "socks5",
            json!({ "username": "u", "password": "p" })
        )));
        assert!(!can_use_direct_proxy_probe(&make_node("vless", json!({}))));
    }
}
