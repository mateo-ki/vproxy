use crate::export::nodes_to_clash_proxies;
use crate::kernel::find_mihomo_executable;
use crate::models::Node;
use anyhow::{anyhow, Context, Result};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

pub use crate::constants::network::{PROXY_CONNECTIVITY_FALLBACK_URL, PROXY_CONNECTIVITY_TEST_URL};
/// Concurrent delay probes through the single shared Mihomo instance. Each probe is a
/// TLS request to generate_204 through a real proxy. Kept moderate: too many concurrent
/// real-proxy connections saturate consumer NICs/routers.
const PROXY_CONCURRENCY: usize = 96;
const MIHOMO_BATCH_CONCURRENCY: usize = 2;
/// Concurrent `mihomo -t` config validations while isolating invalid proxies.
const VALIDATE_CONCURRENCY: usize = 8;

#[derive(Debug, Clone)]
pub struct ProxyProbeResult {
    pub id: String,
    pub ok: bool,
    pub latency_ms: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ProxyProbeProgress {
    pub done: usize,
    pub total: usize,
    pub ok: usize,
    pub fail: usize,
    pub elapsed: Duration,
    pub batch_index: Option<usize>,
    pub batch_total: Option<usize>,
}

#[derive(Clone)]
struct PreparedProxy {
    index: usize,
    id: String,
    name: String,
    config: Value,
}

/// 「常驻内核」打开时一批装下的节点数：一个内核实例装下整轮候选，只付一次冷启动。
pub const PERSISTENT_MIHOMO_BATCH_SIZE: usize = 8192;

pub async fn verify_nodes_with_mihomo_progress_limited(
    nodes: Vec<Node>,
    timeout: Duration,
    progress: Option<impl Fn(ProxyProbeProgress) + Send + Sync>,
    network_limit: Arc<Semaphore>,
    batch_size: usize,
    conditional_isolation: bool,
    test_url: Option<String>,
) -> Result<Vec<ProxyProbeResult>> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let mihomo = find_mihomo_executable().ok_or_else(|| {
        anyhow!("未找到 mihomo.exe；请设置 MIHOMO_PATH，或将 Mihomo 放到 bin/mihomo/mihomo.exe")
    })?;
    let total = nodes.len();
    let started = tokio::time::Instant::now();
    let batches = nodes
        .chunks(batch_size.max(1))
        .map(|batch| batch.to_vec())
        .collect::<Vec<_>>();
    let batch_total = batches.len();
    let mut batches = batches.into_iter();
    let mut tasks = JoinSet::new();
    let mut results = Vec::with_capacity(total);
    let batch_concurrency = if network_limit.available_permits() <= 32 {
        1
    } else {
        MIHOMO_BATCH_CONCURRENCY
    };
    let mut completed_batches = 0usize;
    loop {
        while tasks.len() < batch_concurrency {
            let Some(batch) = batches.next() else { break };
            let ids = batch.iter().map(|node| node.id.clone()).collect::<Vec<_>>();
            let mihomo = mihomo.clone();
            let network_limit = network_limit.clone();
            let test_url = test_url.clone();
            tasks.spawn(async move {
                let outcome = verify_nodes_with_mihomo_path(
                    batch,
                    timeout,
                    &mihomo,
                    None::<fn(ProxyProbeProgress)>,
                    network_limit,
                    conditional_isolation,
                    test_url,
                )
                .await;
                (ids, outcome)
            });
        }
        let Some(joined) = tasks.join_next().await else {
            break;
        };
        let (ids, outcome) = joined.map_err(|error| anyhow!("Mihomo 测速批次失败: {error}"))?;
        match outcome {
            Ok(mut batch_results) => results.append(&mut batch_results),
            Err(error) => results.extend(ids.into_iter().map(|id| ProxyProbeResult {
                id,
                ok: false,
                latency_ms: None,
                message: format!("Mihomo 测速批次失败: {error}"),
            })),
        }
        completed_batches += 1;
        if let Some(progress) = progress.as_ref() {
            let ok = results.iter().filter(|result| result.ok).count();
            progress(ProxyProbeProgress {
                done: results.len(),
                total,
                ok,
                fail: results.len().saturating_sub(ok),
                elapsed: started.elapsed(),
                batch_index: Some(completed_batches),
                batch_total: Some(batch_total),
            });
        }
    }
    Ok(results)
}

async fn verify_nodes_with_mihomo_path(
    nodes: Vec<Node>,
    timeout: Duration,
    mihomo: &Path,
    progress: Option<impl Fn(ProxyProbeProgress) + Send + Sync>,
    network_limit: Arc<Semaphore>,
    conditional_isolation: bool,
    test_url: Option<String>,
) -> Result<Vec<ProxyProbeResult>> {
    let total = nodes.len();
    let started = tokio::time::Instant::now();
    let (prepared, mut results) = prepare_proxies(&nodes);
    report_proxy_progress(&progress, &results, total, started.elapsed());
    if prepared.is_empty() {
        return Ok(results.into_iter().flatten().collect());
    }

    let work_dir = std::env::temp_dir().join(format!("vproxy-mihomo-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&work_dir).await?;
    // 默认先对整批配置做 `mihomo -t` 二分隔离；开启「条件隔离」后先直接测，
    // 只把失败的节点送去二分隔离，省掉一整轮配置验证。
    let (prepared, rejected) = if conditional_isolation {
        (prepared, Vec::new())
    } else {
        isolate_invalid_proxies(prepared, mihomo, &work_dir).await?
    };
    for (proxy, reason) in rejected {
        results[proxy.index] = Some(ProxyProbeResult {
            id: proxy.id,
            ok: false,
            latency_ms: None,
            message: format!("Mihomo 配置不支持: {reason}"),
        });
    }
    report_proxy_progress(&progress, &results, total, started.elapsed());
    if prepared.is_empty() {
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        return Ok(results.into_iter().flatten().collect());
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let controller_port = listener.local_addr()?.port();
    drop(listener);

    // 增量计数：每完成一个探针就把 results 全量扫两遍的话，8192 的批次要迭代
    // 一千三百万次，进度回调节本身就把测速拖平了。
    let mut done_count = results.iter().filter(|slot| slot.is_some()).count();
    let mut ok_count = results
        .iter()
        .filter(|slot| slot.as_ref().is_some_and(|result| result.ok))
        .count();

    let config = build_mihomo_config(&prepared, controller_port);
    let config_path = work_dir.join("config.yaml");
    tokio::fs::write(&config_path, serde_yaml::to_string(&config)?).await?;
    let startup_log = work_dir.join("startup.log");
    let log_file = std::fs::File::create(&startup_log)?;
    // Mihomo writes its logs to stdout; capture both streams or startup errors vanish
    // and the diagnostic degrades to a useless "未知配置错误".
    let log_stdout = log_file.try_clone()?;

    let mut command = Command::new(mihomo);
    command
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .arg("-d")
        .arg(&work_dir)
        .arg("-f")
        .arg(&config_path)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_stdout))
        .stderr(Stdio::from(log_file));
    #[cfg(windows)]
    {
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("启动 {} 失败", mihomo.display()))?;
    if let Some(pid) = child.id() {
        crate::platform::assign_child_process_id(pid);
    }

    // Loading thousands of proxies into one instance can take well over 5s; scale the
    // controller wait with the proxy count so big sets are not misreported as failures.
    let startup_budget = (Duration::from_secs(8)
        + Duration::from_millis(prepared.len() as u64 * 5))
    .min(Duration::from_secs(60));
    let ready = wait_for_controller(&mut child, controller_port, startup_budget).await;
    if !ready {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let detail = tokio::fs::read_to_string(&startup_log)
            .await
            .unwrap_or_default();
        let detail = compact_diagnostic(&detail);
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        return Err(anyhow!("Mihomo 启动失败: {detail}"));
    }

    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(32)
        .connect_timeout(Duration::from_secs(2))
        .timeout(timeout + Duration::from_secs(2))
        .build()?;
    let timeout_ms = timeout.as_millis().clamp(1_000, 15_000).to_string();
    let (primary_url, fallback_url) =
        crate::constants::network::resolve_probe_urls(test_url.as_deref());
    let primary_label = probe_target_label(&primary_url, "Google");
    let fallback_label = if primary_label == "Google" {
        "Cloudflare"
    } else {
        "Google"
    };
    let prepared_all = prepared.clone();
    let mut iter = prepared.into_iter();
    let mut tasks = JoinSet::new();

    loop {
        while tasks.len() < PROXY_CONCURRENCY {
            let Some(proxy) = iter.next() else {
                break;
            };
            let client = client.clone();
            let timeout_ms = timeout_ms.clone();
            let network_limit = network_limit.clone();
            let primary_url = primary_url.clone();
            let fallback_url = fallback_url.clone();
            tasks.spawn(async move {
                let _permit = match network_limit.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        return (
                            proxy.index,
                            ProxyProbeResult {
                                id: proxy.id,
                                ok: false,
                                latency_ms: None,
                                message: "测速并发控制已关闭".into(),
                            },
                        );
                    }
                };
                let encoded = utf8_percent_encode(&proxy.name, NON_ALPHANUMERIC);
                let url = format!("http://127.0.0.1:{controller_port}/proxies/{encoded}/delay");
                let mut outcome = probe_mihomo_target(
                    &client,
                    &url,
                    timeout_ms.as_str(),
                    &primary_url,
                    primary_label,
                )
                .await;
                if outcome.is_err() && primary_url != fallback_url {
                    // 交叉探活：主目标探测失败时（无论阻断还是超时），走备用探测交叉复验
                    if let Ok(cf_res) = probe_mihomo_target(
                        &client,
                        &url,
                        timeout_ms.as_str(),
                        &fallback_url,
                        fallback_label,
                    )
                    .await
                    {
                        outcome = Ok(cf_res);
                    }
                }
                // 二次复测取最小值：P2P 型网络（URnetwork 等）首次连接含组网协商，
                // 冷路径首响应 1~2.5s、暖路径 ~0.6s——取两次最小值更贴近真实可用延迟。
                // 只对首测偏慢（>500ms，冷路径特征）的节点复测：快节点不付双倍时间，
                // 大库测速总时长基本不变。
                if let Ok((delay, target_label)) = outcome {
                    if delay > 500 {
                        let target_url = if target_label == fallback_label {
                            &fallback_url
                        } else {
                            &primary_url
                        };
                        if let Ok((second, _)) = probe_mihomo_target(
                            &client,
                            &url,
                            timeout_ms.as_str(),
                            target_url,
                            target_label,
                        )
                        .await
                        {
                            outcome = Ok((delay.min(second), target_label));
                        }
                    }
                }
                let result = match outcome {
                    Ok((delay, target)) => ProxyProbeResult {
                        id: proxy.id,
                        ok: true,
                        latency_ms: Some(delay),
                        message: format!("{delay} ms (真实代理 · {target})"),
                    },
                    Err(error) => ProxyProbeResult {
                        id: proxy.id,
                        ok: false,
                        latency_ms: None,
                        message: format!("真实代理测试失败: {error}"),
                    },
                };
                (proxy.index, result)
            });
        }

        let Some(joined) = tasks.join_next().await else {
            break;
        };
        if let Ok((index, result)) = joined {
            let was_ok = result.ok;
            results[index] = Some(result);
            done_count += 1;
            if was_ok {
                ok_count += 1;
            }
            emit_proxy_progress(&progress, done_count, ok_count, total, started.elapsed());
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;

    if conditional_isolation {
        let failed: Vec<PreparedProxy> = prepared_all
            .iter()
            .filter(|proxy| {
                results[proxy.index]
                    .as_ref()
                    .is_some_and(|result| !result.ok)
            })
            .cloned()
            .collect();
        if !failed.is_empty() {
            let (_, rejected) = isolate_invalid_proxies(failed, mihomo, &work_dir).await?;
            for (proxy, reason) in rejected {
                results[proxy.index] = Some(ProxyProbeResult {
                    id: proxy.id,
                    ok: false,
                    latency_ms: None,
                    message: format!("Mihomo 配置不支持: {reason}"),
                });
            }
        }
    }
    let _ = tokio::fs::remove_dir_all(&work_dir).await;

    if results.len() != total || results.iter().any(Option::is_none) {
        return Err(anyhow!("真实代理测试结果数量不一致"));
    }
    Ok(results.into_iter().flatten().collect())
}

async fn probe_single_http_204(
    client: &reqwest::Client,
    target_url: &str,
    target_name: &'static str,
) -> std::result::Result<i64, String> {
    let started = tokio::time::Instant::now();
    let response = client
        .get(target_url)
        .send()
        .await
        .map_err(|error| format!("{target_name}: {error}"))?;
    let status = response.status();
    let _ = response.bytes().await;
    if status == reqwest::StatusCode::NO_CONTENT {
        Ok(started.elapsed().as_millis().max(1) as i64)
    } else {
        Err(format!("{target_name}: HTTP {status}"))
    }
}

/// 经本地 HTTP 代理端口探测连通性并返回统一延迟（unified-delay 口径）：
/// 1. 主目标失败回退时独立重新计时，不把主目标的超时等待算入回退延迟；
/// 2. 首轮成功后在同一 HTTP/1.1 Keep-Alive 隧道上复测一次纯 RTT，剔除冷握手耗时，
///    使 sing-box / xray / shoes 与 Mihomo `unified-delay: true`（FlClash 默认）口径一致。
pub(crate) async fn probe_http_proxy_unified_delay(
    client: &reqwest::Client,
    test_url: Option<&str>,
) -> std::result::Result<(i64, &'static str), String> {
    let (primary, fallback) = crate::constants::network::resolve_probe_urls(test_url);
    probe_http_proxy_unified_delay_urls(client, &primary, &fallback).await
}

#[allow(dead_code)]
pub(crate) fn is_connection_failure(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("time out")
        || lower.contains("504")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("reset by peer")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("broken pipe")
        || lower.contains("eof")
        || lower.contains("proxy connection")
        || lower.contains("failed to connect")
        || lower.contains("connectex")
        || lower.contains("10060")
        || lower.contains("10061")
        || lower.contains("10054")
        || lower.contains("10065")
        || lower.contains("10051")
        || lower.contains("10053")
        || lower.contains("deadline")
}

pub(crate) fn probe_target_label(url: &str, default_if_unknown: &'static str) -> &'static str {
    let lower = url.to_ascii_lowercase();
    if lower.contains("google") || lower.contains("gstatic") {
        "Google"
    } else if lower.contains("cloudflare") || lower.contains("fallback") {
        "Cloudflare"
    } else {
        default_if_unknown
    }
}

async fn probe_http_proxy_unified_delay_urls(
    client: &reqwest::Client,
    primary_url: &str,
    fallback_url: &str,
) -> std::result::Result<(i64, &'static str), String> {
    let primary_label = probe_target_label(primary_url, "Google");
    let fallback_label = if primary_label == "Google" {
        "Cloudflare"
    } else {
        "Google"
    };
    let (first_ms, target_url, target_name) =
        match probe_single_http_204(client, primary_url, primary_label).await {
            Ok(ms) => (ms, primary_url, primary_label),
            Err(primary_err) => {
                if primary_url == fallback_url {
                    return Err(primary_err);
                }
                match probe_single_http_204(client, fallback_url, fallback_label).await {
                    Ok(ms) => (ms, fallback_url, fallback_label),
                    Err(_) => return Err(primary_err),
                }
            }
        };

    let unified_ms = match probe_single_http_204(client, target_url, target_name).await {
        Ok(warm_ms) => first_ms.min(warm_ms),
        Err(_) => first_ms,
    };
    Ok((unified_ms, target_name))
}

async fn probe_mihomo_target(
    client: &reqwest::Client,
    controller_url: &str,
    timeout_ms: &str,
    target_url: &str,
    target_name: &'static str,
) -> std::result::Result<(i64, &'static str), String> {
    let response = client
        .get(controller_url)
        .query(&[("url", target_url), ("timeout", timeout_ms)])
        .send()
        .await
        .map_err(|error| format!("{target_name}: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(format!("{target_name}: HTTP {status} {text}"));
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| format!("{target_name}: {error}"))?;
    match body.get("delay").and_then(Value::as_i64) {
        Some(delay) if delay > 0 => Ok((delay, target_name)),
        _ => Err(format!("{target_name}: 未返回有效延迟")),
    }
}

fn emit_proxy_progress(
    progress: &Option<impl Fn(ProxyProbeProgress) + Send + Sync>,
    done: usize,
    ok: usize,
    total: usize,
    elapsed: Duration,
) {
    if let Some(progress) = progress {
        progress(ProxyProbeProgress {
            done,
            total,
            ok,
            fail: done.saturating_sub(ok),
            elapsed,
            batch_index: None,
            batch_total: None,
        });
    }
}

fn report_proxy_progress(
    progress: &Option<impl Fn(ProxyProbeProgress) + Send + Sync>,
    results: &[Option<ProxyProbeResult>],
    total: usize,
    elapsed: Duration,
) {
    if let Some(progress) = progress {
        let done = results.iter().filter(|result| result.is_some()).count();
        let ok = results
            .iter()
            .filter(|result| result.as_ref().is_some_and(|result| result.ok))
            .count();
        progress(ProxyProbeProgress {
            done,
            total,
            ok,
            fail: done.saturating_sub(ok),
            elapsed,
            batch_index: None,
            batch_total: None,
        });
    }
}

fn build_mihomo_config(prepared: &[PreparedProxy], controller_port: u16) -> Value {
    let proxy_configs: Vec<_> = prepared.iter().map(|proxy| proxy.config.clone()).collect();
    let proxy_names: Vec<_> = prepared.iter().map(|proxy| proxy.name.clone()).collect();
    json!({
        "external-controller": format!("127.0.0.1:{controller_port}"),
        "secret": "",
        "allow-lan": false,
        "ipv6": false,
        "mode": "rule",
        "log-level": "warning",
        // 开启统一延迟（与 FlClash / 主流 Clash 客户端一致）：剔除协议冷握手耗时，反映真实链路 RTT
        "unified-delay": true,
        "proxies": proxy_configs,
        "proxy-groups": [{
            "name": "PROXY",
            "type": "select",
            "proxies": proxy_names
        }],
        "rules": ["MATCH,PROXY"]
    })
}

async fn isolate_invalid_proxies(
    prepared: Vec<PreparedProxy>,
    mihomo: &Path,
    work_dir: &Path,
) -> Result<(Vec<PreparedProxy>, Vec<(PreparedProxy, String)>)> {
    let mut level = vec![prepared];
    let mut valid = Vec::new();
    let mut rejected = Vec::new();

    // Validate all batches in a level concurrently, then split only the failing
    // ones into the next level. This replaces the old fully serial descent
    // (one `mihomo -t` spawn at a time) with O(log n) bounded-parallel rounds.
    while !level.is_empty() {
        let mut next = Vec::new();
        let mut iter = level.into_iter();
        let mut tasks: JoinSet<(Vec<PreparedProxy>, Result<Option<String>>)> = JoinSet::new();
        loop {
            while tasks.len() < VALIDATE_CONCURRENCY {
                let Some(batch) = iter.next() else {
                    break;
                };
                let mihomo = mihomo.to_path_buf();
                let work_dir = work_dir.to_path_buf();
                tasks.spawn(async move {
                    let outcome = validate_proxy_batch(&batch, &mihomo, &work_dir).await;
                    (batch, outcome)
                });
            }

            let Some(joined) = tasks.join_next().await else {
                break;
            };
            let (mut batch, outcome) = joined.map_err(|error| anyhow!("校验任务失败: {error}"))?;
            match outcome? {
                None => valid.extend(batch),
                Some(reason) if batch.len() == 1 => {
                    rejected.push((batch.pop().expect("single proxy batch"), reason));
                }
                Some(_) => {
                    let right = batch.split_off(batch.len() / 2);
                    next.push(batch);
                    next.push(right);
                }
            }
        }
        level = next;
    }

    valid.sort_by_key(|proxy| proxy.index);
    rejected.sort_by_key(|(proxy, _)| proxy.index);
    Ok((valid, rejected))
}

async fn validate_proxy_batch(
    batch: &[PreparedProxy],
    mihomo: &Path,
    work_dir: &Path,
) -> Result<Option<String>> {
    let path = work_dir.join(format!("validate-{}.yaml", Uuid::new_v4()));
    let config = build_mihomo_config(batch, 0);
    tokio::fs::write(&path, serde_yaml::to_string(&config)?).await?;
    let mut command = Command::new(mihomo);
    command
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .arg("-t")
        .arg("-d")
        .arg(work_dir)
        .arg("-f")
        .arg(&path)
        .kill_on_drop(true)
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().await?;
    let _ = tokio::fs::remove_file(path).await;
    if output.status.success() {
        return Ok(None);
    }
    let diagnostic = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(Some(compact_diagnostic(&diagnostic)))
}

fn compact_diagnostic(diagnostic: &str) -> String {
    let text = diagnostic
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("未知配置错误");
    text.chars().take(240).collect()
}

fn prepare_proxies(nodes: &[Node]) -> (Vec<PreparedProxy>, Vec<Option<ProxyProbeResult>>) {
    let mut prepared = Vec::new();
    let mut results = vec![None; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        let Some(mut config) = nodes_to_clash_proxies(std::slice::from_ref(node)).pop() else {
            results[index] = Some(ProxyProbeResult {
                id: node.id.clone(),
                ok: false,
                latency_ms: None,
                message: format!("Mihomo 暂不支持协议: {}", node.protocol),
            });
            continue;
        };
        let name = format!("probe-{index}-{}", node.id);
        if let Some(object) = config.as_object_mut() {
            object.insert("name".into(), json!(name));
        }
        prepared.push(PreparedProxy {
            index,
            id: node.id.clone(),
            name,
            config,
        });
    }
    (prepared, results)
}

async fn wait_for_controller(
    child: &mut tokio::process::Child,
    port: u16,
    budget: Duration,
) -> bool {
    let started = tokio::time::Instant::now();
    while started.elapsed() < budget {
        if let Ok(Some(_)) = child.try_wait() {
            return false;
        }
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            let _ = stream.set_zero_linger();
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// 自动切换挑替补前的 TCP 复检：并发拨每个候选的 `host:port`，谁先连上且
/// 上一次延迟最好就用谁（`candidates` 已按延迟从低到高排好）。
///
/// 为什么要这一步：库里那条"测通"可能已经是几小时前的。2026-10-07 实测过 ——
/// 自动切换照 08:24 的 90ms 记录切进一个端口早就不监听的 socks5，结果整个境外
/// 不通，而记录上那个节点仍是"测通"状态。
pub async fn first_reachable(
    candidates: Vec<crate::router::BackupCandidate>,
    timeout: std::time::Duration,
) -> Option<(String, String)> {
    use tokio::net::TcpStream;
    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();
    for (index, node) in candidates.into_iter().enumerate() {
        tasks.spawn(async move {
            let host = node.host.clone();
            let reachable =
                match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), node.port)))
                    .await
                {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_zero_linger();
                        true
                    }
                    _ => false,
                };
            (index, node, reachable)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(row) = joined {
            results.push(row);
        }
    }
    results.sort_by_key(|(index, _, _)| *index);
    results
        .into_iter()
        .find(|(_, _, reachable)| *reachable)
        .map(|(_, node, _)| (node.id, node.name))
}

/// 为单节点拉起独立的临时 Mihomo 代理（开放本地 mixed-port 端口）。
/// 用于单节点下载带宽测速与网络测速，绝不污染或切换主代理活动节点。
pub struct SingleNodeProbeProxy {
    child: tokio::process::Child,
    pub mixed_port: u16,
    work_dir: std::path::PathBuf,
}

impl Drop for SingleNodeProbeProxy {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let work_dir = self.work_dir.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = tokio::fs::remove_dir_all(&work_dir).await;
        });
    }
}

pub async fn spawn_single_node_probe_proxy(node: &Node) -> Result<SingleNodeProbeProxy> {
    let mihomo = find_mihomo_executable().ok_or_else(|| anyhow!("未找到 Mihomo 内核"))?;
    let clash_proxies = nodes_to_clash_proxies(std::slice::from_ref(node));
    let mut clash_proxy = clash_proxies
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("节点无法转换为 Mihomo 配置: {}", node.protocol))?;

    let proxy_name = "speedtest-target".to_string();
    if let Some(map) = clash_proxy.as_object_mut() {
        map.insert("name".into(), json!(proxy_name));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mixed_port = listener.local_addr()?.port();
    drop(listener);

    let ctrl_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ctrl_port = ctrl_listener.local_addr()?.port();
    drop(ctrl_listener);

    let config = json!({
        "mixed-port": mixed_port,
        "external-controller": format!("127.0.0.1:{ctrl_port}"),
        "secret": "",
        "allow-lan": false,
        "ipv6": false,
        "mode": "rule",
        "log-level": "silent",
        "proxies": [clash_proxy],
        "proxy-groups": [{
            "name": "PROXY",
            "type": "select",
            "proxies": [proxy_name]
        }],
        "rules": ["MATCH,PROXY"]
    });

    let work_dir = std::env::temp_dir().join(format!("vproxy-st-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&work_dir).await?;
    let config_path = work_dir.join("config.yaml");
    tokio::fs::write(&config_path, serde_yaml::to_string(&config)?).await?;

    let mut command = Command::new(mihomo);
    command
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .arg("-d")
        .arg(&work_dir)
        .arg("-f")
        .arg(&config_path)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn()?;

    // 等待端口就绪（最多 3 秒）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], mixed_port));
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let _ = tokio::fs::remove_dir_all(&work_dir).await;
            anyhow::bail!("临时测速内核异常退出: {status}");
        }
        if TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    if !ready {
        let _ = child.kill().await;
        let _ = tokio::fs::remove_dir_all(&work_dir).await;
        anyhow::bail!("临时测速内核启动超时");
    }

    Ok(SingleNodeProbeProxy {
        child,
        mixed_port,
        work_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn node(protocol: &str, config: Value) -> Node {
        let now = Utc::now();
        Node {
            id: format!("{protocol}-id"),
            source_id: None,
            protocol: protocol.into(),
            name: "test".into(),
            server: config["server"].as_str().unwrap().into(),
            port: config["port"].as_u64().unwrap() as u16,
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
        }
    }

    #[test]
    fn manual_probe_target_default_is_cloudflare() {
        assert_eq!(
            PROXY_CONNECTIVITY_TEST_URL,
            "http://cp.cloudflare.com/generate_204"
        );
    }

    #[test]
    fn build_mihomo_config_enables_unified_delay() {
        let proxies = vec![PreparedProxy {
            index: 0,
            id: "node-1".into(),
            name: "node-1".into(),
            config: json!({"name":"node-1","type":"http","server":"example.com","port":80}),
        }];
        let config = build_mihomo_config(&proxies, 19090);
        assert_eq!(config.get("unified-delay"), Some(&json!(true)));
    }

    #[tokio::test]
    async fn unified_delay_probe_resets_fallback_timer_and_uses_warm_rtt() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 模拟主目标耗时 140ms 后返回 503，回退目标首包 100ms、复测暖包立即返回 204
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut fallback_hits = 0usize;
            for _ in 0..3 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("GET /primary ") {
                        tokio::time::sleep(Duration::from_millis(140)).await;
                        let _ = stream
                            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        break;
                    } else if req.starts_with("GET /fallback ") {
                        fallback_hits += 1;
                        if fallback_hits == 1 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        let _ = stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
                            .await;
                        if fallback_hits >= 2 {
                            return;
                        }
                    } else {
                        break;
                    }
                }
            }
        });

        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let primary = format!("http://{addr}/primary");
        let fallback = format!("http://{addr}/fallback");
        let (delay_ms, target) = probe_http_proxy_unified_delay_urls(&client, &primary, &fallback)
            .await
            .unwrap();
        let _ = server.await;

        assert_eq!(target, "Cloudflare");
        // 应反映回退目标第二次暖请求延迟（远小于 140ms 主目标失败耗时 + 100ms 首包耗时）
        assert!(
            delay_ms < 90,
            "expected warm unified RTT < 90ms, got {delay_ms}ms"
        );
    }

    #[test]
    fn prepares_supported_nodes_and_reports_unsupported_protocols() {
        let nodes = vec![
            node(
                "vless",
                json!({"server":"1.2.3.4","port":443,"uuid":"11111111-1111-1111-1111-111111111111","network":"ws","security":"tls"}),
            ),
            node(
                "anytls",
                json!({"server":"1.2.3.4","port":443,"password":"secret","sni":"example.com"}),
            ),
            node(
                "mieru",
                json!({"server":"1.2.3.4","port":443,"password":"secret"}),
            ),
        ];
        let (prepared, results) = prepare_proxies(&nodes);
        // mieru 现已受支持（vp-core / mihomo ≥1.18.7），三个节点均可进入探测
        assert_eq!(prepared.len(), 3);
        assert_eq!(prepared[0].id, "vless-id");
        assert!(results[0].is_none());
        assert!(results[1].is_none());
        assert!(results[2].is_none());
    }
    #[tokio::test]
    async fn isolates_invalid_proxy_without_rejecting_valid_batch_members() {
        let Some(mihomo) = find_mihomo_executable() else {
            return;
        };
        let work_dir = std::env::temp_dir().join(format!("vproxy-isolate-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&work_dir).await.unwrap();
        let proxies = vec![
            PreparedProxy {
                index: 0,
                id: "valid".into(),
                name: "valid".into(),
                config: json!({"name":"valid","type":"http","server":"example.com","port":80}),
            },
            PreparedProxy {
                index: 1,
                id: "invalid".into(),
                name: "invalid".into(),
                config: json!({"name":"invalid","type":"not-a-real-protocol","server":"example.com","port":80}),
            },
        ];

        let (valid, rejected) = isolate_invalid_proxies(proxies, &mihomo, &work_dir)
            .await
            .unwrap();

        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].id, "valid");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].0.id, "invalid");
        assert!(!rejected[0].1.is_empty());
        let _ = tokio::fs::remove_dir_all(work_dir).await;
    }

    #[test]
    fn test_is_connection_failure_distinguishes_dead_nodes_from_http_blocks() {
        // 连接不可达/超时/断开：属于死节点，应当跳过回退目标探测
        assert!(is_connection_failure("operation timed out"));
        assert!(is_connection_failure("connection refused"));
        assert!(is_connection_failure("Google: HTTP 504 Gateway Timeout"));
        assert!(is_connection_failure("proxy connection closed"));
        assert!(is_connection_failure(
            "connectex: A connection attempt failed"
        ));
        assert!(is_connection_failure("os error 10060"));
        assert!(is_connection_failure("network is unreachable"));

        // HTTP 状态码拦截（如 Google 403 / 429 / 503 等）：说明隧道畅通但目标受阻，需走回退目标
        assert!(!is_connection_failure("Google: HTTP 403 Forbidden"));
        assert!(!is_connection_failure("Google: HTTP 429 Too Many Requests"));
        assert!(!is_connection_failure(
            "Google: HTTP 503 Service Unavailable"
        ));
    }

    #[tokio::test]
    async fn test_single_node_probe_proxy_lifecycle() {
        let Some(_mihomo) = find_mihomo_executable() else {
            return;
        };
        let node = node("http", json!({"server":"127.0.0.1","port":8080}));
        let runner = spawn_single_node_probe_proxy(&node).await;
        if let Ok(runner) = runner {
            assert!(runner.mixed_port > 0);
            let dir = runner.work_dir.clone();
            assert!(dir.exists());
            drop(runner);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(!dir.exists());
        }
    }
}
