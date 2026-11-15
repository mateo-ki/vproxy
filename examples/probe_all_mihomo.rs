//! 一次性探针（跑完可删）：软件内全部节点经 mihomo 测速，复用 proxy_probe 管线，
//! 输出与 VP-Core 探针同构的结果 JSON。
//!
//! 输入 VPROXY_PROBE_INPUT：[{id, name, protocol, server, port, config(clash json)}]
//! 输出 VPROXY_PROBE_OUT：[{id, ok, latency_ms, message}]

use std::sync::Arc;
use std::time::Duration;

use vproxy::models::Node;
use vproxy::proxy_probe::verify_nodes_with_mihomo_progress_limited;

#[tokio::main]
async fn main() {
    let input =
        std::env::var("VPROXY_PROBE_INPUT").unwrap_or_else(|_| "data/probe/all_nodes.json".into());
    let out_path = std::env::var("VPROXY_PROBE_OUT")
        .unwrap_or_else(|_| "data/probe/results_mihomo.json".into());
    let raw = std::fs::read_to_string(&input).expect("read input");
    let items: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("parse input");
    println!("mihomo 探针：{} 节点", items.len());

    let now = chrono::Utc::now();
    let nodes: Vec<Node> = items
        .iter()
        .map(|v| Node {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            source_id: None,
            protocol: v["protocol"].as_str().unwrap_or("unknown").to_string(),
            name: v["id"].as_str().unwrap_or_default().to_string(),
            server: v["server"].as_str().unwrap_or_default().to_string(),
            port: v["port"].as_u64().unwrap_or(0) as u16,
            raw: String::new(),
            config: v["config"].clone(),
            country: None,
            latency_ms: None,
            latency_ok: None,
            download_kbps: None,
            latency_kernel: None,
            latency_test_kind: None,
            latency_tested_at: None,
            created_at: now,
            updated_at: now,
        })
        .collect();

    let progress = |p: vproxy::proxy_probe::ProxyProbeProgress| {
        if p.done.is_multiple_of(1000) {
            println!("  {}/{} ok={} fail={}", p.done, p.total, p.ok, p.fail);
        }
    };
    let results = verify_nodes_with_mihomo_progress_limited(
        nodes,
        Duration::from_secs(6),
        Some(progress),
        Arc::new(tokio::sync::Semaphore::new(96)),
        8192,
        false,
    )
    .await
    .expect("probe");

    let out: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "ok": r.ok,
                "latency_ms": r.latency_ms,
                "err": if r.ok { serde_json::Value::Null } else { serde_json::Value::String(r.message.clone()) },
            })
        })
        .collect();
    std::fs::write(&out_path, serde_json::to_string(&out).unwrap()).unwrap();
    let ok = out.iter().filter(|r| r["ok"] == true).count();
    println!("mihomo 探针完成：{ok}/{} ok → {out_path}", out.len());
}
