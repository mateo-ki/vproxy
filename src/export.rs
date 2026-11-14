use crate::models::Node;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// Build a Clash-compatible proxy list from stored nodes.
pub fn nodes_to_clash_proxies(nodes: &[Node]) -> Vec<Value> {
    let mut proxies = Vec::new();
    let mut used_names = HashSet::new();
    for (idx, node) in nodes.iter().enumerate() {
        if let Some(mut proxy) = node_to_clash_proxy(node) {
            let base = proxy
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}-{}-{}", node.protocol, node.server, node.port));
            let name = unique_name(&base, &mut used_names, idx);
            if let Some(obj) = proxy.as_object_mut() {
                obj.insert("name".into(), json!(name));
            }
            proxies.push(proxy);
        }
    }
    proxies
}

/// Convert nodes to share URIs (one per line). Rebuilds URI from config when raw is YAML.
pub fn nodes_to_share_uris(nodes: &[Node]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for node in nodes {
        if let Some(uri) = node_to_share_uri(node) {
            if seen.insert(uri.clone()) {
                out.push(uri);
            }
        }
    }
    out
}

fn unique_name(base: &str, used: &mut HashSet<String>, idx: usize) -> String {
    let mut name = sanitize_name(base);
    if name.is_empty() {
        name = format!("node-{}", idx + 1);
    }
    if used.insert(name.clone()) {
        return name;
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{name}-{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            _ => c,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn extract_skip_cert_verify(obj: &Map<String, Value>, node: &Node) -> bool {
    let check_val = |v: Option<&Value>| match v {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        Some(Value::Number(n)) => Some(n.as_i64() == Some(1)),
        _ => None,
    };
    for key in [
        "skip-cert-verify",
        "skip_cert_verify",
        "insecure",
        "allowInsecure",
        "allow_insecure",
    ] {
        if let Some(b) = check_val(obj.get(key)) {
            return b;
        }
        if let Some(b) = check_val(node.config.get(key)) {
            return b;
        }
    }
    let raw_lower = node.raw.to_ascii_lowercase();
    if raw_lower.contains("skip-cert-verify: true")
        || raw_lower.contains("skip-cert-verify: 1")
        || raw_lower.contains("skip_cert_verify=1")
        || raw_lower.contains("skip_cert_verify=true")
        || raw_lower.contains("allowinsecure=1")
        || raw_lower.contains("allowinsecure=true")
        || raw_lower.contains("insecure=1")
        || raw_lower.contains("insecure=true")
    {
        return true;
    }
    false
}

fn node_to_clash_proxy(node: &Node) -> Option<Value> {
    let mut cfg = node.config.clone();
    if !cfg.is_object() {
        cfg = json!({});
    }
    let protocol = node.protocol.to_ascii_lowercase();
    match protocol.as_str() {
        "shadowsocks" | "ss" => Some(normalize_ss(&mut cfg, node)),
        "vmess" => Some(normalize_vmess(&mut cfg, node)),
        "vless" => Some(normalize_vless(&mut cfg, node)),
        "trojan" => Some(normalize_trojan(&mut cfg, node)),
        "hysteria2" | "hy2" => Some(normalize_hysteria2(&mut cfg, node)),
        "hysteria" => Some(normalize_hysteria(&mut cfg, node)),
        "socks5" | "socks" => {
            set_type(&mut cfg, "socks5");
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "http" | "https" => {
            set_type(&mut cfg, "http");
            if protocol == "https" {
                if let Some(map) = cfg.as_object_mut() {
                    map.entry("tls").or_insert_with(|| json!(true));
                }
            }
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "tuic" => {
            set_type(&mut cfg, "tuic");
            ensure_server_port_name(&mut cfg, node);
            if let Some(obj) = cfg.as_object_mut() {
                obj.insert("udp".into(), json!(true));
                let insecure = extract_skip_cert_verify(obj, node);
                obj.remove("allowInsecure");
                obj.remove("insecure");
                obj.insert("skip-cert-verify".into(), json!(insecure));
            }
            Some(cfg)
        }
        // OpenVPN（新版 mihomo 原生出站）：配置整体直通（含 ca/cert/key PEM）
        "openvpn" => {
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "juicity" => {
            set_type(&mut cfg, "juicity");
            ensure_server_port_name(&mut cfg, node);
            if let Some(obj) = cfg.as_object_mut() {
                obj.insert("udp".into(), json!(true));
                let insecure = extract_skip_cert_verify(obj, node);
                obj.remove("allowInsecure");
                obj.insert("insecure".into(), json!(insecure));
                // congestion / pinned 系列重名 alias 归一，防 serde duplicate field
                let c1 = obj.remove("congestion-control");
                let c2 = obj.remove("congestion_control");
                let c3 = obj.remove("congestion-controller");
                let c4 = obj.remove("congestion_controller");
                if let Some(v) = c1.or(c2).or(c3).or(c4) {
                    obj.insert("congestion-control".into(), v);
                }
                let p1 = obj.remove("pinned-cert-chain");
                let p2 = obj.remove("pinned_cert_chain");
                let p3 = obj.remove("pinnedCertChain");
                if let Some(v) = p1.or(p2).or(p3) {
                    obj.insert("pinned-cert-chain".into(), v);
                }
            }
            Some(cfg)
        }
        "anytls" => {
            set_type(&mut cfg, "anytls");
            ensure_server_port_name(&mut cfg, node);
            if let Some(obj) = cfg.as_object_mut() {
                let security = first_str(obj, &["security", "tls"]).unwrap_or_default();
                let sec_l = security.to_ascii_lowercase();
                let is_reality = sec_l == "reality"
                    || obj.contains_key("reality-opts")
                    || obj.contains_key("pbk");
                if is_reality {
                    let mut ro = Map::new();
                    if let Some(pbk) =
                        first_str(obj, &["pbk", "public-key"]).filter(|s| !s.is_empty())
                    {
                        ro.insert("public-key".into(), json!(pbk));
                    }
                    if let Some(sid) =
                        first_str(obj, &["sid", "short-id"]).filter(|s| !s.is_empty())
                    {
                        ro.insert("short-id".into(), json!(sid));
                    }
                    if let Some(spx) =
                        first_str(obj, &["spx", "spider-x"]).filter(|s| !s.is_empty())
                    {
                        ro.insert("spider-x".into(), json!(spx));
                    }
                    obj.insert("reality-opts".into(), Value::Object(ro));
                }
            }
            Some(cfg)
        }
        "mieru" => {
            set_type(&mut cfg, "mieru");
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "wireguard" | "wg" => {
            set_type(&mut cfg, "wireguard");
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "shadowsocksr" | "ssr" => {
            set_type(&mut cfg, "ssr");
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        "masque" => {
            set_type(&mut cfg, "masque");
            ensure_server_port_name(&mut cfg, node);
            Some(cfg)
        }
        _ => None,
    }
}

fn set_type(cfg: &mut Value, ty: &str) {
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert("type".into(), json!(ty));
    }
}

fn ensure_server_port_name(cfg: &mut Value, node: &Node) {
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    if obj
        .get("server")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        obj.insert("server".into(), json!(node.server));
    }
    if obj.get("port").and_then(as_u16).is_none() {
        obj.insert("port".into(), json!(node.port));
    }
    if obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        let name = if node.name.is_empty() {
            format!("{}:{}", node.server, node.port)
        } else {
            node.name.clone()
        };
        obj.insert("name".into(), json!(name));
    }
}

fn normalize_ss(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "ss");
    ensure_server_port_name(cfg, node);
    if let Some(obj) = cfg.as_object_mut() {
        if !obj.contains_key("cipher") {
            if let Some(m) = obj.get("method").cloned() {
                obj.insert("cipher".into(), m);
            }
        }
        obj.remove("method");
        strip_empty_strings(obj, &["plugin", "plugin-opts"]);
    }
    cfg.clone()
}

fn normalize_vmess(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "vmess");
    ensure_server_port_name(cfg, node);
    let Some(obj) = cfg.as_object_mut() else {
        return cfg.clone();
    };

    if !obj.contains_key("uuid") {
        if let Some(id) = obj.get("id").cloned() {
            obj.insert("uuid".into(), id);
        }
    }
    if !obj.contains_key("alterId") {
        if let Some(aid) = obj.get("aid").cloned() {
            obj.insert("alterId".into(), coerce_numberish(aid));
        } else {
            obj.insert("alterId".into(), json!(0));
        }
    } else if let Some(v) = obj.get("alterId").cloned() {
        obj.insert("alterId".into(), coerce_numberish(v));
    }
    if !obj.contains_key("cipher") {
        if let Some(scy) = obj.get("scy").cloned() {
            obj.insert("cipher".into(), scy);
        } else {
            obj.insert("cipher".into(), json!("auto"));
        }
    }

    let network = first_str(obj, &["network", "net"]).unwrap_or_else(|| "tcp".into());
    obj.insert("network".into(), json!(network.clone()));

    let tls = match obj.get("tls") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let s = s.to_ascii_lowercase();
            s == "tls" || s == "true" || s == "1"
        }
        _ => false,
    };
    obj.insert("tls".into(), json!(tls));
    if tls {
        let insecure = extract_skip_cert_verify(obj, node);
        obj.remove("allowInsecure");
        obj.remove("insecure");
        obj.insert("skip-cert-verify".into(), json!(insecure));
    }

    let sni_val = first_str(obj, &["servername", "sni", "server_name", "server-name"])
        .filter(|s| !s.is_empty());
    obj.remove("sni");
    obj.remove("server_name");
    obj.remove("server-name");
    if let Some(sni) = sni_val {
        obj.insert("servername".into(), json!(sni));
    }

    let path = first_str(obj, &["path"]).unwrap_or_default();
    let host = first_str(obj, &["host"]).unwrap_or_default();
    let alpn = first_str(obj, &["alpn"]).unwrap_or_default();

    match network.as_str() {
        "ws" | "websocket" => {
            obj.insert("network".into(), json!("ws"));
            if !obj.contains_key("ws-opts") {
                let mut headers = Map::new();
                if !host.is_empty() {
                    headers.insert("Host".into(), json!(host));
                }
                let mut ws = Map::new();
                if !path.is_empty() {
                    ws.insert("path".into(), json!(path));
                }
                if !headers.is_empty() {
                    ws.insert("headers".into(), Value::Object(headers));
                }
                if !ws.is_empty() {
                    obj.insert("ws-opts".into(), Value::Object(ws));
                }
            }
        }
        "grpc" => {
            if !obj.contains_key("grpc-opts") {
                let sn = first_str(obj, &["serviceName", "servicename"]).unwrap_or(path);
                if !sn.is_empty() {
                    obj.insert("grpc-opts".into(), json!({ "grpc-service-name": sn }));
                }
            }
        }
        "h2" | "http" => {
            if !obj.contains_key("h2-opts") && (!path.is_empty() || !host.is_empty()) {
                let mut h2 = Map::new();
                if !path.is_empty() {
                    h2.insert("path".into(), json!(path));
                }
                if !host.is_empty() {
                    h2.insert("host".into(), json!([host]));
                }
                obj.insert("h2-opts".into(), Value::Object(h2));
            }
        }
        _ => {}
    }

    if let Some(Value::String(s)) = obj.get("alpn").cloned() {
        let list: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if list.is_empty() {
            obj.remove("alpn");
        } else {
            obj.insert("alpn".into(), json!(list));
        }
    } else if !alpn.is_empty() {
        let list: Vec<String> = alpn
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            obj.insert("alpn".into(), json!(list));
        }
    }

    for k in [
        "add",
        "id",
        "aid",
        "net",
        "scy",
        "ps",
        "v",
        "remark",
        "server_port",
        "class",
    ] {
        obj.remove(k);
    }
    strip_empty_strings(obj, &["path", "host", "sni", "servername", "fp"]);

    cfg.clone()
}

fn normalize_vless(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "vless");
    ensure_server_port_name(cfg, node);
    let Some(obj) = cfg.as_object_mut() else {
        return cfg.clone();
    };

    if !obj.contains_key("uuid") {
        if let Some(id) = obj.get("id").cloned() {
            obj.insert("uuid".into(), id);
        }
    }

    let network = first_str(obj, &["network", "net"]).unwrap_or_else(|| "tcp".into());
    obj.insert("network".into(), json!(network.clone()));

    let security = first_str(obj, &["security", "tls"]).unwrap_or_default();
    let sec_l = security.to_ascii_lowercase();
    let is_reality = sec_l == "reality";
    let is_tls = is_reality || sec_l == "tls" || sec_l == "true" || sec_l == "1";
    obj.insert("tls".into(), json!(is_tls));
    if is_reality {
        let mut ro = Map::new();
        if let Some(pbk) = first_str(obj, &["pbk", "public-key"]).filter(|s| !s.is_empty()) {
            ro.insert("public-key".into(), json!(pbk));
        }
        if let Some(sid) = first_str(obj, &["sid", "short-id"]).filter(|s| !s.is_empty()) {
            ro.insert("short-id".into(), json!(sid));
        }
        obj.insert("reality-opts".into(), Value::Object(ro));
    }

    let sni_val = first_str(obj, &["servername", "sni", "server_name", "server-name"])
        .filter(|s| !s.is_empty());
    obj.remove("sni");
    obj.remove("server_name");
    obj.remove("server-name");
    if let Some(sni) = sni_val {
        obj.insert("servername".into(), json!(sni));
    }
    if let Some(fp) = first_str(obj, &["fp", "client-fingerprint"]).filter(|s| !s.is_empty()) {
        obj.insert("client-fingerprint".into(), json!(fp));
    }
    if let Some(flow) = first_str(obj, &["flow"]).filter(|s| !s.is_empty()) {
        obj.insert("flow".into(), json!(flow));
    } else {
        obj.remove("flow");
    }

    // ECH：分享链接 `ech=<查询名>+<DoH URL>` / 裸查询名 → 内核 ech-opts
    // （mihomo / VP-Core 同语法：enable + query-server-name + doh）。
    if let Some(ech) = first_str(obj, &["ech"]).filter(|s| !s.is_empty()) {
        obj.remove("ech");
        if !obj.contains_key("ech-opts") {
            let mut eo = Map::new();
            eo.insert("enable".into(), json!(true));
            match ech.split_once('+') {
                Some((name, doh)) if doh.contains("://") => {
                    if !name.trim().is_empty() {
                        eo.insert("query-server-name".into(), json!(name.trim()));
                    }
                    eo.insert("doh".into(), json!(doh.trim()));
                }
                _ => {
                    eo.insert("query-server-name".into(), json!(ech.trim()));
                }
            }
            obj.insert("ech-opts".into(), Value::Object(eo));
        }
    }

    let path = first_str(obj, &["path"]).unwrap_or_default();
    let host = first_str(obj, &["host"]).unwrap_or_default();

    match network.as_str() {
        "ws" | "websocket" => {
            obj.insert("network".into(), json!("ws"));
            if !obj.contains_key("ws-opts") {
                let mut headers = Map::new();
                if !host.is_empty() {
                    headers.insert("Host".into(), json!(host));
                }
                let mut ws = Map::new();
                if !path.is_empty() {
                    ws.insert("path".into(), json!(path));
                }
                if !headers.is_empty() {
                    ws.insert("headers".into(), Value::Object(headers));
                }
                if !ws.is_empty() {
                    obj.insert("ws-opts".into(), Value::Object(ws));
                }
            }
        }
        "grpc" => {
            if !obj.contains_key("grpc-opts") {
                let sn = first_str(obj, &["serviceName", "servicename"]).unwrap_or(path);
                if !sn.is_empty() {
                    obj.insert("grpc-opts".into(), json!({ "grpc-service-name": sn }));
                }
            }
        }
        _ => {}
    }

    if let Some(Value::String(s)) = obj.get("alpn").cloned() {
        let list: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if list.is_empty() {
            obj.remove("alpn");
        } else {
            obj.insert("alpn".into(), json!(list));
        }
    }

    let insecure = extract_skip_cert_verify(obj, node);
    obj.remove("allowInsecure");
    obj.remove("insecure");
    obj.insert("skip-cert-verify".into(), json!(insecure));

    for k in [
        "security",
        "encryption",
        "pbk",
        "sid",
        "fp",
        "sni",
        "serviceName",
        "allowInsecure",
        "insecure",
        "id",
        "net",
        "add",
    ] {
        obj.remove(k);
    }
    if obj.contains_key("ws-opts") || obj.contains_key("grpc-opts") {
        obj.remove("path");
        obj.remove("host");
    } else {
        strip_empty_strings(obj, &["path", "host"]);
    }
    strip_empty_strings(obj, &["client-fingerprint", "servername", "flow"]);

    cfg.clone()
}

fn normalize_trojan(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "trojan");
    ensure_server_port_name(cfg, node);
    let Some(obj) = cfg.as_object_mut() else {
        return cfg.clone();
    };

    let network = first_str(obj, &["network", "net"]).unwrap_or_else(|| "tcp".into());
    if network == "tcp" {
        if obj.get("network").and_then(|v| v.as_str()) == Some("tcp")
            && !obj.contains_key("ws-opts")
            && !obj.contains_key("grpc-opts")
        {
            obj.remove("network");
        }
    } else {
        obj.insert("network".into(), json!(network.clone()));
    }

    let sni_val = first_str(obj, &["sni", "servername", "server_name", "server-name"])
        .filter(|s| !s.is_empty());
    obj.remove("servername");
    obj.remove("server_name");
    obj.remove("server-name");
    if let Some(sni) = sni_val {
        obj.insert("sni".into(), json!(sni));
    }

    // ECH：分享链接 `ech=<查询名>+<DoH URL>` / 裸查询名 → 内核 ech-opts
    if let Some(ech) = first_str(obj, &["ech"]).filter(|s| !s.is_empty()) {
        obj.remove("ech");
        if !obj.contains_key("ech-opts") {
            let mut eo = Map::new();
            eo.insert("enable".into(), json!(true));
            match ech.split_once('+') {
                Some((name, doh)) if doh.contains("://") => {
                    if !name.trim().is_empty() {
                        eo.insert("query-server-name".into(), json!(name.trim()));
                    }
                    eo.insert("doh".into(), json!(doh.trim()));
                }
                _ => {
                    eo.insert("query-server-name".into(), json!(ech.trim()));
                }
            }
            obj.insert("ech-opts".into(), Value::Object(eo));
        }
    }

    let path = first_str(obj, &["path"]).unwrap_or_default();
    let host = first_str(obj, &["host"]).unwrap_or_default();
    match network.as_str() {
        "ws" | "websocket" => {
            obj.insert("network".into(), json!("ws"));
            if !obj.contains_key("ws-opts") {
                let mut headers = Map::new();
                if !host.is_empty() {
                    headers.insert("Host".into(), json!(host));
                }
                let mut ws = Map::new();
                if !path.is_empty() {
                    ws.insert("path".into(), json!(path));
                }
                if !headers.is_empty() {
                    ws.insert("headers".into(), Value::Object(headers));
                }
                if !ws.is_empty() {
                    obj.insert("ws-opts".into(), Value::Object(ws));
                }
            }
        }
        "grpc" => {
            obj.insert("network".into(), json!("grpc"));
            if !obj.contains_key("grpc-opts") {
                let sn = first_str(obj, &["serviceName", "servicename"]).unwrap_or(path);
                if !sn.is_empty() {
                    obj.insert("grpc-opts".into(), json!({ "grpc-service-name": sn }));
                }
            }
        }
        _ => {}
    }

    let insecure = extract_skip_cert_verify(obj, node);
    obj.remove("allowInsecure");
    obj.remove("insecure");
    obj.insert("skip-cert-verify".into(), json!(insecure));

    if let Some(Value::String(s)) = obj.get("alpn").cloned() {
        let list: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if list.is_empty() {
            obj.remove("alpn");
        } else {
            obj.insert("alpn".into(), json!(list));
        }
    }

    for k in [
        "security",
        "fp",
        "allowInsecure",
        "insecure",
        "serviceName",
        "net",
    ] {
        obj.remove(k);
    }
    if obj.contains_key("ws-opts") || obj.contains_key("grpc-opts") {
        obj.remove("path");
        obj.remove("host");
    } else {
        strip_empty_strings(obj, &["path", "host"]);
    }
    strip_empty_strings(obj, &["sni"]);

    cfg.clone()
}

fn normalize_hysteria2(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "hysteria2");
    ensure_server_port_name(cfg, node);
    let Some(obj) = cfg.as_object_mut() else {
        return cfg.clone();
    };
    if !obj.contains_key("password") {
        if let Some(a) = obj.get("auth").or_else(|| obj.get("auth-str")).cloned() {
            obj.insert("password".into(), a);
        }
    }
    // Hysteria2 基于 QUIC/UDP，强制显式启用 UDP 转发支持
    obj.insert("udp".into(), json!(true));

    // 端口跳跃参数提取
    let ports = first_str(obj, &["ports", "mport", "mports"]).or_else(|| {
        if let Some(map) = node.config.as_object() {
            first_str(map, &["ports", "mport", "mports"])
        } else {
            None
        }
    });
    if let Some(p) = ports {
        obj.insert("ports".into(), json!(p));
    }

    let sni_val = first_str(obj, &["sni", "servername", "server_name", "server-name"])
        .filter(|s| !s.is_empty());
    obj.remove("servername");
    obj.remove("server_name");
    obj.remove("server-name");
    if let Some(sni) = sni_val {
        obj.insert("sni".into(), json!(sni));
    }
    let insecure = extract_skip_cert_verify(obj, node);
    obj.remove("allowInsecure");
    obj.remove("insecure");
    obj.insert("skip-cert-verify".into(), json!(insecure));
    let obfs = first_str(obj, &["obfs"]).unwrap_or_default();
    if obfs.is_empty() {
        obj.remove("obfs");
        obj.remove("obfs-password");
    }
    strip_empty_strings(obj, &["sni", "obfs", "obfs-password"]);
    obj.remove("insecure");
    obj.remove("allowInsecure");
    cfg.clone()
}

fn normalize_hysteria(cfg: &mut Value, node: &Node) -> Value {
    set_type(cfg, "hysteria");
    ensure_server_port_name(cfg, node);
    let Some(obj) = cfg.as_object_mut() else {
        return cfg.clone();
    };

    let auth = first_str(obj, &["auth-str", "auth_str", "auth", "password"]).or_else(|| {
        if let Some(map) = node.config.as_object() {
            first_str(map, &["auth-str", "auth_str", "auth", "password"])
        } else {
            None
        }
    });
    if let Some(a) = auth {
        obj.insert("auth-str".into(), json!(a));
        obj.insert("auth_str".into(), json!(a));
    }

    let insecure = extract_skip_cert_verify(obj, node);
    obj.remove("allowInsecure");
    obj.remove("insecure");
    obj.insert("skip-cert-verify".into(), json!(insecure));
    obj.insert("udp".into(), json!(true));

    if let Some(sni) =
        first_str(obj, &["sni", "peer", "server_name", "server-name"]).filter(|s| !s.is_empty())
    {
        obj.insert("sni".into(), json!(sni));
    }

    let has_alpn = obj
        .get("alpn")
        .and_then(|v| v.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false);
    if !has_alpn {
        obj.insert("alpn".into(), json!(["h3"]));
    }

    let has_proto = obj
        .get("protocol")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !has_proto {
        obj.insert("protocol".into(), json!("udp"));
    }

    if !obj.contains_key("up") {
        if let Some(up) = obj.get("upmbps").or_else(|| obj.get("up_mbps")) {
            obj.insert("up".into(), up.clone());
        } else {
            obj.insert("up".into(), json!("100 Mbps"));
        }
    }
    if !obj.contains_key("down") {
        if let Some(down) = obj.get("downmbps").or_else(|| obj.get("down_mbps")) {
            obj.insert("down".into(), down.clone());
        } else {
            obj.insert("down".into(), json!("500 Mbps"));
        }
    }

    let obfs = first_str(obj, &["obfs"]).unwrap_or_default();
    if obfs.is_empty() {
        obj.remove("obfs");
    }
    strip_empty_strings(obj, &["sni", "obfs"]);
    cfg.clone()
}

fn node_to_share_uri(node: &Node) -> Option<String> {
    // Always rebuild from parsed config. Many free subs mislabel vless as ss://;
    // re-emitting raw would break v2rayN import / connection.
    let cfg = &node.config;
    let protocol = node.protocol.to_ascii_lowercase();
    if let Some(uri) = match protocol.as_str() {
        "shadowsocks" | "ss" => rebuild_ss_uri(cfg, node),
        "vmess" => rebuild_vmess_uri(cfg, node),
        "vless" => rebuild_vless_uri(cfg, node),
        "trojan" => rebuild_trojan_uri(cfg, node),
        "hysteria" => rebuild_hysteria1_uri(cfg, node),
        "hysteria2" | "hy2" => rebuild_hysteria2_uri(cfg, node),
        "socks5" | "socks" => rebuild_socks_uri(cfg, node),
        "http" | "https" => rebuild_http_uri(cfg, node),
        "masque" => crate::parser::warp_masque::rebuild_masque_uri(cfg, node),
        "snell" => rebuild_snell_uri(cfg, node),
        "naive" => rebuild_naive_uri(cfg, node),
        "mieru" => rebuild_mieru_uri(cfg, node),
        "ssh" => rebuild_ssh_uri(cfg, node),
        "tailscale" => rebuild_tailscale_uri(cfg, node),
        "juicity" => rebuild_juicity_uri(cfg, node),
        "shadowtls" => rebuild_shadowtls_uri(cfg, node),
        _ => None,
    } {
        return Some(uri);
    }

    // Fallback: only keep raw when its scheme matches the node protocol.
    let raw = node.raw.trim();
    if looks_like_share_uri(raw) && raw_scheme_matches_protocol(raw, &protocol) {
        return Some(raw.to_string());
    }
    None
}

fn raw_scheme_matches_protocol(raw: &str, protocol: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    match protocol {
        "shadowsocks" | "ss" => lower.starts_with("ss://"),
        "shadowsocksr" | "ssr" => {
            lower.starts_with("ssr://") || lower.starts_with("shadowsocksr://")
        }
        "vmess" => lower.starts_with("vmess://"),
        "vless" => lower.starts_with("vless://"),
        "trojan" => lower.starts_with("trojan://"),
        "tuic" => lower.starts_with("tuic://"),
        "wireguard" | "wg" => lower.starts_with("wireguard://") || lower.starts_with("wg://"),
        "hysteria" => lower.starts_with("hysteria://") && !lower.starts_with("hysteria2://"),
        "hysteria2" | "hy2" => lower.starts_with("hysteria2://") || lower.starts_with("hy2://"),
        "socks5" | "socks" => lower.starts_with("socks5://") || lower.starts_with("socks://"),
        "http" | "https" => lower.starts_with("http://") || lower.starts_with("https://"),
        "masque" => lower.starts_with("masque://"),
        _ => false,
    }
}

fn looks_like_share_uri(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.starts_with("ss://")
        || lower.starts_with("ssr://")
        || lower.starts_with("shadowsocksr://")
        || lower.starts_with("vmess://")
        || lower.starts_with("vless://")
        || lower.starts_with("trojan://")
        || lower.starts_with("tuic://")
        || lower.starts_with("wireguard://")
        || lower.starts_with("wg://")
        || lower.starts_with("hysteria://")
        || lower.starts_with("hysteria2://")
        || lower.starts_with("hy2://")
        || lower.starts_with("socks5://")
        || lower.starts_with("socks://")
        || ((lower.starts_with("http://") || lower.starts_with("https://"))
            && raw.contains('@')
            && !raw.contains('\n'))
}

fn rebuild_ss_uri(cfg: &Value, node: &Node) -> Option<String> {
    // shadow-tls 插件形态（shadowtls:// 内层合并节点）→ 重建 shadowtls:// 链接
    if str_field(cfg, &["plugin"]).as_deref() == Some("shadow-tls") {
        return rebuild_shadowtls_uri(cfg, node);
    }
    let method = str_field(cfg, &["cipher", "method"])?;
    let password = str_field(cfg, &["password"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let userinfo = B64.encode(format!("{method}:{password}"));
    let mut uri = format!("ss://{userinfo}@{server}:{port}");
    if let Some(plugin) = str_field(cfg, &["plugin"]).filter(|s| !s.is_empty()) {
        uri.push_str(&format!("?plugin={}", urlencoding_lite(&plugin)));
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_snell_uri(cfg: &Value, node: &Node) -> Option<String> {
    let psk = str_field(cfg, &["psk", "password"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    q.push((
        "version".into(),
        str_field(cfg, &["version"]).unwrap_or_else(|| "4".into()),
    ));
    if let Some(obfs) = str_field(cfg, &["obfs"]).filter(|s| !s.is_empty()) {
        q.push(("obfs".into(), obfs));
        if let Some(h) = str_field(cfg, &["obfs-host"]).filter(|s| !s.is_empty()) {
            q.push(("obfs-host".into(), h));
        }
    }
    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("snell://{psk}@{server}:{port}?{query}");
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_naive_uri(cfg: &Value, node: &Node) -> Option<String> {
    let username = str_field(cfg, &["username"])?;
    let password = str_field(cfg, &["password"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = str_field(cfg, &["sni", "servername"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    let mut uri = format!("naive+https://{username}:{password}@{server}:{port}");
    if !q.is_empty() {
        let query = q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_mieru_uri(cfg: &Value, node: &Node) -> Option<String> {
    let username = str_field(cfg, &["username"])?;
    let password = str_field(cfg, &["password"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(t) = str_field(cfg, &["transport"]).filter(|s| !s.is_empty()) {
        q.push(("transport".into(), t));
    }
    if let Some(m) = str_field(cfg, &["multiplexing"]).filter(|s| !s.is_empty()) {
        q.push(("multiplexing".into(), m));
    }
    if let Some(pr) = str_field(cfg, &["port-range", "portrange"]).filter(|s| !s.is_empty()) {
        q.push(("portRange".into(), pr));
    }
    let mut uri = format!("mieru://{username}:{password}@{server}:{port}");
    if !q.is_empty() {
        let query = q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_ssh_uri(cfg: &Value, node: &Node) -> Option<String> {
    let username = str_field(cfg, &["username", "user"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let password = str_field(cfg, &["password"]);
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(hk) = str_field(cfg, &["host-key", "host_key"]).filter(|s| !s.is_empty()) {
        q.push(("host-key".into(), hk));
    }
    // 私钥 PEM 多行文本 → base64 内联进查询串（无密码登录的节点也能完整分享）
    if let Some(pk) = str_field(cfg, &["private-key", "private_key"]).filter(|s| !s.is_empty()) {
        q.push(("private-key".into(), B64.encode(pk.as_bytes())));
    }
    let mut uri = match &password {
        Some(p) => format!("ssh://{username}:{p}@{server}:{port}"),
        None => format!("ssh://{username}@{server}:{port}"),
    };
    if !q.is_empty() {
        let query = q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_tailscale_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let authkey = str_field(cfg, &["auth-key", "authkey", "auth_key"]).unwrap_or_default();
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(h) = str_field(cfg, &["hostname"]).filter(|s| !s.is_empty()) {
        q.push(("hostname".into(), h));
    }
    if let Some(en) = str_field(cfg, &["exit-node", "exit_node"]).filter(|s| !s.is_empty()) {
        q.push(("exit-node".into(), en));
        if let Some(b) = cfg.get("exit-node-allow-lan").and_then(|v| v.as_bool()) {
            if b {
                q.push(("exit-node-allow-lan".into(), "1".into()));
            }
        }
    }
    if let Some(cu) = str_field(cfg, &["control-url", "control_url"]).filter(|s| !s.is_empty()) {
        q.push(("control-url".into(), cu));
    }
    let userinfo = if authkey.is_empty() {
        String::new()
    } else {
        format!("{authkey}@")
    };
    let mut uri = format!("tailscale://{userinfo}{server}:{port}");
    if !q.is_empty() {
        let query = q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_juicity_uri(cfg: &Value, node: &Node) -> Option<String> {
    let uuid = str_field(cfg, &["uuid"])?;
    let password = str_field(cfg, &["password"]).unwrap_or_default();
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = str_field(cfg, &["sni"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if let Some(cc) =
        str_field(cfg, &["congestion-control", "congestion_control"]).filter(|s| !s.is_empty())
    {
        q.push(("congestion_control".into(), cc));
    }
    if let Some(true) = cfg.get("insecure").and_then(|v| v.as_bool()) {
        q.push(("allow_insecure".into(), "1".into()));
    }
    if let Some(chain) =
        str_field(cfg, &["pinned-cert-chain", "pinned_cert_chain"]).filter(|s| !s.is_empty())
    {
        q.push(("pinned_cert_chain".into(), chain));
    }
    let mut uri = format!("juicity://{uuid}:{password}@{server}:{port}");
    if !q.is_empty() {
        let query = q
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
            .collect::<Vec<_>>()
            .join("&");
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

/// shadowtls://password@host:port?sni=..&version=..&next=<内层 ss 链接>#name
/// （cfg 为内层合并后的 ss + plugin 形态；无内层字段时输出存档形态）
fn rebuild_shadowtls_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let opts = cfg.get("plugin-opts").cloned().unwrap_or(Value::Null);
    let password = str_field(&opts, &["password"])
        .or_else(|| str_field(cfg, &["password"]).filter(|_| cfg.get("plugin").is_none()))?;
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(host) = str_field(&opts, &["host", "sni"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), host));
    }
    q.push((
        "version".into(),
        str_field(&opts, &["version"]).unwrap_or_else(|| "3".into()),
    ));
    // 内层 ss 链接（plugin 形态才携带 next=）
    if cfg.get("plugin").and_then(|v| v.as_str()) == Some("shadow-tls") {
        let method = str_field(cfg, &["cipher", "method"])?;
        let inner_password = str_field(cfg, &["password"])?;
        let userinfo = B64.encode(format!("{method}:{inner_password}"));
        let inner = format!("ss://{userinfo}@{server}:{port}");
        q.push(("next".into(), inner));
    }
    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("shadowtls://{password}@{server}:{port}?{query}");
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_vmess_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server", "add"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let uuid = str_field(cfg, &["uuid", "id"])?;
    let name = str_field(cfg, &["name", "ps"]).unwrap_or_else(|| node.name.clone());
    let network = str_field(cfg, &["network", "net"]).unwrap_or_else(|| "tcp".into());
    let tls = match cfg.get("tls") {
        Some(Value::Bool(true)) => "tls".to_string(),
        Some(Value::String(s)) if !s.is_empty() && s != "false" && s != "0" => s.clone(),
        _ => String::new(),
    };
    let aid = cfg
        .get("alterId")
        .or_else(|| cfg.get("aid"))
        .map(|v| match v {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => "0".into(),
        })
        .unwrap_or_else(|| "0".into());
    let cipher = str_field(cfg, &["cipher", "scy"]).unwrap_or_else(|| "auto".into());
    let path = ws_path(cfg)
        .or_else(|| str_field(cfg, &["path"]))
        .unwrap_or_default();
    let host = ws_host(cfg)
        .or_else(|| str_field(cfg, &["host"]))
        .unwrap_or_default();
    let sni = str_field(cfg, &["servername", "sni"]).unwrap_or_default();
    let alpn = match cfg.get("alpn") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    let payload = json!({
        "v": "2",
        "ps": name,
        "add": server,
        "port": port.to_string(),
        "id": uuid,
        "aid": aid,
        "scy": cipher,
        "net": network,
        "type": "none",
        "host": host,
        "path": path,
        "tls": tls,
        "sni": sni,
        "alpn": alpn,
    });
    let encoded = B64.encode(payload.to_string());
    Some(format!("vmess://{encoded}"))
}

fn rebuild_vless_uri(cfg: &Value, node: &Node) -> Option<String> {
    let uuid = str_field(cfg, &["uuid", "id"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let network = str_field(cfg, &["network", "net"]).unwrap_or_else(|| "tcp".into());
    let mut q: Vec<(String, String)> = Vec::new();
    q.push((
        "encryption".into(),
        str_field(cfg, &["encryption"]).unwrap_or_else(|| "none".into()),
    ));
    q.push(("type".into(), network.clone()));

    let is_reality = cfg.get("reality-opts").is_some()
        || str_field(cfg, &["security"]).as_deref() == Some("reality");
    let tls = match cfg.get("tls") {
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => {
            let s = s.to_ascii_lowercase();
            s == "tls" || s == "true" || s == "1" || s == "reality"
        }
        _ => is_reality,
    };
    if is_reality {
        q.push(("security".into(), "reality".into()));
        if let Some(pbk) = cfg
            .pointer("/reality-opts/public-key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| str_field(cfg, &["pbk"]))
            .filter(|s| !s.is_empty())
        {
            q.push(("pbk".into(), pbk));
        }
        if let Some(sid) = cfg
            .pointer("/reality-opts/short-id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| str_field(cfg, &["sid"]))
            .filter(|s| !s.is_empty())
        {
            q.push(("sid".into(), sid));
        }
    } else if tls {
        q.push(("security".into(), "tls".into()));
    }

    if let Some(sni) = str_field(cfg, &["servername", "sni"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if let Some(fp) = str_field(cfg, &["client-fingerprint", "fp"]).filter(|s| !s.is_empty()) {
        q.push(("fp".into(), fp));
    }
    if let Some(flow) = str_field(cfg, &["flow"]).filter(|s| !s.is_empty()) {
        q.push(("flow".into(), flow));
    }
    if let Some(path) = ws_path(cfg)
        .or_else(|| str_field(cfg, &["path"]))
        .filter(|s| !s.is_empty())
    {
        q.push(("path".into(), path));
    }
    if let Some(host) = ws_host(cfg)
        .or_else(|| str_field(cfg, &["host"]))
        .filter(|s| !s.is_empty())
    {
        q.push(("host".into(), host));
    }
    if network == "grpc" {
        if let Some(sn) = cfg
            .pointer("/grpc-opts/grpc-service-name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| str_field(cfg, &["serviceName"]))
            .filter(|s| !s.is_empty())
        {
            q.push(("serviceName".into(), sn));
        }
    }
    if let Some(alpn) = match cfg.get("alpn") {
        Some(Value::Array(a)) => {
            let s = a
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",");
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    } {
        q.push(("alpn".into(), alpn));
    }

    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("vless://{uuid}@{server}:{port}?{query}");
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_trojan_uri(cfg: &Value, node: &Node) -> Option<String> {
    let password = str_field(cfg, &["password"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = str_field(cfg, &["sni", "servername"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    let network = str_field(cfg, &["network"]).unwrap_or_else(|| "tcp".into());
    if network != "tcp" {
        q.push(("type".into(), network));
    }
    if let Some(path) = ws_path(cfg)
        .or_else(|| str_field(cfg, &["path"]))
        .filter(|s| !s.is_empty())
    {
        q.push(("path".into(), path));
    }
    if let Some(host) = ws_host(cfg)
        .or_else(|| str_field(cfg, &["host"]))
        .filter(|s| !s.is_empty())
    {
        q.push(("host".into(), host));
    }
    if matches!(cfg.get("skip-cert-verify"), Some(Value::Bool(true))) {
        q.push(("allowInsecure".into(), "1".into()));
    }
    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("trojan://{password}@{server}:{port}");
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_hysteria1_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let auth = str_field(cfg, &["auth", "auth-str", "auth_str", "password"]).unwrap_or_default();
    let mut q: Vec<(String, String)> = Vec::new();
    if !auth.is_empty() {
        q.push(("auth".into(), auth));
    }
    if let Some(sni) =
        str_field(cfg, &["sni", "peer", "server_name", "server-name"]).filter(|s| !s.is_empty())
    {
        q.push(("peer".into(), sni));
    }
    let insecure =
        extract_skip_cert_verify(cfg.as_object().unwrap_or(&serde_json::Map::new()), node);
    if insecure {
        q.push(("insecure".into(), "1".into()));
    }
    if let Some(up) = cfg.get("up").and_then(Value::as_u64) {
        q.push(("upmbps".into(), up.to_string()));
    }
    if let Some(down) = cfg.get("down").and_then(Value::as_u64) {
        q.push(("downmbps".into(), down.to_string()));
    }
    if let Some(proto) = str_field(cfg, &["protocol"]).filter(|s| !s.is_empty()) {
        q.push(("protocol".into(), proto));
    }
    if let Some(obfs) = str_field(cfg, &["obfs"]).filter(|s| !s.is_empty()) {
        q.push(("obfs".into(), obfs));
    }
    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("hysteria://{server}:{port}");
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_hysteria2_uri(cfg: &Value, node: &Node) -> Option<String> {
    let password = str_field(cfg, &["password", "auth", "auth-str"])?;
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = str_field(cfg, &["sni", "servername"]).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if let Some(obfs) = str_field(cfg, &["obfs"]).filter(|s| !s.is_empty()) {
        q.push(("obfs".into(), obfs));
    }
    if let Some(op) = str_field(cfg, &["obfs-password"]).filter(|s| !s.is_empty()) {
        q.push(("obfs-password".into(), op));
    }
    if let Some(mport) = str_field(cfg, &["mport", "ports"]).filter(|s| !s.is_empty()) {
        q.push(("mport".into(), mport));
    }
    if matches!(cfg.get("skip-cert-verify"), Some(Value::Bool(true)))
        || matches!(
            str_field(cfg, &["insecure"]).as_deref(),
            Some("1") | Some("true")
        )
    {
        q.push(("insecure".into(), "1".into()));
    }
    let query = q
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding_lite(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut uri = format!("hysteria2://{password}@{server}:{port}");
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(&query);
    }
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_socks_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let user = str_field(cfg, &["username"]).unwrap_or_default();
    let pass = str_field(cfg, &["password"]).unwrap_or_default();
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let mut uri = if user.is_empty() {
        format!("socks5://{server}:{port}")
    } else {
        format!("socks5://{user}:{pass}@{server}:{port}")
    };
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn rebuild_http_uri(cfg: &Value, node: &Node) -> Option<String> {
    let server = str_field(cfg, &["server"]).unwrap_or_else(|| node.server.clone());
    let port = port_field(cfg).unwrap_or(node.port);
    let user = str_field(cfg, &["username"]).unwrap_or_default();
    let pass = str_field(cfg, &["password"]).unwrap_or_default();
    let name = str_field(cfg, &["name"]).unwrap_or_else(|| node.name.clone());
    let tls = matches!(cfg.get("tls"), Some(Value::Bool(true)));
    let scheme = if tls { "https" } else { "http" };
    let mut uri = if user.is_empty() {
        format!("{scheme}://{server}:{port}")
    } else {
        format!("{scheme}://{user}:{pass}@{server}:{port}")
    };
    if !name.is_empty() {
        uri.push('#');
        uri.push_str(&urlencoding_lite(&name));
    }
    Some(uri)
}

fn ws_path(cfg: &Value) -> Option<String> {
    cfg.pointer("/ws-opts/path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ws_host(cfg: &Value) -> Option<String> {
    cfg.pointer("/ws-opts/headers/Host")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            cfg.pointer("/ws-opts/headers/host")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

fn str_field(cfg: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = cfg.get(*k) {
            match v {
                Value::String(s) if !s.is_empty() => return Some(s.clone()),
                Value::Number(n) => return Some(n.to_string()),
                Value::Bool(b) => return Some(b.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn port_field(cfg: &Value) -> Option<u16> {
    as_u16(cfg.get("port")?)
}

fn as_u16(v: &Value) -> Option<u16> {
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok();
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    None
}

fn first_str(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = obj.get(*k) {
            match v {
                Value::String(s) => return Some(s.clone()),
                Value::Number(n) => return Some(n.to_string()),
                Value::Bool(b) => return Some(b.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn coerce_numberish(v: Value) -> Value {
    match v {
        Value::Number(_) => v,
        Value::String(s) => s
            .parse::<i64>()
            .map(|n| json!(n))
            .unwrap_or(Value::String(s)),
        other => other,
    }
}

fn strip_empty_strings(obj: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(Value::String(s)) = obj.get(*k) {
            if s.is_empty() {
                obj.remove(*k);
            }
        }
    }
}

fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_node(protocol: &str, config: Value, raw: &str) -> Node {
        let now = Utc::now();
        Node {
            id: "1".into(),
            source_id: None,
            protocol: protocol.into(),
            name: config
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("n")
                .into(),
            server: config
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| config.get("add").and_then(|v| v.as_str()))
                .unwrap_or("1.2.3.4")
                .into(),
            port: config.get("port").and_then(as_u16).unwrap_or(443),
            raw: raw.into(),
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
    fn clash_type_ss_not_shadowsocks() {
        let node = sample_node(
            "shadowsocks",
            json!({
                "type": "shadowsocks",
                "server": "1.2.3.4",
                "port": 8388,
                "cipher": "aes-256-gcm",
                "password": "pw",
                "name": "ss1"
            }),
            "cipher: aes-256-gcm\n",
        );
        let proxies = nodes_to_clash_proxies(&[node]);
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0]["type"], "ss");
        assert_eq!(proxies[0]["cipher"], "aes-256-gcm");
    }

    #[test]
    fn clash_vmess_from_uri_config() {
        let node = sample_node(
            "vmess",
            json!({
                "add": "8.8.8.8",
                "id": "04621bae-ab36-11ec-b909-0242ac120002",
                "name": "v1",
                "net": "tcp",
                "port": 22324,
                "ps": "v1",
                "scy": "auto",
                "server": "8.8.8.8",
                "type": "vmess",
                "v": "2"
            }),
            "vmess://xxx",
        );
        let proxies = nodes_to_clash_proxies(&[node]);
        assert_eq!(proxies[0]["type"], "vmess");
        assert_eq!(proxies[0]["uuid"], "04621bae-ab36-11ec-b909-0242ac120002");
        assert_eq!(proxies[0]["server"], "8.8.8.8");
        assert_eq!(proxies[0]["network"], "tcp");
        assert!(proxies[0].get("add").is_none());
        assert!(proxies[0].get("id").is_none());
    }

    #[test]
    fn clash_vless_ws_tls() {
        let node = sample_node(
            "vless",
            json!({
                "type": "vless",
                "server": "1.1.1.1",
                "port": 443,
                "uuid": "f775978b-6e22-41a8-ae5e-5f9779e6745f",
                "name": "vl",
                "network": "ws",
                "security": "tls",
                "sni": "example.com",
                "host": "example.com",
                "path": "/ws",
                "encryption": "none"
            }),
            "vless://aaaaaaaa-bbbb-4ccc-8ddd-000000000003@1.1.1.1:443?type=ws",
        );
        let proxies = nodes_to_clash_proxies(&[node]);
        assert_eq!(proxies[0]["type"], "vless");
        assert_eq!(proxies[0]["tls"], true);
        assert_eq!(proxies[0]["network"], "ws");
        assert_eq!(proxies[0]["ws-opts"]["path"], "/ws");
        assert_eq!(proxies[0]["ws-opts"]["headers"]["Host"], "example.com");
        assert_eq!(proxies[0]["servername"], "example.com");
        assert!(proxies[0].get("security").is_none());
    }

    #[test]
    fn clash_vless_ech_name_plus_doh() {
        // 分享链接 `ech=查询名+DoH URL` 应转成 ech-opts（mihomo / VP-Core 同语法）
        let node = sample_node(
            "vless",
            json!({
                "type": "vless",
                "server": "www.visa.cn",
                "port": 443,
                "uuid": "dffc2650-0fc4-450e-8c0e-19de6d5345b1",
                "name": "ech-node",
                "network": "ws",
                "security": "tls",
                "sni": "loukas.ccwu.cc",
                "host": "loukas.ccwu.cc",
                "path": "/",
                "ech": "cloudflare-ech.com+https://dns.alidns.com/dns-query"
            }),
            "vless://dffc2650-0fc4-450e-8c0e-19de6d5345b1@www.visa.cn:443?security=tls&type=ws&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query&host=loukas.ccwu.cc&sni=loukas.ccwu.cc&path=%2F",
        );
        let proxies = nodes_to_clash_proxies(&[node]);
        let eo = &proxies[0]["ech-opts"];
        assert_eq!(eo["enable"], true, "{:?}", proxies[0]);
        assert_eq!(eo["query-server-name"], "cloudflare-ech.com");
        assert_eq!(eo["doh"], "https://dns.alidns.com/dns-query");
        assert!(proxies[0].get("ech").is_none(), "原始 ech 字段应被消费掉");
    }

    #[test]
    fn uri_rebuild_from_yaml_ss() {
        let node = sample_node(
            "shadowsocks",
            json!({
                "type": "shadowsocks",
                "server": "1.2.3.4",
                "port": 443,
                "cipher": "aes-256-cfb",
                "password": "pw",
                "name": "ss-yaml"
            }),
            "cipher: aes-256-cfb\nname: ss-yaml\n",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("ss://"));
        assert!(uris[0].contains("@1.2.3.4:443"));
    }

    #[test]
    fn unique_proxy_names() {
        let n1 = sample_node(
            "trojan",
            json!({"type":"trojan","server":"1.1.1.1","port":443,"password":"p","name":"same"}),
            "trojan://p@1.1.1.1:443#same",
        );
        let n2 = sample_node(
            "trojan",
            json!({"type":"trojan","server":"2.2.2.2","port":443,"password":"p","name":"same"}),
            "trojan://p@2.2.2.2:443#same",
        );
        let proxies = nodes_to_clash_proxies(&[n1, n2]);
        assert_eq!(proxies[0]["name"], "same");
        assert_eq!(proxies[1]["name"], "same-2");
    }

    #[test]
    fn rebuild_mislabeled_ss_raw_as_vless() {
        // protocol/config say vless, but raw still has ss://
        let node = sample_node(
            "vless",
            json!({
                "type": "vless",
                "server": "203.0.113.200",
                "port": 80,
                "uuid": "11111111-2222-4333-8444-555555555555",
                "name": "fix-me",
                "network": "ws",
                "security": "none",
                "host": "example.org",
                "path": "/?ed=2080",
                "encryption": "none"
            }),
            "ss://11111111-2222-4333-8444-555555555555@203.0.113.200:80?path=%2F&security=none&type=ws#bad",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("vless://"), "got {}", uris[0]);
        assert!(uris[0].contains("type=ws"));
        assert!(uris[0].contains("11111111-2222-4333-8444-555555555555@203.0.113.200:80"));
    }

    #[test]
    fn skip_cert_verify_propagation() {
        let node_hy2 = sample_node(
            "hysteria2",
            json!({
                "type": "hysteria2",
                "server": "1.1.1.1",
                "port": 443,
                "password": "pw",
                "sni": "bing.com",
                "skip-cert-verify": true
            }),
            "skip-cert-verify: true\n",
        );
        let proxies = nodes_to_clash_proxies(&[node_hy2]);
        assert_eq!(proxies[0]["skip-cert-verify"], json!(true));

        let node_trojan = sample_node(
            "trojan",
            json!({
                "type": "trojan",
                "server": "1.1.1.1",
                "port": 443,
                "password": "pw",
                "allowInsecure": true
            }),
            "",
        );
        let proxies = nodes_to_clash_proxies(&[node_trojan]);
        assert_eq!(proxies[0]["skip-cert-verify"], json!(true));

        let node_hy1 = sample_node(
            "hysteria",
            json!({
                "type": "hysteria",
                "server": "198.200.57.142",
                "port": 22335,
                "auth-str": "token123",
                "protocol": "udp",
                "skip-cert-verify": true
            }),
            "",
        );
        let proxies = nodes_to_clash_proxies(&[node_hy1]);
        assert_eq!(proxies[0]["type"], "hysteria");
        assert_eq!(proxies[0]["auth-str"], "token123");
        assert_eq!(proxies[0]["auth_str"], "token123");
        assert_eq!(proxies[0]["skip-cert-verify"], json!(true));
        assert_eq!(proxies[0]["alpn"], json!(["h3"]));
        assert_eq!(proxies[0]["protocol"], "udp");
    }

    #[test]
    fn rebuild_hysteria1_share_uri() {
        let node = sample_node(
            "hysteria",
            json!({
                "type": "hysteria",
                "server": "1.2.3.4",
                "port": 22335,
                "auth": "secret",
                "name": "my-hy1",
                "protocol": "udp",
                "skip-cert-verify": true
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("hysteria://1.2.3.4:22335"));
        assert!(uris[0].contains("auth=secret"));
        assert!(uris[0].contains("insecure=1"));
        assert!(uris[0].contains("#my-hy1"));
    }

    #[test]
    fn rebuild_snell_share_uri() {
        let node = sample_node(
            "snell",
            json!({
                "type": "snell",
                "server": "5.6.7.8",
                "port": 6160,
                "psk": "psk-secret",
                "version": 4,
                "name": "my-snell"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("snell://psk-secret@5.6.7.8:6160"));
        assert!(uris[0].contains("version=4"));
        assert!(uris[0].contains("#my-snell"));
    }

    #[test]
    fn rebuild_naive_share_uri() {
        let node = sample_node(
            "naive",
            json!({
                "type": "naive",
                "server": "9.9.9.9",
                "port": 443,
                "username": "alice",
                "password": "wonder",
                "sni": "naive.example.com",
                "name": "my-naive"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("naive+https://alice:wonder@9.9.9.9:443"));
        assert!(uris[0].contains("sni=naive.example.com"));
        assert!(uris[0].contains("#my-naive"));
    }

    #[test]
    fn rebuild_mieru_share_uri() {
        let node = sample_node(
            "mieru",
            json!({
                "type": "mieru",
                "server": "7.7.7.7",
                "port": 28888,
                "username": "bob",
                "password": "builder",
                "transport": "wss",
                "multiplexing": "QUIC",
                "name": "my-mieru"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("mieru://bob:builder@7.7.7.7:28888"));
        assert!(uris[0].contains("transport=wss"));
        assert!(uris[0].contains("multiplexing=QUIC"));
        assert!(uris[0].contains("#my-mieru"));
    }

    #[test]
    fn rebuild_ssh_share_uri() {
        let node = sample_node(
            "ssh",
            json!({
                "type": "ssh",
                "server": "8.8.8.8",
                "port": 22,
                "username": "root",
                "password": "toor",
                "name": "my-ssh"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("ssh://root:toor@8.8.8.8:22"));
        assert!(uris[0].contains("#my-ssh"));
    }

    #[test]
    fn openvpn_node_exports_full_config() {
        let node = Node {
            id: "ovpn-1".into(),
            source_id: None,
            name: "家宽JP".into(),
            protocol: "openvpn".into(),
            server: "158.217.184.31".into(),
            port: 995,
            raw: String::new(),
            config: serde_json::json!({
                "type": "openvpn",
                "server": "158.217.184.31",
                "port": 995,
                "proto": "tcp",
                "udp": false,
                "username": "vpn",
                "password": "vpn",
                "ca": "-----BEGIN CERTIFICATE-----
MIIBtest
-----END CERTIFICATE-----",
                "cert": "-----BEGIN CERTIFICATE-----
MIIBcert
-----END CERTIFICATE-----",
                "key": "-----BEGIN PRIVATE KEY-----
MIIBkey
-----END PRIVATE KEY-----"
            }),
            country: None,
            latency_ms: None,
            latency_ok: None,
            download_kbps: None,
            latency_kernel: None,
            latency_test_kind: None,
            latency_tested_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let proxies = nodes_to_clash_proxies(std::slice::from_ref(&node));
        assert_eq!(proxies.len(), 1, "openvpn 节点应直通导出");
        let p = &proxies[0];
        assert_eq!(p["type"], "openvpn");
        assert_eq!(p["proto"], "tcp");
        assert_eq!(p["username"], "vpn");
        assert!(p["ca"].as_str().unwrap().contains("MIIBtest"));
        assert!(p["key"].as_str().unwrap().contains("MIIBkey"));
    }

    #[test]
    fn rebuild_juicity_share_uri() {
        let node = sample_node(
            "juicity",
            json!({
                "type": "juicity",
                "server": "6.6.6.6",
                "port": 8443,
                "uuid": "b54d39f7-9204-4680-ba76-2e84c59ff06a",
                "password": "juice",
                "sni": "jc.example.com",
                "congestion-control": "bbr",
                "name": "my-juicity"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0]
            .starts_with("juicity://b54d39f7-9204-4680-ba76-2e84c59ff06a:juice@6.6.6.6:8443"));
        assert!(uris[0].contains("sni=jc.example.com"));
        assert!(uris[0].contains("congestion_control=bbr"));
        assert!(uris[0].contains("#my-juicity"));
    }

    #[test]
    fn rebuild_shadowtls_merged_share_uri() {
        let node = sample_node(
            "shadowsocks",
            json!({
                "type": "ss",
                "server": "st.example.com",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "sspass",
                "plugin": "shadow-tls",
                "plugin-opts": {
                    "host": "www.apple.com",
                    "password": "stls-pass",
                    "version": 3
                },
                "name": "my-stls"
            }),
            "",
        );
        let uris = nodes_to_share_uris(&[node]);
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("shadowtls://stls-pass@st.example.com:443"));
        assert!(uris[0].contains("sni=www.apple.com"));
        assert!(uris[0].contains("version=3"));
        // 内层 ss 链接以 next= 形式携带（URL 编码）
        assert!(uris[0].contains("next=ss%3A%2F%2F"));
        assert!(uris[0].contains("#my-stls"));

        // 导出的链接应能被解析器无损还原
        let parsed = crate::parser::parse_uri(&uris[0], None).expect("round-trip parse");
        assert_eq!(parsed.protocol, "shadowsocks");
        assert_eq!(parsed.server, "st.example.com");
        assert_eq!(
            parsed.config.get("cipher").and_then(|v| v.as_str()),
            Some("aes-128-gcm")
        );
        assert_eq!(
            parsed.config.get("password").and_then(|v| v.as_str()),
            Some("sspass")
        );
    }
}
