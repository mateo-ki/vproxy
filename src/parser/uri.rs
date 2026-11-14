use super::common::{
    decode_base64_str, looks_like_uuid, normalize_uri, parse_authority, parse_query,
    percent_decode, split_host_port, split_userinfo_hostport, strip_query_fragment,
};
use super::make_node;
use crate::models::Node;
use serde_json::json;
use url::Url;

pub fn parse_uri(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let uri = normalize_uri(uri);
    let lower = uri.to_ascii_lowercase();

    // Some subscription dumps mislabel VLESS/VMess links as ss://
    if lower.starts_with("ss://") {
        if let Some(node) = try_parse_mislabeled_ss_as_vless(&uri, source_id) {
            return Some(node);
        }
        if let Some(node) = try_parse_mislabeled_ss_as_vmess(&uri, source_id) {
            return Some(node);
        }
        return parse_ss(&uri, source_id);
    }
    if lower.starts_with("vmess://") {
        return parse_vmess(&uri, source_id);
    }
    if lower.starts_with("vless://") {
        return parse_vless(&uri, source_id);
    }
    if lower.starts_with("trojan://") {
        return parse_trojan(&uri, source_id);
    }
    if lower.starts_with("tuic://") {
        return parse_tuic(&uri, source_id);
    }
    if lower.starts_with("ssr://") || lower.starts_with("shadowsocksr://") {
        return parse_ssr(&uri, source_id);
    }
    if lower.starts_with("wireguard://") || lower.starts_with("wg://") {
        return parse_wireguard(&uri, source_id);
    }
    if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        return parse_hysteria2(&uri, source_id);
    }
    if lower.starts_with("hysteria://") {
        return parse_hysteria1(&uri, source_id);
    }
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return parse_socks(&uri, source_id);
    }
    if lower.starts_with("masque://") {
        return super::warp_masque::parse_masque_uri(&uri, source_id);
    }
    if lower.starts_with("snell://") {
        return parse_snell(&uri, source_id);
    }
    if lower.starts_with("naive+https://")
        || lower.starts_with("naive+quic://")
        || lower.starts_with("naive://")
    {
        return parse_naive(&uri, source_id);
    }
    if lower.starts_with("mieru://") {
        return parse_mieru(&uri, source_id);
    }
    if lower.starts_with("ssh://") {
        return parse_ssh(&uri, source_id);
    }
    if lower.starts_with("tailscale://") {
        return parse_tailscale(&uri, source_id);
    }
    if lower.starts_with("juicity://") {
        return parse_juicity(&uri, source_id);
    }
    if lower.starts_with("shadowtls://") {
        return parse_shadowtls(&uri, source_id);
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        // Only treat as proxy URI when it has userinfo (proxy auth style)
        if let Ok(u) = Url::parse(&uri) {
            if u.username().is_empty() {
                return None;
            }
            return parse_http_proxy(&uri, source_id);
        }
    }
    None
}

/// ss://uuid@host:port?type=ws&security=tls... is often a mislabeled vless link.
fn try_parse_mislabeled_ss_as_vless(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri.trim_start_matches("ss://").trim_start_matches("SS://");
    let (body, _) = split_fragment(rest);
    if !body.contains('@') || !body.contains('?') {
        return None;
    }
    let (userinfo, hostport) = body.split_once('@')?;
    let userinfo = strip_query_fragment(userinfo);
    // UUID-like, or plain user with vless-style query.
    let q = body.split_once('?').map(|(_, q)| q).unwrap_or("");
    let ql = q.to_ascii_lowercase();
    let vless_like = ql.contains("security=")
        || ql.contains("encryption=")
        || ql.contains("type=")
        || ql.contains("sni=")
        || ql.contains("path=");
    if !vless_like {
        return None;
    }
    if !looks_like_uuid(userinfo) && !userinfo.contains(':') {
        // username@host with vless query params (common mislabel)
    } else if !looks_like_uuid(userinfo) {
        return None;
    }
    let _ = split_host_port(hostport)?;
    let rewritten = format!("vless://{rest}");
    parse_vless(&rewritten, source_id).map(|mut n| {
        n.raw = uri.to_string();
        n
    })
}

/// ss://eyJ... base64 JSON is often a mislabeled vmess payload.
fn try_parse_mislabeled_ss_as_vmess(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri.trim_start_matches("ss://").trim_start_matches("SS://");
    let (body, _) = split_fragment(rest);
    // Only attempt when body looks like base64 JSON (starts with eyJ after optional pad).
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let looks_json_b64 = cleaned.starts_with("eyJ") || cleaned.starts_with("eyj");
    if !looks_json_b64 {
        return None;
    }
    let rewritten = format!("vmess://{cleaned}");
    parse_vmess(&rewritten, source_id).map(|mut n| {
        n.raw = uri.to_string();
        n
    })
}

fn parse_ss(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri.trim_start_matches("ss://").trim_start_matches("SS://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.as_deref().map(percent_decode).unwrap_or_default();

    // SIP002: ss://base64(method:password)@host:port#name
    //          ss://base64(method:password)@host:port/?plugin=...#name
    // Legacy: ss://base64(method:password@host:port)#name
    if body.contains('@') {
        let (userinfo, host, port) = split_userinfo_hostport(body)?;
        let userinfo_decoded = decode_base64_str(&userinfo).unwrap_or_else(|| userinfo.clone());
        let (method, password) = if let Some(pair) = userinfo_decoded.split_once(':') {
            pair
        } else {
            // userinfo is raw password without method (rare) — skip
            return None;
        };

        let query = body.split_once('?').map(|(_, q)| q).unwrap_or("");
        let q = parse_query(query);
        let mut config = json!({
            "type": "ss",
            "server": host,
            "port": port,
            "cipher": method,
            "password": password,
            "name": name,
        });
        if let Some(obj) = config.as_object_mut() {
            if let Some(plugin) = q.get("plugin") {
                obj.insert("plugin".into(), json!(plugin));
            }
            if let Some(plugin_opts) = q.get("plugin-opts").or_else(|| q.get("plugin_opts")) {
                obj.insert("plugin-opts".into(), json!(plugin_opts));
            }
        }
        return Some(make_node(
            "shadowsocks",
            &name,
            &host,
            port,
            uri,
            config,
            source_id,
        ));
    }

    // legacy full base64, or mislabeled vmess json base64
    let decoded = decode_base64_str(body)?;
    if decoded.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&decoded) {
            if v.get("add").is_some() || v.get("id").is_some() {
                let rewritten = format!("vmess://{body}");
                return parse_vmess(&rewritten, source_id).map(|mut n| {
                    n.raw = uri.to_string();
                    n
                });
            }
        }
    }
    // method:password@host:port
    let (method_pass, hostport) = decoded.rsplit_once('@')?;
    let (method, password) = method_pass.split_once(':')?;
    let (host, port_s) = split_host_port(hostport)?;
    let port: u16 = port_s.parse().ok()?;
    let config = json!({
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "name": name,
    });
    Some(make_node(
        "shadowsocks",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

fn parse_vmess(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("vmess://")
        .trim_start_matches("VMESS://");
    let rest = rest.split(['#', '?']).next().unwrap_or(rest);
    let decoded = decode_base64_str(rest)?;
    let v: serde_json::Value = serde_json::from_str(&decoded).ok()?;
    let server = v
        .get("add")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("server").and_then(|x| x.as_str()))?
        .to_string();
    let port = v
        .get("port")
        .and_then(parse_port_value)
        .or_else(|| v.get("server_port").and_then(parse_port_value))?;
    let name = v
        .get("ps")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("remark").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let mut config = v;
    if let Some(obj) = config.as_object_mut() {
        obj.insert("type".into(), json!("vmess"));
        obj.insert("server".into(), json!(server));
        obj.insert("port".into(), json!(port));
        obj.insert("name".into(), json!(name));
    }
    Some(make_node(
        "vmess", &name, &server, port, uri, config, source_id,
    ))
}

fn parse_vless(uri: &str, source_id: Option<&str>) -> Option<Node> {
    if let Ok(url) = Url::parse(uri) {
        let uuid = percent_decode(url.username());
        if uuid.is_empty() {
            return None;
        }
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(443);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        return Some(vless_node(uri, source_id, &uuid, &host, port, &name, q));
    }

    // Fallback for odd fragments / encoding that Url rejects.
    let (_scheme, uuid, port, host, query, name) = parse_authority(uri)?;
    if uuid.is_empty() {
        return None;
    }
    let q = parse_query(&query);
    Some(vless_node(uri, source_id, &uuid, &host, port, &name, q))
}

fn vless_node(
    uri: &str,
    source_id: Option<&str>,
    uuid: &str,
    host: &str,
    port: u16,
    name: &str,
    q: std::collections::HashMap<String, String>,
) -> Node {
    let config = json!({
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid,
        "name": name,
        "flow": q.get("flow").cloned().unwrap_or_default(),
        "encryption": q.get("encryption").cloned().unwrap_or_else(|| "none".into()),
        "network": q.get("type").cloned().unwrap_or_else(|| "tcp".into()),
        "security": q.get("security").cloned().unwrap_or_default(),
        "sni": q.get("sni").cloned().unwrap_or_default(),
        "fp": q.get("fp").cloned().unwrap_or_default(),
        "pbk": q.get("pbk").cloned().unwrap_or_default(),
        "sid": q.get("sid").cloned().unwrap_or_default(),
        "path": q.get("path").cloned().unwrap_or_default(),
        "host": q.get("host").cloned().unwrap_or_default(),
        "serviceName": q.get("serviceName").cloned().unwrap_or_default(),
        "alpn": q.get("alpn").cloned().unwrap_or_default(),
        // ECH（Encrypted Client Hello）请求：`<HTTPS(type65) 查询名>+<DoH URL>`
        // 或裸查询名；导出时转成内核的 ech-opts。
        "ech": q.get("ech").cloned().unwrap_or_default(),
        // 查询参数来自订阅链接本身，不能让它关掉证书校验。
        "allowInsecure": json!(false),
    });
    make_node("vless", name, host, port, uri, config, source_id)
}

fn parse_trojan(uri: &str, source_id: Option<&str>) -> Option<Node> {
    if let Ok(url) = Url::parse(uri) {
        let password = percent_decode(url.username());
        if password.is_empty() {
            return None;
        }
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(443);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        return Some(trojan_node(
            uri, source_id, &password, &host, port, &name, q,
        ));
    }
    let (_scheme, password, port, host, query, name) = parse_authority(uri)?;
    if password.is_empty() {
        return None;
    }
    let q = parse_query(&query);
    Some(trojan_node(
        uri, source_id, &password, &host, port, &name, q,
    ))
}

fn trojan_node(
    uri: &str,
    source_id: Option<&str>,
    password: &str,
    host: &str,
    port: u16,
    name: &str,
    q: std::collections::HashMap<String, String>,
) -> Node {
    let config = json!({
        "type": "trojan",
        "server": host,
        "port": port,
        "password": password,
        "name": name,
        "sni": q.get("sni").cloned().unwrap_or_default(),
        "network": q.get("type").cloned().unwrap_or_else(|| "tcp".into()),
        "security": q.get("security").cloned().unwrap_or_else(|| "tls".into()),
        "fp": q.get("fp").cloned().unwrap_or_default(),
        "alpn": q.get("alpn").cloned().unwrap_or_default(),
        "ech": q.get("ech").cloned().unwrap_or_default(),
        "path": q.get("path").cloned().unwrap_or_default(),
        "host": q.get("host").cloned().unwrap_or_default(),
        // 查询参数来自订阅链接本身，不能让它关掉证书校验。
        "allowInsecure": json!(false),
    });
    make_node("trojan", name, host, port, uri, config, source_id)
}

fn parse_hysteria2(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let normalized =
        uri.replacen("hy2://", "hysteria2://", 1)
            .replacen("HY2://", "hysteria2://", 1);
    if let Ok(url) = Url::parse(&normalized) {
        let auth = percent_decode(url.username());
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(443);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        let mut config = json!({
            "type": "hysteria2",
            "server": host,
            "port": port,
            "password": auth,
            "name": name,
            "sni": q.get("sni").cloned().unwrap_or_default(),
            "insecure": json!(false),
            "obfs": q.get("obfs").cloned().unwrap_or_default(),
            "obfs-password": q.get("obfs-password").cloned().unwrap_or_default(),
            "udp": json!(true),
        });
        if let Some(mport) = q
            .get("mport")
            .or_else(|| q.get("ports"))
            .filter(|s| !s.is_empty())
        {
            config["ports"] = json!(mport);
        }
        return Some(make_node(
            "hysteria2",
            &name,
            &host,
            port,
            uri,
            config,
            source_id,
        ));
    }
    let (_scheme, auth, port, host, query, name) = parse_authority(&normalized)?;
    let q = parse_query(&query);
    let mut config = json!({
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": auth,
        "name": name,
        "sni": q.get("sni").cloned().unwrap_or_default(),
        "insecure": json!(false),
        "obfs": q.get("obfs").cloned().unwrap_or_default(),
        "obfs-password": q.get("obfs-password").cloned().unwrap_or_default(),
        "udp": json!(true),
    });
    if let Some(mport) = q
        .get("mport")
        .or_else(|| q.get("ports"))
        .filter(|s| !s.is_empty())
    {
        config["ports"] = json!(mport);
    }
    Some(make_node(
        "hysteria2",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

fn parse_socks(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let url = Url::parse(uri).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(1080);
    let name = url.fragment().map(percent_decode).unwrap_or_default();
    let username = url.username().to_string();
    let password = url.password().map(percent_decode).unwrap_or_default();
    let config = json!({
        "type": "socks5",
        "server": host,
        "port": port,
        "username": username,
        "password": password,
        "name": name,
    });
    Some(make_node(
        "socks5", &name, &host, port, uri, config, source_id,
    ))
}

fn parse_http_proxy(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let url = Url::parse(uri).ok()?;
    let host = url.host_str()?.to_string();
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let name = url.fragment().map(percent_decode).unwrap_or_default();
    let username = url.username().to_string();
    let password = url.password().map(percent_decode).unwrap_or_default();
    let config = json!({
        "type": "http",
        "server": host,
        "port": port,
        "username": username,
        "password": password,
        "tls": url.scheme() == "https",
        "name": name,
    });
    Some(make_node(
        "http", &name, &host, port, uri, config, source_id,
    ))
}

fn parse_tuic(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let (mut uuid, mut password, host, port, name, q) = if let Ok(url) = Url::parse(uri) {
        let u = percent_decode(url.username());
        let p = url.password().map(percent_decode).unwrap_or_default();
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(443);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        (u, p, host, port, name, q)
    } else {
        let (_scheme, auth, port, host, query, name) = parse_authority(uri)?;
        let q = parse_query(&query);
        let (u, p) = if let Some((u, p)) = auth.split_once(':') {
            (u.to_string(), p.to_string())
        } else {
            (auth, String::new())
        };
        (u, p, host, port, name, q)
    };

    if password.is_empty() {
        if let Some((u, p)) = uuid.split_once(':') {
            let u_str = u.to_string();
            password = p.to_string();
            uuid = u_str;
        } else if let Some(p) = q.get("password").or_else(|| q.get("pass")) {
            password = p.clone();
        }
    }

    let name = if name.is_empty() {
        q.get("remarks")
            .cloned()
            .unwrap_or_else(|| format!("{}:{}", host, port))
    } else {
        name
    };

    let sni = q
        .get("sni")
        .or_else(|| q.get("server_name"))
        .cloned()
        .unwrap_or_else(|| host.clone());

    let alpn = if let Some(a) = q.get("alpn") {
        if a.contains(',') {
            a.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        } else if !a.is_empty() {
            vec![a.clone()]
        } else {
            vec!["h3".to_string()]
        }
    } else {
        vec!["h3".to_string()]
    };

    let congestion_control = q
        .get("congestion_control")
        .or_else(|| q.get("congestion-controller"))
        .or_else(|| q.get("cc"))
        .cloned()
        .unwrap_or_else(|| "bbr".to_string());

    let udp_relay_mode = q
        .get("udp_relay_mode")
        .or_else(|| q.get("udp-relay-mode"))
        .cloned()
        .unwrap_or_else(|| "native".to_string());

    let config = json!({
        "type": "tuic",
        "server": host,
        "port": port,
        "uuid": uuid,
        "password": password,
        "name": name,
        "sni": sni,
        "alpn": alpn,
        "congestion-controller": congestion_control,
        "congestion_control": congestion_control,
        "udp-relay-mode": udp_relay_mode,
        "udp_relay_mode": udp_relay_mode,
        "allowInsecure": json!(false),
        "insecure": json!(false),
    });

    Some(make_node(
        "tuic", &name, &host, port, uri, config, source_id,
    ))
}

fn parse_ssr(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let raw_b64 = uri
        .trim_start_matches("ssr://")
        .trim_start_matches("SSR://")
        .trim_start_matches("shadowsocksr://")
        .trim_start_matches("SHADOWSOCKSR://");
    let (b64_part, _) = split_fragment(raw_b64);
    let decoded = decode_base64_str(b64_part)?;

    let (main_part, query_part) = match decoded.split_once("/?") {
        Some((m, q)) => (m, Some(q)),
        None => match decoded.split_once('?') {
            Some((m, q)) => (m, Some(q)),
            None => (decoded.as_str(), None),
        },
    };

    // main_part: host:port:protocol:method:obfs:base64pass
    // rsplitn(6, ':') handles IPv6 host or colons in host correctly
    let parts: Vec<&str> = main_part.rsplitn(6, ':').collect();
    if parts.len() < 6 {
        return None;
    }
    let base64pass = parts[0];
    let obfs = parts[1].to_string();
    let method = parts[2].to_string();
    let protocol = parts[3].to_string();
    let port: u16 = parts[4].parse().ok()?;
    let host = parts[5].trim_matches('[').trim_matches(']').to_string();

    let password = decode_base64_str(base64pass).unwrap_or_else(|| base64pass.to_string());

    let q = parse_query(query_part.unwrap_or(""));

    let obfs_param = q
        .get("obfsparam")
        .and_then(|p| decode_base64_str(p))
        .unwrap_or_else(|| q.get("obfsparam").cloned().unwrap_or_default());

    let proto_param = q
        .get("protoparam")
        .and_then(|p| decode_base64_str(p))
        .unwrap_or_else(|| q.get("protoparam").cloned().unwrap_or_default());

    let name = q
        .get("remarks")
        .and_then(|r| decode_base64_str(r))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}:{}", host, port));

    let config = json!({
        "type": "ssr",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
        "protocol": protocol,
        "protocol-param": proto_param,
        "protocolparam": proto_param,
        "obfs": obfs,
        "obfs-param": obfs_param,
        "obfsparam": obfs_param,
        "name": name,
    });

    Some(make_node(
        "shadowsocksr",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

fn parse_wireguard(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let normalized = uri
        .replacen("wg://", "wireguard://", 1)
        .replacen("WG://", "wireguard://", 1);
    let (mut private_key, host, port, name, q) = if let Ok(url) = Url::parse(&normalized) {
        let pk = percent_decode(url.username());
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(51820);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        (pk, host, port, name, q)
    } else {
        let (_scheme, auth, port, host, query, name) = parse_authority(&normalized)?;
        let q = parse_query(&query);
        (auth, host, port, name, q)
    };

    if private_key.is_empty() {
        if let Some(pk) = q
            .get("privatekey")
            .or_else(|| q.get("private-key"))
            .or_else(|| q.get("private_key"))
        {
            private_key = pk.clone();
        }
    }

    let public_key = q
        .get("publickey")
        .or_else(|| q.get("public-key"))
        .or_else(|| q.get("public_key"))
        .or_else(|| q.get("peer_public_key"))
        .or_else(|| q.get("pubkey"))
        .cloned()
        .unwrap_or_default();

    let name = if name.is_empty() {
        q.get("name")
            .or_else(|| q.get("remarks"))
            .cloned()
            .unwrap_or_else(|| format!("{}:{}", host, port))
    } else {
        name
    };

    let mut address_list = Vec::new();
    if let Some(addr_str) = q
        .get("address")
        .or_else(|| q.get("ip"))
        .or_else(|| q.get("local_address"))
        .or_else(|| q.get("local-address"))
    {
        for item in addr_str.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() {
                address_list.push(trimmed.to_string());
            }
        }
    }
    if address_list.is_empty() {
        address_list.push("172.16.0.2/32".to_string());
    }

    let pre_shared_key = q
        .get("presharedkey")
        .or_else(|| q.get("pre-shared-key"))
        .or_else(|| q.get("pre_shared_key"))
        .or_else(|| q.get("psk"))
        .cloned();

    let reserved: Option<Vec<u64>> = q.get("reserved").and_then(|res_str| {
        let items: Vec<u64> = res_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .collect();
        if items.is_empty() {
            None
        } else {
            Some(items)
        }
    });

    let mtu: Option<u64> = q.get("mtu").and_then(|m| m.parse::<u64>().ok());

    let mut config = json!({
        "type": "wireguard",
        "server": host,
        "port": port,
        "name": name,
        "private-key": private_key,
        "public-key": public_key,
        "ip": address_list,
        "address": address_list,
    });

    if let Some(obj) = config.as_object_mut() {
        if let Some(psk) = pre_shared_key {
            obj.insert("pre-shared-key".into(), json!(psk));
        }
        if let Some(res) = reserved {
            obj.insert("reserved".into(), json!(res));
        }
        if let Some(m) = mtu {
            obj.insert("mtu".into(), json!(m));
        }
    }

    Some(make_node(
        "wireguard",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

fn parse_hysteria1(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let (mut auth, host, port, name, q) = if let Ok(url) = Url::parse(uri) {
        let auth = percent_decode(url.username());
        let host = url.host_str()?.to_string();
        let port = url.port().unwrap_or(443);
        let name = url.fragment().map(percent_decode).unwrap_or_default();
        let q = parse_query(url.query().unwrap_or(""));
        (auth, host, port, name, q)
    } else {
        let (_scheme, auth, port, host, query, name) = parse_authority(uri)?;
        let q = parse_query(&query);
        (auth, host, port, name, q)
    };

    if auth.is_empty() {
        if let Some(a) = q
            .get("auth")
            .or_else(|| q.get("auth_str"))
            .or_else(|| q.get("auth-str"))
        {
            auth = a.clone();
        }
    }

    let name = if name.is_empty() {
        q.get("name")
            .or_else(|| q.get("remarks"))
            .cloned()
            .unwrap_or_else(|| format!("{}:{}", host, port))
    } else {
        name
    };

    let peer = q
        .get("peer")
        .or_else(|| q.get("sni"))
        .or_else(|| q.get("server_name"))
        .cloned()
        .unwrap_or_else(|| host.clone());

    let up = q
        .get("upmbps")
        .or_else(|| q.get("up_mbps"))
        .or_else(|| q.get("up"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(100);

    let down = q
        .get("downmbps")
        .or_else(|| q.get("down_mbps"))
        .or_else(|| q.get("down"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(500);

    let obfs = q.get("obfs").cloned().unwrap_or_default();
    let protocol = q
        .get("protocol")
        .cloned()
        .unwrap_or_else(|| "udp".to_string());

    let insecure = q
        .get("insecure")
        .or_else(|| q.get("allowInsecure"))
        .or_else(|| q.get("allow_insecure"))
        .or_else(|| q.get("skip-cert-verify"))
        .or_else(|| q.get("skip_cert_verify"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let alpn = if let Some(a) = q.get("alpn") {
        if a.contains(',') {
            a.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        } else if !a.is_empty() {
            vec![a.clone()]
        } else {
            vec!["h3".to_string()]
        }
    } else {
        vec!["h3".to_string()]
    };

    let config = json!({
        "type": "hysteria",
        "server": host,
        "port": port,
        "name": name,
        "auth": auth,
        "auth-str": auth,
        "auth_str": auth,
        "server-name": peer,
        "sni": peer,
        "up": up,
        "down": down,
        "obfs": obfs,
        "protocol": protocol,
        "alpn": alpn,
        "skip-cert-verify": json!(insecure),
        "insecure": json!(insecure),
        "allowInsecure": json!(insecure),
    });

    Some(make_node(
        "hysteria", &name, &host, port, uri, config, source_id,
    ))
}

fn split_fragment(s: &str) -> (&str, Option<&str>) {
    match s.split_once('#') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    }
}

// ---------------------------------------------------------------------------
// snell / naive / mieru / ssh / tailscale / juicity / shadowtls
// ---------------------------------------------------------------------------

/// snell://PSK@host:port?version=4&obfs=http&obfs-host=xxx#name
/// （社区通用格式；Surge 原生无 URI，订阅转换站普遍输出该形态）
fn parse_snell(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("snell://")
        .trim_start_matches("SNELL://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let psk = percent_decode(&userinfo);
    if psk.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let version: u8 = q.get("version").and_then(|v| v.parse().ok()).unwrap_or(4);
    let mut config = json!({
        "type": "snell",
        "server": host,
        "port": port,
        "psk": psk,
        "password": psk,
        "version": version,
        "name": name,
    });
    if let Some(obj) = config.as_object_mut() {
        if let Some(obfs) = q
            .get("obfs")
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
        {
            obj.insert("obfs".into(), json!(obfs));
            if let Some(obfs_host) = q.get("obfs-host").or_else(|| q.get("obfs_host")) {
                obj.insert("obfs-host".into(), json!(obfs_host));
            }
        }
    }
    Some(make_node(
        "snell", &name, &host, port, uri, config, source_id,
    ))
}

/// naive://user:pass@host:port?sni=xxx#name
/// 以及 naive+https:// / naive+quic://（naive 客户端分发链接惯例）
fn parse_naive(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let lower = uri.to_ascii_lowercase();
    let rest = if lower.starts_with("naive+https://") {
        &uri["naive+https://".len()..]
    } else if lower.starts_with("naive+quic://") {
        &uri["naive+quic://".len()..]
    } else {
        uri.trim_start_matches("naive://")
            .trim_start_matches("NAIVE://")
    };
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    if !body.contains('@') {
        return None;
    }
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let (username, password) = userinfo.split_once(':')?;
    let username = percent_decode(username);
    let password = percent_decode(password);
    if username.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    // naive+quic 走 QUIC(H3) 承载，其余默认 HTTPS(H2)
    let is_quic = lower.starts_with("naive+quic://");
    let sni = q
        .get("sni")
        .or_else(|| q.get("host"))
        .cloned()
        .unwrap_or_default();
    let config = json!({
        "type": "naive",
        "server": host,
        "port": port,
        "username": username,
        "password": password,
        "sni": sni,
        "tls": json!(!is_quic),
        "insecure": json!(false),
        "name": name,
    });
    Some(make_node(
        "naive", &name, &host, port, uri, config, source_id,
    ))
}

/// mieru://user:pass@host:port?protocol=socks5&transport=wss&portRange=10000-20000&multiplexing=QUIC#name
fn parse_mieru(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("mieru://")
        .trim_start_matches("MIERU://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    if !body.contains('@') {
        return None;
    }
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let (username, password) = userinfo.split_once(':')?;
    let username = percent_decode(username);
    let password = percent_decode(password);
    if username.is_empty() || password.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let mut config = json!({
        "type": "mieru",
        "server": host,
        "port": port,
        "username": username,
        "password": password,
        "name": name,
    });
    if let Some(obj) = config.as_object_mut() {
        if let Some(transport) = q
            .get("transport")
            .or_else(|| q.get("profile"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("transport".into(), json!(transport));
        }
        if let Some(mux) = q
            .get("multiplexing")
            .or_else(|| q.get("multiplex"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("multiplexing".into(), json!(mux));
        }
        if let Some(pr) = q
            .get("portrange")
            .or_else(|| q.get("port-range"))
            .or_else(|| q.get("port_range"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("port-range".into(), json!(pr));
            obj.insert("portrange".into(), json!(pr));
        }
    }
    Some(make_node(
        "mieru", &name, &host, port, uri, config, source_id,
    ))
}

/// ssh://user:pass@host:port?private-key=<base64 PEM>&host-key=SHA256:xxx#name
fn parse_ssh(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("ssh://")
        .trim_start_matches("SSH://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    if !body.contains('@') {
        return None;
    }
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (percent_decode(u), percent_decode(p)),
        None => (percent_decode(&userinfo), String::new()),
    };
    if username.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let mut config = json!({
        "type": "ssh",
        "server": host,
        "port": port,
        "username": username,
        "name": name,
    });
    if let Some(obj) = config.as_object_mut() {
        if !password.is_empty() {
            obj.insert("password".into(), json!(password));
        }
        // private-key 支持内联 PEM 或 base64 编码 PEM
        if let Some(pk) = q
            .get("private-key")
            .or_else(|| q.get("private_key"))
            .or_else(|| q.get("key"))
            .filter(|s| !s.is_empty())
        {
            let decoded = decode_base64_str(pk).unwrap_or_else(|| pk.clone());
            obj.insert("private-key".into(), json!(decoded));
        }
        if let Some(pass) = q
            .get("private-key-passphrase")
            .or_else(|| q.get("key-passphrase"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("private-key-passphrase".into(), json!(pass));
        }
        if let Some(hk) = q
            .get("host-key")
            .or_else(|| q.get("host_key"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("host-key".into(), json!(hk));
        }
    }
    Some(make_node("ssh", &name, &host, port, uri, config, source_id))
}

/// tailscale://authkey@host:port?hostname=xxx&exit-node=xxx&control-url=xxx#name
fn parse_tailscale(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("tailscale://")
        .trim_start_matches("TAILSCALE://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    let (host, port, userinfo) = if body.contains('@') {
        let (u, h, p) = split_userinfo_hostport(body)?;
        (h, p, percent_decode(&u))
    } else {
        let (h, p) = split_host_port(body)?;
        (h, p.parse().unwrap_or(443), String::new())
    };
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let authkey = q
        .get("authkey")
        .or_else(|| q.get("auth-key"))
        .or_else(|| q.get("auth_key"))
        .cloned()
        .unwrap_or(userinfo);
    let mut config = json!({
        "type": "tailscale",
        "server": host,
        "port": port,
        "udp": json!(true),
        "name": name,
    });
    if let Some(obj) = config.as_object_mut() {
        if !authkey.is_empty() {
            obj.insert("auth-key".into(), json!(authkey));
        }
        if let Some(v) = q.get("hostname").filter(|s| !s.is_empty()) {
            obj.insert("hostname".into(), json!(v));
        }
        if let Some(v) = q
            .get("exit-node")
            .or_else(|| q.get("exit_node"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("exit-node".into(), json!(v));
            if let Some(allow) = q.get("exit-node-allow-lan").or_else(|| q.get("allow-lan")) {
                obj.insert(
                    "exit-node-allow-lan".into(),
                    json!(allow == "1" || allow.eq_ignore_ascii_case("true")),
                );
            }
        }
        if let Some(v) = q
            .get("control-url")
            .or_else(|| q.get("control_url"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("control-url".into(), json!(v));
        }
    }
    Some(make_node(
        "tailscale",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

/// juicity://uuid:password@host:port?sni=xxx&congestion_control=bbr&allow_insecure=1&pinned_cert_chain=xxx#name
/// （juicity-client --generate-share-link 输出格式）
fn parse_juicity(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("juicity://")
        .trim_start_matches("JUICITY://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    if !body.contains('@') {
        return None;
    }
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let (uuid, password) = match userinfo.split_once(':') {
        Some((u, p)) => (percent_decode(u), percent_decode(p)),
        None => (percent_decode(&userinfo), String::new()),
    };
    if uuid.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let sni = q.get("sni").cloned().unwrap_or_else(|| host.clone());
    let cc = q
        .get("congestion_control")
        .or_else(|| q.get("congestion-control"))
        .or_else(|| q.get("cc"))
        .cloned()
        .unwrap_or_else(|| "bbr".to_string());
    let insecure = q
        .get("allow_insecure")
        .or_else(|| q.get("allow-insecure"))
        .or_else(|| q.get("insecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut config = json!({
        "type": "juicity",
        "server": host,
        "port": port,
        "uuid": uuid,
        "password": password,
        "sni": sni,
        "congestion-control": cc,
        "congestion_control": cc,
        "udp": json!(true),
        "insecure": json!(insecure),
        "allowInsecure": json!(insecure),
        "name": name,
    });
    if let Some(obj) = config.as_object_mut() {
        if let Some(chain) = q
            .get("pinned_cert_chain")
            .or_else(|| q.get("pinned-cert-chain"))
            .filter(|s| !s.is_empty())
        {
            obj.insert("pinned-cert-chain".into(), json!(chain));
        }
    }
    Some(make_node(
        "juicity", &name, &host, port, uri, config, source_id,
    ))
}

/// shadowtls://password@host:port?sni=xxx&version=3&next=<内层 ss 分享链接>#name
///
/// ShadowTLS 本质是 TLS 伪装前置层，必须与内层代理（惯例为 Shadowsocks）串联使用：
/// - 携带 `next=` 时解析为**合并后的 ss 节点**（mihomo `plugin: shadow-tls` 形态），
///   直接可被 mihomo / VP-Core 运行；
/// - 未携带 `next=` 时仅存档 shadow-tls 层参数（type: shadowtls），暂不可运行。
fn parse_shadowtls(uri: &str, source_id: Option<&str>) -> Option<Node> {
    let rest = uri
        .trim_start_matches("shadowtls://")
        .trim_start_matches("SHADOWTLS://");
    let (body, fragment) = split_fragment(rest);
    let name = fragment.map(percent_decode).unwrap_or_default();
    let (userinfo, host, port) = split_userinfo_hostport(body)?;
    let password = percent_decode(&userinfo);
    if password.is_empty() {
        return None;
    }
    let q = parse_query(body.split_once('?').map(|(_, q)| q).unwrap_or(""));
    let sni = q
        .get("sni")
        .or_else(|| q.get("host"))
        .cloned()
        .unwrap_or_default();
    let version: u32 = q.get("version").and_then(|v| v.parse().ok()).unwrap_or(3);

    // next= 内层分享链接（允许 URL 编码）
    let next_raw = q
        .get("next")
        .or_else(|| q.get("inner"))
        .or_else(|| q.get("proxy"))
        .cloned()
        .unwrap_or_default();
    let next_uri = if next_raw.is_empty() {
        None
    } else {
        let decoded = percent_decode(&next_raw);
        let trimmed = decoded.trim().to_string();
        if trimmed.is_empty() {
            None
        } else if trimmed.contains("://") {
            Some(trimmed)
        } else {
            // base64 形式的分享链接
            decode_base64_str(&trimmed).filter(|s| s.contains("://"))
        }
    };

    if let Some(inner) = next_uri {
        let inner_node = parse_uri(&inner, source_id)
            .or_else(|| parse_uri(&format!("ss://{inner}"), source_id))?;
        let mut cfg = inner_node.config;
        if let Some(obj) = cfg.as_object_mut() {
            obj.insert("type".into(), json!("ss"));
            obj.insert("server".into(), json!(host));
            obj.insert("port".into(), json!(port));
            if name.is_empty() {
                obj.insert("name".into(), json!(inner_node.name));
            } else {
                obj.insert("name".into(), json!(name));
            }
            obj.insert("plugin".into(), json!("shadow-tls"));
            obj.insert(
                "plugin-opts".into(),
                json!({
                    "host": sni,
                    "password": password,
                    "version": version,
                }),
            );
        }
        let merged_name = if name.is_empty() {
            inner_node.name
        } else {
            name
        };
        return Some(make_node(
            "shadowsocks",
            &merged_name,
            &host,
            port,
            uri,
            cfg,
            source_id,
        ));
    }

    // 无内层：仅存档 shadow-tls 层参数
    let config = json!({
        "type": "shadowtls",
        "server": host,
        "port": port,
        "password": password,
        "sni": sni,
        "version": version,
        "name": name,
    });
    Some(make_node(
        "shadowtls",
        &name,
        &host,
        port,
        uri,
        config,
        source_id,
    ))
}

fn parse_port_value(v: &serde_json::Value) -> Option<u16> {
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok();
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[test]
    fn parses_tuic_uri() {
        let uri = "tuic://b54d39f7-9204-4680-ba76-2e84c59ff06a:secretpass@tuic.example.com:8443/?sni=tuic.example.com&alpn=h3&congestion_control=bbr#TuicNode";
        let node = parse_uri(uri, None).expect("tuic parse");
        assert_eq!(node.protocol, "tuic");
        assert_eq!(node.name, "TuicNode");
        assert_eq!(node.server, "tuic.example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(
            node.config.get("uuid").and_then(|v| v.as_str()),
            Some("b54d39f7-9204-4680-ba76-2e84c59ff06a")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("secretpass")
        );
        assert_eq!(
            node.config
                .get("congestion-controller")
                .and_then(|v| v.as_str()),
            Some("bbr")
        );
    }

    #[test]
    fn parses_ssr_uri() {
        // 1.2.3.4:8388:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:cGFzc3dvcmQ/?remarks=U1NSTm9kZQ
        // remarks is base64("SSRNode") = U1NSTm9kZQ
        // password is base64("password") = cGFzc3dvcmQ
        let raw_payload = "1.2.3.4:8388:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:cGFzc3dvcmQ/?remarks=U1NSTm9kZQ";
        let b64 = URL_SAFE_NO_PAD.encode(raw_payload.as_bytes());
        let uri = format!("ssr://{}", b64);

        let node = parse_uri(&uri, None).expect("ssr parse");
        assert_eq!(node.protocol, "shadowsocksr");
        assert_eq!(node.name, "SSRNode");
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 8388);
        assert_eq!(
            node.config.get("cipher").and_then(|v| v.as_str()),
            Some("aes-128-cfb")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("password")
        );
        assert_eq!(
            node.config.get("protocol").and_then(|v| v.as_str()),
            Some("auth_aes128_md5")
        );
        assert_eq!(
            node.config.get("obfs").and_then(|v| v.as_str()),
            Some("tls1.2_ticket_auth")
        );
    }

    #[test]
    fn parses_wireguard_uri() {
        let uri = "wireguard://aW5pdGlhbF9wcml2YXRlX2tleQ==@wg.example.com:51820/?publickey=cHVibGljX2tleQ==&address=10.0.0.2/32&reserved=1,2,3&mtu=1420#WireGuardNode";
        let node = parse_uri(uri, None).expect("wireguard parse");
        assert_eq!(node.protocol, "wireguard");
        assert_eq!(node.name, "WireGuardNode");
        assert_eq!(node.server, "wg.example.com");
        assert_eq!(node.port, 51820);
        assert_eq!(
            node.config.get("private-key").and_then(|v| v.as_str()),
            Some("aW5pdGlhbF9wcml2YXRlX2tleQ==")
        );
        assert_eq!(
            node.config.get("public-key").and_then(|v| v.as_str()),
            Some("cHVibGljX2tleQ==")
        );
        let res = node
            .config
            .get("reserved")
            .and_then(|v| v.as_array())
            .expect("reserved array");
        assert_eq!(res.len(), 3);
        assert_eq!(res[0], 1);
    }

    #[test]
    fn parses_hysteria1_uri() {
        let uri = "hysteria://hy.example.com:443/?auth=mysecrettoken&peer=hy.example.com&upmbps=100&downmbps=500&obfs=myobfs&insecure=1#Hysteria1Node";
        let node = parse_uri(uri, None).expect("hysteria1 parse");
        assert_eq!(node.protocol, "hysteria");
        assert_eq!(node.name, "Hysteria1Node");
        assert_eq!(node.server, "hy.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(
            node.config.get("auth").and_then(|v| v.as_str()),
            Some("mysecrettoken")
        );
        assert_eq!(
            node.config.get("server-name").and_then(|v| v.as_str()),
            Some("hy.example.com")
        );
        assert_eq!(node.config.get("up").and_then(|v| v.as_u64()), Some(100));
        assert_eq!(node.config.get("down").and_then(|v| v.as_u64()), Some(500));
        assert_eq!(node.config.get("skip-cert-verify"), Some(&json!(true)));
        assert_eq!(node.config.get("alpn"), Some(&json!(["h3"])));
    }

    #[test]
    fn parses_snell_uri() {
        let uri = "snell://psk-secret@snell.example.com:6160?version=4&obfs=http&obfs-host=cdn.example.com#SnellNode";
        let node = parse_uri(uri, None).expect("snell parse");
        assert_eq!(node.protocol, "snell");
        assert_eq!(node.name, "SnellNode");
        assert_eq!(node.server, "snell.example.com");
        assert_eq!(node.port, 6160);
        assert_eq!(
            node.config.get("psk").and_then(|v| v.as_str()),
            Some("psk-secret")
        );
        assert_eq!(node.config.get("version").and_then(|v| v.as_u64()), Some(4));
        assert_eq!(
            node.config.get("obfs").and_then(|v| v.as_str()),
            Some("http")
        );
        assert_eq!(
            node.config.get("obfs-host").and_then(|v| v.as_str()),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn parses_naive_uris() {
        for scheme in ["naive://", "naive+https://"] {
            let uri = format!(
                "{scheme}user:pass123@naive.example.com:443?sni=naive.example.com#NaiveNode"
            );
            let node = parse_uri(&uri, None).unwrap_or_else(|| panic!("naive parse {scheme}"));
            assert_eq!(node.protocol, "naive");
            assert_eq!(node.name, "NaiveNode");
            assert_eq!(node.server, "naive.example.com");
            assert_eq!(node.port, 443);
            assert_eq!(
                node.config.get("username").and_then(|v| v.as_str()),
                Some("user")
            );
            assert_eq!(
                node.config.get("password").and_then(|v| v.as_str()),
                Some("pass123")
            );
            assert_eq!(
                node.config.get("type").and_then(|v| v.as_str()),
                Some("naive")
            );
        }
    }

    #[test]
    fn parses_mieru_uri() {
        let uri = "mieru://alice:wonderland@mieru.example.com:28888?transport=wss&multiplexing=QUIC&portRange=10000-20000#MieruNode";
        let node = parse_uri(uri, None).expect("mieru parse");
        assert_eq!(node.protocol, "mieru");
        assert_eq!(node.name, "MieruNode");
        assert_eq!(node.server, "mieru.example.com");
        assert_eq!(node.port, 28888);
        assert_eq!(
            node.config.get("username").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("wonderland")
        );
        assert_eq!(
            node.config.get("transport").and_then(|v| v.as_str()),
            Some("wss")
        );
        assert_eq!(
            node.config.get("multiplexing").and_then(|v| v.as_str()),
            Some("QUIC")
        );
    }

    #[test]
    fn parses_ssh_uri() {
        let uri = "ssh://root:pa55word@ssh.example.com:22?host-key=SHA256%3Aabcdef#SshNode";
        let node = parse_uri(uri, None).expect("ssh parse");
        assert_eq!(node.protocol, "ssh");
        assert_eq!(node.name, "SshNode");
        assert_eq!(node.server, "ssh.example.com");
        assert_eq!(node.port, 22);
        assert_eq!(
            node.config.get("username").and_then(|v| v.as_str()),
            Some("root")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("pa55word")
        );
        assert_eq!(
            node.config.get("host-key").and_then(|v| v.as_str()),
            Some("SHA256:abcdef")
        );
    }

    #[test]
    fn parses_tailscale_uri() {
        let uri = "tailscale://tskey-auth-abc123@ts.example.com:443?hostname=vproxy-node&exit-node=us-east&exit-node-allow-lan=1#TailscaleNode";
        let node = parse_uri(uri, None).expect("tailscale parse");
        assert_eq!(node.protocol, "tailscale");
        assert_eq!(node.name, "TailscaleNode");
        assert_eq!(node.server, "ts.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(
            node.config.get("auth-key").and_then(|v| v.as_str()),
            Some("tskey-auth-abc123")
        );
        assert_eq!(
            node.config.get("exit-node").and_then(|v| v.as_str()),
            Some("us-east")
        );
        assert_eq!(node.config.get("exit-node-allow-lan"), Some(&json!(true)));
    }

    #[test]
    fn parses_juicity_uri() {
        let uri = "juicity://b54d39f7-9204-4680-ba76-2e84c59ff06a:juice-pass@jc.example.com:8443?sni=jc.example.com&congestion_control=bbr&allow_insecure=0#JuicityNode";
        let node = parse_uri(uri, None).expect("juicity parse");
        assert_eq!(node.protocol, "juicity");
        assert_eq!(node.name, "JuicityNode");
        assert_eq!(node.server, "jc.example.com");
        assert_eq!(node.port, 8443);
        assert_eq!(
            node.config.get("uuid").and_then(|v| v.as_str()),
            Some("b54d39f7-9204-4680-ba76-2e84c59ff06a")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("juice-pass")
        );
        assert_eq!(
            node.config
                .get("congestion-control")
                .and_then(|v| v.as_str()),
            Some("bbr")
        );
        assert_eq!(node.config.get("insecure"), Some(&json!(false)));
    }

    #[test]
    fn parses_shadowtls_uri_with_inner_ss() {
        // next= 内层 ss 链接（URL 编码），合并为 mihomo plugin 形态的 ss 节点
        let inner = "ss://YWVzLTEyOC1nY206c3NwYXNz@1.2.3.4:8388#InnerSS";
        let encoded =
            percent_encoding::utf8_percent_encode(inner, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let uri = format!(
            "shadowtls://stls-pass@st.example.com:443?sni=www.apple.com&version=3&next={}#StNode",
            encoded
        );
        let node = parse_uri(&uri, None).expect("shadowtls parse");
        assert_eq!(node.protocol, "shadowsocks");
        assert_eq!(node.name, "StNode");
        assert_eq!(node.server, "st.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.config.get("type").and_then(|v| v.as_str()), Some("ss"));
        assert_eq!(
            node.config.get("cipher").and_then(|v| v.as_str()),
            Some("aes-128-gcm")
        );
        assert_eq!(
            node.config.get("password").and_then(|v| v.as_str()),
            Some("sspass")
        );
        assert_eq!(
            node.config.get("plugin").and_then(|v| v.as_str()),
            Some("shadow-tls")
        );
        let opts = node
            .config
            .get("plugin-opts")
            .and_then(|v| v.as_object())
            .expect("plugin-opts");
        assert_eq!(
            opts.get("host").and_then(|v| v.as_str()),
            Some("www.apple.com")
        );
        assert_eq!(
            opts.get("password").and_then(|v| v.as_str()),
            Some("stls-pass")
        );
        assert_eq!(opts.get("version").and_then(|v| v.as_u64()), Some(3));
    }

    #[test]
    fn parses_shadowtls_uri_without_inner() {
        let uri = "shadowtls://stls-pass@st.example.com:443?sni=www.apple.com&version=3#StOnly";
        let node = parse_uri(uri, None).expect("shadowtls parse");
        assert_eq!(node.protocol, "shadowtls");
        assert_eq!(node.name, "StOnly");
        assert_eq!(node.server, "st.example.com");
        assert_eq!(
            node.config.get("type").and_then(|v| v.as_str()),
            Some("shadowtls")
        );
        assert_eq!(
            node.config.get("sni").and_then(|v| v.as_str()),
            Some("www.apple.com")
        );
        assert_eq!(node.config.get("version").and_then(|v| v.as_u64()), Some(3));
    }
}
