use crate::models::Node;
use crate::parser::make_node;
use base64::Engine;

/// 解析 VPN Gate (https://www.vpngate.net/cn/) 导出的 CSV 服务器列表
/// 官方数据接口: `https://www.vpngate.net/api/iphone/`
pub fn parse_vpngate_csv(content: &str, source_id: Option<&str>) -> Vec<Node> {
    let mut nodes = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }

        // CSV 行格式:
        // #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64
        // OpenVPN 配置 Base64 位于最后一个逗号之后
        let Some((info_part, b64_ovpn)) = line.rsplit_once(',') else {
            continue;
        };
        let b64_ovpn = b64_ovpn.trim();
        if b64_ovpn.is_empty() {
            continue;
        }

        let cols: Vec<&str> = info_part.split(',').collect();
        if cols.len() < 7 {
            continue;
        }

        let host_name = cols[0].trim();
        let ip = cols[1].trim();
        let country_short = cols[6].trim().to_uppercase();

        let Ok(ovpn_bytes) = base64::engine::general_purpose::STANDARD.decode(b64_ovpn) else {
            continue;
        };
        let Ok(ovpn_str) = String::from_utf8(ovpn_bytes) else {
            continue;
        };

        if let Some(node) = parse_single_ovpn(&ovpn_str, host_name, ip, &country_short, source_id) {
            nodes.push(node);
        }
    }

    nodes
}

fn parse_single_ovpn(
    ovpn: &str,
    host_name: &str,
    default_ip: &str,
    country_short: &str,
    source_id: Option<&str>,
) -> Option<Node> {
    let mut proto = "tcp".to_string();
    let mut remote_host = default_ip.to_string();
    let mut remote_port: u16 = 443;
    let mut dev = "tun".to_string();
    let mut cipher = "AES-128-CBC".to_string();
    let mut auth = "SHA1".to_string();

    let mut ca = String::new();
    let mut cert = String::new();
    let mut key = String::new();

    let mut in_ca = false;
    let mut in_cert = false;
    let mut in_key = false;

    for line in ovpn.lines() {
        let trimmed = line.trim();

        if trimmed == "<ca>" {
            in_ca = true;
            continue;
        } else if trimmed == "</ca>" {
            in_ca = false;
            continue;
        } else if trimmed == "<cert>" {
            in_cert = true;
            continue;
        } else if trimmed == "</cert>" {
            in_cert = false;
            continue;
        } else if trimmed == "<key>" {
            in_key = true;
            continue;
        } else if trimmed == "</key>" {
            in_key = false;
            continue;
        }

        if in_ca {
            ca.push_str(line);
            ca.push('\n');
            continue;
        }
        if in_cert {
            cert.push_str(line);
            cert.push('\n');
            continue;
        }
        if in_key {
            key.push_str(line);
            key.push('\n');
            continue;
        }

        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "proto" if parts.len() >= 2 => {
                let p = parts[1].to_ascii_lowercase();
                if p.contains("udp") {
                    proto = "udp".into();
                } else {
                    proto = "tcp".into();
                }
            }
            "remote" if parts.len() >= 3 => {
                remote_host = parts[1].to_string();
                if let Ok(p) = parts[2].parse::<u16>() {
                    remote_port = p;
                }
            }
            "remote" if parts.len() == 2 => {
                remote_host = parts[1].to_string();
            }
            "dev" if parts.len() >= 2 => {
                dev = parts[1].to_string();
            }
            "cipher" if parts.len() >= 2 => {
                cipher = parts[1].to_string();
            }
            "auth" if parts.len() >= 2 => {
                auth = parts[1].to_string();
            }
            _ => {}
        }
    }

    if remote_host.is_empty() {
        remote_host = default_ip.to_string();
    }

    let display_name = if !country_short.is_empty() {
        format!("{country_short} - {host_name} ({remote_host}:{remote_port})")
    } else {
        format!("{host_name} ({remote_host}:{remote_port})")
    };

    let ca_trimmed = ca.trim().to_string();
    let cert_trimmed = cert.trim().to_string();
    let key_trimmed = key.trim().to_string();

    let mut config = serde_json::json!({
        "type": "openvpn",
        "name": &display_name,
        "server": &remote_host,
        "port": remote_port,
        "proto": &proto,
        "udp": proto == "udp",
        "username": "vpn",
        "password": "vpn",
        "dev": dev,
        "cipher": cipher,
        "auth": auth,
    });

    if !ca_trimmed.is_empty() {
        config["ca"] = serde_json::json!(ca_trimmed);
    }
    if !cert_trimmed.is_empty() {
        config["cert"] = serde_json::json!(cert_trimmed);
    }
    if !key_trimmed.is_empty() {
        config["key"] = serde_json::json!(key_trimmed);
    }

    let mut node = make_node(
        "openvpn",
        &display_name,
        &remote_host,
        remote_port,
        &format!("openvpn://vpn:vpn@{remote_host}:{remote_port}"),
        config,
        source_id,
    );

    if !country_short.is_empty() {
        node.country = Some(country_short.to_string());
    }

    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vpngate_csv() {
        let fake_ovpn = r#"
dev tun
proto tcp
remote 219.100.37.91 443
cipher AES-128-CBC
auth SHA1
<ca>
-----BEGIN CERTIFICATE-----
MIIBTESTCA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBTESTCERT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
MIIBTESTKEY
-----END RSA PRIVATE KEY-----
</key>
"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(fake_ovpn.as_bytes());
        let csv = format!(
            "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\npublic-vpn-133,219.100.37.91,3099037,13,236902471,Japan,JP,72,1997523029,13694165,715513367957856,2weeks,Daiyuu Nobori_ Japan. Academic Use Only.,,{b64}\n*\n"
        );

        let nodes = parse_vpngate_csv(&csv, Some("vpngate-test"));
        assert_eq!(nodes.len(), 1);
        let n = &nodes[0];
        assert_eq!(n.protocol, "openvpn");
        assert_eq!(n.server, "219.100.37.91");
        assert_eq!(n.port, 443);
        assert_eq!(n.country.as_deref(), Some("JP"));
        assert!(n.name.contains("public-vpn-133"));
        assert_eq!(n.config["type"], "openvpn");
        assert_eq!(n.config["proto"], "tcp");
        assert_eq!(n.config["cipher"], "AES-128-CBC");
        assert_eq!(n.config["auth"], "SHA1");
        assert!(n.config["ca"].as_str().unwrap().contains("MIIBTESTCA"));
        assert!(n.config["cert"].as_str().unwrap().contains("MIIBTESTCERT"));
        assert!(n.config["key"].as_str().unwrap().contains("MIIBTESTKEY"));
    }
}
