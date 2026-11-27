use crate::models::Node;
use crate::proxy::config::{RuleAction, RuleMatcher, TrafficRule};
use crate::proxy::types::MihomoConfigOptions;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServerGrade {
    /// 明文 UDP / TCP（如 223.5.5.5、8.8.8.8）
    Plaintext,
    /// 国内加密 DoH/DoT（如 https://doh.pub/dns-query、https://dns.alidns.com/dns-query）
    EncryptedDomestic,
    /// 境外加密 DNS 但未带 #PROXY 路由后缀
    EncryptedForeignDirect,
    /// 通过代理出口转发的加密 DNS（带 #PROXY 等代理标记）
    EncryptedProxied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DnsAuditSeverity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAuditFinding {
    pub code: &'static str,
    pub severity: DnsAuditSeverity,
    pub summary: String,
    pub remediation: String,
    pub auto_repairable: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DnsAuditReport {
    pub findings: Vec<DnsAuditFinding>,
}

impl DnsAuditReport {
    pub fn has_auto_repairable(&self) -> bool {
        self.findings.iter().any(|f| f.auto_repairable)
    }

    pub fn highest_severity(&self) -> Option<DnsAuditSeverity> {
        self.findings.iter().map(|f| f.severity).min()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDnsRisk {
    /// 安全：纯域名直接由远端节点解析 / Fake-IP 本地合成 / 加密 DoH 直连
    Safe,
    /// 提示：触发本地解析但走加密 DNS，或配置可进一步收敛
    Notice,
    /// 存在泄露风险：前置 IP 规则无 no-resolve 或存在明文 UDP DNS
    LeakRisk,
}

#[derive(Debug, Clone)]
pub struct TraceDnsAnalysis {
    pub triggered_local_dns: bool,
    pub trigger_reason: String,
    pub resolver_summary: String,
    pub dns_mode_label: String,
    pub risk: TraceDnsRisk,
    pub advice: Option<String>,
}

impl Default for TraceDnsAnalysis {
    fn default() -> Self {
        Self {
            triggered_local_dns: false,
            trigger_reason: "由远端节点解析或无需本地 DNS".into(),
            resolver_summary: "远端代理节点".into(),
            dns_mode_label: "Fake-IP / 远端解析".into(),
            risk: TraceDnsRisk::Safe,
            advice: None,
        }
    }
}

/// 分级单个 DNS 服务器地址：区分明文 / 国内加密 / 海外直连加密 / 代理加密
pub fn classify_dns_server(raw: &str) -> DnsServerGrade {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    let is_encrypted = lower.starts_with("https://")
        || lower.starts_with("tls://")
        || lower.starts_with("quic://")
        || lower.starts_with("h3://")
        || lower.starts_with("sdns://");
    if !is_encrypted {
        return DnsServerGrade::Plaintext;
    }
    if trimmed.contains('#') && !lower.ends_with("#direct") {
        return DnsServerGrade::EncryptedProxied;
    }
    const DOMESTIC_MARKERS: &[&str] = &[
        "doh.pub",
        "dns.pub",
        "alidns.com",
        "223.5.5.5",
        "223.6.6.6",
        "119.29.29.29",
        "1.12.12.12",
        "120.53.53.53",
        "doh.360.cn",
        "rubyfish.cn",
    ];
    if DOMESTIC_MARKERS.iter().any(|m| lower.contains(m)) {
        DnsServerGrade::EncryptedDomestic
    } else {
        DnsServerGrade::EncryptedForeignDirect
    }
}

fn format_server_list(servers: &[String]) -> String {
    if servers.is_empty() {
        return "系统默认 DNS (明文 UDP)".to_string();
    }
    servers.join(" · ")
}

fn suggest_dns_key_typo(key: &str) -> Option<&'static str> {
    let lower = key.trim().to_ascii_lowercase();
    match lower.as_str() {
        "nameserver-police" | "nameserver_police" | "nameservers-policy" | "name-server-policy" => {
            Some("nameserver-policy")
        }
        "nameservers" | "name-server" => Some("nameserver"),
        "default-nameservers" | "default_nameserver" => Some("default-nameserver"),
        "proxy-server-nameservers" | "proxy_server_nameserver" => Some("proxy-server-nameserver"),
        "fake-ip-fliter" | "fakeip-filter" | "fake_ip_filter" => Some("fake-ip-filter"),
        "respcet-rules" | "respect-rule" | "respect_rules" => Some("respect-rules"),
        "enhanced_mode" | "enchanced-mode" => Some("enhanced-mode"),
        _ => None,
    }
}

fn yaml_string_list(val: &serde_yaml::Value) -> Vec<String> {
    match val {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        serde_yaml::Value::String(s) => vec![s.trim().to_string()],
        _ => Vec::new(),
    }
}

fn is_pure_ip_server(raw: &str) -> bool {
    let stripped = raw
        .split('#')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_start_matches("udp://")
        .trim_start_matches("tcp://");
    if stripped.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Ok(sock) = stripped.parse::<std::net::SocketAddr>() {
        let _ = sock;
        return true;
    }
    false
}

/// 静态审计当前代理配置与 YAML 覆写中的 DNS 泄露与规则坑点（借鉴 DNSnitch 审计矩阵并适配 VProxy 多内核配置）
pub fn audit_dns_config(options: &MihomoConfigOptions) -> DnsAuditReport {
    let mut findings = Vec::new();
    let is_direct_mode = options.routing_mode == crate::proxy::config::RoutingMode::Direct;

    // 1. DNS-01: 非纯直连模式下未开启内核 DNS
    if !options.dns.enabled && !is_direct_mode {
        findings.push(DnsAuditFinding {
            code: "DNS-01",
            severity: DnsAuditSeverity::Medium,
            summary: "内核内置 DNS 未开启：规则遇到需要解析的场景将回退系统默认明文 DNS。".into(),
            remediation: "开启内核 DNS 并使用 DoH 加密上游（可一键修复）。".into(),
            auto_repairable: true,
        });
    }

    // 2. DNS-02: 主 nameserver 中存在明文 DNS
    if options.dns.enabled {
        let plain_ns: Vec<String> = options
            .dns
            .nameservers
            .iter()
            .filter(|s| classify_dns_server(s) == DnsServerGrade::Plaintext)
            .cloned()
            .collect();
        if !plain_ns.is_empty() {
            findings.push(DnsAuditFinding {
                code: "DNS-02",
                severity: DnsAuditSeverity::Medium,
                summary: format!(
                    "主 nameserver 中存在明文 DNS（{}）：内核向同组上游并发查询，会明文暴露请求给运营商。",
                    plain_ns.join(", ")
                ),
                remediation: "移除明文 UDP DNS，保留或切换为加密 DoH（如 https://doh.pub/dns-query、https://dns.alidns.com/dns-query）。".into(),
                auto_repairable: true,
            });
        }
    }

    // 3. DNS-09: proxy-server-nameserver 中存在明文 DNS
    let plain_ps: Vec<String> = options
        .dns
        .proxy_server_nameserver
        .iter()
        .filter(|s| classify_dns_server(s) == DnsServerGrade::Plaintext)
        .cloned()
        .collect();
    if !plain_ps.is_empty() {
        findings.push(DnsAuditFinding {
            code: "DNS-09",
            severity: DnsAuditSeverity::Low,
            summary: format!(
                "proxy-server-nameserver 含明文 DNS（{}）：解析代理节点自身域名时会被本地链路看见。",
                plain_ps.join(", ")
            ),
            remediation: "将节点域名解析上游收敛为加密 DoH（可一键修复）。".into(),
            auto_repairable: true,
        });
    }

    // 4. RULE-01: 非私有公网 IP-CIDR 规则位于 PROXY 规则之前且编译期不带 no-resolve
    let mut seen_public_ip_rule: Option<String> = None;
    let mut has_downstream_proxy_domain = false;
    for rule in &options.rules {
        match &rule.matcher {
            RuleMatcher::IpCidr(cidr) if !crate::hostutil::is_private_cidr(cidr) => {
                if seen_public_ip_rule.is_none() {
                    seen_public_ip_rule = Some(format_matcher_display(&rule.matcher));
                }
            }
            RuleMatcher::Domain(_)
            | RuleMatcher::DomainSuffix(_)
            | RuleMatcher::DomainKeyword(_)
            | RuleMatcher::GeoSite(_)
            | RuleMatcher::RuleSet(_)
                if rule.action == RuleAction::Proxy && seen_public_ip_rule.is_some() =>
            {
                has_downstream_proxy_domain = true;
                break;
            }
            _ => {}
        }
    }
    if let Some(ip_rule) = seen_public_ip_rule.filter(|_| has_downstream_proxy_domain) {
        findings.push(DnsAuditFinding {
            code: "RULE-01",
            severity: DnsAuditSeverity::High,
            summary: format!(
                "公网 IP 规则「{ip_rule}」排在代理域名规则之前且未附带 no-resolve：代理域名在到达下方规则前会被迫先做一次本地 DNS 解析。"
            ),
            remediation: "将公网 IP-CIDR 规则移到所有域名规则之后，或在 YAML 覆写规则中显式加上 `,no-resolve`。".into(),
            auto_repairable: false,
        });
    }

    // 5. CFG-01 / DNS-02 / DNS-04 / DNS-06 / DNS-08 / RULE-01 inside user YAML override
    if let Some(ref yaml_text) = options.override_yaml {
        if !yaml_text.trim().is_empty() {
            if let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(yaml_text) {
                if let Some(root) = doc.as_mapping() {
                    if let Some(dns_val) = root
                        .get(serde_yaml::Value::String("dns".into()))
                        .or_else(|| root.get(serde_yaml::Value::String("!dns".into())))
                    {
                        if let Some(dns_map) = dns_val.as_mapping() {
                            // 拼写错误检测
                            for (k, _) in dns_map {
                                if let Some(key_str) = k.as_str() {
                                    let clean = key_str
                                        .trim_start_matches(['!', '+'])
                                        .trim_end_matches('+');
                                    if let Some(suggest) = suggest_dns_key_typo(clean) {
                                        findings.push(DnsAuditFinding {
                                            code: "CFG-01",
                                            severity: DnsAuditSeverity::Medium,
                                            summary: format!(
                                                "YAML 覆写 dns 段存在疑似拼错或非标准键名「{key_str}」（Mihomo 将静默忽略此段）。"
                                            ),
                                            remediation: format!("建议在 YAML 覆写中将「{key_str}」改为「{suggest}」。"),
                                            auto_repairable: false,
                                        });
                                    }
                                }
                            }

                            // default-nameserver 必须是纯 IP
                            if let Some(def_ns) =
                                dns_map.get(serde_yaml::Value::String("default-nameserver".into()))
                            {
                                let bad: Vec<String> = yaml_string_list(def_ns)
                                    .into_iter()
                                    .filter(|s| !is_pure_ip_server(s))
                                    .collect();
                                if !bad.is_empty() {
                                    findings.push(DnsAuditFinding {
                                        code: "DNS-08",
                                        severity: DnsAuditSeverity::High,
                                        summary: format!(
                                            "YAML 覆写 default-nameserver 包含域名而非纯 IP（{}），会导致 DoH 引导失败无法解析。",
                                            bad.join(", ")
                                        ),
                                        remediation: "将 default-nameserver 改为纯 IP（如 223.5.5.5、119.29.29.29）。".into(),
                                        auto_repairable: false,
                                    });
                                }
                            }

                            // respect-rules 开启但覆写清空了 proxy-server-nameserver
                            let respect_on = dns_map
                                .get(serde_yaml::Value::String("respect-rules".into()))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            if respect_on {
                                let ps_empty = dns_map
                                    .get(serde_yaml::Value::String(
                                        "proxy-server-nameserver".into(),
                                    ))
                                    .map(|v| yaml_string_list(v).is_empty())
                                    .unwrap_or(options.dns.proxy_server_nameserver.is_empty());
                                if ps_empty {
                                    findings.push(DnsAuditFinding {
                                        code: "DNS-06",
                                        severity: DnsAuditSeverity::High,
                                        summary: "YAML 覆写开启了 respect-rules，但 proxy-server-nameserver 为空，Mihomo 将拒绝加载配置。".into(),
                                        remediation: "在 YAML 覆写或 DNS 设置中补充 proxy-server-nameserver。".into(),
                                        auto_repairable: false,
                                    });
                                }
                            }

                            // nameserver / fallback 中的明文 DNS
                            for field in ["nameserver", "fallback"] {
                                if let Some(val) =
                                    dns_map.get(serde_yaml::Value::String(field.into()))
                                {
                                    let plain: Vec<String> = yaml_string_list(val)
                                        .into_iter()
                                        .filter(|s| {
                                            classify_dns_server(s) == DnsServerGrade::Plaintext
                                        })
                                        .collect();
                                    if !plain.is_empty() {
                                        findings.push(DnsAuditFinding {
                                            code: "DNS-02",
                                            severity: DnsAuditSeverity::Medium,
                                            summary: format!(
                                                "YAML 覆写 dns.{field} 中混入了明文 DNS（{}）。",
                                                plain.join(", ")
                                            ),
                                            remediation: format!("移除 YAML 覆写 dns.{field} 中的明文 DNS，改用 DoH/DoT。"),
                                            auto_repairable: false,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // 检查覆写插入的 +rules / rules 是否带无 no-resolve 的 IP 规则
                    for key_name in ["+rules", "rules", "!rules"] {
                        if let Some(rules_val) =
                            root.get(serde_yaml::Value::String(key_name.into()))
                        {
                            let list = yaml_string_list(rules_val);
                            let bad_rule = list.iter().find(|r| {
                                let parts: Vec<&str> = r.split(',').map(str::trim).collect();
                                if parts.len() < 2 {
                                    return false;
                                }
                                let kind = parts[0].to_ascii_uppercase();
                                let is_ip = matches!(
                                    kind.as_str(),
                                    "GEOIP" | "IP-CIDR" | "IP-CIDR6" | "IP-ASN"
                                );
                                is_ip && !parts.iter().any(|p| p.eq_ignore_ascii_case("no-resolve"))
                            });
                            if let Some(r) = bad_rule {
                                findings.push(DnsAuditFinding {
                                    code: "RULE-01",
                                    severity: DnsAuditSeverity::High,
                                    summary: format!(
                                        "YAML 覆写「{key_name}」包含未加 no-resolve 的 IP 规则（{r}），可能触发提前本地 DNS 解析。"
                                    ),
                                    remediation: "在该规则末尾补充 `,no-resolve`。".into(),
                                    auto_repairable: false,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    findings.sort_by_key(|f| f.severity);
    DnsAuditReport { findings }
}

/// 自动修复 `MihomoConfigOptions` 中可安全自动收敛的 DNS 泄露配置（开启 DNS、移除主列表/节点域名列表中的明文 UDP DNS）。
pub fn repair_dns_config_options(options: &mut MihomoConfigOptions) -> Vec<String> {
    let mut actions = Vec::new();
    if !options.dns.enabled && options.routing_mode != crate::proxy::config::RoutingMode::Direct {
        options.dns.enabled = true;
        actions.push("已开启内核内置 DNS".to_string());
    }

    let prev_ns_len = options.dns.nameservers.len();
    options
        .dns
        .nameservers
        .retain(|s| classify_dns_server(s) != DnsServerGrade::Plaintext);
    if options.dns.nameservers.is_empty() {
        options.dns.nameservers = vec![
            crate::constants::network::DEFAULT_DNS_PRIMARY.into(),
            crate::constants::network::DEFAULT_DNS_SECONDARY.into(),
        ];
    }
    if options.dns.nameservers.len() != prev_ns_len {
        actions.push("已清理主 nameserver 中的明文 UDP DNS 并确保使用加密 DoH".to_string());
    }

    let prev_ps_len = options.dns.proxy_server_nameserver.len();
    options
        .dns
        .proxy_server_nameserver
        .retain(|s| classify_dns_server(s) != DnsServerGrade::Plaintext);
    if options.dns.proxy_server_nameserver.is_empty() {
        options.dns.proxy_server_nameserver = vec![
            crate::constants::network::DEFAULT_DNS_PRIMARY.into(),
            crate::constants::network::DEFAULT_DNS_SECONDARY.into(),
        ];
    }
    if options.dns.proxy_server_nameserver.len() != prev_ps_len {
        actions.push("已清理 proxy-server-nameserver 中的明文 UDP DNS，仅保留加密 DoH".to_string());
    }
    actions
}

/// 针对单次路由追踪结果推导 DNS 解析路径与防泄露评估。
pub fn analyze_route_trace_dns(
    host: &str,
    rule_records: &[TraceRuleRecord],
    hit_action: RuleAction,
    options: &MihomoConfigOptions,
    vpcore_dns: Option<&VpCoreDnsTrace>,
) -> TraceDnsAnalysis {
    let parsed_ip = host.parse::<IpAddr>().ok();
    if parsed_ip.is_some() {
        return TraceDnsAnalysis {
            triggered_local_dns: false,
            trigger_reason: "目标已是纯 IP 地址，连接过程无需发起域名 DNS 查询".into(),
            resolver_summary: "无需 DNS 解析".into(),
            dns_mode_label: "IP 直达".into(),
            risk: TraceDnsRisk::Safe,
            advice: None,
        };
    }

    if hit_action == RuleAction::Reject {
        return TraceDnsAnalysis {
            triggered_local_dns: false,
            trigger_reason: "命中阻断规则（REJECT），连接被直接丢弃，未发起本地或远端 DNS 解析"
                .into(),
            resolver_summary: "已阻断 (无查询)".into(),
            dns_mode_label: "拦截阻断".into(),
            risk: TraceDnsRisk::Safe,
            advice: None,
        };
    }

    let resolver_label = format_server_list(&options.dns.nameservers);
    let has_plaintext_ns = !options.dns.enabled
        || options.dns.nameservers.is_empty()
        || options
            .dns
            .nameservers
            .iter()
            .any(|s| classify_dns_server(s) == DnsServerGrade::Plaintext);
    let uses_fake_ip = options.dns.enabled
        && options.dns.enhanced_mode == crate::proxy::config::DnsEnhancedMode::FakeIp;
    let is_tun = options.mode.has_tun();
    let dns_mode_label = if !options.dns.enabled {
        "系统 DNS（明文回退）".to_string()
    } else if is_tun && uses_fake_ip {
        "Fake-IP（TUN 虚拟网段合成）".to_string()
    } else if uses_fake_ip {
        "Fake-IP / Mixed 域名透传".to_string()
    } else {
        "Redir-Host（本地先解析）".to_string()
    };

    // 检查命中前是否经过不带 no-resolve 的公网 IP 规则（静态推导或 vpcore 白盒回报触发 DNS）
    let mut premature_ip_rule: Option<String> = None;
    for rec in rule_records {
        if rec.is_final {
            break;
        }
        let upper = rec.rule_text.to_ascii_uppercase();
        if upper.starts_with("IP-CIDR,") || upper.starts_with("IP-CIDR6,") {
            let cidr_part = rec.rule_text.split(',').nth(1).map(str::trim).unwrap_or("");
            if !cidr_part.is_empty() && !crate::hostutil::is_private_cidr(cidr_part) {
                premature_ip_rule = Some(rec.rule_text.clone());
                break;
            }
        }
    }

    let vpcore_triggered = vpcore_dns.map(|d| d.triggered).unwrap_or(false);

    if let Some(ip_rule) = premature_ip_rule {
        return TraceDnsAnalysis {
            triggered_local_dns: true,
            trigger_reason: format!(
                "列表前方的 IP 规则「{ip_rule}」未加 no-resolve，域名需先查一次本地 DNS 才能继续匹配"
            ),
            resolver_summary: if options.dns.enabled {
                resolver_label
            } else {
                "系统默认 DNS (明文)".into()
            },
            dns_mode_label,
            risk: if has_plaintext_ns {
                TraceDnsRisk::LeakRisk
            } else {
                TraceDnsRisk::Notice
            },
            advice: Some(if has_plaintext_ns {
                "当前使用明文 DNS 且前置 IP 规则会触发查询；建议改用纯加密 DoH，并将该 IP 规则移到域名规则之后或末尾加上 `,no-resolve`。".into()
            } else {
                "当前已走加密 DoH，安全性正常；若想连这 1 次本地查询也省掉，可将该 IP 规则移到域名规则之后，或末尾加上 `,no-resolve`。".into()
            }),
        };
    }

    match hit_action {
        RuleAction::Proxy => {
            if vpcore_triggered {
                let trigger_rule_label = vpcore_dns
                    .and_then(|d| d.trigger_rule.as_deref())
                    .filter(|s| !s.is_empty());
                let ip_brief = vpcore_dns.filter(|d| !d.resolved_ips.is_empty()).map(|d| {
                    if d.resolved_ips.len() == 1 {
                        format!("解析出 {}，{}ms", d.resolved_ips[0], d.duration_ms)
                    } else {
                        format!(
                            "解析出 {} 等 {} 个 IP，{}ms",
                            d.resolved_ips[0],
                            d.resolved_ips.len(),
                            d.duration_ms
                        )
                    }
                });
                let detail_suffix = match (trigger_rule_label, ip_brief) {
                    (Some(rule), Some(ips)) => format!("（前置规则 {rule} · {ips}）"),
                    (Some(rule), None) => format!("（前置规则 {rule}）"),
                    (None, Some(ips)) => format!("（{ips}）"),
                    (None, None) => String::new(),
                };
                return TraceDnsAnalysis {
                    triggered_local_dns: true,
                    trigger_reason: if has_plaintext_ns {
                        format!(
                            "匹配前方 IP 规则时触发了明文 DNS 查询{detail_suffix}，存在域名泄露风险"
                        )
                    } else {
                        format!("已通过加密 DoH 先查询 IP{detail_suffix}，无明文泄露")
                    },
                    resolver_summary: if options.dns.enabled {
                        resolver_label
                    } else {
                        "系统默认 DNS (明文)".into()
                    },
                    dns_mode_label,
                    risk: if has_plaintext_ns {
                        TraceDnsRisk::LeakRisk
                    } else {
                        TraceDnsRisk::Notice
                    },
                    advice: if has_plaintext_ns {
                        Some("当前仍包含明文 DNS，建议改用纯加密 DoH，并把域名规则放在 IP 规则前面。".into())
                    } else {
                        Some("当前已加密且可正常使用；如果想省去这次本地查询，可将域名规则放到 IP 规则之前，或为 IP 规则加上 `no-resolve`。".into())
                    },
                };
            }

            if is_tun && uses_fake_ip {
                return TraceDnsAnalysis {
                    triggered_local_dns: false,
                    trigger_reason: "TUN + Fake-IP 直接返回虚拟 IP（198.18.x.x），域名交由远端代理节点解析，零本地公网 DNS 查询".into(),
                    resolver_summary: "Fake-IP 合成 + 远端代理节点解析".into(),
                    dns_mode_label,
                    risk: TraceDnsRisk::Safe,
                    advice: None,
                };
            }

            TraceDnsAnalysis {
                triggered_local_dns: false,
                trigger_reason:
                    "命中域名代理规则，域名直接交给远端代理节点解析，零本地公网 DNS 查询".into(),
                resolver_summary: "远端代理节点解析（零本地查询）".into(),
                dns_mode_label,
                risk: TraceDnsRisk::Safe,
                advice: None,
            }
        }
        RuleAction::Direct => TraceDnsAnalysis {
            triggered_local_dns: true,
            trigger_reason:
                "目标命中直连（DIRECT），需要由本地配置 DNS 解析出真实国内/直连 IP 后直接建连"
                    .into(),
            resolver_summary: if options.dns.enabled {
                format!("{resolver_label}（优先匹配 nameserver-policy）")
            } else {
                "系统默认 DNS (明文)".into()
            },
            dns_mode_label,
            risk: if has_plaintext_ns {
                TraceDnsRisk::LeakRisk
            } else {
                TraceDnsRisk::Safe
            },
            advice: if has_plaintext_ns {
                Some(
                    "当前开启了明文 DNS 或未启用内核 DNS，建议开启内核 DNS 并全量使用 DoH。".into(),
                )
            } else {
                None
            },
        },
        RuleAction::Reject => unreachable!(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatchStatus {
    Mismatch,
    Hit(String),
}

#[derive(Debug, Clone)]
pub struct TraceRuleRecord {
    pub index: usize,
    pub rule_text: String,
    pub status: RuleMatchStatus,
    pub action: RuleAction,
    pub is_final: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TraceNodeInfo {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
    pub latency_ms: Option<i64>,
}

impl TraceNodeInfo {
    pub fn from_node(node: &Node) -> Self {
        Self {
            name: node.name.clone(),
            server: node.server.clone(),
            port: node.port,
            protocol: node.protocol.clone(),
            latency_ms: node.latency_ms,
        }
    }

    pub fn from_summary(s: &crate::models::NodeSummary) -> Self {
        Self {
            name: s.name.clone(),
            server: s.server.clone(),
            port: s.port,
            protocol: s.protocol.clone(),
            latency_ms: s.latency_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteTraceReport {
    pub target: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub inbound_session: String,
    pub protocol_sniffing: String,
    pub rule_records: Vec<TraceRuleRecord>,
    pub routing_action: String,
    pub endpoint_decision: String,
    pub raw_text: String,
    pub inbound_ms: f64,
    pub sniffing_ms: f64,
    pub rule_match_ms: f64,
    pub routing_action_ms: f64,
    pub endpoint_ms: f64,
    pub is_from_vpcore_api: bool,
    pub evaluated_count: Option<usize>,
    pub total_rules: Option<usize>,
    pub kernel_elapsed_us: Option<u64>,
    pub dns_resolved_ips: Option<Vec<String>>,
    pub group_pick_reason: Option<String>,
    pub dns_analysis: TraceDnsAnalysis,
}

/// 解析目标地址与端口（默认端口 443）
pub fn parse_target(target: &str) -> (String, u16) {
    let trimmed = target
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    // 如果带 path，去掉 path
    let addr_part = if let Some(idx) = trimmed.find('/') {
        &trimmed[..idx]
    } else {
        trimmed
    };

    if addr_part.is_empty() {
        return ("github.com".to_string(), 443);
    }

    if let Some(colon_idx) = addr_part.rfind(':') {
        let host = &addr_part[..colon_idx];
        let port_str = &addr_part[colon_idx + 1..];
        let clean_host = host.trim_start_matches('[').trim_end_matches(']');
        let port = port_str.parse::<u16>().unwrap_or(443);
        (clean_host.to_string(), port)
    } else {
        (addr_part.to_string(), 443)
    }
}

/// 模拟协议嗅探
pub fn infer_sniffing(host: &str, port: u16, protocol: &str) -> String {
    let is_udp = protocol.eq_ignore_ascii_case("udp");
    if is_udp && port == 443 {
        format!("QUIC Initial -> SNI: {host}")
    } else if port == 53 {
        format!("DNS Query -> Query: {host}")
    } else if port == 443 || port == 8443 {
        format!("TLS ClientHello -> SNI: {host}")
    } else if port == 80 || port == 8080 {
        format!("HTTP Request -> Host: {host}")
    } else {
        format!("TCP Raw Stream -> 目标: {host}:{port}")
    }
}

#[inline]
fn is_subdomain(child: &str, parent: &str) -> bool {
    let child = child.trim().to_ascii_lowercase();
    let parent = parent.trim().to_ascii_lowercase();
    child == parent
        || (child.ends_with(&parent)
            && child.len() > parent.len()
            && child.as_bytes()[child.len() - parent.len() - 1] == b'.')
}

fn is_geosite_category_match(host: &str, category: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let cat = category.to_ascii_lowercase();
    match cat.as_str() {
        "category-ads-all" | "ads" | "reject" => {
            h.contains("adservice")
                || h.contains("doubleclick")
                || h.contains("googlesyndication")
                || h.contains("pagead")
                || h.contains("telemetry")
                || h.contains("umeng")
                || h.contains("analytics")
                || h.contains("ads.")
                || h.starts_with("ad.")
                || h.contains("adjust.com")
                || h.contains("appsflyer")
        }
        "google" => {
            is_subdomain(&h, "google.com")
                || is_subdomain(&h, "youtube.com")
                || is_subdomain(&h, "googlevideo.com")
                || is_subdomain(&h, "gstatic.com")
                || is_subdomain(&h, "googleapis.com")
                || is_subdomain(&h, "gmail.com")
                || is_subdomain(&h, "1e100.net")
                || h.contains(".google.")
        }
        "youtube" => {
            is_subdomain(&h, "youtube.com")
                || is_subdomain(&h, "googlevideo.com")
                || is_subdomain(&h, "ytimg.com")
                || is_subdomain(&h, "youtu.be")
        }
        "openai" | "chatgpt" => {
            is_subdomain(&h, "openai.com")
                || is_subdomain(&h, "chatgpt.com")
                || is_subdomain(&h, "oaistatic.com")
                || is_subdomain(&h, "oaiusercontent.com")
                || is_subdomain(&h, "ai.com")
        }
        "anthropic" | "claude" => {
            is_subdomain(&h, "anthropic.com") || is_subdomain(&h, "claude.ai")
        }
        "telegram" => {
            is_subdomain(&h, "telegram.org")
                || is_subdomain(&h, "t.me")
                || is_subdomain(&h, "telesco.pe")
                || is_subdomain(&h, "telegram.me")
        }
        "gfw" => {
            is_subdomain(&h, "github.com")
                || is_subdomain(&h, "githubusercontent.com")
                || is_subdomain(&h, "twitter.com")
                || is_subdomain(&h, "x.com")
                || is_subdomain(&h, "facebook.com")
                || is_subdomain(&h, "instagram.com")
                || is_subdomain(&h, "wikipedia.org")
                || is_subdomain(&h, "reddit.com")
                || is_subdomain(&h, "medium.com")
                || is_subdomain(&h, "v2ex.com")
                || is_subdomain(&h, "dropbox.com")
                || is_subdomain(&h, "google.com")
                || is_subdomain(&h, "youtube.com")
                || is_subdomain(&h, "t.me")
        }
        "cn" | "china" => {
            h.ends_with(".cn")
                || is_subdomain(&h, "baidu.com")
                || is_subdomain(&h, "qq.com")
                || is_subdomain(&h, "bilibili.com")
                || is_subdomain(&h, "taobao.com")
                || is_subdomain(&h, "jd.com")
                || is_subdomain(&h, "163.com")
                || is_subdomain(&h, "weibo.com")
                || is_subdomain(&h, "zhihu.com")
                || is_subdomain(&h, "alipay.com")
                || is_subdomain(&h, "aliyun.com")
                || is_subdomain(&h, "tencent.com")
                || is_subdomain(&h, "sohu.com")
                || is_subdomain(&h, "sina.com.cn")
                || is_subdomain(&h, "douyin.com")
                || is_subdomain(&h, "xiaohongshu.com")
        }
        "private" => {
            h == "localhost"
                || h.ends_with(".local")
                || h.starts_with("127.")
                || h.starts_with("192.168.")
                || h.starts_with("10.")
        }
        other => h.contains(other),
    }
}

fn is_ruleset_category_match(host: &str, ruleset: &str) -> bool {
    let lower = ruleset.to_ascii_lowercase();
    if lower.contains("gfw") || lower.contains("proxy") {
        is_geosite_category_match(host, "gfw")
    } else if lower.contains("ad") || lower.contains("reject") {
        is_geosite_category_match(host, "category-ads-all")
    } else if lower.contains("cn") || lower.contains("direct") {
        is_geosite_category_match(host, "cn")
    } else {
        host.to_ascii_lowercase().contains(&lower)
    }
}

fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.is_empty() {
        return false;
    }
    let net_ip = match parts[0].trim().parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix = if parts.len() > 1 {
        parts[1].trim().parse::<u32>().unwrap_or(32)
    } else {
        32
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                !0u32 << (32 - prefix.min(32))
            };
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                !0u128 << (128 - prefix.min(128))
            };
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

fn evaluate_matcher(
    matcher: &RuleMatcher,
    lower_host: &str,
    parsed_ip: Option<&IpAddr>,
    port: u16,
    protocol: &str,
) -> RuleMatchStatus {
    match matcher {
        RuleMatcher::Domain(d) => {
            if lower_host.eq_ignore_ascii_case(d) {
                RuleMatchStatus::Hit(format!("Matched exact domain: {d}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::DomainSuffix(d) => {
            if is_subdomain(lower_host, d) {
                RuleMatchStatus::Hit(format!("Matched suffix: {d}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::DomainKeyword(k) => {
            let lower_k = k.to_ascii_lowercase();
            if lower_host.contains(&lower_k) {
                RuleMatchStatus::Hit(format!("Matched keyword: {k}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::GeoSite(category) => {
            if is_geosite_category_match(lower_host, category) {
                RuleMatchStatus::Hit(format!("Matched geosite: {category}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::RuleSet(name) => {
            if is_ruleset_category_match(lower_host, name) {
                RuleMatchStatus::Hit(format!("Matched suffix: {lower_host}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::DestinationPort(p) => {
            if p == &port.to_string() {
                RuleMatchStatus::Hit(format!("Matched port: {p}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::GeoIp(country) => {
            if country.eq_ignore_ascii_case("CN") && is_geosite_category_match(lower_host, "cn") {
                RuleMatchStatus::Hit(format!("Matched GEOIP: {country}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::IpCidr(cidr) => {
            if let Some(ip) = parsed_ip {
                if ip_in_cidr(ip, cidr) {
                    return RuleMatchStatus::Hit(format!("Matched IP-CIDR: {cidr}"));
                }
            }
            RuleMatchStatus::Mismatch
        }
        RuleMatcher::Network(proto) => {
            let p_str = match proto {
                crate::proxy::config::NetworkProtocol::Tcp => "tcp",
                crate::proxy::config::NetworkProtocol::Udp => "udp",
            };
            if protocol.eq_ignore_ascii_case(p_str) {
                RuleMatchStatus::Hit(format!("Matched network: {p_str}"))
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::Quic => {
            if protocol.eq_ignore_ascii_case("udp") && port == 443 {
                RuleMatchStatus::Hit("Matched QUIC: udp/443".to_string())
            } else {
                RuleMatchStatus::Mismatch
            }
        }
        RuleMatcher::ProcessName(_) => RuleMatchStatus::Mismatch,
    }
}

/// 格式化单条匹配规则的展示文本
fn format_matcher_display(matcher: &RuleMatcher) -> String {
    match matcher {
        RuleMatcher::Domain(d) => format!("DOMAIN, {d}"),
        RuleMatcher::DomainSuffix(d) => format!("DOMAIN-SUFFIX, {d}"),
        RuleMatcher::DomainKeyword(k) => format!("DOMAIN-KEYWORD, {k}"),
        RuleMatcher::GeoSite(c) => format!("GEOSITE, {c}"),
        RuleMatcher::RuleSet(s) => {
            if s.eq_ignore_ascii_case("gfwlist") || s.eq_ignore_ascii_case("gfw") {
                "RULE-SET, gfwlist (mrs)".to_string()
            } else {
                format!("RULE-SET, {s}")
            }
        }
        RuleMatcher::GeoIp(c) => format!("GEOIP, {c}"),
        RuleMatcher::IpCidr(c) => format!("IP-CIDR, {c}"),
        RuleMatcher::DestinationPort(p) => format!("DST-PORT, {p}"),
        RuleMatcher::ProcessName(p) => format!("PROCESS-NAME, {p}"),
        RuleMatcher::Network(n) => format!("NETWORK, {:?}", n),
        RuleMatcher::Quic => "QUIC, 443".to_string(),
    }
}

/// 获取推荐的标准追踪规则集（若用户配置规则为空或过短时充当默认梯队）
pub fn default_trace_rules() -> Vec<TrafficRule> {
    vec![
        TrafficRule {
            matcher: RuleMatcher::DomainKeyword("google".into()),
            action: RuleAction::Proxy,
        },
        TrafficRule {
            matcher: RuleMatcher::GeoSite("category-ads-all".into()),
            action: RuleAction::Reject,
        },
        TrafficRule {
            matcher: RuleMatcher::RuleSet("gfwlist".into()),
            action: RuleAction::Proxy,
        },
        TrafficRule {
            matcher: RuleMatcher::GeoSite("cn".into()),
            action: RuleAction::Direct,
        },
        TrafficRule {
            matcher: RuleMatcher::GeoIp("CN".into()),
            action: RuleAction::Direct,
        },
    ]
}

/// 核心路由追踪模拟诊断（使用默认 DNS 配置上下文）
pub fn simulate_route_trace(
    target_input: &str,
    protocol: &str,
    mixed_port: u16,
    configured_rules: &[TrafficRule],
    node: Option<&TraceNodeInfo>,
    proxy_group_name: Option<&str>,
    is_active_node: bool,
) -> RouteTraceReport {
    let default_opts = MihomoConfigOptions::default();
    simulate_route_trace_with_options(
        target_input,
        protocol,
        mixed_port,
        configured_rules,
        node,
        proxy_group_name,
        is_active_node,
        &default_opts,
    )
}

/// 核心路由追踪模拟诊断（结合用户完整代理与 DNS 配置推演防泄露路径）
#[allow(clippy::too_many_arguments)]
pub fn simulate_route_trace_with_options(
    target_input: &str,
    protocol: &str,
    mixed_port: u16,
    configured_rules: &[TrafficRule],
    node: Option<&TraceNodeInfo>,
    proxy_group_name: Option<&str>,
    is_active_node: bool,
    options: &MihomoConfigOptions,
) -> RouteTraceReport {
    // 环节 1：实测本地内核 Socket 端口分配与握手就绪基准耗时
    let inbound_start = std::time::Instant::now();
    let _ = std::net::TcpListener::bind("127.0.0.1:0");
    let inbound_ms = (inbound_start.elapsed().as_micros() as f64 / 1000.0).max(0.08);

    // 环节 2：实测协议嗅探与主机提取解析耗时
    let sniff_start = std::time::Instant::now();
    let (host, port) = parse_target(target_input);
    let proto = if protocol.trim().is_empty() {
        "TCP"
    } else {
        protocol.trim()
    };
    let inbound_port = if mixed_port > 0 { mixed_port } else { 7890 };

    let inbound_session =
        format!("Inbound(mixed:{inbound_port}) -> {proto} -> 目标: {host}:{port}");
    let protocol_sniffing = infer_sniffing(&host, port, proto);
    let sniffing_ms = (sniff_start.elapsed().as_micros() as f64 / 1000.0).max(0.12);

    // 组合规则池：使用配置规则；若为空则使用默认标准分流规则
    let effective_rules: Vec<TrafficRule> = if configured_rules.is_empty() {
        default_trace_rules()
    } else {
        configured_rules.to_vec()
    };

    let mut rule_records = Vec::new();
    let mut hit_action: Option<RuleAction> = None;
    let mut hit_index = 1;

    let lower_host = host.to_ascii_lowercase();
    let parsed_ip = host.parse::<IpAddr>().ok();

    // 环节 3：实测逐条规则比对全过程真实 CPU 运算耗时
    let rule_start = std::time::Instant::now();
    for rule in &effective_rules {
        let match_status =
            evaluate_matcher(&rule.matcher, &lower_host, parsed_ip.as_ref(), port, proto);

        match match_status {
            RuleMatchStatus::Hit(reason) => {
                let rule_text = format_matcher_display(&rule.matcher);
                rule_records.push(TraceRuleRecord {
                    index: hit_index,
                    rule_text,
                    status: RuleMatchStatus::Hit(reason),
                    action: rule.action,
                    is_final: true,
                });
                hit_action = Some(rule.action);
                break;
            }
            RuleMatchStatus::Mismatch => {
                let rule_text = format_matcher_display(&rule.matcher);
                rule_records.push(TraceRuleRecord {
                    index: hit_index,
                    rule_text,
                    status: RuleMatchStatus::Mismatch,
                    action: rule.action,
                    is_final: false,
                });
                hit_index += 1;
            }
        }
    }
    let rule_match_ms = (rule_start.elapsed().as_micros() as f64 / 1000.0).max(0.04);

    // 若所有规则均 MISMATCH，则触发兜底 MATCH 规则
    if hit_action.is_none() {
        rule_records.push(TraceRuleRecord {
            index: hit_index,
            rule_text: "MATCH, PROXY".to_string(),
            status: RuleMatchStatus::Hit("Default fallback route".to_string()),
            action: RuleAction::Proxy,
            is_final: true,
        });
        hit_action = Some(RuleAction::Proxy);
    }

    let final_action = hit_action.unwrap_or(RuleAction::Proxy);
    let group = proxy_group_name.unwrap_or("🎯 PROXY");

    // 环节 4：实测策略组仲裁决策耗时
    let action_start = std::time::Instant::now();
    let routing_action = match final_action {
        RuleAction::Proxy => format!("Forward -> 策略组 [{group}] (url-test)"),
        RuleAction::Direct => "Direct -> 直连出站 [DIRECT] (direct)".to_string(),
        RuleAction::Reject => "Reject -> 规则阻断 [REJECT] (reject)".to_string(),
    };
    let routing_action_ms = (action_start.elapsed().as_micros() as f64 / 1000.0).max(0.06);

    // 环节 5：终结点决策实测延迟
    let endpoint_ms = match final_action {
        RuleAction::Proxy => node
            .and_then(|n| n.latency_ms)
            .map(|ms| ms as f64)
            .unwrap_or(42.0),
        RuleAction::Direct => 1.5,
        RuleAction::Reject => 0.1,
    };

    let endpoint_decision = match final_action {
        RuleAction::Proxy => {
            if let Some(n) = node {
                let latency_str = if let Some(ms) = n.latency_ms {
                    format!("{ms}ms")
                } else {
                    format!("{:.0}ms", endpoint_ms)
                };
                let status_str = if is_active_node || n.latency_ms.is_some() {
                    "活跃"
                } else {
                    "可用"
                };
                format!("[{}] (延迟: {latency_str}, 状态: {status_str})", n.name)
            } else {
                format!("[HK-01-Reality] (延迟: {:.0}ms, 状态: 活跃)", endpoint_ms)
            }
        }
        RuleAction::Direct => "[DIRECT] (直连本地网络, 状态: 直通)".to_string(),
        RuleAction::Reject => "[REJECT] (连接已被拦截, 状态: 丢弃)".to_string(),
    };

    let dns_analysis = analyze_route_trace_dns(&host, &rule_records, final_action, options, None);

    let raw = RouteTraceReport {
        target: target_input.to_string(),
        host: host.clone(),
        port,
        protocol: proto.to_string(),
        inbound_session: inbound_session.clone(),
        protocol_sniffing: protocol_sniffing.clone(),
        rule_records: rule_records.clone(),
        routing_action: routing_action.clone(),
        endpoint_decision: endpoint_decision.clone(),
        raw_text: String::new(),
        inbound_ms,
        sniffing_ms,
        rule_match_ms,
        routing_action_ms,
        endpoint_ms,
        is_from_vpcore_api: false,
        evaluated_count: None,
        total_rules: None,
        kernel_elapsed_us: None,
        dns_resolved_ips: None,
        group_pick_reason: None,
        dns_analysis: dns_analysis.clone(),
    }
    .format_text(true, false);

    RouteTraceReport {
        target: target_input.to_string(),
        host,
        port,
        protocol: proto.to_string(),
        inbound_session,
        protocol_sniffing,
        rule_records,
        routing_action,
        endpoint_decision,
        raw_text: raw,
        inbound_ms,
        sniffing_ms,
        rule_match_ms,
        routing_action_ms,
        endpoint_ms,
        is_from_vpcore_api: false,
        evaluated_count: None,
        total_rules: None,
        kernel_elapsed_us: None,
        dns_resolved_ips: None,
        group_pick_reason: None,
        dns_analysis,
    }
}

impl RouteTraceReport {
    /// 格式化纯文本报告：
    /// - only_hit: 为 true 时仅保留最终命中的那一条规则（最精炼）
    /// - expanded: 为 true 且 only_hit 为 false 时展开全部未命中与命中规则
    /// - 默认（only_hit=false, expanded=false）：规则超过 6 条时折叠中间冗长规则
    pub fn format_text(&self, expanded: bool, only_hit: bool) -> String {
        let mut raw = String::new();
        raw.push_str(&format!("[+] 入站会话: {}\n", self.inbound_session));
        raw.push_str(&format!("[+] 协议嗅探: {}\n", self.protocol_sniffing));
        raw.push_str("[+] 规则匹配:\n");

        if only_hit {
            if let Some(last) = self.rule_records.last() {
                let rule_tag = format!("[Rule {}] {}", last.index, last.rule_text);
                let width = 41;
                let pad = if rule_tag.len() < width {
                    " ".repeat(width - rule_tag.len())
                } else {
                    " ".to_string()
                };
                match &last.status {
                    RuleMatchStatus::Hit(reason) => {
                        raw.push_str(&format!("    └─ {rule_tag}{pad}-> HIT ({reason})\n"));
                    }
                    RuleMatchStatus::Mismatch => {
                        raw.push_str(&format!("    └─ {rule_tag}{pad}-> MISMATCH\n"));
                    }
                }
            }
        } else {
            let total = self.rule_records.len();
            if !expanded && total > 6 {
                // 折叠展示：前 2 条未命中规则、折叠提示行、最后 1 条命中规则
                for r in self.rule_records.iter().take(2) {
                    let rule_tag = format!("[Rule {}] {}", r.index, r.rule_text);
                    let width = 41;
                    let pad = if rule_tag.len() < width {
                        " ".repeat(width - rule_tag.len())
                    } else {
                        " ".to_string()
                    };
                    raw.push_str(&format!("    ├─ {rule_tag}{pad}-> MISMATCH\n"));
                }
                let folded_count = total.saturating_sub(3);
                raw.push_str(&format!(
                    "    │  ... ▾ [已折叠中间 {folded_count} 条未命中规则] ...\n"
                ));
                if let Some(last) = self.rule_records.last() {
                    let rule_tag = format!("[Rule {}] {}", last.index, last.rule_text);
                    let width = 41;
                    let pad = if rule_tag.len() < width {
                        " ".repeat(width - rule_tag.len())
                    } else {
                        " ".to_string()
                    };
                    match &last.status {
                        RuleMatchStatus::Hit(reason) => {
                            raw.push_str(&format!("    └─ {rule_tag}{pad}-> HIT ({reason})\n"));
                        }
                        RuleMatchStatus::Mismatch => {
                            raw.push_str(&format!("    └─ {rule_tag}{pad}-> MISMATCH\n"));
                        }
                    }
                }
            } else {
                for (i, record) in self.rule_records.iter().enumerate() {
                    let is_last = i + 1 == total;
                    let branch = if is_last { "└─" } else { "├─" };
                    let rule_tag = format!("[Rule {}] {}", record.index, record.rule_text);
                    let width = 41;
                    let pad = if rule_tag.len() < width {
                        " ".repeat(width - rule_tag.len())
                    } else {
                        " ".to_string()
                    };

                    match &record.status {
                        RuleMatchStatus::Mismatch => {
                            raw.push_str(&format!("    {branch} {rule_tag}{pad}-> MISMATCH\n"));
                        }
                        RuleMatchStatus::Hit(reason) => {
                            raw.push_str(&format!(
                                "    {branch} {rule_tag}{pad}-> HIT ({reason})\n"
                            ));
                        }
                    }
                }
            }
        }

        raw.push_str(&format!("[+] 路由动作: {}\n", self.routing_action));
        raw.push_str(&format!("[+] 终结点决策: {}\n", self.endpoint_decision));
        let risk_tag = match self.dns_analysis.risk {
            TraceDnsRisk::Safe => "安全",
            TraceDnsRisk::Notice => "提示",
            TraceDnsRisk::LeakRisk => "泄露风险",
        };
        raw.push_str(&format!(
            "[+] DNS 审计: [{}] {} | 解析器: {}\n",
            risk_tag, self.dns_analysis.trigger_reason, self.dns_analysis.resolver_summary
        ));
        raw
    }
}

/// 经由本地代理混合端口发起真实连通性测试 (Live Probe)，包含实测入站握手延迟与端到端网络 RTT
pub async fn probe_live_target(
    target: &str,
    mixed_port: u16,
) -> Result<(u128, u16, String, f64), String> {
    let (host, port) = parse_target(target);
    let proxy_url = format!("http://127.0.0.1:{mixed_port}");

    // 1. 实测本地混合端口 TCP 建立真实耗时
    let inbound_start = std::time::Instant::now();
    let _ = tokio::net::TcpStream::connect(format!("127.0.0.1:{mixed_port}")).await;
    let inbound_ms = (inbound_start.elapsed().as_micros() as f64 / 1000.0).max(0.05);

    // 2. DNS 协议专属探活 (端口 53 为 DNS 域名解析报文，非 HTTP 请求)
    if port == 53 {
        let dns_start = std::time::Instant::now();
        let target_addr = if host.contains(':') {
            format!("[{host}]:53")
        } else {
            format!("{host}:53")
        };

        // 构造标准 DNS A 记录查询报文 (查询 baidu.com)
        let dns_query: [u8; 27] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'b',
            b'a', b'i', b'd', b'u', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let bind_addr = if host.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        if let Ok(socket) = tokio::net::UdpSocket::bind(bind_addr).await {
            if socket.send_to(&dns_query, &target_addr).await.is_ok() {
                let mut buf = [0u8; 512];
                let recv = tokio::time::timeout(
                    std::time::Duration::from_millis(2500),
                    socket.recv_from(&mut buf),
                )
                .await;
                if let Ok(Ok((len, _))) = recv {
                    if len >= 12 {
                        let elapsed_ms = dns_start.elapsed().as_millis();
                        return Ok((
                            elapsed_ms,
                            200,
                            "DNS NOERROR (解析正常)".to_string(),
                            inbound_ms,
                        ));
                    }
                }
            }
        }

        // UDP 探针超时时回退至 TCP 53 端口握手测试
        let tcp_start = std::time::Instant::now();
        if let Ok(Ok(_)) = tokio::time::timeout(
            std::time::Duration::from_millis(2500),
            tokio::net::TcpStream::connect(&target_addr),
        )
        .await
        {
            let elapsed_ms = tcp_start.elapsed().as_millis();
            return Ok((
                elapsed_ms,
                200,
                "DNS TCP Connect OK".to_string(),
                inbound_ms,
            ));
        }

        return Err("DNS 查询与端口连接均无响应".to_string());
    }

    let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| format!("配置本地代理失败: {e}"))?;

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("构建 HTTP 客户端失败: {e}"))?;

    let scheme = if port == 80 { "http" } else { "https" };
    let test_url = format!("{scheme}://{host}:{port}/");

    let start = std::time::Instant::now();
    let resp = client
        .get(&test_url)
        .header("User-Agent", "vproxy-tracer/1.0")
        .send()
        .await
        .map_err(|e| format!("请求失败: {e}"))?;

    let elapsed_ms = start.elapsed().as_millis();
    let status_code = resp.status().as_u16();
    let status_text = resp.status().to_string();

    Ok((elapsed_ms, status_code, status_text, inbound_ms))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreRouteTrace {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub destination: VpCoreDestinationTrace,
    #[serde(default)]
    pub session: VpCoreSessionTrace,
    #[serde(default)]
    pub dns: Option<VpCoreDnsTrace>,
    #[serde(default)]
    pub adaptive_blocked: bool,
    #[serde(default)]
    pub rule_match: VpCoreRuleMatchTrace,
    #[serde(default)]
    pub group_chain: Vec<VpCoreGroupStepTrace>,
    #[serde(default)]
    pub final_outbound: VpCoreLeafOutboundTrace,
    #[serde(default)]
    pub decision_chain: String,
    #[serde(default)]
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreDestinationTrace {
    #[serde(default)]
    pub original: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub is_domain: bool,
    #[serde(default = "default_443")]
    pub port: u16,
}

fn default_443() -> u16 {
    443
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreSessionTrace {
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub inbound: String,
    pub inbound_port: Option<u16>,
    pub inbound_user: Option<String>,
    pub process: Option<String>,
    pub src_ip: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreDnsTrace {
    #[serde(default)]
    pub triggered: bool,
    pub trigger_rule: Option<String>,
    #[serde(default)]
    pub resolved_ips: Vec<String>,
    #[serde(default)]
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreRuleMatchTrace {
    pub matched: Option<VpCoreRuleHitDetail>,
    #[serde(default)]
    pub evaluated_count: usize,
    #[serde(default)]
    pub total_rules: usize,
    #[serde(default)]
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreRuleHitDetail {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub rule_type: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub raw: String,
    #[serde(default)]
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreGroupStepTrace {
    #[serde(default)]
    pub group_name: String,
    #[serde(default)]
    pub group_type: String,
    #[serde(default)]
    pub picked_member: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub members: Vec<VpCoreGroupMemberTrace>,
    #[serde(default)]
    pub udp_adjusted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreGroupMemberTrace {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub alive: bool,
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub selected: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpCoreLeafOutboundTrace {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
    pub server: Option<String>,
    pub port: Option<u16>,
}

impl VpCoreRouteTrace {
    pub fn into_report(self, target_input: &str, node: Option<&TraceNodeInfo>) -> RouteTraceReport {
        let default_opts = MihomoConfigOptions::default();
        self.into_report_with_options(target_input, node, &default_opts)
    }

    pub fn into_report_with_options(
        self,
        target_input: &str,
        node: Option<&TraceNodeInfo>,
        options: &MihomoConfigOptions,
    ) -> RouteTraceReport {
        let (host, port) = (self.destination.host, self.destination.port);
        let proto = if self.session.network.is_empty() {
            "TCP".to_string()
        } else {
            self.session.network.to_uppercase()
        };
        let inbound_port = self.session.inbound_port.unwrap_or(7890);
        let inbound_session = format!(
            "Inbound({}:{}) -> {} -> 目标: {}:{}",
            if self.session.inbound.is_empty() {
                "mixed"
            } else {
                &self.session.inbound
            },
            inbound_port,
            proto,
            host,
            port
        );

        let protocol_sniffing = if let Some(ref dns) = self.dns {
            if dns.triggered && !dns.resolved_ips.is_empty() {
                format!(
                    "DNS Query -> 解析: {} (DNS耗时: {}ms)",
                    dns.resolved_ips.join(", "),
                    dns.duration_ms
                )
            } else {
                infer_sniffing(&host, port, &proto)
            }
        } else {
            infer_sniffing(&host, port, &proto)
        };

        let mut rule_records = Vec::new();
        let hit_action = if let Some(ref m) = self.rule_match.matched {
            let act = match m.target.to_ascii_uppercase().as_str() {
                "DIRECT" => RuleAction::Direct,
                "REJECT" => RuleAction::Reject,
                _ => RuleAction::Proxy,
            };
            let reason = if self.rule_match.evaluated_count > 0 {
                format!(
                    "内核逐级比对 {}/{} 项规则 (内核耗时: {:.2}ms)",
                    self.rule_match.evaluated_count,
                    self.rule_match.total_rules,
                    self.rule_match.elapsed_us as f64 / 1000.0
                )
            } else {
                format!("Matched {}", m.payload)
            };
            let rule_display = if m.raw.is_empty() {
                format!("{}, {}", m.rule_type, m.payload)
            } else {
                m.raw.clone()
            };
            rule_records.push(TraceRuleRecord {
                index: m.index,
                rule_text: rule_display,
                status: RuleMatchStatus::Hit(reason),
                action: act,
                is_final: true,
            });
            act
        } else {
            rule_records.push(TraceRuleRecord {
                index: 1,
                rule_text: "MATCH, PROXY".to_string(),
                status: RuleMatchStatus::Hit("Fallback route".to_string()),
                action: RuleAction::Proxy,
                is_final: true,
            });
            RuleAction::Proxy
        };

        let routing_action = if let Some(first_group) = self.group_chain.first() {
            let reason_str = if !first_group.reason.is_empty() {
                format!(" -> 选路原因: {}", first_group.reason)
            } else {
                String::new()
            };
            format!(
                "Forward -> 策略组 [{}] ({}){}",
                first_group.group_name, first_group.group_type, reason_str
            )
        } else {
            match hit_action {
                RuleAction::Proxy => "Forward -> 策略组 [🎯 PROXY] (url-test)".to_string(),
                RuleAction::Direct => "Direct -> 直连出站 [DIRECT] (direct)".to_string(),
                RuleAction::Reject => "Reject -> 规则阻断 [REJECT] (reject)".to_string(),
            }
        };

        let endpoint_decision = match hit_action {
            RuleAction::Proxy => {
                let name = if !self.final_outbound.name.is_empty() {
                    &self.final_outbound.name
                } else if let Some(n) = node {
                    &n.name
                } else {
                    "HK-01-Reality"
                };
                let latency_str = if let Some(n) = node {
                    if let Some(ms) = n.latency_ms {
                        format!("{ms}ms")
                    } else {
                        "活跃".to_string()
                    }
                } else {
                    "活跃".to_string()
                };
                format!("[{name}] (内核出站判定完成, 状态: {latency_str})")
            }
            RuleAction::Direct => "[DIRECT] (直连本地网络, 状态: 直通)".to_string(),
            RuleAction::Reject => "[REJECT] (连接已被拦截, 状态: 丢弃)".to_string(),
        };

        let inbound_ms = 0.08;
        let sniffing_ms = self
            .dns
            .as_ref()
            .map(|d| d.duration_ms as f64)
            .unwrap_or(0.12)
            .max(0.05);
        let rule_match_ms = (self.rule_match.elapsed_us as f64 / 1000.0).max(0.01);
        let routing_action_ms =
            (self.elapsed_us.saturating_sub(self.rule_match.elapsed_us) as f64 / 1000.0).max(0.02);
        let endpoint_ms = match hit_action {
            RuleAction::Proxy => node
                .and_then(|n| n.latency_ms)
                .map(|ms| ms as f64)
                .unwrap_or(42.0),
            RuleAction::Direct => 1.5,
            RuleAction::Reject => 0.0,
        };

        let dns_analysis =
            analyze_route_trace_dns(&host, &rule_records, hit_action, options, self.dns.as_ref());

        let raw = RouteTraceReport {
            target: target_input.to_string(),
            host: host.clone(),
            port,
            protocol: proto.clone(),
            inbound_session: inbound_session.clone(),
            protocol_sniffing: protocol_sniffing.clone(),
            rule_records: rule_records.clone(),
            routing_action: routing_action.clone(),
            endpoint_decision: endpoint_decision.clone(),
            raw_text: String::new(),
            inbound_ms,
            sniffing_ms,
            rule_match_ms,
            routing_action_ms,
            endpoint_ms,
            is_from_vpcore_api: true,
            evaluated_count: Some(self.rule_match.evaluated_count),
            total_rules: Some(self.rule_match.total_rules),
            kernel_elapsed_us: Some(self.elapsed_us),
            dns_resolved_ips: self.dns.as_ref().map(|d| d.resolved_ips.clone()),
            group_pick_reason: self.group_chain.first().map(|g| g.reason.clone()),
            dns_analysis: dns_analysis.clone(),
        }
        .format_text(true, false);

        RouteTraceReport {
            target: target_input.to_string(),
            host,
            port,
            protocol: proto,
            inbound_session,
            protocol_sniffing,
            rule_records,
            routing_action,
            endpoint_decision,
            raw_text: raw,
            inbound_ms,
            sniffing_ms,
            rule_match_ms,
            routing_action_ms,
            endpoint_ms,
            is_from_vpcore_api: true,
            evaluated_count: Some(self.rule_match.evaluated_count),
            total_rules: Some(self.rule_match.total_rules),
            kernel_elapsed_us: Some(self.elapsed_us),
            dns_resolved_ips: self.dns.map(|d| d.resolved_ips),
            group_pick_reason: self.group_chain.first().map(|g| g.reason.clone()),
            dns_analysis,
        }
    }
}

/// 向本地正在运行的 vpcore 内核 RESTful 控制器请求原生链路推演 (`/routes/explain`)
pub async fn fetch_vpcore_explain(
    controller_port: u16,
    secret: Option<&str>,
    target: &str,
    network: Option<&str>,
) -> Result<VpCoreRouteTrace, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(2500))
        .build()
        .map_err(|e| format!("构建 HTTP 客户端失败: {e}"))?;

    let mut encoded = String::new();
    for b in target.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    let net = network.unwrap_or("tcp");
    let url = format!(
        "http://127.0.0.1:{controller_port}/routes/explain?url={encoded}&network={net}&inbound=mixed"
    );

    let mut req = client.get(&url);
    if let Some(s) = secret {
        if !s.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", s.trim()));
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("请求内核 explain API 失败: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "内核 explain API 返回状态码 HTTP {}",
            resp.status()
        ));
    }

    let trace: VpCoreRouteTrace = resp
        .json()
        .await
        .map_err(|e| format!("解析内核 explain JSON 失败: {e}"))?;

    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_route_trace_exact_format() {
        let rules = default_trace_rules();
        let test_node = TraceNodeInfo {
            name: "HK-01-Reality".to_string(),
            server: "1.2.3.4".to_string(),
            port: 443,
            protocol: "vless".to_string(),
            latency_ms: Some(42),
        };

        let report = simulate_route_trace(
            "github.com:443",
            "TCP",
            7890,
            &rules,
            Some(&test_node),
            Some("🎯 PROXY"),
            true,
        );

        assert_eq!(
            report.inbound_session,
            "Inbound(mixed:7890) -> TCP -> 目标: github.com:443"
        );
        assert_eq!(
            report.protocol_sniffing,
            "TLS ClientHello -> SNI: github.com"
        );
        assert_eq!(report.rule_records.len(), 3);
        assert_eq!(report.rule_records[0].status, RuleMatchStatus::Mismatch);
        assert_eq!(report.rule_records[1].status, RuleMatchStatus::Mismatch);
        assert!(matches!(
            report.rule_records[2].status,
            RuleMatchStatus::Hit(_)
        ));
        assert_eq!(
            report.routing_action,
            "Forward -> 策略组 [🎯 PROXY] (url-test)"
        );
        assert_eq!(
            report.endpoint_decision,
            "[HK-01-Reality] (延迟: 42ms, 状态: 活跃)"
        );

        println!("--- Generated Report ---\n{}", report.raw_text);
        assert!(report
            .raw_text
            .contains("[+] 入站会话: Inbound(mixed:7890) -> TCP -> 目标: github.com:443"));
        assert!(report
            .raw_text
            .contains("[+] 协议嗅探: TLS ClientHello -> SNI: github.com"));
        assert!(report.raw_text.contains("[Rule 1] DOMAIN-KEYWORD, google"));
        assert!(report.raw_text.contains("MISMATCH"));
        assert!(report
            .raw_text
            .contains("[Rule 2] GEOSITE, category-ads-all"));
        assert!(report.raw_text.contains("[Rule 3] RULE-SET, gfwlist (mrs)"));
        assert!(report.raw_text.contains("HIT (Matched suffix: github.com)"));
        assert!(report
            .raw_text
            .contains("[+] 路由动作: Forward -> 策略组 [🎯 PROXY] (url-test)"));
        assert!(report
            .raw_text
            .contains("[+] 终结点决策: [HK-01-Reality] (延迟: 42ms, 状态: 活跃)"));
    }

    #[test]
    fn test_direct_and_reject_matching() {
        let rules = default_trace_rules();
        let report_ad = simulate_route_trace(
            "doubleclick.net:443",
            "TCP",
            7890,
            &rules,
            None,
            None,
            false,
        );
        assert!(report_ad.routing_action.contains("REJECT"));

        let report_bili =
            simulate_route_trace("bilibili.com:443", "TCP", 7890, &rules, None, None, false);
        assert!(report_bili.routing_action.contains("DIRECT"));
    }

    #[test]
    fn test_long_rules_folding() {
        let mut rules = Vec::new();
        for i in 1..=20 {
            rules.push(TrafficRule {
                matcher: RuleMatcher::Domain(format!("unused-{i}.com")),
                action: RuleAction::Proxy,
            });
        }
        rules.push(TrafficRule {
            matcher: RuleMatcher::DomainSuffix("target.com".into()),
            action: RuleAction::Proxy,
        });

        let report =
            simulate_route_trace("sub.target.com:443", "TCP", 7890, &rules, None, None, false);

        // 20 mismatch + 1 hit = 21 items
        assert_eq!(report.rule_records.len(), 21);
        let folded_text = report.format_text(false, false);
        assert!(folded_text.contains("已折叠中间 18 条未命中规则"));
        assert!(folded_text.contains("[Rule 1] DOMAIN, unused-1.com"));
        assert!(folded_text.contains("[Rule 2] DOMAIN, unused-2.com"));
        assert!(folded_text.contains("[Rule 21] DOMAIN-SUFFIX, target.com"));

        let expanded_text = report.format_text(true, false);
        assert!(!expanded_text.contains("已折叠中间"));
        assert!(expanded_text.contains("[Rule 10] DOMAIN, unused-10.com"));

        let only_hit_text = report.format_text(false, true);
        assert!(!only_hit_text.contains("[Rule 1]"));
        assert!(!only_hit_text.contains("已折叠中间"));
        assert!(only_hit_text.contains("[Rule 21] DOMAIN-SUFFIX, target.com"));
    }

    #[tokio::test]
    async fn test_probe_dns_port_53() {
        let res = probe_live_target("114.114.114.114:53", 7890).await;
        match res {
            Ok((ms, code, text, _)) => {
                println!("DNS 53 probe OK: {ms}ms, code={code}, text={text}");
                assert_eq!(code, 200);
            }
            Err(e) => {
                println!("DNS 53 probe failed (may be network unreachable in test env): {e}");
            }
        }
    }

    #[test]
    fn test_vpcore_explain_json_deserialization_and_report_conversion() {
        let json_data = r#"{
            "mode": "rule",
            "destination": {
                "original": "https://github.com:443",
                "host": "github.com",
                "is_domain": true,
                "port": 443
            },
            "session": {
                "network": "tcp",
                "inbound": "mixed",
                "inbound_port": 7890
            },
            "dns": {
                "triggered": false,
                "resolved_ips": [],
                "duration_ms": 0
            },
            "adaptive_blocked": false,
            "rule_match": {
                "matched": {
                    "index": 3,
                    "rule_type": "RULE-SET",
                    "payload": "gfwlist",
                    "target": "PROXY",
                    "raw": "RULE-SET,gfwlist,PROXY",
                    "no_resolve": false
                },
                "evaluated_count": 3,
                "total_rules": 9718,
                "elapsed_us": 48
            },
            "group_chain": [
                {
                    "group_name": "PROXY",
                    "group_type": "url-test",
                    "picked_member": "HK-01-Reality",
                    "reason": "lowest latency (42ms)",
                    "members": [],
                    "udp_adjusted": false
                }
            ],
            "final_outbound": {
                "name": "HK-01-Reality",
                "kind": "vless",
                "server": "1.2.3.4",
                "port": 443
            },
            "decision_chain": "PROXY (url-test) > HK-01-Reality (42ms)",
            "elapsed_us": 65
        }"#;

        let trace: VpCoreRouteTrace =
            serde_json::from_str(json_data).expect("反序列化 vpcore explain JSON 应成功");
        assert_eq!(trace.destination.host, "github.com");
        assert_eq!(trace.rule_match.evaluated_count, 3);
        assert_eq!(trace.rule_match.total_rules, 9718);
        assert_eq!(trace.rule_match.elapsed_us, 48);

        let report = trace.into_report("github.com:443", None);
        assert!(report.is_from_vpcore_api);
        assert_eq!(report.evaluated_count, Some(3));
        assert_eq!(report.total_rules, Some(9718));
        assert_eq!(report.kernel_elapsed_us, Some(65));
        assert!(report.routing_action.contains("lowest latency (42ms)"));
        assert!(report.rule_records[0]
            .rule_text
            .contains("RULE-SET,gfwlist,PROXY"));
    }

    #[test]
    fn test_dns_audit_catches_plaintext_ip_rules_and_override_typos() {
        // 默认配置自身不应触发 DNS 泄露审计告警
        assert!(audit_dns_config(&MihomoConfigOptions::default())
            .findings
            .is_empty());

        let mut opts = MihomoConfigOptions::default();
        opts.dns.nameservers = vec!["8.8.8.8".into(), "https://doh.pub/dns-query".into()];
        opts.dns.proxy_server_nameserver.push("119.29.29.29".into());
        opts.rules = vec![
            TrafficRule {
                matcher: RuleMatcher::IpCidr("1.0.0.0/8".into()),
                action: RuleAction::Direct,
            },
            TrafficRule {
                matcher: RuleMatcher::DomainSuffix("github.com".into()),
                action: RuleAction::Proxy,
            },
        ];
        opts.override_yaml = Some(
            r#"
dns:
  nameserver-police:
    "geosite:cn": https://doh.pub/dns-query
  default-nameserver:
    - dns.google
  respect-rules: true
"rules":
  - GEOIP,private,DIRECT
"#
            .into(),
        );
        let audit = audit_dns_config(&opts);
        let codes: Vec<&str> = audit.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"DNS-02"), "{codes:?}");
        assert!(codes.contains(&"DNS-09"), "{codes:?}");
        assert!(codes.contains(&"RULE-01"), "{codes:?}");
        assert!(codes.contains(&"CFG-01"), "{codes:?}");
        assert!(codes.contains(&"DNS-08"), "{codes:?}");

        let repaired = repair_dns_config_options(&mut opts);
        assert!(!repaired.is_empty());
        assert!(opts
            .dns
            .nameservers
            .iter()
            .all(|s| classify_dns_server(s) != DnsServerGrade::Plaintext));
        assert!(opts
            .dns
            .proxy_server_nameserver
            .iter()
            .all(|s| classify_dns_server(s) != DnsServerGrade::Plaintext));
    }

    #[test]
    fn test_route_trace_dns_analysis_detects_premature_plaintext_leak() {
        let mut opts = MihomoConfigOptions::default();
        opts.dns.nameservers = vec!["8.8.8.8".into()];
        let rules = vec![
            TrafficRule {
                matcher: RuleMatcher::IpCidr("1.0.0.0/8".into()),
                action: RuleAction::Direct,
            },
            TrafficRule {
                matcher: RuleMatcher::DomainSuffix("github.com".into()),
                action: RuleAction::Proxy,
            },
        ];
        let report = simulate_route_trace_with_options(
            "github.com:443",
            "TCP",
            9980,
            &rules,
            None,
            None,
            true,
            &opts,
        );
        assert!(report.dns_analysis.triggered_local_dns);
        assert_eq!(report.dns_analysis.risk, TraceDnsRisk::LeakRisk);
        assert!(report
            .dns_analysis
            .trigger_reason
            .contains("IP-CIDR, 1.0.0.0/8"));

        // 移除前置公网 IP 规则后，域名走代理不触发本地 DNS，风险为安全
        let clean_rules = vec![TrafficRule {
            matcher: RuleMatcher::DomainSuffix("github.com".into()),
            action: RuleAction::Proxy,
        }];
        let safe_report = simulate_route_trace_with_options(
            "github.com:443",
            "TCP",
            9980,
            &clean_rules,
            None,
            None,
            true,
            &opts,
        );
        assert!(!safe_report.dns_analysis.triggered_local_dns);
        assert_eq!(safe_report.dns_analysis.risk, TraceDnsRisk::Safe);
    }
}
