use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

pub const VPNGATE_SOURCE_ID: &str = "plugin-vpngate";
pub const GIST_SOURCE_ID: &str = "plugin-gist";

#[derive(Debug, Clone)]
pub struct PluginMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub author: &'static str,
    pub website: &'static str,
    pub icon_name: &'static str,
}

pub const PLUGIN_CATALOG: &[PluginMeta] = &[
    PluginMeta {
        id: "gist",
        name: "GitHub Gist 发现",
        version: "1.2.0",
        category: "订阅采集",
        description: "全网扫描 GitHub Gist 搜索结果，按协议过滤规则自动抓取公开分享的节点与订阅（支持深度翻页与历史去重）。",
        author: "VProxy Community",
        website: "https://gist.github.com/",
        icon_name: "search",
    },
    PluginMeta {
        id: "vpngate",
        name: "VPN Gate 公共节点",
        version: "2.1.0",
        category: "学术镜像",
        description: "日本筑波大学学术实验项目，每日实时更新全球志愿者免费提供的 OpenVPN 镜像服务器节点（全自动解析接入）。",
        author: "Tsukuba Univ. / VPN Gate",
        website: "https://www.vpngate.net/cn/",
        icon_name: "globe",
    },
];

fn plugin_state_path() -> PathBuf {
    crate::data_root().join("installed_plugins.json")
}

pub fn load_installed_plugins() -> HashSet<String> {
    let path = plugin_state_path();
    if !path.exists() {
        return HashSet::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<Vec<String>>(&json) {
            Ok(list) => list.into_iter().collect(),
            Err(e) => {
                tracing::warn!(error = %e, "解析 installed_plugins.json 失败，回退为空");
                HashSet::new()
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "读取 installed_plugins.json 失败");
            HashSet::new()
        }
    }
}

pub fn save_installed_plugins(installed: &HashSet<String>) -> Result<()> {
    let path = plugin_state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let list: Vec<String> = installed.iter().cloned().collect();
    let json = serde_json::to_string_pretty(&list)?;
    std::fs::write(&path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_integrity() {
        assert_eq!(PLUGIN_CATALOG.len(), 2);
        assert!(PLUGIN_CATALOG.iter().any(|p| p.id == "gist"));
        assert!(PLUGIN_CATALOG.iter().any(|p| p.id == "vpngate"));
    }
}
