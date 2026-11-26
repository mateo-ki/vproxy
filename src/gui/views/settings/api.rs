use super::{pill_toggle, settings_divider, settings_group, settings_row};
use crate::gui::theme;
use crate::gui::types::BgMsg;
use crate::gui::widgets::{fold_title, normalize_api_base};
use crate::gui::VpnApp;
use eframe::egui::{self, CornerRadius, Frame, Margin, RichText, Sense, Stroke, Ui};

impl VpnApp {
    pub(crate) fn ui_api(&mut self, ui: &mut Ui) {
        let mut auto_save = false;
        let is_running = self.api_controller.is_running();

        settings_group(ui, "本地 HTTP API", None, |ui| {
            let mut service_on = is_running;
            settings_row(
                ui,
                "api_service_status",
                "本地 HTTP 服务",
                Some(if is_running {
                    "运行中，正在响应本地接口与导出请求"
                } else {
                    "已停止，端口未占用"
                }),
                |ui| {
                    if pill_toggle(ui, &mut service_on).changed() {
                        if service_on {
                            self.start_api_server();
                        } else {
                            self.stop_api_server();
                        }
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "api_listen_addr",
                "监听地址",
                Some("点击可复制本地 API 根地址"),
                |ui| {
                    let base = format!("http://{}", self.api_addr);
                    if ui
                        .add(
                            egui::Label::new(
                                RichText::new(&base).monospace().color(theme::accent()),
                            )
                            .sense(Sense::click()),
                        )
                        .on_hover_text("点击复制地址")
                        .clicked()
                    {
                        ui.ctx().copy_text(base.clone());
                        self.status = format!("已复制: {base}");
                    }
                },
            );

            if let Some(token) = self.api_controller.token().map(|t| t.to_string()) {
                settings_divider(ui);
                settings_row(
                    ui,
                    "api_access_token",
                    "访问令牌",
                    Some("点击复制 Bearer / Query Token"),
                    |ui| {
                        if ui.button("复制 Token").clicked() {
                            ui.ctx().copy_text(token.clone());
                            self.status = "已复制访问令牌".into();
                        }
                        let preview = if token.len() > 10 {
                            format!("{}…{}", &token[..4], &token[token.len() - 4..])
                        } else {
                            token.clone()
                        };
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(preview).monospace().color(theme::muted()),
                                )
                                .sense(Sense::click()),
                            )
                            .on_hover_text("点击复制完整 Token")
                            .clicked()
                        {
                            ui.ctx().copy_text(token);
                            self.status = "已复制访问令牌".into();
                        }
                    },
                );
            }

            settings_divider(ui);

            settings_row(
                ui,
                "api_auto_start",
                "启动时自动开启",
                Some("应用启动后自动拉起本地 HTTP 服务"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_http_server_enabled).changed() {
                        auto_save = true;
                    }
                },
            );
        });

        let remote_status = self.remote_api_status.clone();
        settings_group(ui, "节点发布服务器", None, |ui| {
            settings_row(ui, "api_pub_addr", "服务器地址", None, |ui| {
                let addr_field = ui.add(
                    egui::TextEdit::singleline(&mut self.remote_api_edit)
                        .hint_text("https://example.com（默认留空）")
                        .desired_width(240.0),
                );
                crate::gui::widgets::note_text_field(ui, &addr_field);
            });

            settings_divider(ui);

            settings_row(ui, "api_pub_token", "推送 Token", None, |ui| {
                let token_field = ui.add(
                    egui::TextEdit::singleline(&mut self.remote_api_token)
                        .password(true)
                        .hint_text("Bearer Token")
                        .desired_width(240.0),
                );
                crate::gui::widgets::note_text_field(ui, &token_field);
            });

            settings_divider(ui);

            settings_row(
                ui,
                "api_pub_actions",
                "配置操作",
                Some(remote_status.as_str()).filter(|s| !s.is_empty()),
                |ui| {
                    if ui.button("检查连接").clicked() {
                        self.check_remote_api();
                    }
                    if ui.button("清空").clicked() {
                        self.remote_api_addr = None;
                        self.remote_api_edit.clear();
                        self.remote_api_token.clear();
                        self.save_publisher(String::new(), String::new());
                    }
                    if ui.button("保存").clicked() {
                        let addr = if self.remote_api_edit.trim().is_empty() {
                            self.remote_api_addr = None;
                            String::new()
                        } else {
                            let normalized = normalize_api_base(self.remote_api_edit.trim());
                            self.remote_api_edit = normalized.clone();
                            self.remote_api_addr = Some(normalized.clone());
                            normalized
                        };
                        self.remote_api_token = self.remote_api_token.trim().to_string();
                        self.save_publisher(addr, self.remote_api_token.clone());
                    }
                },
            );
        });

        struct ApiItem {
            method: &'static str,
            path: &'static str,
            desc: &'static str,
            openable: bool,
        }
        let items = [
            ApiItem { method: "GET", path: "/api/health", desc: "健康检查", openable: true },
            ApiItem { method: "GET", path: "/api/stats", desc: "统计信息", openable: true },
            ApiItem { method: "GET", path: "/api/settings", desc: "读取设置", openable: true },
            ApiItem { method: "PUT", path: "/api/settings", desc: "更新设置", openable: false },
            ApiItem { method: "GET", path: "/api/sources", desc: "订阅源列表", openable: true },
            ApiItem { method: "POST", path: "/api/sources", desc: "创建订阅源", openable: false },
            ApiItem { method: "DELETE", path: "/api/sources/{id}", desc: "删除订阅源及关联节点", openable: false },
            ApiItem { method: "POST", path: "/api/sources/fetch-all", desc: "拉取全部启用源", openable: false },
            ApiItem { method: "GET", path: "/api/nodes?page=1&sort=latency", desc: "节点分页查询", openable: true },
            ApiItem { method: "POST", path: "/api/nodes/speedtest", desc: "自动内核真实代理批量测速，可传 ids 只测本页", openable: false },
            ApiItem { method: "GET", path: "/api/kernels", desc: "检测 Mihomo、Xray、Sing-box 路径和版本", openable: true },
            ApiItem { method: "GET", path: "/api/proxy/status", desc: "读取代理运行状态", openable: true },
            ApiItem { method: "GET", path: "/api/proxy/config", desc: "读取 TUN、DNS 与分流规则配置", openable: true },
            ApiItem { method: "PUT", path: "/api/proxy/config", desc: "更新并持久化代理配置", openable: false },
            ApiItem { method: "GET", path: "/api/proxy/log", desc: "读取当前代理内核最近日志", openable: true },
            ApiItem { method: "POST", path: "/api/proxy/start", desc: "按 node_id 自动选择内核启动（系统代理或 TUN）", openable: false },
            ApiItem { method: "POST", path: "/api/proxy/stop", desc: "停止当前代理内核并恢复系统代理", openable: false },
            ApiItem { method: "POST", path: "/api/proxy/restart", desc: "按 node_id 重启代理", openable: false },
            ApiItem { method: "POST", path: "/api/nodes/delete-dead", desc: "删除超时/失败节点", openable: false },
            ApiItem { method: "POST", path: "/api/nodes/delete-invalid", desc: "删除 127.0.0.1/内网/localhost 等无效主机", openable: false },
            ApiItem { method: "POST", path: "/api/nodes/dedupe", desc: "去除重复节点（同协议/地址/端口/认证）", openable: false },
            ApiItem { method: "GET", path: "/api/export/json?quality_only=true&max_latency_ms=500&min_download_kbps=0&limit=50", desc: "导出 TopN TCP 可用节点 JSON", openable: true },
            ApiItem { method: "GET", path: "/api/export/clash?quality_only=true&max_latency_ms=500&min_download_kbps=0&limit=50", desc: "导出 TopN Clash 配置", openable: true },
            ApiItem { method: "GET", path: "/api/export/vp?quality_only=true&max_latency_ms=500&min_download_kbps=0&limit=50", desc: "导出 TopN 原生 VP-Core (.vp DSL) 声明式配置", openable: true },
            ApiItem { method: "GET", path: "/api/export/uri?quality_only=true&max_latency_ms=500&min_download_kbps=0&limit=50&base64=true", desc: "导出 TopN 订阅（Base64）", openable: true },
            ApiItem { method: "GET", path: "/api/export/uri?quality_only=true&max_latency_ms=300&limit=30&base64=true", desc: "导出 Top30 订阅（延迟≤300ms，Base64）", openable: true },
            ApiItem { method: "GET", path: "/api/export/clash?quality_only=false", desc: "导出全部节点 Clash（关闭过滤）", openable: true },
        ];

        egui::CollapsingHeader::new(fold_title(&format!("接口列表 ({} 个)", items.len())))
            .id_salt("api_endpoints_fold")
            .default_open(false)
            .show(ui, |ui| {
                Frame::NONE
                    .fill(theme::panel())
                    .stroke(theme::card_stroke())
                    .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        for (idx, item) in items.iter().enumerate() {
                            if idx > 0 {
                                super::settings_divider(ui);
                            }
                            let full_url = self.api_url(item.path, item.openable);
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                let (m_bg, m_fg) = match item.method {
                                    "GET" => (theme::accent_bg(), theme::accent_strong()),
                                    "POST" => (theme::success_bg(), theme::success()),
                                    "PUT" => (theme::warning_bg(), theme::warning()),
                                    "DELETE" => (theme::danger_bg(), theme::danger()),
                                    _ => (theme::panel(), theme::muted()),
                                };
                                Frame::NONE
                                    .fill(m_bg)
                                    .stroke(Stroke::new(1.0_f32, m_fg.gamma_multiply(0.4)))
                                    .corner_radius(CornerRadius::same(4))
                                    .inner_margin(Margin::symmetric(6, 2))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(item.method).strong().color(m_fg).small(),
                                        );
                                    });
                                let resp = ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(item.path)
                                                .monospace()
                                                .size(12.0)
                                                .color(theme::accent()),
                                        )
                                        .truncate()
                                        .sense(Sense::click()),
                                    )
                                    .on_hover_text(format!("{}\n点击复制 {full_url}", item.desc));
                                if resp.clicked() {
                                    ui.ctx().copy_text(full_url.clone());
                                    self.status = format!("已复制: {full_url}");
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if item.openable
                                            && !item.path.contains('{')
                                            && ui.small_button("打开").clicked()
                                        {
                                            let _ = crate::platform::open_url_in_browser(&full_url);
                                            ui.ctx().open_url(egui::OpenUrl::new_tab(&full_url));
                                        }
                                        if ui.small_button("复制").clicked() {
                                            ui.ctx().copy_text(full_url.clone());
                                            self.status = format!("已复制: {full_url}");
                                        }
                                    },
                                );
                            });
                            ui.label(RichText::new(item.desc).small().color(theme::muted()));
                            ui.add_space(4.0);
                        }
                    });
            });

        if auto_save && self.settings_dirty() {
            self.save_settings();
        }
    }

    pub(crate) fn publish_available_nodes(&mut self) {
        if self.busy {
            self.status = "请等待当前任务完成后再推送节点".into();
            return;
        }
        let Some(base) = self
            .remote_api_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        else {
            self.status = "尚未配置发布服务器地址，请先在系统设置里填写".into();
            return;
        };
        let token = self.remote_api_token.trim().to_string();
        if token.is_empty() {
            self.status = "尚未配置推送 Token，请先在系统设置里填写".into();
            return;
        }
        let db = self.db.clone();
        let tx = self.tx.clone();
        let keywords = self.settings.exclude_keywords.clone();
        self.busy = true;
        self.status = "正在读取全部真实代理验证成功的节点...".into();
        self.rt.spawn(async move {
            // 标了“不推送”的源、以及命中排除关键词的节点，都不参与推送。
            let (nodes, excluded_count) =
                match db.export_pushable_nodes(Some(2000), &keywords).await {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = tx.send(BgMsg::PublishDone(Err(error.to_string())));
                        return;
                    }
                };
            if nodes.is_empty() {
                let _ = tx.send(BgMsg::PublishDone(Err(if excluded_count > 0 {
                    format!("验证成功的节点全部来自标记为不推送的源（跳过 {excluded_count} 个）")
                } else {
                    "当前没有真实代理验证成功的节点可推送".into()
                })));
                return;
            }
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let result = client
                .post(format!("{base}/api/push/nodes"))
                .bearer_auth(token)
                .json(&serde_json::json!({"nodes": nodes}))
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
                .map_err(|error| format!("连接失败: {error}"))
                .and_then(|response| {
                    response
                        .error_for_status()
                        .map_err(|error| format!("服务器返回错误: {error}"))
                });
            let result = match result {
                Ok(response) => response
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|error| format!("解析服务器响应失败: {error}")),
                Err(error) => Err(error),
            };
            let message = match result {
                Ok(body) => {
                    let data = body.get("data").cloned().unwrap_or_default();
                    let skipped_note = if excluded_count > 0 {
                        format!("，已跳过不推送源 {excluded_count} 个节点")
                    } else {
                        String::new()
                    };
                    Ok(format!(
                        "已推送 {} 个节点，服务器保存 {} 个（版本 {}）{skipped_note}",
                        nodes.len(),
                        data.get("stored").and_then(|v| v.as_i64()).unwrap_or(0),
                        data.get("version").and_then(|v| v.as_i64()).unwrap_or(0)
                    ))
                }
                Err(error) => Err(error),
            };
            let _ = tx.send(BgMsg::PublishDone(message));
        });
    }

    /// 拼出可直接在浏览器打开的完整 API URL，并按需带上访问令牌
    /// （服务端只对只读 GET 接受 `?token=`，写操作必须走 Bearer 头）。
    pub(crate) fn api_url(&self, path: &str, with_token: bool) -> String {
        let url = format!("http://{}{path}", self.api_addr);
        match (with_token, self.api_controller.token()) {
            (true, Some(token)) if !token.is_empty() => {
                let sep = if url.contains('?') { '&' } else { '?' };
                format!("{url}{sep}token={token}")
            }
            _ => url,
        }
    }

    pub(crate) fn check_remote_api(&mut self) {
        let Some(base) = self
            .remote_api_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        else {
            self.remote_api_status = "尚未配置发布服务器地址".into();
            return;
        };
        let token = self.remote_api_token.trim().to_string();
        let tx = self.tx.clone();
        self.remote_api_status = "检查中...".into();
        self.rt.spawn(async move {
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let result = client
                .get(format!("{base}/api/push/health"))
                .bearer_auth(token)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .and_then(|response| response.error_for_status())
                .map(|_| "远程服务在线且 Token 验证成功".to_string())
                .map_err(|error| format!("连接失败: {error}"));
            let _ = tx.send(BgMsg::RemoteApiCheck(result));
        });
    }
}
