use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::widgets::primary_btn;
use crate::gui::VpnApp;
use crate::proxy::tracer::{
    simulate_route_trace_with_options, RuleMatchStatus, TraceDnsRisk, TraceNodeInfo,
};
use crate::proxy::{ProxyState, RuleAction};
use eframe::egui::{
    self, Color32, CornerRadius, Frame, Margin, Pos2, RichText, Sense, Stroke, Vec2,
};

impl VpnApp {
    pub(crate) fn ui_route_trace_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_route_trace_dialog {
            return;
        }

        let mut open = self.show_route_trace_dialog;
        let mut should_recalculate = false;
        let mut copy_payload: Option<String> = None;
        let mut trigger_probe = false;
        let mut close_dialog = false;

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            close_dialog = true;
        }

        if let Some(win_rect) =
            ctx.memory(|mem| mem.area_rect(egui::Id::new("route_trace_modal_window_v8")))
        {
            if ctx.input(|i| i.pointer.any_click()) {
                if let Some(pos) = ctx.input(|i| i.pointer.interact_pos()) {
                    if !win_rect.contains(pos) {
                        close_dialog = true;
                    }
                }
            }
        }

        // 柔和半透明遮罩
        let screen = ctx.viewport_rect();
        egui::Area::new(egui::Id::new("route_trace_dialog_backdrop_v8"))
            .fixed_pos(screen.min)
            .order(egui::Order::Middle)
            .show(ctx, |ui| {
                ui.set_width(screen.width());
                ui.set_height(screen.height());
                ui.painter()
                    .rect_filled(screen, 0.0, Color32::from_black_alpha(110));
            });

        let win_w = 640.0_f32.min(screen.width() - 32.0);
        let win_h = (screen.height() * 0.78).clamp(440.0, 560.0);

        egui::Window::new("route_trace_modal_window_v8")
            .id(egui::Id::new("route_trace_modal_window_v8"))
            .title_bar(false)
            .open(&mut open)
            .order(egui::Order::Tooltip)
            .collapsible(false)
            .resizable(false)
            .fixed_size([win_w, win_h])
            .min_size([win_w, win_h])
            .max_size([win_w, win_h])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(
                Frame::NONE
                    .fill(theme::panel())
                    .stroke(Stroke::new(1.0_f32, theme::border()))
                    .shadow(theme::card_shadow())
                    .corner_radius(CornerRadius::same(14))
                    .inner_margin(Margin::same(18)),
            )
            .show(ctx, |ui| {
                let inner_w = win_w - 36.0;
                ui.set_width(inner_w);
                ui.set_min_width(inner_w);
                ui.set_max_width(inner_w);

                let node_info = self.route_trace_node.clone();
                let is_active = self.route_trace_is_active;
                let running = matches!(
                    self.proxy_status.state,
                    ProxyState::Running | ProxyState::Degraded
                );
                let is_probing = self.route_trace_live_probing;

                // ===== 1. 极简顶栏 + 参考节点摘要 =====
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Radar, 18.0, theme::accent());
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("路由与 DNS 链路追踪")
                            .size(16.0)
                            .strong()
                            .color(theme::text_primary()),
                    );
                    ui.add_space(6.0);
                    if is_active {
                        soft_pill(ui, "当前节点", theme::success(), theme::success_bg());
                    } else {
                        soft_pill(ui, "模拟推演", theme::muted(), theme::page_bg());
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let close_resp = ui
                            .add(crate::gui::icons::icon_btn_square(Icon::Close, 12.0))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text("关闭 (Esc)");
                        if close_resp.clicked() {
                            close_dialog = true;
                        }
                    });
                });

                ui.add_space(3.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if let Some(ref n) = node_info {
                        let lat = n
                            .latency_ms
                            .map(|ms| format!("历史 {ms}ms"))
                            .unwrap_or_else(|| "未测速".to_string());
                        ui.label(
                            RichText::new(format!(
                                "参考出口: {} · {} · {}",
                                n.name,
                                n.protocol.to_ascii_uppercase(),
                                lat
                            ))
                            .size(11.5)
                            .color(theme::muted()),
                        );
                    } else {
                        ui.label(
                            RichText::new("未选中节点（按当前默认代理组与配置推演）")
                                .size(11.5)
                                .color(theme::muted()),
                        );
                    }
                });

                ui.add_space(10.0);

                // ===== 2. 目标输入栏 + 快捷胶囊 =====
                Frame::NONE
                    .fill(theme::page_bg())
                    .stroke(Stroke::new(1.0_f32, theme::border_subtle()))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::symmetric(10, 7))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            icon_label(ui, Icon::Search, 15.0, theme::icon_secondary());
                            ui.add_space(4.0);
                            let edit_w = (inner_w - 136.0).max(180.0);
                            let edit_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.route_trace_target)
                                    .hint_text("输入目标域名或 IP:端口（如 github.com:443）")
                                    .frame(Frame::NONE)
                                    .desired_width(edit_w),
                            );
                            let enter_pressed =
                                edit_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                            if edit_resp.changed() {
                                should_recalculate = true;
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let btn_text = if is_probing { "追踪中..." } else { "开始追踪" };
                                let diag_btn = ui.add_enabled(!is_probing, primary_btn(btn_text));
                                if diag_btn.clicked() || enter_pressed {
                                    should_recalculate = true;
                                    self.route_trace_live_result = None;
                                    self.route_trace_last_diagnosed = Some(std::time::Instant::now());
                                    if running {
                                        trigger_probe = true;
                                    }
                                }
                            });
                        });
                    });

                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
                    ui.label(RichText::new("快捷").size(11.0).color(theme::muted()));
                    let presets = [
                        ("github.com:443", "github.com", "代理"),
                        ("google.com:443", "google.com", "Google"),
                        ("bilibili.com:443", "bilibili.com", "直连"),
                        ("doubleclick.net:443", "doubleclick.net", "拦截"),
                        ("114.114.114.114:53", "114.114.114.114", "DNS"),
                    ];
                    for (target, short_host, label) in presets {
                        let is_current = self.route_trace_target.trim() == target;
                        let (fill, stroke, fg) = if is_current {
                            (
                                theme::accent_bg(),
                                Stroke::new(1.0_f32, theme::accent()),
                                theme::accent_strong(),
                            )
                        } else {
                            (
                                theme::page_bg(),
                                Stroke::new(1.0_f32, theme::border_subtle()),
                                theme::text_secondary(),
                            )
                        };
                        let resp = Frame::NONE
                            .fill(fill)
                            .stroke(stroke)
                            .corner_radius(CornerRadius::same(12))
                            .inner_margin(Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    ui.label(RichText::new(short_host).size(11.0).monospace().color(fg));
                                    ui.label(RichText::new(label).size(10.5).color(theme::muted()));
                                });
                            })
                            .response
                            .interact(Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand);
                        if resp.clicked() {
                            self.route_trace_target = target.to_string();
                            should_recalculate = true;
                            self.route_trace_live_result = None;
                            self.route_trace_last_diagnosed = Some(std::time::Instant::now());
                            if running {
                                trigger_probe = true;
                            }
                        }
                    }
                });

                ui.add_space(10.0);

                // 重算追踪报告
                if should_recalculate || self.route_trace_report.is_none() {
                    let trace_node = node_info.as_ref().map(TraceNodeInfo::from_summary);
                    let mixed_port = self.proxy_status.mixed_port;
                    let rules = &self.proxy_config.rules;
                    let group = if !self.proxy_selected_group.is_empty()
                        && self.proxy_selected_group != "全部"
                    {
                        self.proxy_selected_group.as_str()
                    } else {
                        "🎯 PROXY"
                    };
                    let report = simulate_route_trace_with_options(
                        &self.route_trace_target,
                        "TCP",
                        mixed_port,
                        rules,
                        trace_node.as_ref(),
                        Some(group),
                        is_active,
                        &self.proxy_config,
                    );
                    self.route_trace_report = Some(report);
                }

                // ===== 3. 滚动主体区域（单屏直出，零多余点击） =====
                egui::ScrollArea::vertical()
                    .id_salt("route_trace_body_scroll_v8")
                    .max_height(win_h - 178.0)
                    .max_width(inner_w)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let Some(ref report) = self.route_trace_report else {
                            return;
                        };

                        let inbound_port = if self.proxy_status.mixed_port > 0 {
                            self.proxy_status.mixed_port
                        } else {
                            9980
                        };
                        let host = &report.host;
                        let port = report.port;
                        let proto = &report.protocol;

                        let hit_record = report.rule_records.last();
                        let hit_index = hit_record.map(|r| r.index).unwrap_or(1);
                        let hit_text = hit_record
                            .map(|r| r.rule_text.as_str())
                            .unwrap_or("MATCH, PROXY");
                        let hit_action = hit_record.map(|r| r.action).unwrap_or(RuleAction::Proxy);
                        let hit_reason = hit_record
                            .and_then(|r| match &r.status {
                                RuleMatchStatus::Hit(reason) => Some(reason.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "默认兜底".to_string());

                        let (live_probe_rtt_ms, live_inbound_ms) = match &self.route_trace_live_result {
                            Some(Ok((ms, _, _, in_ms))) => (Some(*ms as f64), Some(*in_ms)),
                            _ => (None, None),
                        };
                        let total_ms = if hit_action == RuleAction::Reject {
                            live_inbound_ms.unwrap_or(report.inbound_ms)
                                + report.sniffing_ms
                                + report.rule_match_ms
                                + report.routing_action_ms
                        } else {
                            live_inbound_ms.unwrap_or(report.inbound_ms)
                                + report.sniffing_ms
                                + report.rule_match_ms
                                + report.routing_action_ms
                                + live_probe_rtt_ms.unwrap_or(report.endpoint_ms)
                        };

                        // --- 3.1 结论概览三联卡 ---
                        let (action_label, action_color, action_bg) = match hit_action {
                            RuleAction::Proxy => ("代理转发", theme::accent_strong(), theme::accent_bg()),
                            RuleAction::Direct => ("直连出站", theme::success(), theme::success_bg()),
                            RuleAction::Reject => ("拦截丢弃", theme::danger(), theme::danger_bg()),
                        };
                        let dns_info = &report.dns_analysis;
                        let (dns_badge, dns_color, dns_bg) = match dns_info.risk {
                            TraceDnsRisk::Safe => (
                                if dns_info.triggered_local_dns {
                                    "加密 DoH · 安全"
                                } else {
                                    "零本地解析"
                                },
                                theme::success(),
                                theme::success_bg(),
                            ),
                            TraceDnsRisk::Notice => {
                                ("加密 DoH · 安全", theme::accent_strong(), theme::accent_bg())
                            }
                            TraceDnsRisk::LeakRisk => {
                                ("存在泄露风险", theme::danger(), theme::danger_bg())
                            }
                        };

                        Frame::NONE
                            .fill(theme::page_bg())
                            .stroke(Stroke::new(1.0_f32, theme::border_subtle()))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(14, 11))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                let col_w = ((ui.available_width() - 34.0) / 3.0).max(140.0);
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 8.0;

                                    // 列1: 分流去向
                                    ui.allocate_ui(Vec2::new(col_w, 52.0), |ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new("分流去向").size(11.0).color(theme::muted()));
                                            ui.add_space(4.0);
                                            ui.horizontal(|ui| {
                                                soft_pill(ui, action_label, action_color, action_bg);
                                            });
                                            ui.add_space(4.0);
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!("#{hit_index} · {hit_text}"))
                                                        .size(11.0)
                                                        .monospace()
                                                        .color(theme::text_secondary()),
                                                )
                                                .truncate(),
                                            );
                                        });
                                    });

                                    vertical_hairline(ui, 44.0);

                                    // 列2: DNS 安全
                                    ui.allocate_ui(Vec2::new(col_w, 52.0), |ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new("DNS 安全").size(11.0).color(theme::muted()));
                                            ui.add_space(4.0);
                                            ui.horizontal(|ui| {
                                                soft_pill(ui, dns_badge, dns_color, dns_bg);
                                            });
                                            ui.add_space(4.0);
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&dns_info.resolver_summary)
                                                        .size(11.0)
                                                        .color(theme::text_secondary()),
                                                )
                                                .truncate(),
                                            );
                                        });
                                    });

                                    vertical_hairline(ui, 44.0);

                                    // 列3: 链路延迟
                                    ui.allocate_ui(Vec2::new(col_w, 52.0), |ui| {
                                        ui.vertical(|ui| {
                                            ui.label(RichText::new("链路耗时").size(11.0).color(theme::muted()));
                                            ui.add_space(4.0);
                                            if is_probing {
                                                ui.horizontal(|ui| {
                                                    ui.spinner();
                                                    ui.label(
                                                        RichText::new("实测中...")
                                                            .size(13.0)
                                                            .color(theme::accent_strong()),
                                                    );
                                                });
                                            } else if hit_action == RuleAction::Reject {
                                                ui.label(
                                                    RichText::new("已本地拦截")
                                                        .size(14.5)
                                                        .strong()
                                                        .color(theme::danger()),
                                                );
                                            } else if let Some(ms) = live_probe_rtt_ms {
                                                ui.label(
                                                    RichText::new(format!("{ms:.0} ms（实测）"))
                                                        .size(14.5)
                                                        .strong()
                                                        .monospace()
                                                        .color(theme::success()),
                                                );
                                            } else {
                                                ui.label(
                                                    RichText::new(format!("~{total_ms:.0} ms（估算）"))
                                                        .size(14.5)
                                                        .strong()
                                                        .monospace()
                                                        .color(theme::text_primary()),
                                                );
                                            }
                                            ui.add_space(2.0);
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&dns_info.dns_mode_label)
                                                        .size(11.0)
                                                        .color(theme::muted()),
                                                )
                                                .truncate(),
                                            );
                                        });
                                    });
                                });
                            });

                        // 仅在真正存在泄露风险或实测失败时展示告警横幅（加密 DoH 安全解析不再弹告警条）
                        if dns_info.risk == TraceDnsRisk::LeakRisk {
                            ui.add_space(8.0);
                            Frame::NONE
                                .fill(theme::danger_bg())
                                .stroke(Stroke::new(1.0_f32, theme::danger_stroke()))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(10, 7))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        icon_label(ui, Icon::Alert, 15.0, theme::danger());
                                        ui.add_space(4.0);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&dns_info.trigger_reason)
                                                    .size(11.5)
                                                    .color(theme::danger()),
                                            )
                                            .wrap(),
                                        );
                                    });
                                });
                        }

                        if let Some(Err(ref err)) = self.route_trace_live_result.as_ref() {
                            if hit_action != RuleAction::Reject {
                                ui.add_space(8.0);
                                Frame::NONE
                                    .fill(theme::danger_bg())
                                    .stroke(Stroke::new(1.0_f32, theme::danger_stroke()))
                                    .corner_radius(CornerRadius::same(8))
                                    .inner_margin(Margin::symmetric(10, 7))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            icon_label(ui, Icon::Alert, 15.0, theme::danger());
                                            ui.add_space(4.0);
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!(
                                                        "真实网络探测未通: {err}（规则仍按配置推演）"
                                                    ))
                                                    .size(11.5)
                                                    .color(theme::danger()),
                                                )
                                                .wrap(),
                                            );
                                        });
                                    });
                            }
                        }

                        ui.add_space(10.0);

                        // --- 3.2 单屏四步极简链路卡片 ---
                        let node_name = node_info
                            .as_ref()
                            .map(|n| n.name.as_str())
                            .unwrap_or("未选中节点");
                        let node_proto = node_info
                            .as_ref()
                            .map(|n| n.protocol.to_ascii_uppercase())
                            .unwrap_or_else(|| "AUTO".to_string());
                        let group_name = if !self.proxy_selected_group.is_empty()
                            && self.proxy_selected_group != "全部"
                        {
                            self.proxy_selected_group.as_str()
                        } else {
                            "PROXY"
                        };

                        let exit_desc = match hit_action {
                            RuleAction::Reject => {
                                "命中拦截规则，已在本地阻断（未向外网发起连接）".to_string()
                            }
                            RuleAction::Direct => {
                                if let Some(ms) = live_probe_rtt_ms {
                                    format!("直接连往目标服务器（实测 {ms:.0}ms）")
                                } else {
                                    "直接连往目标服务器（不经过代理节点）".to_string()
                                }
                            }
                            RuleAction::Proxy => {
                                if let Some(ms) = live_probe_rtt_ms {
                                    format!(
                                        "经策略组 [{group_name}] → {node_name} ({node_proto}) · 实测 {ms:.0}ms"
                                    )
                                } else {
                                    format!(
                                        "经策略组 [{group_name}] → {node_name} ({node_proto})"
                                    )
                                }
                            }
                        };

                        Frame::NONE
                            .fill(theme::page_bg())
                            .stroke(Stroke::new(1.0_f32, theme::border_subtle()))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::same(14))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());

                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("链路过程")
                                            .size(12.5)
                                            .strong()
                                            .color(theme::text_primary()),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            let source_tag = if report.is_from_vpcore_api {
                                                "VP-Core 实时引擎"
                                            } else {
                                                "本地规则推演"
                                            };
                                            ui.label(
                                                RichText::new(source_tag)
                                                    .size(11.0)
                                                    .color(theme::muted()),
                                            );
                                        },
                                    );
                                });

                                ui.add_space(10.0);

                                // 1. 入站
                                trace_flow_row(
                                    ui,
                                    "1. 入站",
                                    theme::accent_strong(),
                                    &format!("本地端口 127.0.0.1:{inbound_port} 接收 {proto} 请求 → {host}:{port}"),
                                    None,
                                    true,
                                );

                                // 2. DNS
                                trace_flow_row(
                                    ui,
                                    "2. DNS",
                                    dns_color,
                                    &dns_info.trigger_reason,
                                    dns_info.advice.as_deref(),
                                    true,
                                );

                                // 3. 规则
                                trace_flow_row(
                                    ui,
                                    "3. 规则",
                                    action_color,
                                    &format!("第 {hit_index} 条命中：{hit_text}（{hit_reason}）"),
                                    None,
                                    true,
                                );

                                if !report.rule_records.is_empty() {
                                    ui.horizontal(|ui| {
                                        ui.add_space(20.0);
                                        let toggle_label = if self.route_trace_expand_rules {
                                            format!("收起已比对规则（共 {} 条）", report.rule_records.len())
                                        } else {
                                            format!("展开已比对规则（共 {} 条）", report.rule_records.len())
                                        };
                                        if ui
                                            .link(
                                                RichText::new(toggle_label)
                                                    .size(11.0)
                                                    .color(theme::accent_strong()),
                                            )
                                            .clicked()
                                        {
                                            self.route_trace_expand_rules =
                                                !self.route_trace_expand_rules;
                                        }
                                    });
                                    if self.route_trace_expand_rules {
                                        ui.add_space(4.0);
                                        for rec in &report.rule_records {
                                            let (tag, col) = match &rec.status {
                                                RuleMatchStatus::Hit(_) => ("HIT", action_color),
                                                RuleMatchStatus::Mismatch => ("SKIP", theme::muted()),
                                            };
                                            ui.horizontal(|ui| {
                                                ui.add_space(20.0);
                                                ui.label(
                                                    RichText::new(format!("#{:<2} [{tag}]", rec.index))
                                                        .size(10.5)
                                                        .monospace()
                                                        .color(col),
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(&rec.rule_text)
                                                            .size(11.0)
                                                            .monospace()
                                                            .color(if rec.is_final {
                                                                theme::text_primary()
                                                            } else {
                                                                theme::text_secondary()
                                                            }),
                                                    )
                                                    .wrap(),
                                                );
                                            });
                                        }
                                    }
                                    ui.add_space(4.0);
                                }

                                // 4. 出口
                                let exit_dot = if hit_action == RuleAction::Reject {
                                    theme::danger()
                                } else {
                                    theme::success()
                                };
                                trace_flow_row(ui, "4. 出口", exit_dot, &exit_desc, None, false);
                            });
                    });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(8.0);

                // ===== 4. 底部操作栏 =====
                ui.horizontal(|ui| {
                    let probe_btn = ui.add_enabled(
                        running && !is_probing,
                        egui::Button::new(RichText::new("实测网络连通").size(12.0)),
                    );
                    if probe_btn.clicked() {
                        trigger_probe = true;
                        self.route_trace_live_result = None;
                        self.route_trace_last_diagnosed = Some(std::time::Instant::now());
                    }
                    if !running {
                        probe_btn.on_hover_text("需先启动代理后方可实测目标连通性与延迟");
                    }

                    let copy_btn = ui.button(RichText::new("复制报告").size(12.0));
                    if copy_btn.clicked() {
                        if let Some(ref report) = self.route_trace_report {
                            copy_payload = Some(report.format_text(self.route_trace_expand_rules, false));
                        }
                    }

                    if let Some(t) = self.route_trace_copied_notice {
                        if t.elapsed() < std::time::Duration::from_secs(3) {
                            ui.add_space(6.0);
                            icon_label(ui, Icon::Check, 13.0, theme::success());
                            ui.label(RichText::new("已复制").size(11.5).color(theme::success()));
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button(RichText::new("关闭").size(12.0))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            close_dialog = true;
                        }
                    });
                });
            });

        if close_dialog {
            open = false;
        }
        self.show_route_trace_dialog = open;

        if let Some(text) = copy_payload {
            ctx.copy_text(text);
            self.route_trace_copied_notice = Some(std::time::Instant::now());
        }
        if trigger_probe {
            self.start_live_route_probe();
        }
    }
}

fn trace_flow_row(
    ui: &mut egui::Ui,
    label: &str,
    dot_color: Color32,
    summary: &str,
    hint: Option<&str>,
    has_next: bool,
) {
    ui.horizontal(|ui| {
        let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 18.0), Sense::hover());
        ui.painter().circle_filled(
            Pos2::new(dot_rect.center().x, dot_rect.min.y + 8.5),
            3.5,
            dot_color,
        );

        ui.add_space(2.0);
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.allocate_ui(Vec2::new(50.0, 16.0), |ui| {
                    ui.label(
                        RichText::new(label)
                            .size(11.5)
                            .strong()
                            .color(theme::text_primary()),
                    );
                });
                ui.add(
                    egui::Label::new(
                        RichText::new(summary)
                            .size(12.0)
                            .color(theme::text_secondary()),
                    )
                    .wrap(),
                );
            });
            if let Some(tip) = hint {
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("说明：{tip}"))
                            .size(11.0)
                            .color(theme::muted()),
                    )
                    .wrap(),
                );
            }
        });
    });
    if has_next {
        ui.add_space(6.0);
    }
}

fn vertical_hairline(ui: &mut egui::Ui, height: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(4.0, height), Sense::hover());
    ui.painter().line_segment(
        [
            Pos2::new(rect.center().x, rect.min.y + 2.0),
            Pos2::new(rect.center().x, rect.max.y - 2.0),
        ],
        Stroke::new(1.0_f32, theme::border_subtle()),
    );
}

fn soft_pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    Frame::NONE
        .fill(bg)
        .stroke(Stroke::new(1.0_f32, fg.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).strong().color(fg));
        });
}
