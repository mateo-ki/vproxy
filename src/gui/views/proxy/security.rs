use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::widgets::{panel_frame, section_title};
use crate::gui::VpnApp;
use crate::proxy::ProxyMode;
use eframe::egui::{self, CornerRadius, RichText, Stroke, Ui};

impl VpnApp {
    pub(crate) fn ui_proxy_security(&mut self, ui: &mut Ui) {
        section_title(
            ui,
            self.tr("隐私安全"),
            "uTLS 指纹伪装 · WebRTC 防泄漏 · 隐私追踪拦截 · 端口跳跃",
        );

        let mut changed = false;

        egui::ScrollArea::vertical()
            .id_salt("proxy_security_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
            // 顶部总览卡片
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Shield, 18.0, theme::accent());
                    ui.label(RichText::new("抗追踪与身份安全防护中心").strong().size(15.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("⚡ 一键开启最佳防护")
                                        .strong()
                                        .size(12.5)
                                        .color(theme::accent_strong()),
                                )
                                .fill(theme::accent_bg())
                                .stroke(Stroke::new(1.0_f32, theme::accent().gamma_multiply(0.40)))
                                .corner_radius(CornerRadius::same(8)),
                            )
                            .on_hover_text("一键启用 Chrome 指纹伪装、WebRTC 防泄漏与隐私追踪广告过滤")
                            .clicked()
                        {
                            self.proxy_config.client_fingerprint = Some("chrome".to_string());
                            self.proxy_config.block_webrtc = true;
                            self.proxy_config.block_trackers = true;
                            changed = true;
                            self.status = "已一键开启最佳安全隐私防护".to_string();
                        }
                    });
                });
                ui.add_space(4.0);
                ui.label(
                    RichText::new("TLS 指纹伪装、防 IP/DNS 泄露与追踪拦截。")
                        .small()
                        .color(theme::text_secondary()),
                );
            });

            ui.add_space(8.0);

            // -------------------------------------------------------------
            // 卡片 1：全局 uTLS 浏览器指纹伪装
            // -------------------------------------------------------------
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Globe, 16.0, theme::accent());
                    ui.label(
                        RichText::new("全局 uTLS 浏览器指纹伪装")
                            .strong()
                            .size(14.0),
                    );
                });
                ui.add_space(4.0);
                ui.label(
                    RichText::new("模拟主流浏览器的 TLS 指纹特征，未配置 fp 的节点也会自动注入。")
                        .small()
                        .color(theme::text_secondary()),
                );
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("模拟浏览器预设:").strong());

                    let current_fp_label = match self.proxy_config.client_fingerprint.as_deref() {
                        Some("chrome") => "Chrome",
                        Some("safari") => "Safari",
                        Some("firefox") => "Firefox",
                        Some("edge") => "Microsoft Edge",
                        Some("ios") => "iOS WebKit",
                        Some("randomized") => "Randomized（每次随机）",
                        Some(other) => other,
                        None => "关闭指纹伪装",
                    };

                    egui::ComboBox::from_id_salt("security_utls_fingerprint")
                        .selected_text(current_fp_label)
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            let options = [
                                (Some("chrome".to_string()), "Chrome"),
                                (Some("safari".to_string()), "Safari"),
                                (Some("firefox".to_string()), "Firefox"),
                                (Some("edge".to_string()), "Microsoft Edge"),
                                (Some("ios".to_string()), "iOS WebKit"),
                                (Some("randomized".to_string()), "Randomized（每次随机）"),
                                (None, "关闭指纹伪装"),
                            ];
                            for (val, label) in options {
                                let is_selected = self.proxy_config.client_fingerprint == val;
                                if ui.selectable_label(is_selected, label).clicked() {
                                    self.proxy_config.client_fingerprint = val;
                                    changed = true;
                                }
                            }
                        });
                });
            });

            ui.add_space(8.0);

            // -------------------------------------------------------------
            // 卡片 2：WebRTC 真实 IP 泄漏防御 (Anti-WebRTC Leak)
            // -------------------------------------------------------------
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Shield, 16.0, theme::warning());
                    ui.label(
                        RichText::new("WebRTC 真实 IP 防泄露")
                            .strong()
                            .size(14.0),
                    );
                    help_tooltip(
                        ui,
                        "在内核层拦截 STUN/TURN 探测流量与端口；搭配 TUN 模式可实现彻底防护。",
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_fill, btn_color) = if self.proxy_config.block_webrtc {
                            ("● 已启用防御", theme::accent_bg(), theme::accent_strong())
                        } else {
                            ("○ 未启用", theme::panel_hover(), theme::muted())
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(btn_text).size(12.0).color(btn_color),
                                )
                                .fill(btn_fill),
                            )
                            .on_hover_text("点击切换 WebRTC 真实 IP 防泄漏开关")
                            .clicked()
                        {
                            self.proxy_config.block_webrtc = !self.proxy_config.block_webrtc;
                            changed = true;
                        }
                    });
                });
            });

            ui.add_space(8.0);

            // -------------------------------------------------------------
            // 卡片 3：DNS 防泄露
            // -------------------------------------------------------------
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Globe, 16.0, theme::accent());
                    ui.label(
                        RichText::new("DNS 真实泄露防御")
                            .strong()
                            .size(14.0),
                    );
                    help_tooltip(
                        ui,
                        "国内与海外 DNS 分流解析；推荐配合 TUN 模式劫持全系统 DNS。",
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (mode_badge, mode_color) = if self.proxy_config.mode == ProxyMode::Tun {
                            ("● TUN 全局接管保护中", theme::accent())
                        } else {
                            ("⚠️ 系统代理模式（存在旁路风险）", theme::warning())
                        };
                        ui.label(RichText::new(mode_badge).small().color(mode_color));
                    });
                });
            });

            ui.add_space(8.0);

            // -------------------------------------------------------------
            // 卡片 4：隐私与行为追踪广告过滤
            // -------------------------------------------------------------
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Alert, 16.0, theme::accent());
                    ui.label(
                        RichText::new("隐私与追踪广告过滤")
                            .strong()
                            .size(14.0),
                    );
                    help_tooltip(
                        ui,
                        "加载广告与隐私追踪过滤规则库（ads / privacy / reject）。",
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_fill, btn_color) = if self.proxy_config.block_trackers {
                            ("● 已启用拦截", theme::accent_bg(), theme::accent_strong())
                        } else {
                            ("○ 未启用", theme::panel_hover(), theme::muted())
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(btn_text).size(12.0).color(btn_color),
                                )
                                .fill(btn_fill),
                            )
                            .on_hover_text("点击切换行为追踪与广告拦截开关")
                            .clicked()
                        {
                            self.proxy_config.block_trackers = !self.proxy_config.block_trackers;
                            changed = true;
                        }
                    });
                });
            });

            ui.add_space(8.0);

            // -------------------------------------------------------------
            // 卡片 5：UDP 端口跳跃
            // -------------------------------------------------------------
            panel_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    icon_label(ui, Icon::Lightning, 16.0, theme::accent());
                    ui.label(
                        RichText::new("UDP 端口跳跃")
                            .strong()
                            .size(14.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_fill, btn_color) = if self.proxy_config.udp_port_hopping {
                            ("● 已启用", theme::accent_bg(), theme::accent_strong())
                        } else {
                            ("○ 未启用", theme::panel_hover(), theme::muted())
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(btn_text).size(12.0).color(btn_color),
                                )
                                .fill(btn_fill),
                            )
                            .on_hover_text("点击切换 UDP 端口跳跃开关")
                            .clicked()
                        {
                            self.proxy_config.udp_port_hopping = !self.proxy_config.udp_port_hopping;
                            changed = true;
                        }
                    });
                });
                ui.add_space(4.0);
                ui.label(
                    RichText::new("用于 Hysteria2 / TUIC 协议的多端口跳跃传输，改善晚高峰单端口限速与丢包。")
                        .small()
                        .color(theme::text_secondary()),
                );
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("端口跳跃范围:").strong());
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.proxy_config.hop_ports)
                            .desired_width(140.0)
                            .hint_text("如 20000-40000"),
                    );
                    if edit.lost_focus() {
                        changed = true;
                    }
                    ui.label(
                        RichText::new("（服务端支持的端口范围，格式如 20000-40000）")
                            .small()
                            .color(theme::muted()),
                    );
                });
            });
        });

        if changed {
            self.save_proxy_config();
        }
    }
}

fn help_tooltip(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Button::new(RichText::new("?").strong().size(11.0).color(theme::muted()))
            .min_size(egui::vec2(18.0, 18.0))
            .corner_radius(CornerRadius::same(9))
            .fill(theme::panel_hover())
            .stroke(Stroke::new(1.0, theme::border_subtle())),
    )
    .on_hover_text(text);
}
