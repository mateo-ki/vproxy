use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::types::Tab;
use crate::gui::widgets::{card_frame, primary_btn, section_title};
use crate::gui::VpnApp;
use crate::plugin::PLUGIN_CATALOG;
use eframe::egui::{self, RichText, Ui};

impl VpnApp {
    pub(crate) fn ui_plugin_store(&mut self, ui: &mut Ui) {
        section_title(ui, self.tr("插件商店"), "功能扩展 · 节点采集 · 自动化订阅");

        egui::ScrollArea::vertical()
            .id_salt("plugin_store_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);

                for plugin in PLUGIN_CATALOG {
                    let is_installed = self.is_plugin_installed(plugin.id);
                    let icon = match plugin.icon_name {
                        "globe" => Icon::Globe,
                        "search" => Icon::Search,
                        _ => Icon::Package,
                    };

                    card_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            icon_label(ui, icon, 18.0, theme::accent());
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(plugin.name)
                                    .strong()
                                    .size(15.0)
                                    .color(theme::text_primary()),
                            );
                            ui.label(
                                RichText::new(format!("v{}", plugin.version))
                                    .small()
                                    .color(theme::muted()),
                            );
                            ui.label(
                                RichText::new(format!("[{}]", plugin.category))
                                    .small()
                                    .color(theme::accent_strong()),
                            );

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if is_installed {
                                        ui.label(
                                            RichText::new("已安装")
                                                .strong()
                                                .color(theme::success()),
                                        );
                                    } else {
                                        ui.label(
                                            RichText::new("未安装").small().color(theme::muted()),
                                        );
                                    }
                                },
                            );
                        });

                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(plugin.description)
                                .size(12.0)
                                .color(theme::text_secondary()),
                        );

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("作者: {}", plugin.author))
                                    .small()
                                    .color(theme::muted()),
                            );
                            ui.add_space(10.0);
                            ui.hyperlink_to("官网 / 项目主页 ↗", plugin.website);
                        });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            if !is_installed {
                                if ui
                                    .add(primary_btn("📥 下载并安装"))
                                    .on_hover_text(
                                        "下载并安装此插件，自动在订阅源中启用对应节点采集",
                                    )
                                    .clicked()
                                {
                                    self.install_plugin(plugin.id);
                                }
                            } else {
                                let pull_label = match plugin.id {
                                    "gist" => "⚡ 立即发现 Gist 节点",
                                    "vpngate" => "⚡ 立即拉取 VPN Gate 节点",
                                    _ => "⚡ 立即拉取订阅",
                                };
                                if ui
                                    .add_enabled(!self.busy, primary_btn(pull_label))
                                    .on_hover_text("立即拉取并更新该插件提供的节点数据")
                                    .clicked()
                                {
                                    match plugin.id {
                                        "gist" => self.discover_gists(),
                                        "vpngate" => self.fetch_vpngate_nodes(),
                                        _ => {}
                                    }
                                }

                                if ui
                                    .button("📋 查看订阅源")
                                    .on_hover_text("跳转到订阅源管理页面查看已添加的源")
                                    .clicked()
                                {
                                    self.tab = Tab::Sources;
                                }

                                if plugin.id == "gist"
                                    && ui
                                        .button("⚙️ 抓取配置")
                                        .on_hover_text("配置 Gist 搜索协议与翻页深度")
                                        .clicked()
                                {
                                    self.show_gist_config_modal = true;
                                }

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .button(RichText::new("卸载").color(theme::warning()))
                                            .on_hover_text("卸载此插件并从订阅源中移除对应配置")
                                            .clicked()
                                        {
                                            self.uninstall_plugin(plugin.id);
                                        }
                                    },
                                );
                            }
                        });
                    });

                    ui.add_space(10.0);
                }
            });
    }
}
