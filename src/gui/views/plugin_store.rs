use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::types::Tab;
use crate::gui::widgets::{primary_btn, section_title};
use crate::gui::VpnApp;
use crate::plugin::{PluginMeta, PLUGIN_CATALOG};
use eframe::egui::{self, CornerRadius, Frame, Margin, RichText, Stroke, Ui};

#[derive(Clone, Copy)]
enum PluginCardAction {
    Install(&'static str),
    Uninstall(&'static str),
    DiscoverGists,
    FetchVpnGate,
    ViewSources,
    ConfigGist,
}

impl VpnApp {
    pub(crate) fn ui_plugin_store(&mut self, ui: &mut Ui) {
        section_title(ui, self.tr("插件商店"), "功能扩展 · 节点采集 · 自动化订阅");

        egui::ScrollArea::vertical()
            .id_salt("plugin_store_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);

                let available_width = ui.available_width();
                let target_width = 380.0;
                let cols = ((available_width / target_width).floor() as usize).clamp(1, 3);

                let catalog = PLUGIN_CATALOG;
                let rows = catalog.len().div_ceil(cols);
                let mut pending_action: Option<PluginCardAction> = None;

                for row in 0..rows {
                    let start = row * cols;
                    let end = (start + cols).min(catalog.len());
                    let row_items = &catalog[start..end];

                    if cols == 1 {
                        for plugin in row_items {
                            let is_installed = self.is_plugin_installed(plugin.id);
                            if let Some(act) =
                                Self::render_plugin_card(ui, plugin, is_installed, self.busy)
                            {
                                pending_action = Some(act);
                            }
                            ui.add_space(8.0);
                        }
                    } else {
                        ui.columns(cols, |column_uis| {
                            for (col_idx, col_ui) in column_uis.iter_mut().enumerate() {
                                if let Some(plugin) = row_items.get(col_idx) {
                                    let is_installed = self.is_plugin_installed(plugin.id);
                                    if let Some(act) = Self::render_plugin_card(
                                        col_ui,
                                        plugin,
                                        is_installed,
                                        self.busy,
                                    ) {
                                        pending_action = Some(act);
                                    }
                                }
                            }
                        });
                        ui.add_space(8.0);
                    }
                }

                if let Some(action) = pending_action {
                    match action {
                        PluginCardAction::Install(id) => self.install_plugin(id),
                        PluginCardAction::Uninstall(id) => self.uninstall_plugin(id),
                        PluginCardAction::DiscoverGists => self.discover_gists(),
                        PluginCardAction::FetchVpnGate => self.fetch_vpngate_nodes(),
                        PluginCardAction::ViewSources => self.tab = Tab::Sources,
                        PluginCardAction::ConfigGist => self.show_gist_config_modal = true,
                    }
                }
            });
    }

    fn render_plugin_card(
        ui: &mut Ui,
        plugin: &PluginMeta,
        is_installed: bool,
        busy: bool,
    ) -> Option<PluginCardAction> {
        let mut action: Option<PluginCardAction> = None;
        let icon = match plugin.icon_name {
            "globe" => Icon::Globe,
            "search" => Icon::Search,
            _ => Icon::Package,
        };

        let card_frame = Frame::NONE
            .fill(theme::panel())
            .stroke(theme::card_stroke())
            .shadow(theme::card_shadow())
            .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
            .inner_margin(Margin::symmetric(14, 12));

        card_frame.show(ui, |ui| {
            // 顶部：图标 + 标题 + 版本 + 状态徽标
            ui.horizontal(|ui| {
                icon_label(ui, icon, 16.0, theme::accent());
                ui.add_space(2.0);
                ui.label(
                    RichText::new(plugin.name)
                        .strong()
                        .size(14.0)
                        .color(theme::text_primary()),
                );
                ui.label(
                    RichText::new(format!("v{}", plugin.version))
                        .small()
                        .color(theme::muted()),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if is_installed {
                        Frame::NONE
                            .fill(theme::success().gamma_multiply(0.12))
                            .stroke(Stroke::new(1.0, theme::success().gamma_multiply(0.35)))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("已安装")
                                        .size(10.5)
                                        .strong()
                                        .color(theme::success()),
                                );
                            });
                    } else {
                        Frame::NONE
                            .fill(theme::panel_hover())
                            .stroke(Stroke::new(1.0, theme::border_subtle()))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(RichText::new("未安装").size(10.5).color(theme::muted()));
                            });
                    }
                });
            });

            ui.add_space(3.0);
            // 分类与作者信息
            ui.horizontal(|ui| {
                Frame::NONE
                    .fill(theme::accent().gamma_multiply(0.10))
                    .corner_radius(CornerRadius::same(3))
                    .inner_margin(Margin::symmetric(5, 1))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(plugin.category)
                                .size(10.0)
                                .strong()
                                .color(theme::accent()),
                        );
                    });
                ui.add_space(2.0);
                ui.label(
                    RichText::new(format!("by {}", plugin.author))
                        .small()
                        .color(theme::muted()),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.hyperlink_to("官网 / 主页 ↗", plugin.website);
                });
            });

            ui.add_space(5.0);
            // 描述
            ui.label(
                RichText::new(plugin.description)
                    .size(11.5)
                    .color(theme::text_secondary()),
            );

            ui.add_space(8.0);
            // 底部操作按钮
            ui.horizontal(|ui| {
                if !is_installed {
                    if ui
                        .add(primary_btn("📥 安装插件"))
                        .on_hover_text("安装此插件并在订阅源中启用对应节点采集")
                        .clicked()
                    {
                        action = Some(PluginCardAction::Install(plugin.id));
                    }
                } else {
                    let pull_label = match plugin.id {
                        "gist" => "⚡ 发现节点",
                        "vpngate" => "⚡ 拉取节点",
                        _ => "⚡ 立即拉取",
                    };
                    if ui
                        .add_enabled(!busy, primary_btn(pull_label))
                        .on_hover_text("立即拉取并更新该插件提供的节点数据")
                        .clicked()
                    {
                        action = Some(match plugin.id {
                            "gist" => PluginCardAction::DiscoverGists,
                            "vpngate" => PluginCardAction::FetchVpnGate,
                            _ => PluginCardAction::ViewSources,
                        });
                    }

                    if ui
                        .button("📋 订阅源")
                        .on_hover_text("跳转到订阅源管理页面查看已添加的源")
                        .clicked()
                    {
                        action = Some(PluginCardAction::ViewSources);
                    }

                    if plugin.id == "gist"
                        && ui
                            .button("⚙️ 配置")
                            .on_hover_text("配置 Gist 搜索协议与翻页深度")
                            .clicked()
                    {
                        action = Some(PluginCardAction::ConfigGist);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button(RichText::new("卸载").size(11.0).color(theme::warning()))
                            .on_hover_text("卸载此插件并从订阅源中移除对应配置")
                            .clicked()
                        {
                            action = Some(PluginCardAction::Uninstall(plugin.id));
                        }
                    });
                }
            });
        });

        action
    }
}
