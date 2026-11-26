use super::{pill_toggle, settings_divider, settings_group, settings_row, stepper_u32};
use crate::gui::VpnApp;
use eframe::egui::{self, Ui};

const SPEEDTEST_URL_PRESETS: [(&str, &str); 4] = [
    ("http://cp.cloudflare.com/generate_204", "Cloudflare HTTP"),
    ("https://www.google.com/generate_204", "Google 204"),
    ("http://www.gstatic.com/generate_204", "Gstatic HTTP"),
    ("https://cp.cloudflare.com/generate_204", "Cloudflare HTTPS"),
];

impl VpnApp {
    pub(crate) fn ui_settings_automation(&mut self, ui: &mut Ui) {
        let mut auto_save = false;

        let last_fetch_hint = self.settings.last_auto_fetch_at.map(|t| {
            format!(
                "上次自动拉取: {}",
                t.with_timezone(&chrono::Local).format("%m-%d %H:%M")
            )
        });
        settings_group(ui, "订阅同步与过滤", None, |ui| {
            settings_row(
                ui,
                "auto_fetch_enabled",
                "定时自动拉取",
                last_fetch_hint
                    .as_deref()
                    .or(Some("按固定周期后台更新已启用订阅")),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_auto_fetch).changed() {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "auto_fetch_interval",
                "同步间隔",
                Some("两次自动拉取的间隔时间"),
                |ui| {
                    if stepper_u32(ui, &mut self.edit_interval_min, 5..=1440, 15, " 分钟") {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "auto_exclude_keywords",
                "节点关键词排除",
                Some("逗号分隔，命中关键词的节点不入库"),
                |ui| {
                    let resp = ui.add_sized(
                        [220.0, 26.0],
                        egui::TextEdit::singleline(&mut self.edit_exclude_keywords)
                            .hint_text("例如: 官网,到期,剩余流量"),
                    );
                    if resp.changed() {
                        auto_save = true;
                    }
                },
            );
        });

        let last_speed_hint = self.settings.last_auto_speedtest_at.map(|t| {
            format!(
                "上次自动测速: {}",
                t.with_timezone(&chrono::Local).format("%m-%d %H:%M")
            )
        });
        settings_group(ui, "节点测速", None, |ui| {
            settings_row(
                ui,
                "auto_speedtest_enabled",
                "拉取后自动测速",
                last_speed_hint
                    .as_deref()
                    .or(Some("全部订阅同步完成后自动测速")),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_auto_speed).changed() {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "speedtest_added_source",
                "新增订阅源后自动测速",
                Some("导入或新建订阅拉取成功后自动测速"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_speedtest_added_source).changed() {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "speedtest_concurrency",
                "测速并发数",
                Some("同时探测节点数量上限"),
                |ui| {
                    if stepper_u32(
                        ui,
                        &mut self.edit_speedtest_concurrency,
                        1..=256,
                        8,
                        " 并发",
                    ) {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "speedtest_timeout_ms",
                "连接超时",
                Some("单节点探测等待上限"),
                |ui| {
                    if stepper_u32(ui, &mut self.edit_timeout_ms, 300..=15_000, 200, " ms") {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "speedtest_url",
                "测速目标",
                Some("用于判断节点连通性的探测地址"),
                |ui| {
                    let trimmed = self.edit_speedtest_url.trim().to_string();
                    let current_label = SPEEDTEST_URL_PRESETS
                        .iter()
                        .find(|(url, _)| *url == trimmed)
                        .map(|(_, label)| *label)
                        .unwrap_or("自定义");
                    let edit_resp = ui.add_sized(
                        [210.0, 24.0],
                        egui::TextEdit::singleline(&mut self.edit_speedtest_url)
                            .hint_text("http://cp.cloudflare.com/generate_204"),
                    );
                    if edit_resp.changed() {
                        auto_save = true;
                    }
                    egui::ComboBox::from_id_salt("speedtest_url_preset")
                        .selected_text(current_label)
                        .width(126.0)
                        .show_ui(ui, |ui| {
                            for &(url, label) in &SPEEDTEST_URL_PRESETS {
                                if ui.selectable_label(trimmed == url, label).clicked() {
                                    self.edit_speedtest_url = url.to_string();
                                    auto_save = true;
                                }
                            }
                        });
                },
            );
        });

        if auto_save && self.settings_dirty() {
            self.save_settings();
        }
    }
}
