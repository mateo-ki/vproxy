use super::{pill_toggle, settings_divider, settings_group, settings_row, stepper_u32};
use crate::gui::VpnApp;
use eframe::egui::Ui;

impl VpnApp {
    pub(crate) fn ui_settings_network(&mut self, ui: &mut Ui) {
        let mut auto_save = false;

        let failover_hint = self
            .failover_last_reason
            .clone()
            .unwrap_or_else(|| "当前节点失联或延迟超标时自动切到备用节点".into());
        settings_group(ui, "故障自动切换", None, |ui| {
            settings_row(
                ui,
                "network_auto_failover",
                "故障自动切换",
                Some(&failover_hint),
                |ui| {
                    if pill_toggle(ui, &mut self.auto_failover).changed() {
                        let on = self.auto_failover;
                        self.set_auto_failover(on);
                        self.status = if on {
                            "已启用节点故障自动切换".into()
                        } else {
                            "已关闭节点故障自动切换".into()
                        };
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "network_failover_latency",
                self.tr("切换延迟阈值"),
                Some("超过该阈值触发节点切换评估"),
                |ui| {
                    if stepper_u32(
                        ui,
                        &mut self.edit_failover_latency_ms,
                        200..=15_000,
                        100,
                        " ms",
                    ) {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "network_bandwidth_guard",
                "最低带宽保护",
                Some("持续低于该速率时自动切线（0 表示不限）"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_bandwidth_guard).changed() {
                        auto_save = true;
                    }
                    if self.edit_bandwidth_guard {
                        ui.add_space(6.0);
                        if stepper_u32(
                            ui,
                            &mut self.edit_bandwidth_min_kbps,
                            0..=102_400,
                            128,
                            " KB/s",
                        ) {
                            auto_save = true;
                        }
                    }
                },
            );
        });

        let geo_hint = if self.geo_updating {
            "正在下载并更新 GeoIP / GeoSite 规则数据库..."
        } else {
            "更新本地 GeoIP 与 GeoSite 分流规则数据"
        };
        settings_group(ui, "代理防打断与规则库", None, |ui| {
            settings_row(
                ui,
                "network_rearm_system_proxy",
                "保护系统代理不被其他软件覆盖",
                Some("被外部工具修改或清空时自动恢复本软件代理设置"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_auto_rearm_system_proxy).changed() {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "network_geo_update",
                "分流规则数据库",
                Some(geo_hint),
                |ui| {
                    if ui
                        .add_enabled(!self.geo_updating, eframe::egui::Button::new("在线更新"))
                        .clicked()
                    {
                        self.update_geo_data();
                    }
                },
            );
        });

        if auto_save && self.settings_dirty() {
            self.save_settings();
        }
    }
}
