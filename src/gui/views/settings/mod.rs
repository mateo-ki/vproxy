pub mod api;
pub mod appearance;
pub mod automation;
pub mod cleanup;
pub mod general;
pub mod network;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub(crate) use appearance::{
    font_scale_ticks, handle_travel_range, FONT_SCALE_MAX, FONT_SCALE_MIN,
};

use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::types::SettingsTab;
use crate::gui::widgets::macos_segmented_tabs;
pub(super) use crate::gui::widgets::{
    pill_toggle, segmented_pills, settings_divider, settings_group, settings_row, stepper_u32,
};
use crate::gui::VpnApp;
use eframe::egui::{self, Align, Frame, Layout, Margin, RichText, Ui};

impl VpnApp {
    pub(crate) fn ui_settings(&mut self, ui: &mut Ui) {
        let mut tab = self.settings_tab;
        let dirty = self.settings_dirty();
        let saving = self.settings_saving;
        let tr_title = self.tr("系统设置");
        let tr_auto_save = self.tr("修改后自动保存");
        let tr_general = self.tr("常规");
        let tr_appearance = self.tr("外观");
        let tr_automation = self.tr("订阅测速");
        let tr_network = self.tr("代理守护");
        let tr_api = self.tr("接口");
        let tr_cleanup = self.tr("清理");
        let tr_reset = self.tr("重置修改");

        let mut reset_clicked = false;
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(tr_title)
                        .strong()
                        .size(20.0)
                        .color(theme::text_primary()),
                );
                ui.label(RichText::new(tr_auto_save).size(11.5).color(theme::muted()));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if dirty
                    && !saving
                    && ui
                        .button(tr_reset)
                        .on_hover_text("恢复为当前已保存的配置")
                        .clicked()
                {
                    reset_clicked = true;
                }
                if saving {
                    ui.label(RichText::new("正在保存...").color(theme::accent()).small());
                    ui.spinner();
                } else if dirty {
                    ui.label(RichText::new("待保存").color(theme::warning()).small());
                    icon_label(ui, Icon::Alert, 12.0, theme::warning());
                } else {
                    ui.label(
                        RichText::new(self.tr("已同步"))
                            .color(theme::accent_strong())
                            .small(),
                    );
                    icon_label(ui, Icon::Check, 12.0, theme::accent_strong());
                }
            });
        });

        ui.add_space(10.0);
        macos_segmented_tabs(
            ui,
            &mut tab,
            &[
                (SettingsTab::General, Icon::Gear, tr_general),
                (SettingsTab::Appearance, Icon::Appearance, tr_appearance),
                (SettingsTab::Automation, Icon::Lightning, tr_automation),
                (SettingsTab::Network, Icon::Shield, tr_network),
                (SettingsTab::Api, Icon::Plug, tr_api),
                (SettingsTab::Cleanup, Icon::Trash, tr_cleanup),
            ],
        );

        self.settings_tab = tab;
        if reset_clicked {
            self.sync_edit_settings();
            self.reload_settings();
        }
        ui.add_space(14.0);

        // 设置页内容可能高于当前窗口，整体放进 ScrollArea 保证窄屏也能滚到底部。
        egui::ScrollArea::vertical()
            .id_salt("settings_main_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                Frame::NONE
                    .inner_margin(Margin {
                        left: 0,
                        right: 6,
                        top: 0,
                        bottom: 4,
                    })
                    .show(ui, |ui| match self.settings_tab {
                        SettingsTab::General => self.ui_settings_general(ui),
                        SettingsTab::Appearance => self.ui_settings_appearance(ui),
                        SettingsTab::Automation => self.ui_settings_automation(ui),
                        SettingsTab::Network => self.ui_settings_network(ui),
                        SettingsTab::Api => self.ui_api(ui),
                        SettingsTab::Cleanup => self.ui_settings_cleanup(ui),
                    });
            });
    }
}
