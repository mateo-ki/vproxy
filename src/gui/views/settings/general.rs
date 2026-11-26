use super::{pill_toggle, segmented_pills, settings_divider, settings_group, settings_row};
use crate::gui::theme;
use crate::gui::VpnApp;
use eframe::egui::{RichText, Ui};

impl VpnApp {
    pub(crate) fn ui_settings_general(&mut self, ui: &mut Ui) {
        let mut auto_save = false;

        let close_tray_label = self.tr("托盘运行");
        let close_exit_label = self.tr("直接退出");
        settings_group(ui, "启动与窗口", None, |ui| {
            settings_row(
                ui,
                "general_close_to_tray",
                "关闭主窗口时",
                Some("点击右上角关闭按钮后的行为"),
                |ui| {
                    if segmented_pills(
                        ui,
                        &mut self.edit_close_to_tray,
                        &[(true, close_tray_label), (false, close_exit_label)],
                    ) {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "general_launch_at_startup",
                "开机自启",
                Some("登录系统后自动在后台运行"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_launch_at_startup).changed() {
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            let admin_hint =
                if self.edit_launch_as_admin && crate::platform::admin_relaunch_cancelled() {
                    "上次 UAC 授权已取消，仍可正常使用系统代理"
                } else {
                    "开启 TUN 虚拟网卡模式需要管理员权限"
                };
            settings_row(
                ui,
                "general_launch_as_admin",
                "以管理员权限启动",
                Some(admin_hint),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_launch_as_admin).changed() {
                        auto_save = true;
                        self.status = if self.edit_launch_as_admin {
                            "已开启以管理员方式启动（下次启动时请求提权）".into()
                        } else {
                            "已关闭自动请求管理员权限".into()
                        };
                    }
                },
            );
        });

        let mem_hint = self
            .memory_trimmed_status
            .clone()
            .unwrap_or_else(|| "释放闲置工作集与缓存连接池".into());
        let fw_hint = self
            .firewall_status
            .clone()
            .unwrap_or_else(|| "允许主程序与代理内核通过系统防火墙".into());
        settings_group(ui, "系统与安全", None, |ui| {
            settings_row(
                ui,
                "general_trim_memory",
                "内存整理",
                Some(&mem_hint),
                |ui| {
                    if ui.button(self.tr("深度整理内存")).clicked() {
                        self.trim_memory();
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "general_firewall_auto",
                self.tr("软件启动时自动加入防火墙放行规则"),
                Some("避免每次升级内核弹出防火墙拦截提示"),
                |ui| {
                    if pill_toggle(ui, &mut self.edit_firewall_auto_allow).changed() {
                        auto_save = true;
                        if self.edit_firewall_auto_allow && crate::platform::is_elevated() {
                            self.apply_firewall_rules();
                        }
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "general_firewall_now",
                self.tr("Windows 防火墙放行"),
                Some(&fw_hint),
                |ui| {
                    if ui.button(self.tr("立即写入防火墙规则")).clicked() {
                        self.apply_firewall_rules();
                    }
                },
            );
        });

        let backup_status_hint = self.profile_status.clone();
        settings_group(ui, "配置备份与迁移", None, |ui| {
            settings_row(
                ui,
                "general_backup_local",
                "本地配置快照",
                Some("保存全部订阅源、设置与分流规则至 backups"),
                |ui| {
                    if ui.button("备份至本地").clicked() {
                        self.export_profile_to_backup();
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "general_backup_file",
                "配置文件迁移",
                Some("跨设备导入或导出完整 YAML 配置"),
                |ui| {
                    if ui.button("导出文件").clicked() {
                        self.export_profile_to_file();
                    }
                    if ui.button("导入文件").clicked() {
                        self.import_profile_from_file();
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "general_backup_clipboard",
                "剪贴板恢复",
                Some("识别剪贴板中的配置内容并快速还原"),
                |ui| {
                    if ui.button("从剪贴板恢复").clicked() {
                        self.import_profile_from_clipboard();
                    }
                },
            );

            if let Some((status, is_err)) = backup_status_hint {
                settings_divider(ui);
                let color = if is_err {
                    theme::danger()
                } else {
                    theme::accent_strong()
                };
                ui.add_space(4.0);
                ui.label(RichText::new(status).small().color(color));
                ui.add_space(6.0);
            }
        });

        if auto_save && self.settings_dirty() {
            self.save_settings();
        }
    }
}
