use crate::app_update::{self, AppReleaseInfo, AppUpdateProgress, AppUpdateStage};
use crate::constants::brand::{RELEASES_URL, REPO_URL, TAGLINE};
use crate::gui::icons::{icon_label, Icon};
use crate::gui::theme;
use crate::gui::types::BgMsg;
use crate::gui::widgets::{
    card_frame, fold_title, format_bytes, icon_tile, pill, primary_btn, section_title,
    segmented_pills, settings_divider, status_badge,
};
use crate::gui::VpnApp;
use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, ProgressBar, RichText, Sense,
    Stroke, Ui, Vec2,
};

/// 开源与免责说明要点（精炼 4 条，避免文字墙）。
const DISCLAIMER_LINES: [&str; 4] = [
    "VProxy 基于 MIT 协议开源，仅提供订阅解析、节点管理与本地内核调度能力，不提供任何内置节点或线路服务。",
    "请遵守当地法律法规合法使用；因使用方式产生的一切责任由使用者自行承担。",
    "所有订阅、节点与测速数据仅保存于本地「数据目录」，无任何统计上报；仅在主动拉取订阅、检查更新、测速或查询 IP 风险时发起联网请求。",
    "VP-Core、Mihomo、Sing-box、Xray 等第三方内核与规则库均由对应开源项目提供，界面延迟与速率仅为瞬时实测参考。",
];

/// 后台自动检查在线更新的间隔：**6 小时**（按需拉取，避开 GitHub 匿名限流）。第一次仍然在启动后 1 秒查。
const APP_UPDATE_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60;

fn render_disclaimer_lines(ui: &mut Ui) {
    for (idx, line) in DISCLAIMER_LINES.iter().enumerate() {
        ui.add(
            egui::Label::new(
                RichText::new(*line)
                    .size(11.5)
                    .color(theme::text_secondary()),
            )
            .wrap(),
        );
        if idx + 1 < DISCLAIMER_LINES.len() {
            ui.add_space(4.0);
        }
    }
}

fn disclaimer_card(ui: &mut Ui) {
    card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::CollapsingHeader::new(fold_title("开源许可与使用声明"))
            .id_salt("about:disclaimer")
            .default_open(false)
            .show_background(false)
            .show(ui, |ui| {
                ui.add_space(4.0);
                render_disclaimer_lines(ui);
            });
    });
}

impl VpnApp {
    pub(crate) fn ui_about(&mut self, ui: &mut Ui) {
        section_title(ui, self.tr("关于"), "版本 · 更新 · 运行环境");

        egui::ScrollArea::vertical()
            .id_salt("about_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                Frame::NONE
                    .inner_margin(Margin {
                        left: 0,
                        right: 6,
                        top: 0,
                        bottom: 4,
                    })
                    .show(ui, |ui| {
                        self.ui_about_identity(ui);
                        ui.add_space(12.0);
                        self.ui_about_update(ui);
                        self.ui_about_paths(ui);
                        disclaimer_card(ui);
                    });
            });
    }

    fn ui_about_identity(&mut self, ui: &mut Ui) {
        let mut copy_version = false;
        let mut copy_diag = false;
        let mut open_repo = false;
        let current_ver = app_update::current_version();

        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let row_top = ui.cursor().top();
            let row_left = ui.max_rect().left();
            let row_right = ui.max_rect().right();
            let total_w = (row_right - row_left).max(200.0);
            let action_area_w = 210.0_f32.min(total_w * 0.42);
            let left_w = (total_w - action_area_w - 12.0).max(120.0);

            ui.horizontal(|ui| {
                ui.scope_builder(
                    egui::UiBuilder::new()
                        .id_salt("about:identity:left")
                        .max_rect(egui::Rect::from_min_size(
                            egui::pos2(row_left, row_top),
                            Vec2::new(left_w, 56.0),
                        )),
                    |ui| {
                        ui.horizontal(|ui| {
                            let texture = self.ensure_logo_texture(ui.ctx());
                            ui.add(
                                egui::Image::new(&texture)
                                    .fit_to_exact_size(Vec2::splat(46.0))
                                    .corner_radius(CornerRadius::same(10)),
                            );
                            ui.add_space(8.0);
                            ui.vertical(|ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new("VProxy")
                                            .strong()
                                            .size(20.0)
                                            .color(theme::text_primary()),
                                    );
                                    ui.add_space(4.0);
                                    let ver_text = format!("v{current_ver}");
                                    let ver_resp = ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new(&ver_text)
                                                    .size(11.5)
                                                    .strong()
                                                    .color(theme::accent_strong()),
                                            )
                                            .fill(theme::accent_bg())
                                            .stroke(Stroke::NONE)
                                            .corner_radius(CornerRadius::same(10))
                                            .min_size(Vec2::new(0.0, 22.0)),
                                        )
                                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                                        .on_hover_text("点击复制版本号");
                                    if ver_resp.clicked() {
                                        copy_version = true;
                                    }
                                    pill(ui, "MIT", theme::text_secondary(), theme::panel_hover());
                                    pill(
                                        ui,
                                        &format!("{} · {}", os_label(), std::env::consts::ARCH),
                                        theme::muted(),
                                        theme::sidebar(),
                                    );
                                });
                                ui.add_space(2.0);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(TAGLINE)
                                            .size(12.0)
                                            .color(theme::text_secondary()),
                                    )
                                    .truncate(),
                                );
                            });
                        });
                    },
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(button("GitHub ↗"))
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(REPO_URL)
                        .clicked()
                    {
                        open_repo = true;
                    }
                    if ui
                        .add(button(self.tr("复制环境信息")))
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("复制版本、系统、目录与内核状态摘要（不含订阅与节点密钥）")
                        .clicked()
                    {
                        copy_diag = true;
                    }
                });
            });
        });

        if copy_version {
            ui.ctx().copy_text(format!("v{current_ver}"));
            self.status = format!("已复制版本号 v{current_ver}");
        }
        if copy_diag {
            let summary = self.build_diagnostics_summary();
            ui.ctx().copy_text(summary);
            self.status = "已复制运行环境信息到剪贴板".into();
        }
        if open_repo {
            let _ = crate::platform::open_url_in_browser(REPO_URL);
            ui.ctx().open_url(egui::OpenUrl::new_tab(REPO_URL));
        }
    }

    fn build_diagnostics_summary(&self) -> String {
        let mut lines = vec![
            format!("VProxy v{}", app_update::current_version()),
            format!(
                "System: {} / {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            format!(
                "Channel: {}",
                if self.edit_insider_channel {
                    "insider"
                } else {
                    "stable"
                }
            ),
            format!("Data Root: {}", crate::data_root().display()),
            format!(
                "Proxy: {} (kernel pref: {:?})",
                if self.proxy_status.local_proxy_active() {
                    format!("active (mixed:{})", self.proxy_status.mixed_port)
                } else {
                    "inactive".into()
                },
                self.proxy_config.kernel_preference
            ),
        ];
        if !self.kernels.is_empty() {
            let kernel_desc = self
                .kernels
                .iter()
                .map(|k| {
                    let ver = k.version.as_deref().unwrap_or(if k.available {
                        "installed"
                    } else {
                        "missing"
                    });
                    format!("{:?}={}", k.kind, ver)
                })
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("Kernels: {kernel_desc}"));
        }
        lines.join("\n")
    }

    fn ui_about_update(&mut self, ui: &mut Ui) {
        let mut insider = self.edit_insider_channel;
        let tr_stable = self.tr("稳定版");
        let tr_insider = self.tr("预发版");
        let tr_title = self.tr("应用更新");
        let mut channel_changed = false;

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(tr_title)
                    .strong()
                    .size(13.0)
                    .color(theme::text_primary()),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if segmented_pills(ui, &mut insider, &[(false, tr_stable), (true, tr_insider)]) {
                    channel_changed = true;
                }
            });
        });

        if channel_changed {
            self.edit_insider_channel = insider;
            self.app_release = None;
            self.app_update_progress = None;
            self.app_update_checked_at = None;
            self.save_settings();
            if !self.app_update_busy {
                self.check_app_update();
            } else {
                self.status = format!(
                    "更新通道已切至{}",
                    if insider { "预发版" } else { "稳定版" }
                );
            }
        }

        ui.add_space(6.0);
        Frame::NONE
            .fill(theme::panel())
            .stroke(theme::card_stroke())
            .shadow(theme::card_shadow())
            .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
            .inner_margin(Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                let main_installer_ready = self
                    .app_installer_path
                    .as_ref()
                    .zip(self.app_installer_tag.as_ref())
                    .zip(self.app_release.as_ref())
                    .is_some_and(|((_, inst_tag), rel)| inst_tag == &rel.tag);

                let (title, title_color, tile_icon, tile_color) = if main_installer_ready {
                    let tag = self
                        .app_installer_tag
                        .as_deref()
                        .unwrap_or(app_update::current_version());
                    (
                        format!("安装包已就绪 · {tag}"),
                        theme::success(),
                        Icon::Check,
                        theme::success(),
                    )
                } else {
                    match &self.app_release {
                        Some(info) if info.update_available => (
                            format!("{} · {}", self.tr("发现新版本"), info.tag),
                            theme::accent_strong(),
                            Icon::ArrowUp,
                            theme::accent(),
                        ),
                        Some(info) => (
                            format!("{} · v{}", self.tr("已是最新"), info.current_version),
                            theme::accent_strong(),
                            Icon::Check,
                            theme::accent(),
                        ),
                        None if self.app_update_busy => (
                            self.tr("正在检查更新…").to_string(),
                            theme::text_primary(),
                            Icon::Sync,
                            theme::muted(),
                        ),
                        None => (
                            format!("当前版本 v{}", app_update::current_version()),
                            theme::text_primary(),
                            Icon::Sync,
                            theme::accent(),
                        ),
                    }
                };

                let mut sub_parts = vec![format!(
                    "{}通道",
                    if self.edit_insider_channel {
                        "预发"
                    } else {
                        "稳定"
                    }
                )];
                if let Some(at) = &self.app_update_checked_at {
                    sub_parts.push(format!("上次检查 {at}"));
                }
                if let Some(asset) = self.app_release.as_ref().and_then(|r| r.asset.as_ref()) {
                    sub_parts.push(format!("{} ({})", asset.name, format_bytes(asset.size)));
                }
                let subtitle = sub_parts.join(" · ");

                let mut action_check = false;
                let mut action_download = false;
                let mut action_install_path = None;
                let mut action_show_notes = None;

                ui.horizontal(|ui| {
                    icon_tile(ui, tile_icon, tile_color, theme::panel_hover());
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(title).strong().size(16.0).color(title_color));
                            if self.app_release.as_ref().is_some_and(|i| i.prerelease) {
                                status_badge(ui, self.tr("预发版"), theme::warning());
                            }
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(subtitle).size(11.5).color(theme::muted()),
                            )
                            .truncate(),
                        );
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.app_update_busy {
                            if ui.add(button("取消")).clicked() {
                                self.app_update_cancel
                                    .store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            ui.spinner();
                        } else if main_installer_ready {
                            if let Some(path) = self.app_installer_path.clone() {
                                let hint = install_platform_hint();
                                if ui
                                    .add(primary_btn("立即安装"))
                                    .on_hover_text(hint)
                                    .clicked()
                                {
                                    action_install_path = Some(path);
                                }
                            }
                            if ui.add(button(self.tr("检查更新"))).clicked() {
                                action_check = true;
                            }
                            if let Some(info) = &self.app_release {
                                if (info.update_available || info.body.is_some())
                                    && ui.add(button("更新日志")).clicked()
                                {
                                    action_show_notes = Some(release_notes_payload(info));
                                }
                            }
                        } else if let Some(info) = &self.app_release {
                            let can_install = info.can_install();
                            if info.update_available && can_install {
                                if ui
                                    .add(primary_btn(self.tr("下载更新")))
                                    .on_hover_text("下载并校验安装包")
                                    .clicked()
                                {
                                    action_download = true;
                                }
                                if ui.add(button(self.tr("检查更新"))).clicked() {
                                    action_check = true;
                                }
                            } else {
                                if ui.add(primary_btn(self.tr("检查更新"))).clicked() {
                                    action_check = true;
                                }
                                if can_install
                                    && ui
                                        .add(button("重下本版"))
                                        .on_hover_text("重新下载并校验当前版本安装包")
                                        .clicked()
                                {
                                    action_download = true;
                                }
                            }
                            if (info.update_available || info.body.is_some())
                                && ui.add(button("更新日志")).clicked()
                            {
                                action_show_notes = Some(release_notes_payload(info));
                            }
                        } else if ui.add(primary_btn(self.tr("检查更新"))).clicked() {
                            action_check = true;
                        }
                    });
                });

                if action_check {
                    self.check_app_update();
                }
                if action_download {
                    self.download_app_update();
                }
                if let Some(path) = action_install_path {
                    self.install_app_update(&path);
                }
                if let Some((tag, content)) = action_show_notes {
                    self.release_notes_content = Some((tag, content));
                    self.show_release_notes_modal = true;
                }

                if let Some(progress) = &self.app_update_progress {
                    ui.add_space(8.0);
                    self.ui_app_update_progress(ui, progress);
                }

                // 若用户从「历史版本」下载了与顶部主检测不同的安装包，仍保留醒目的安装条
                if !main_installer_ready {
                    if let Some(path) = self.app_installer_path.clone() {
                        let ready_tag = self.app_installer_tag.as_deref().unwrap_or("选定版本");
                        ui.add_space(8.0);
                        let mut install_ready_now = false;
                        Frame::NONE
                            .fill(theme::success_bg())
                            .stroke(Stroke::new(1.0, theme::success().gamma_multiply(0.45)))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(12, 8))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    icon_label(ui, Icon::Check, 14.0, theme::success());
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "安装包 {ready_tag} 已完成下载与校验"
                                        ))
                                        .size(12.5)
                                        .strong()
                                        .color(theme::text_primary()),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui
                                            .add(primary_btn("立即安装"))
                                            .on_hover_text(install_platform_hint())
                                            .clicked()
                                        {
                                            install_ready_now = true;
                                        }
                                        if let Some(parent) = path.parent() {
                                            if ui.add(button("打开位置")).clicked() {
                                                open_in_file_manager(parent);
                                            }
                                        }
                                    });
                                });
                            });
                        if install_ready_now {
                            self.install_app_update(&path);
                        }
                    }
                }

                ui.add_space(8.0);
                settings_divider(ui);
                ui.add_space(4.0);

                // 安装包检验细节（仅看包名/大小/SHA-256）
                let detail = self.app_release.clone();
                egui::CollapsingHeader::new(fold_title("安装包详情"))
                    .id_salt("about:release-detail")
                    .default_open(false)
                    .show_background(false)
                    .show(ui, |ui| {
                        let Some(info) = detail.as_ref() else {
                            ui.label(
                                RichText::new("尚未获取到版本元数据，请点击右上角「检查更新」。")
                                    .size(11.5)
                                    .color(theme::muted()),
                            );
                            return;
                        };
                        kv_row(
                            ui,
                            "目标版本",
                            &format!("v{} → {}", info.current_version, info.tag),
                            None,
                        );
                        if let Some(asset) = &info.asset {
                            let name = asset.name.clone();
                            if kv_row(ui, "安装包", &name, Some("复制")) {
                                ui.ctx().copy_text(name);
                                self.status = "已复制安装包文件名".into();
                            }
                            kv_row(ui, "大小", &format_bytes(asset.size), None);
                            let digest = asset
                                .sha256
                                .clone()
                                .unwrap_or_else(|| "待从 sha256.txt 获取".to_string());
                            if kv_row(ui, "SHA-256", &digest, Some("复制")) {
                                ui.ctx().copy_text(digest);
                                self.status = "已复制 SHA-256 摘要".into();
                            }
                        }
                        if kv_row(ui, "Releases", RELEASES_URL, Some("打开")) {
                            let _ = crate::platform::open_url_in_browser(RELEASES_URL);
                            ui.ctx().open_url(egui::OpenUrl::new_tab(RELEASES_URL));
                        }
                    });

                ui.add_space(4.0);
                settings_divider(ui);
                ui.add_space(4.0);

                // 历史版本与回退（原位操作，不覆写顶部主更新状态）
                let switcher_title = self.tr("历史版本与回退").to_string();
                egui::CollapsingHeader::new(fold_title(&switcher_title))
                    .id_salt("about:version-switcher")
                    .default_open(false)
                    .show_background(false)
                    .show(ui, |ui| {
                        self.ui_version_switcher(ui);
                    });
            });
        ui.add_space(14.0);
    }

    fn ui_version_switcher(&mut self, ui: &mut Ui) {
        if self.available_releases.is_empty()
            && !self.fetching_releases
            && !self.releases_requested_once
        {
            self.releases_requested_once = true;
            self.fetch_available_releases();
        }

        ui.horizontal(|ui| {
            let status_hint = if self.fetching_releases {
                "正在读取 GitHub Releases 版本列表…".to_string()
            } else if self.available_releases.is_empty() {
                "暂无可用版本记录".to_string()
            } else {
                format!(
                    "共 {} 个可用版本 · 支持直接下载升级或回退",
                    self.available_releases.len()
                )
            };
            ui.label(RichText::new(status_hint).size(11.5).color(theme::muted()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(!self.fetching_releases, button("刷新"))
                    .on_hover_text("重新拉取 GitHub Releases 列表")
                    .clicked()
                {
                    self.releases_requested_once = true;
                    self.fetch_available_releases();
                }
                if self.fetching_releases {
                    ui.spinner();
                }
            });
        });

        if self.available_releases.is_empty() {
            return;
        }

        ui.add_space(6.0);
        let current = app_update::current_version().to_string();
        let mut download_target: Option<AppReleaseInfo> = None;
        let mut install_target: Option<std::path::PathBuf> = None;
        let mut notes_target: Option<(String, String)> = None;

        let releases = self.available_releases.clone();
        egui::ScrollArea::vertical()
            .id_salt("about_releases_list")
            .max_height(240.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                for item in &releases {
                    let selected = self.selected_release_tag.as_deref() == Some(item.tag.as_str());
                    let is_ready_installer = self
                        .app_installer_tag
                        .as_deref()
                        .is_some_and(|t| t == item.tag)
                        && self.app_installer_path.is_some();
                    let is_newer = app_update::version_is_newer(&item.tag, &current);

                    let frame = Frame::NONE
                        .fill(if selected {
                            theme::panel_hover()
                        } else {
                            theme::sidebar()
                        })
                        .stroke(Stroke::new(
                            1.0,
                            if selected {
                                theme::accent().gamma_multiply(0.45)
                            } else {
                                theme::border_subtle()
                            },
                        ))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::symmetric(10, 7));

                    frame.show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(&item.tag)
                                            .strong()
                                            .size(13.0)
                                            .color(theme::text_primary()),
                                    );
                                    if item.is_current {
                                        status_badge(ui, "当前", theme::accent());
                                    } else if is_newer {
                                        status_badge(ui, "可升级", theme::success());
                                    }
                                    if item.prerelease {
                                        status_badge(ui, "预发", theme::warning());
                                    }
                                });
                                let mut meta = Vec::new();
                                if let Some(date) = &item.published_at {
                                    meta.push(date.clone());
                                }
                                if item.asset_size > 0 {
                                    meta.push(format_bytes(item.asset_size));
                                }
                                if let Some(name) = &item.asset_name {
                                    meta.push(name.clone());
                                }
                                if !meta.is_empty() {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(meta.join(" · "))
                                                .size(11.0)
                                                .color(theme::muted()),
                                        )
                                        .truncate(),
                                    );
                                }
                            });

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if is_ready_installer {
                                    if let Some(path) = self.app_installer_path.clone() {
                                        if ui
                                            .add_enabled(
                                                !self.app_update_busy,
                                                primary_btn("安装"),
                                            )
                                            .on_hover_text(install_platform_hint())
                                            .clicked()
                                        {
                                            self.selected_release_tag = Some(item.tag.clone());
                                            install_target = Some(path);
                                        }
                                    }
                                } else if item.asset_url.is_some() {
                                    let action_label = if item.is_current {
                                        "重装"
                                    } else if is_newer {
                                        "升级"
                                    } else {
                                        "切换"
                                    };
                                    if ui
                                        .add_enabled(
                                            !self.app_update_busy,
                                            button(action_label),
                                        )
                                        .on_hover_text(format!("下载并校验 {}", item.tag))
                                        .clicked()
                                    {
                                        self.selected_release_tag = Some(item.tag.clone());
                                        download_target = Some(item.to_release_info(&current));
                                    }
                                } else {
                                    ui.label(
                                        RichText::new("无本机包")
                                            .size(11.0)
                                            .color(theme::muted()),
                                    );
                                }

                                if ui
                                    .add(button("说明"))
                                    .on_hover_text("查看此版本的更新日志")
                                    .clicked()
                                {
                                    self.selected_release_tag = Some(item.tag.clone());
                                    let content = item.body.clone().unwrap_or_else(|| {
                                        format!(
                                            "版本 {}\n\n暂无内嵌更新说明，可点击右下角前往 GitHub Releases 查看完整内容。",
                                            item.tag
                                        )
                                    });
                                    notes_target = Some((item.tag.clone(), content));
                                }
                            });
                        });
                    });
                    ui.add_space(5.0);
                }
            });

        if let Some(info) = download_target {
            self.download_release(info);
        }
        if let Some(path) = install_target {
            self.install_app_update(&path);
        }
        if let Some((tag, content)) = notes_target {
            self.release_notes_content = Some((tag, content));
            self.show_release_notes_modal = true;
        }
    }

    fn ui_about_paths(&mut self, ui: &mut Ui) {
        let data_root = crate::data_root();
        let dirs: [(&str, Option<std::path::PathBuf>); 5] = [
            ("程序目录", current_exe_dir()),
            ("数据目录", Some(data_root.clone())),
            ("内核目录", Some(crate::kernel::managed_kernel_root())),
            ("日志目录", Some(data_root.join("logs"))),
            ("更新暂存", Some(app_update::installer_cache_dir())),
        ];

        let mut copied: Option<(&str, String)> = None;
        let mut opened: Option<std::path::PathBuf> = None;

        card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::CollapsingHeader::new(fold_title(self.tr("本机目录")))
                .id_salt("about:paths")
                .default_open(false)
                .show_background(false)
                .show(ui, |ui| {
                    ui.add_space(4.0);
                    for (idx, (label, dir)) in dirs.iter().enumerate() {
                        if idx > 0 {
                            settings_divider(ui);
                        }
                        match dir {
                            Some(path) => {
                                let path_text = path.display().to_string();
                                match path_row(ui, label, &path_text) {
                                    PathRowAction::None => {}
                                    PathRowAction::Copy => copied = Some((label, path_text)),
                                    PathRowAction::Open => opened = Some(path.clone()),
                                }
                            }
                            None => {
                                kv_row(ui, label, "未知", None);
                            }
                        }
                    }
                });
        });
        ui.add_space(10.0);

        if let Some((label, path_text)) = copied {
            ui.ctx().copy_text(path_text);
            self.status = format!("已复制{label}路径");
        }
        if let Some(path) = opened {
            open_in_file_manager(&path);
        }
    }

    fn ui_app_update_progress(&self, ui: &mut Ui, progress: &AppUpdateProgress) {
        ui.label(
            RichText::new(format!("{} · {}", progress.stage.label(), progress.message))
                .size(11.5)
                .color(theme::text_secondary()),
        );
        ui.add_space(4.0);
        if matches!(progress.stage, AppUpdateStage::Downloading) {
            ui.add(
                ProgressBar::new(progress.fraction())
                    .desired_width(ui.available_width().min(480.0))
                    .text(""),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new(format!(
                    "{} / {} · {}",
                    format_bytes(progress.downloaded),
                    format_bytes(progress.total),
                    crate::gui::widgets::format_speed(progress.rate())
                ))
                .size(11.0)
                .color(theme::muted()),
            );
        }
    }

    /// 侧栏那个绿色↑：有可更新的新版时返回要显示的版本号，否则 None。
    pub(crate) fn pending_update_tag(&self) -> Option<String> {
        self.app_release
            .as_ref()
            .and_then(|release| release.marker())
            .map(|tag| tag.to_string())
    }

    /// 启动后自己查一次更新，只为点亮侧栏的↑。不占进度条、不动状态栏。
    pub(crate) fn check_app_update_quiet(&mut self) {
        let tx = self.tx.clone();
        let proxy = self.app_update_proxy();
        // 后台这次按**已保存**的通道查：编辑态可能正被用户改到一半。
        let insider = self.settings.insider_channel;
        self.app_update_quiet = true;
        self.rt.spawn(async move {
            let result = app_update::check(
                proxy.as_deref(),
                app_update::current_version(),
                app_update::UpdateChannel::from_insider_flag(insider),
            )
            .await
            .map_err(|error| error.to_string());
            let _ = tx.send(BgMsg::AppUpdateCheck(result));
        });
    }

    /// 自动检查的节奏：**每 6 小时一次**。留足余量给手动检查和内核更新。
    /// 用户已经在关于页手动查过（或正在查）就跳过这一次。
    pub(crate) fn maybe_check_app_update(&mut self) {
        let Some(due) = self.app_update_due else {
            return;
        };
        if std::time::Instant::now() < due {
            return;
        }
        self.app_update_due = Some(
            std::time::Instant::now()
                + std::time::Duration::from_secs(APP_UPDATE_CHECK_INTERVAL_SECS),
        );
        if self.app_release.is_some() || self.app_update_busy || self.app_update_quiet {
            return;
        }
        self.check_app_update_quiet();
    }

    pub(crate) fn check_app_update(&mut self) {
        let tx = self.tx.clone();
        let proxy = self.app_update_proxy();
        let insider = self.edit_insider_channel;
        self.app_update_busy = true;
        self.app_update_progress = Some(AppUpdateProgress {
            stage: AppUpdateStage::Checking,
            downloaded: 0,
            total: 0,
            bytes_per_second: 0.0,
            message: format!(
                "正在读取最新 Release（{}通道）",
                if insider { "预发" } else { "稳定" }
            ),
        });
        self.status = "正在检查更新...".into();
        self.rt.spawn(async move {
            let result = app_update::check(
                proxy.as_deref(),
                app_update::current_version(),
                app_update::UpdateChannel::from_insider_flag(insider),
            )
            .await
            .map_err(|error| error.to_string());
            let _ = tx.send(BgMsg::AppUpdateCheck(result));
        });
    }

    pub(crate) fn download_app_update(&mut self) {
        let Some(info) = self.app_release.clone() else {
            self.status = "先检查一次更新".into();
            return;
        };
        self.download_release(info);
    }

    pub(crate) fn download_release(&mut self, info: AppReleaseInfo) {
        let tx = self.tx.clone();
        let proxy = self.app_update_proxy();
        let cancelled = self.app_update_cancel.clone();
        cancelled.store(false, std::sync::atomic::Ordering::Relaxed);
        self.app_update_busy = true;
        self.app_installer_path = None;
        self.app_installer_tag = None;
        self.app_update_progress = Some(AppUpdateProgress {
            stage: AppUpdateStage::Downloading,
            downloaded: 0,
            total: info.asset.as_ref().map(|asset| asset.size).unwrap_or(0),
            bytes_per_second: 0.0,
            message: format!("正在准备下载 {}", info.tag),
        });
        self.status = format!("正在下载 {}...", info.tag);
        let target_tag = info.tag.clone();
        self.rt.spawn(async move {
            let progress_tx = tx.clone();
            let result =
                app_update::download(&info, proxy.as_deref(), &cancelled, &move |progress| {
                    let _ = progress_tx.send(BgMsg::AppUpdateProgress(progress));
                })
                .await
                .map_err(|error| error.to_string());
            let _ = tx.send(BgMsg::AppUpdateDownloaded {
                tag: target_tag,
                result,
            });
        });
    }

    pub(crate) fn install_app_update(&mut self, path: &std::path::Path) {
        // 安装向导一启动就会强杀本进程：先优雅停止代理并清理状态，再交棒给安装器。
        let manager = self.proxy_manager.clone();
        let path = path.to_path_buf();
        let tx = self.tx.clone();
        self.status = "正在停止内核并准备安装更新...".into();
        self.rt.spawn(async move {
            if let Err(error) = manager.stop().await {
                crate::startup_log(&format!("[更新] 安装前停止内核失败（继续安装）: {error:#}"));
            }
            let result = match app_update::launch_installer(&path) {
                Ok(app_update::Handoff::WizardLaunched) => Ok(format!(
                    "内核已停止，安装向导已启动：{}（本程序马上会被关闭并由向导带回）",
                    path.display()
                )),
                Ok(app_update::Handoff::ManualInstall { command }) => {
                    Ok(format!("内核已停止，包已就位，请执行：{command}"))
                }
                Err(error) => Err(format!("启动安装程序失败: {error:#}")),
            };
            let _ = tx.send(BgMsg::OpDone {
                result,
                unlock: false,
            });
        });
    }

    /// 更新走不走代理，只看当下有没有在跑的应用内代理。
    fn app_update_proxy(&self) -> Option<String> {
        self.proxy_status
            .local_proxy_active()
            .then(|| format!("http://127.0.0.1:{}", self.proxy_status.mixed_port))
    }

    pub(crate) fn fetch_available_releases(&mut self) {
        let tx = self.tx.clone();
        let proxy = self.app_update_proxy();
        self.fetching_releases = true;
        self.status = "正在拉取 GitHub Releases 版本列表...".into();
        self.rt.spawn(async move {
            let result =
                app_update::list_releases(proxy.as_deref(), app_update::current_version(), 30)
                    .await
                    .map_err(|error| error.to_string());
            let _ = tx.send(BgMsg::AppReleasesListed(result));
        });
    }

    pub(crate) fn ui_release_notes_modal(&mut self, ctx: &egui::Context) {
        if !self.show_release_notes_modal {
            return;
        }
        let Some((tag, notes)) = &self.release_notes_content else {
            self.show_release_notes_modal = false;
            return;
        };

        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.show_release_notes_modal = false;
            return;
        }

        let mut close_modal = false;
        let screen = ctx.viewport_rect();
        egui::Area::new(egui::Id::new("release_notes_modal_backdrop"))
            .fixed_pos(screen.min)
            .order(egui::Order::Tooltip)
            .show(ctx, |ui| {
                let (_, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
                ui.painter()
                    .rect_filled(screen, 0.0, Color32::from_black_alpha(110));
                if resp.clicked() {
                    close_modal = true;
                }
            });

        let is_latest = tag.contains("最新");
        let tag_display = tag.split_whitespace().next().unwrap_or(tag.as_str());
        const MODAL_WIDTH: f32 = 480.0;

        egui::Window::new("vproxy:release-notes-modal-v5")
            .id(egui::Id::new("vproxy:release-notes-modal-v5"))
            .title_bar(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .order(egui::Order::Tooltip)
            .collapsible(false)
            .resizable(false)
            .default_width(MODAL_WIDTH)
            .max_width(MODAL_WIDTH)
            .frame(
                Frame::NONE
                    .fill(theme::panel())
                    .stroke(Stroke::new(1.0_f32, theme::border_subtle()))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::symmetric(16, 14)),
            )
            .show(ctx, |ui| {
                let inner_w = MODAL_WIDTH - 32.0;
                ui.set_width(inner_w);
                ui.set_max_width(inner_w);

                ui.allocate_ui_with_layout(
                    Vec2::new(inner_w, 26.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        icon_label(ui, Icon::Package, 15.0, theme::accent());
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("版本说明")
                                .strong()
                                .size(14.0)
                                .color(theme::text_primary()),
                        );
                        ui.add_space(6.0);
                        if is_latest {
                            pill(ui, tag_display, theme::success(), theme::success_bg());
                        } else {
                            pill(ui, tag_display, theme::accent(), theme::accent_bg());
                        }

                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let close_btn =
                                ui.add(crate::gui::icons::icon_btn_square(Icon::Close, 11.0));
                            if close_btn
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .on_hover_text("关闭窗口 (Esc)")
                                .clicked()
                            {
                                close_modal = true;
                            }
                        });
                    },
                );
                ui.add_space(8.0);

                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.set_width(inner_w);
                        ui.set_max_width(inner_w);
                        Frame::NONE
                            .fill(theme::sidebar())
                            .stroke(Stroke::new(1.0_f32, theme::border_subtle()))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(12, 10))
                            .show(ui, |ui| {
                                crate::gui::widgets::render_markdown(ui, notes);
                            });
                    });

                ui.add_space(10.0);

                ui.allocate_ui_with_layout(
                    Vec2::new(inner_w, 28.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        if ui
                            .add(button("复制说明"))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            ctx.copy_text(notes.clone());
                            self.status = format!("已复制版本 {tag_display} 的更新说明到剪贴板");
                        }
                        ui.add_space(6.0);
                        if ui
                            .add(button("关闭"))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            close_modal = true;
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let release_url = if tag_display.starts_with('v') {
                                format!("{RELEASES_URL}/tag/{tag_display}")
                            } else {
                                RELEASES_URL.to_string()
                            };
                            if ui
                                .add(primary_btn("在 GitHub 查看 ↗"))
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .clicked()
                            {
                                let _ = crate::platform::open_url_in_browser(&release_url);
                                ui.ctx().open_url(egui::OpenUrl::new_tab(&release_url));
                            }
                        });
                    },
                );
            });

        if close_modal {
            self.show_release_notes_modal = false;
        }
    }
}

fn release_notes_payload(info: &AppReleaseInfo) -> (String, String) {
    let tag_title = format!(
        "{} {}",
        info.tag,
        if info.update_available {
            "（最新版本）"
        } else {
            ""
        }
    );
    let content = info.body.clone().unwrap_or_else(|| {
        format!(
            "版本 {}\n\n暂无内嵌更新说明，可点击右下角前往 GitHub Releases 查看完整内容。",
            info.tag
        )
    });
    (tag_title, content)
}

fn install_platform_hint() -> &'static str {
    if cfg!(windows) {
        "启动安装向导并在完成后自动重新启动"
    } else {
        "校验完成后将在状态栏显示本地安装命令"
    }
}

fn os_label() -> &'static str {
    match std::env::consts::OS {
        "windows" => "Windows",
        "macos" => "macOS",
        "linux" => "Linux",
        other => other,
    }
}

fn button(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).strong())
        .fill(theme::panel())
        .stroke(Stroke::new(1.0_f32, theme::border()))
        .min_size(Vec2::new(64.0, 26.0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRowAction {
    None,
    Copy,
    Open,
}

fn path_row(ui: &mut Ui, label: &str, value: &str) -> PathRowAction {
    const LABEL_W: f32 = 76.0;
    const BTN_W: f32 = 46.0;
    const BTN_GAP: f32 = 4.0;
    const ACTIONS_W: f32 = BTN_W * 2.0 + BTN_GAP;
    const GAP: f32 = 8.0;
    const ROW_H: f32 = 30.0;
    const VALUE_SIZE: f32 = 11.5;

    let row = egui::Rect::from_min_max(
        egui::pos2(ui.max_rect().left(), ui.cursor().top()),
        egui::pos2(ui.max_rect().right(), ui.cursor().top() + ROW_H),
    );
    let value_w = (row.width() - LABEL_W - ACTIONS_W - GAP * 2.0).max(60.0);
    let cell = egui::Rect::from_min_size(
        egui::pos2(row.left() + LABEL_W + GAP, row.min.y),
        Vec2::new(value_w, ROW_H),
    );
    let shown =
        crate::gui::widgets::ellipsize(ui, value, value_w, egui::FontId::monospace(VALUE_SIZE));

    ui.scope_builder(
        egui::UiBuilder::new()
            .id_salt(("about:path", label))
            .max_rect(egui::Rect::from_min_size(
                row.min,
                Vec2::new(LABEL_W, ROW_H),
            )),
        |ui| {
            ui.add_space(6.0);
            ui.label(RichText::new(label).size(12.5).color(theme::text_primary()));
        },
    );

    let val_resp = ui
        .scope_builder(
            egui::UiBuilder::new()
                .id_salt(("about:path", label, "value"))
                .max_rect(cell),
            |ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(cell));
                ui.add_space(6.0);
                ui.label(
                    RichText::new(&shown)
                        .monospace()
                        .size(VALUE_SIZE)
                        .color(theme::muted()),
                );
            },
        )
        .response;
    if shown != value {
        val_resp.on_hover_text(value);
    }

    let mut action = PathRowAction::None;
    let copy_rect = egui::Rect::from_min_size(
        egui::pos2(row.right() - ACTIONS_W, row.min.y + 3.0),
        Vec2::new(BTN_W, ROW_H - 6.0),
    );
    let open_rect = egui::Rect::from_min_size(
        egui::pos2(row.right() - BTN_W, row.min.y + 3.0),
        Vec2::new(BTN_W, ROW_H - 6.0),
    );

    if ui
        .scope_builder(
            egui::UiBuilder::new()
                .id_salt(("about:path", label, "copy"))
                .max_rect(copy_rect),
            |ui| {
                ui.add(
                    egui::Button::new(
                        RichText::new("复制")
                            .size(11.5)
                            .color(theme::text_secondary()),
                    )
                    .fill(theme::sidebar())
                    .stroke(Stroke::NONE)
                    .corner_radius(CornerRadius::same(6))
                    .min_size(copy_rect.size()),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("复制完整路径")
                .clicked()
            },
        )
        .inner
    {
        action = PathRowAction::Copy;
    }

    if ui
        .scope_builder(
            egui::UiBuilder::new()
                .id_salt(("about:path", label, "open"))
                .max_rect(open_rect),
            |ui| {
                ui.add(
                    egui::Button::new(
                        RichText::new("打开")
                            .size(11.5)
                            .color(theme::accent_strong()),
                    )
                    .fill(theme::accent_bg())
                    .stroke(Stroke::NONE)
                    .corner_radius(CornerRadius::same(6))
                    .min_size(open_rect.size()),
                )
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("在文件管理器中打开")
                .clicked()
            },
        )
        .inner
    {
        action = PathRowAction::Open;
    }

    ui.advance_cursor_after_rect(row);
    action
}

fn kv_row(ui: &mut Ui, label: &str, value: &str, action: Option<&str>) -> bool {
    const LABEL_W: f32 = 76.0;
    const ACTION_W: f32 = 52.0;
    const GAP: f32 = 8.0;
    const ROW_H: f32 = 26.0;
    const VALUE_SIZE: f32 = 11.5;

    let row = egui::Rect::from_min_max(
        egui::pos2(ui.max_rect().left(), ui.cursor().top()),
        egui::pos2(ui.max_rect().right(), ui.cursor().top() + ROW_H),
    );
    let value_w = (row.width() - LABEL_W - ACTION_W - GAP * 2.0).max(60.0);
    let cell = egui::Rect::from_min_size(
        egui::pos2(row.left() + LABEL_W + GAP, row.min.y),
        Vec2::new(value_w, ROW_H),
    );
    let shown =
        crate::gui::widgets::ellipsize(ui, value, value_w, egui::FontId::monospace(VALUE_SIZE));
    ui.scope_builder(
        egui::UiBuilder::new()
            .id_salt(("about:kv", label))
            .max_rect(egui::Rect::from_min_size(
                row.min,
                Vec2::new(LABEL_W, ROW_H),
            )),
        |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new(label).size(11.5).color(theme::muted()));
        },
    );
    let val_resp = ui
        .scope_builder(
            egui::UiBuilder::new()
                .id_salt(("about:kv", label, "value"))
                .max_rect(cell),
            |ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(cell));
                ui.add_space(4.0);
                ui.label(
                    RichText::new(&shown)
                        .monospace()
                        .size(VALUE_SIZE)
                        .color(theme::text_secondary()),
                );
            },
        )
        .response;
    if shown != value {
        val_resp.on_hover_text(value);
    }
    let mut clicked = false;
    if let Some(text) = action {
        clicked = ui
            .scope_builder(
                egui::UiBuilder::new()
                    .id_salt(("about:kv", label, "action"))
                    .max_rect(egui::Rect::from_min_size(
                        egui::pos2(row.right() - ACTION_W, row.min.y + 2.0),
                        Vec2::new(ACTION_W, ROW_H - 4.0),
                    )),
                |ui| {
                    ui.add(
                        egui::Button::new(
                            RichText::new(text).size(11.5).color(theme::accent_strong()),
                        )
                        .fill(theme::panel())
                        .stroke(Stroke::NONE)
                        .corner_radius(CornerRadius::same(6))
                        .min_size(Vec2::new(ACTION_W, ROW_H - 4.0)),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                },
            )
            .inner;
    }
    ui.advance_cursor_after_rect(row);
    clicked
}

fn current_exe_dir() -> Option<std::path::PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.to_path_buf())
}

fn open_in_file_manager(path: &std::path::Path) {
    let _ = std::fs::create_dir_all(path);
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

#[cfg(test)]
mod about_layout_probe_tests {
    use super::{button, kv_row, path_row, render_disclaimer_lines, DISCLAIMER_LINES, TAGLINE};
    use crate::gui::icons::Icon;
    use crate::gui::theme;
    use crate::gui::widgets::{card_frame, icon_tile, pill};
    use eframe::egui::{self, Frame, Margin, RawInput, Rect, RichText, Vec2};

    type Painted = Vec<(String, f32, f32, f32)>;

    fn read_text(ctx: &egui::Context, layer: egui::LayerId) -> Painted {
        ctx.graphics_mut(|g| {
            let mut out = Painted::new();
            let Some(list) = g.get(layer) else {
                return out;
            };
            for shape in list.all_entries() {
                if let egui::Shape::Text(text) = &shape.shape {
                    let left = text.pos.x;
                    out.push((
                        text.galley.text().to_string(),
                        left,
                        left + text.galley.size().x,
                        shape.clip_rect.max.x,
                    ));
                }
            }
            out
        })
    }

    fn in_card(width: f32, body: impl FnOnce(&mut egui::Ui, egui::LayerId)) {
        let mut slot = Some(body);
        let ctx = egui::Context::default();
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(width, 800.0),
            )),
            ..Default::default()
        };
        let _ = crate::gui::run_test_ui(&ctx, input, |ui| {
            egui::CentralPanel::default()
                .frame(
                    Frame::NONE
                        .fill(egui::Color32::WHITE)
                        .inner_margin(Margin::symmetric(18, 14)),
                )
                .show(ui, |ui| {
                    card_frame().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let layer = ui.layer_id();
                        if let Some(body) = slot.take() {
                            body(ui, layer);
                        }
                    });
                });
        });
    }

    #[test]
    fn the_value_column_starts_on_one_vertical_and_is_clipped_in_its_own_cell() {
        let mut painted = Painted::new();
        let mut card_right = 0.0_f32;
        in_card(1330.0, |ui, layer| {
            let _ = path_row(ui, "程序目录", "C:\\Apps\\VProxy");
            let _ = path_row(ui, "更新暂存", "C:\\Apps\\VProxy\\data\\updates");
            let _ = kv_row(ui, "SHA-256", &"a".repeat(64), Some("复制"));
            painted = read_text(ui.ctx(), layer);
            card_right = ui.max_rect().right();
        });
        let values: Vec<&(String, f32, f32, f32)> = painted
            .iter()
            .filter(|p| p.0.starts_with("C:") || p.0.chars().all(|c| c == 'a'))
            .collect();
        assert_eq!(values.len(), 3, "三行值没都画出来");
        let first = values[0].1;
        for value in &values {
            assert!(
                (value.1 - first).abs() < 0.6,
                "值列起点不齐：{} 在 x={:.1}，第一行在 {first:.1}",
                value.0,
                value.1
            );
            assert!(
                value.3 <= card_right + 0.1,
                "{} 的裁剪右界 {:.1} 出了卡片 {:.1}",
                value.0,
                value.3,
                card_right
            );
        }

        let mut wide = Painted::new();
        let mut cell_right = 0.0_f32;
        in_card(960.0, |ui, layer| {
            let _ = path_row(ui, "数据目录", &format!("C:\\{}", "z".repeat(300)));
            wide = read_text(ui.ctx(), layer);
            cell_right = ui.max_rect().right();
        });
        let long = wide
            .iter()
            .find(|p| p.0.starts_with("C:\\z"))
            .expect("长路径没画出来");
        assert!(
            long.0.ends_with(char::from_u32(0x2026).unwrap()) && long.0.chars().count() < 300,
            "长路径未被截断：{:?}",
            long.0
        );
        assert!(
            long.2 <= long.3 + 0.5 && long.3 < cell_right,
            "长路径越出裁剪框：natural={:.1}, clip={:.1}, card={:.1}",
            long.2,
            long.3,
            cell_right
        );
    }

    #[test]
    fn path_row_preserves_outer_vertical_clip_rect() {
        let ctx = egui::Context::default();
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(900.0, 400.0),
            )),
            ..Default::default()
        };
        let outer_clip_bottom = 80.0_f32;
        let mut target_layer = None;
        let _ = crate::gui::run_test_ui(&ctx, input, |ui| {
            let mut clipped = ui.new_child(egui::UiBuilder::new().max_rect(Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                Vec2::new(900.0, 200.0),
            )));
            clipped.set_clip_rect(Rect::from_min_max(
                egui::pos2(0.0, 0.0),
                egui::pos2(900.0, outer_clip_bottom),
            ));
            clipped.add_space(70.0);
            target_layer = Some(clipped.layer_id());
            let _ = path_row(&mut clipped, "日志目录", "C:\\Apps\\VProxy\\data\\logs");
        });
        let layer = target_layer.unwrap();
        let max_clip_bottom = ctx.graphics_mut(|g| {
            g.get(layer)
                .map(|list| {
                    list.all_entries()
                        .filter_map(|e| match &e.shape {
                            egui::Shape::Text(t) if t.galley.text().contains("logs") => {
                                Some(e.clip_rect.max.y)
                            }
                            _ => None,
                        })
                        .fold(0.0_f32, f32::max)
                })
                .unwrap_or(0.0)
        });
        assert!(
            max_clip_bottom <= outer_clip_bottom + 0.1,
            "路径文本覆盖到了外层裁剪边界以下：clip_bottom={max_clip_bottom:.1} > outer={outer_clip_bottom:.1}"
        );
    }

    #[test]
    fn pills_wrap_instead_of_widening_the_card() {
        let mut pill_right = 0.0_f32;
        let mut max_right = 0.0_f32;
        in_card(1330.0, |ui, _layer| {
            max_right = ui.max_rect().right();
            ui.horizontal_wrapped(|ui| {
                for _ in 0..14 {
                    pill(
                        ui,
                        "v1.5.0 可更新",
                        theme::accent_strong(),
                        theme::accent_bg(),
                    );
                }
            });
            pill_right = ui.min_rect().max.x;
        });
        assert!(
            pill_right <= max_right + 0.5,
            "胶囊把卡片撑到了 x={pill_right:.1}，内容右界只有 {max_right:.1}"
        );
    }

    #[test]
    fn the_identity_header_keeps_the_repo_button_clear_of_the_tagline() {
        for width in [960.0, 1100.0, 1330.0] {
            let mut painted = Painted::new();
            let mut button_left = f32::MAX;
            let mut button_right = 0.0_f32;
            let mut card_right = 0.0_f32;
            in_card(width, |ui, layer| {
                let row_top = ui.cursor().top();
                let row_left = ui.max_rect().left();
                let row_right = ui.max_rect().right();
                let total_w = (row_right - row_left).max(200.0);
                let action_area_w = 210.0_f32.min(total_w * 0.42);
                let left_w = (total_w - action_area_w - 12.0).max(120.0);

                ui.horizontal(|ui| {
                    ui.scope_builder(
                        egui::UiBuilder::new()
                            .id_salt("probe:identity:left")
                            .max_rect(egui::Rect::from_min_size(
                                egui::pos2(row_left, row_top),
                                Vec2::new(left_w, 56.0),
                            )),
                        |ui| {
                            ui.horizontal(|ui| {
                                icon_tile(ui, Icon::Brand, theme::accent(), theme::accent_bg());
                                ui.add_space(6.0);
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("VProxy").strong().size(20.0));
                                        pill(
                                            ui,
                                            &format!("v{}", crate::app_update::current_version()),
                                            theme::accent_strong(),
                                            theme::accent_bg(),
                                        );
                                    });
                                    ui.add(
                                        egui::Label::new(RichText::new(TAGLINE).size(12.0))
                                            .truncate(),
                                    );
                                });
                            });
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let r1 = ui.add(button("GitHub \u{2197}"));
                        let r2 = ui.add(button("复制环境信息"));
                        button_left = r1.rect.left().min(r2.rect.left());
                        button_right = r1.rect.right().max(r2.rect.right());
                    });
                });
                painted = read_text(ui.ctx(), layer);
                card_right = ui.max_rect().right();
            });
            let tagline = painted
                .iter()
                .find(|p| p.0.starts_with("采集订阅"))
                .expect("介绍语没画出来");
            assert!(
                tagline.2 <= button_left - 4.0,
                "{width} 宽时介绍语右界 {:.1} 顶到了按钮左界 {button_left:.1}",
                tagline.2
            );
            assert!(
                button_right <= card_right + 0.1,
                "{width} 宽时按钮右界 {button_right:.1} 出了卡片 {card_right:.1}"
            );
        }
    }

    #[test]
    fn the_disclaimer_paints_every_line_inside_the_card() {
        const MAX_CHARS: usize = 120;
        for width in [1330.0, 960.0, 420.0] {
            let mut painted = Painted::new();
            let mut card_right = 0.0_f32;
            in_card(width, |ui, layer| {
                render_disclaimer_lines(ui);
                painted = read_text(ui.ctx(), layer);
                card_right = ui.max_rect().right();
            });
            let heads: Vec<String> = DISCLAIMER_LINES
                .iter()
                .map(|line| line.chars().take(6).collect::<String>())
                .collect();
            for (index, head) in heads.iter().enumerate() {
                let entry = painted
                    .iter()
                    .find(|p| p.0.starts_with(head.as_str()))
                    .unwrap_or_else(|| {
                        panic!(
                            "{width:.0} 宽时免责第 {} 条（开头 {head}）没画出来",
                            index + 1,
                        )
                    });
                assert!(
                    entry.2 <= entry.3 + 0.5 && entry.2 <= card_right + 0.5,
                    "{width:.0} 宽时免责第 {} 条右界 {:.1} 出了裁剪框 {:.1} / 卡片 {card_right:.1}",
                    index + 1,
                    entry.2,
                    entry.3
                );
            }
        }
        for (index, line) in DISCLAIMER_LINES.iter().enumerate() {
            assert!(
                line.chars().count() <= MAX_CHARS,
                "免责第 {} 条超过 {MAX_CHARS} 字：{}",
                index + 1,
                line.chars().count()
            );
        }
    }
}
