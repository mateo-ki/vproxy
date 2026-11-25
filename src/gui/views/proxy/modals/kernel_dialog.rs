use crate::gui::theme;
use crate::gui::widgets::primary_btn;
use crate::gui::VpnApp;
use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Vec2};

impl VpnApp {
    pub(crate) fn ui_kernel_dialog(&mut self, ctx: &egui::Context) {
        use crate::kernel::{source_from_id, KernelSource, SOURCE_OPTIONS};
        if !self.show_kernel_dialog {
            return;
        }
        let Some(kind) = self.kernel_dialog_kind else {
            return;
        };
        let mut open = true;
        let mut start: Option<(KernelSource, Option<std::path::PathBuf>)> = None;

        const SOURCE_W: f32 = 424.0;
        const PAD: f32 = 11.0;
        const DOT_W: f32 = 22.0;

        // 半透明遮罩：Order::Tooltip 确保压在抽屉 (Foreground) 之上
        let screen = ctx.viewport_rect();
        egui::Area::new(egui::Id::new("kernel_dialog_backdrop"))
            .fixed_pos(screen.min)
            .order(egui::Order::Tooltip)
            .show(ctx, |ui| {
                ui.painter()
                    .rect_filled(screen, 0.0, Color32::from_black_alpha(110));
            });

        egui::Window::new(format!("下载内核 · {}", kind.display_name()))
            .id(egui::Id::new("kernel-download-dialog"))
            .collapsible(false)
            .resizable(false)
            .order(egui::Order::Tooltip)
            .default_width(SOURCE_W)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                // 把 zip 直接拖进窗口就能当本地导入的路径，省得他手打。
                let dropped: Vec<std::path::PathBuf> = ui.input(|input| {
                    input
                        .raw
                        .dropped_files
                        .iter()
                        .map(|file| file.path().to_path_buf())
                        .collect()
                });
                for path in dropped {
                    let is_zip = path
                        .extension()
                        .map(|ext| ext.eq_ignore_ascii_case("zip"))
                        .unwrap_or(false);
                    if is_zip {
                        self.kernel_dialog_path = path.display().to_string();
                        self.kernel_dialog_source = "local".to_string();
                    }
                }

                ui.set_width(SOURCE_W);
                ui.label(
                    RichText::new("下载方式")
                        .strong()
                        .size(15.0)
                        .color(theme::text_primary()),
                );
                for option in SOURCE_OPTIONS {
                    let selected = self.kernel_dialog_source == option.id;
                    let mut job = egui::text::LayoutJob {
                        break_on_newline: true,
                        ..Default::default()
                    };
                    job.wrap.max_width = SOURCE_W - 2.0 * PAD - DOT_W;
                    job.append(
                        option.label,
                        0.0,
                        egui::text::TextFormat::simple(
                            egui::FontId::proportional(14.0),
                            if selected {
                                theme::accent_strong()
                            } else {
                                theme::text_primary()
                            },
                        ),
                    );
                    job.append(
                        &format!("\n{}", option.hint),
                        0.0,
                        egui::text::TextFormat::simple(
                            egui::FontId::proportional(11.5),
                            theme::text_secondary(),
                        ),
                    );
                    let galley = ui.painter().layout_job(job);
                    let (rect, response) = ui.allocate_exact_size(
                        Vec2::new(SOURCE_W, galley.size().y + 2.0 * PAD),
                        Sense::click(),
                    );
                    if response.clicked() {
                        self.kernel_dialog_source = option.id.to_string();
                    }
                    let fill = if selected {
                        theme::accent_bg()
                    } else if response.hovered() {
                        theme::panel_hover()
                    } else {
                        theme::panel()
                    };
                    // 未选中的行也是白底 + 冷调细边，不用灰底铺满整列。
                    let stroke = if selected {
                        Stroke::new(1.0_f32, theme::accent())
                    } else {
                        Stroke::new(1.0_f32, theme::border())
                    };
                    ui.painter().rect(
                        rect,
                        CornerRadius::same(theme::RADIUS_BTN),
                        fill,
                        stroke,
                        egui::epaint::StrokeKind::Inside,
                    );
                    let dot = egui::pos2(rect.min.x + PAD + 5.0, rect.min.y + PAD + 8.0);
                    if selected {
                        ui.painter()
                            .circle_stroke(dot, 5.0, Stroke::new(1.6_f32, theme::accent()));
                        ui.painter().circle_filled(dot, 2.3_f32, theme::accent());
                    } else {
                        ui.painter()
                            .circle_stroke(dot, 5.0, Stroke::new(1.2_f32, theme::muted()));
                    }
                    ui.painter().galley(
                        egui::pos2(rect.min.x + PAD + DOT_W, rect.min.y + PAD - 1.0),
                        galley,
                        theme::text_primary(),
                    );
                    ui.add_space(4.0);
                }
                if self.kernel_dialog_source == "local" {
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("本地 zip（也可以把文件拖进这个窗口）")
                            .small()
                            .color(theme::text_secondary()),
                    );
                    let path_field = ui.add(
                        egui::TextEdit::singleline(&mut self.kernel_dialog_path)
                            .desired_width(SOURCE_W - 4.0)
                            .hint_text(r"D:\downloads\mihomo-windows-amd64-v3-v1.19.32.zip"),
                    );
                    crate::gui::widgets::note_text_field(ui, &path_field);
                }

                ui.add_space(6.0);
                ui.separator();
                let source = source_from_id(&self.kernel_dialog_source);
                let ready =
                    source != KernelSource::Local || !self.kernel_dialog_path.trim().is_empty();
                ui.horizontal(|ui| {
                    if !ready {
                        ui.label(
                            RichText::new("先选好本地 zip 文件")
                                .small()
                                .color(theme::warning()),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(ready && !self.kernel_busy, primary_btn("开始下载"))
                            .clicked()
                        {
                            let path = (source == KernelSource::Local)
                                .then(|| std::path::PathBuf::from(self.kernel_dialog_path.trim()));
                            start = Some((source, path));
                            open = false;
                        }
                        if ui.button("关闭").clicked() {
                            open = false;
                        }
                    });
                });
            });

        self.show_kernel_dialog = open;
        if let Some((source, path)) = start {
            self.update_kernel_from(kind, source, path, true);
        }
    }

    pub(crate) fn ui_kernel_history_dialog(&mut self, ctx: &egui::Context) {
        use crate::gui::widgets::{format_bytes, status_badge};
        use crate::kernel::{source_from_id, KernelSource, SOURCE_OPTIONS};

        if !self.show_kernel_history_dialog {
            return;
        }
        let Some(kind) = self.kernel_history_kind else {
            return;
        };

        let mut open = true;
        let mut refresh_clicked = false;
        let mut install_tag: Option<(String, KernelSource)> = None;
        let mut history_source_popup_layer: Option<egui::LayerId> = None;

        const MODAL_W: f32 = 540.0;
        let screen = ctx.viewport_rect();
        egui::Area::new(egui::Id::new("kernel_history_dialog_backdrop"))
            .fixed_pos(screen.min)
            .order(egui::Order::Tooltip)
            .show(ctx, |ui| {
                ui.painter()
                    .rect_filled(screen, 0.0, Color32::from_black_alpha(110));
            });

        egui::Window::new(format!("历史版本 · {}", kind.display_name()))
            .id(egui::Id::new("kernel-history-dialog"))
            .collapsible(false)
            .resizable(false)
            .order(egui::Order::Tooltip)
            .default_width(MODAL_W)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(MODAL_W);

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("下载方式：")
                            .small()
                            .color(theme::text_secondary()),
                    );
                    let cur_source = source_from_id(&self.kernel_history_source);
                    // 注意：弹窗本身位于 Order::Tooltip（压在 Network 抽屉 Foreground 之上），
                    // 而 egui::ComboBox 默认把弹出层挂在 Order::Foreground，会被遮罩和弹窗挡住导致
                    // 点了看似没反应。这里改用 PopupKind::Tooltip 并在帧末置顶，确保菜单悬浮在弹窗前方。
                    history_source_popup_layer = show_tooltip_dropdown(
                        ui,
                        egui::Id::new("kernel_history_source_combo"),
                        cur_source.label(),
                        170.0,
                        |ui| {
                            for opt in SOURCE_OPTIONS
                                .iter()
                                .filter(|o| o.id != KernelSource::Local.id())
                            {
                                ui.selectable_value(
                                    &mut self.kernel_history_source,
                                    opt.id.to_string(),
                                    opt.label,
                                );
                            }
                        },
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(!self.kernel_history_loading, egui::Button::new("刷新"))
                            .clicked()
                        {
                            refresh_clicked = true;
                        }
                        if self.kernel_history_loading {
                            ui.spinner();
                        }
                    });
                });

                if self.proxy_status.kernel_in_use(kind) {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "提示：该内核正在运行，下载并校验通过后将自动备份旧文件并重启代理切换生效。",
                        )
                        .small()
                        .color(theme::warning()),
                    );
                }

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(6.0);

                if self.kernel_history_loading && self.kernel_history_entries.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(24.0);
                        ui.spinner();
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("正在从 GitHub Releases 拉取历史版本...")
                                .small()
                                .color(theme::text_secondary()),
                        );
                        ui.add_space(24.0);
                    });
                } else if let Some(ref err) = self.kernel_history_error {
                    ui.vertical_centered(|ui| {
                        ui.add_space(16.0);
                        ui.label(RichText::new(err).small().color(theme::danger()));
                        ui.add_space(8.0);
                        if ui.button("重试拉取").clicked() {
                            refresh_clicked = true;
                        }
                        ui.add_space(16.0);
                    });
                } else if self.kernel_history_entries.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.label(
                            RichText::new("未找到适用于当前系统的历史发布版本")
                                .small()
                                .color(theme::muted()),
                        );
                        ui.add_space(20.0);
                    });
                } else {
                    let selected_source = source_from_id(&self.kernel_history_source);
                    egui::ScrollArea::vertical()
                        .id_salt("kernel_history_list_scroll")
                        .max_height(340.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            for entry in &self.kernel_history_entries {
                                egui::Frame::NONE
                                    .fill(if entry.is_current {
                                        theme::accent_bg()
                                    } else {
                                        theme::panel()
                                    })
                                    .stroke(Stroke::new(
                                        1.0_f32,
                                        if entry.is_current {
                                            theme::accent()
                                        } else {
                                            theme::border_subtle()
                                        },
                                    ))
                                    .corner_radius(CornerRadius::same(8))
                                    .inner_margin(egui::Margin::symmetric(10, 7))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.vertical(|ui| {
                                                ui.set_max_width(MODAL_W - 140.0);
                                                ui.horizontal(|ui| {
                                                    ui.label(
                                                        RichText::new(&entry.tag_name)
                                                            .strong()
                                                            .size(13.5)
                                                            .color(theme::text_primary()),
                                                    );
                                                    if entry.is_current {
                                                        status_badge(
                                                            ui,
                                                            "当前",
                                                            theme::accent(),
                                                        );
                                                    }
                                                    if entry.prerelease {
                                                        status_badge(
                                                            ui,
                                                            "预发",
                                                            theme::warning(),
                                                        );
                                                    }
                                                    if let Some(ref date) = entry.published_at {
                                                        ui.label(
                                                            RichText::new(date)
                                                                .small()
                                                                .color(theme::muted()),
                                                        );
                                                    }
                                                });
                                                ui.add_space(2.0);
                                                let meta = format!(
                                                    "{} · {}{}",
                                                    entry.asset_name,
                                                    format_bytes(entry.asset_size),
                                                    if entry.has_sha256 {
                                                        ""
                                                    } else {
                                                        " · 缺官方SHA256"
                                                    }
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(meta)
                                                            .small()
                                                            .monospace()
                                                            .color(theme::text_secondary()),
                                                    )
                                                    .truncate(),
                                                );
                                            });

                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    let btn_text = if entry.is_current {
                                                        "重装"
                                                    } else {
                                                        "下载替换"
                                                    };
                                                    let can_install =
                                                        entry.has_sha256 && !self.kernel_busy;
                                                    let btn = if entry.is_current {
                                                        egui::Button::new(
                                                            RichText::new(btn_text).small(),
                                                        )
                                                    } else {
                                                        primary_btn(btn_text)
                                                    };
                                                    if ui
                                                        .add_enabled(can_install, btn)
                                                        .on_hover_text(if entry.has_sha256 {
                                                            format!(
                                                                "下载并校验 {} {} 后替换当前内核",
                                                                kind.display_name(),
                                                                entry.tag_name
                                                            )
                                                        } else {
                                                            "该历史资产缺少 SHA-256 摘要，不支持自动安装"
                                                                .to_string()
                                                        })
                                                        .clicked()
                                                    {
                                                        install_tag = Some((
                                                            entry.tag_name.clone(),
                                                            selected_source,
                                                        ));
                                                        open = false;
                                                    }
                                                },
                                            );
                                        });
                                    });
                                ui.add_space(5.0);
                            }
                        });
                }

                ui.add_space(6.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("仓库: github.com/")
                            .small()
                            .color(theme::muted()),
                    );
                    ui.label(
                        RichText::new(kind.github_repository())
                            .small()
                            .monospace()
                            .color(theme::text_secondary()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("关闭").clicked() {
                            open = false;
                        }
                    });
                });
            });

        if let Some(layer_id) = history_source_popup_layer {
            ctx.move_to_top(layer_id);
        }

        self.show_kernel_history_dialog = open;
        if refresh_clicked {
            self.refresh_kernel_history(kind);
        }
        if let Some((tag, source)) = install_tag {
            self.install_kernel_version(kind, tag, source);
        }
    }
}

/// 在 `Order::Tooltip` 模态弹窗内渲染下拉框：使用 `PopupKind::Tooltip` 避免被同级/下级遮罩盖住。
fn show_tooltip_dropdown(
    ui: &mut egui::Ui,
    id: egui::Id,
    selected_text: &str,
    width: f32,
    menu_contents: impl FnOnce(&mut egui::Ui),
) -> Option<egui::LayerId> {
    let popup_id = id.with("popup");
    let is_open = egui::Popup::is_id_open(ui.ctx(), popup_id);
    let height = ui.spacing().interact_size.y.max(24.0);
    let (_, rect) = ui.allocate_space(Vec2::new(width, height));
    let btn_resp = ui.interact(rect, id, Sense::click());

    if ui.is_rect_visible(rect) {
        let visuals = if is_open {
            &ui.visuals().widgets.open
        } else {
            ui.style().interact(&btn_resp)
        };
        ui.painter().rect(
            rect,
            visuals.corner_radius,
            visuals.weak_bg_fill,
            visuals.bg_stroke,
            egui::epaint::StrokeKind::Inside,
        );
        let pad_x = ui.spacing().button_padding.x.max(8.0);
        let icon_w = 10.0;
        let galley = ui.painter().layout_no_wrap(
            selected_text.to_string(),
            egui::FontId::proportional(13.0),
            visuals.text_color(),
        );
        let text_pos = egui::pos2(rect.min.x + pad_x, rect.center().y - galley.size().y * 0.5);
        let text_clip = rect.shrink2(Vec2::new(pad_x, 0.0));
        ui.painter()
            .with_clip_rect(egui::Rect::from_min_max(
                text_clip.min,
                egui::pos2(
                    (rect.max.x - pad_x - icon_w).max(text_clip.min.x),
                    text_clip.max.y,
                ),
            ))
            .galley(text_pos, galley, visuals.text_color());

        let cx = rect.max.x - pad_x - icon_w * 0.4;
        let cy = rect.center().y + 1.0;
        ui.painter().add(egui::Shape::convex_polygon(
            vec![
                egui::pos2(cx - 3.5, cy - 2.0),
                egui::pos2(cx + 3.5, cy - 2.0),
                egui::pos2(cx, cy + 2.5),
            ],
            visuals.fg_stroke.color,
            Stroke::NONE,
        ));
    }

    egui::Popup::menu(&btn_resp)
        .id(popup_id)
        .kind(egui::PopupKind::Tooltip)
        .width(width)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClick)
        .show(|ui| {
            ui.set_min_width(ui.available_width());
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            menu_contents(ui);
        })
        .map(|ir| ir.response.layer_id)
}

#[cfg(test)]
mod tests {
    use crate::gui::run_test_ui;
    use crate::gui::views::nodes::empty_pool_modal_tests::app_with_an_empty_library;
    use crate::kernel::KernelKind;
    use eframe::egui;

    fn screen_input(events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            events,
            ..Default::default()
        }
    }

    fn click_events(pos: egui::Pos2) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    #[test]
    fn kernel_history_source_dropdown_opens_above_tooltip_dialog_and_selects() {
        let mut app = app_with_an_empty_library();
        app.show_kernel_history_dialog = true;
        app.kernel_history_kind = Some(KernelKind::Mihomo);
        app.kernel_history_source = "ghfast".to_string();

        let ctx = egui::Context::default();
        let combo_id = egui::Id::new("kernel_history_source_combo");
        let popup_id = combo_id.with("popup");
        let dialog_layer =
            egui::LayerId::new(egui::Order::Tooltip, egui::Id::new("kernel-history-dialog"));

        // 前 3 帧让居中 Window 完成尺寸测算与锚点落位
        for _ in 0..3 {
            let _ = run_test_ui(&ctx, screen_input(vec![]), |_ui| {
                app.ui_kernel_history_dialog(&ctx);
            });
        }
        let trigger_rect = ctx
            .read_response(combo_id)
            .expect("dropdown trigger should exist")
            .rect;

        // 真实鼠标交互顺序：先移动悬停，再按下并抬起触发点击
        let _ = run_test_ui(
            &ctx,
            screen_input(vec![egui::Event::PointerMoved(trigger_rect.center())]),
            |_ui| {
                app.ui_kernel_history_dialog(&ctx);
            },
        );
        let _ = run_test_ui(
            &ctx,
            screen_input(click_events(trigger_rect.center())),
            |_ui| {
                app.ui_kernel_history_dialog(&ctx);
            },
        );
        assert!(
            egui::Popup::is_id_open(&ctx, popup_id),
            "clicking dropdown trigger should open popup (hit_before={:?})",
            ctx.layer_id_at(trigger_rect.center())
        );
        // 再跑一帧以拿到稳定布局的弹出层区域与图层顺序
        let _ = run_test_ui(&ctx, screen_input(vec![]), |_ui| {
            app.ui_kernel_history_dialog(&ctx);
        });

        let popup_layer = egui::LayerId::new(egui::Order::Tooltip, popup_id);
        let popup_rect = ctx
            .read_response(popup_id)
            .expect("popup area response should exist")
            .rect;
        // SOURCE_OPTIONS[0] 是默认的 ghfast，点击最后一项（不在首行）验证确实切走了来源且弹出层处于模态窗口上方
        let last_item_pos = egui::pos2(popup_rect.center().x, popup_rect.max.y - 16.0);
        let _ = run_test_ui(
            &ctx,
            screen_input(vec![egui::Event::PointerMoved(last_item_pos)]),
            |_ui| {
                app.ui_kernel_history_dialog(&ctx);
            },
        );
        assert_eq!(
            ctx.layer_id_at(last_item_pos),
            Some(popup_layer),
            "popup layer must be top-most hit target above dialog ({dialog_layer:?})"
        );
        let _ = run_test_ui(&ctx, screen_input(click_events(last_item_pos)), |_ui| {
            app.ui_kernel_history_dialog(&ctx);
        });

        assert_ne!(app.kernel_history_source, "ghfast");
        assert!(!egui::Popup::is_id_open(&ctx, popup_id));
    }
}
