use super::{segmented_pills, settings_divider, settings_group, settings_row};
use crate::gui::theme;
use crate::gui::VpnApp;
use eframe::egui::{self, Ui};

/// 字号滑杆的刻度带留多高（刻度线 + 数字）。
pub(crate) const FONT_TICK_BAND_HEIGHT: f32 = 20.0;
pub(crate) const FONT_SCALE_MIN: i32 = 85;
pub(crate) const FONT_SCALE_MAX: i32 = 140;

impl VpnApp {
    /// 外观分区：语言、明暗、主题配色与整体缩放（改动即时生效并自动落库）。
    pub(crate) fn ui_settings_appearance(&mut self, ui: &mut Ui) {
        let mut auto_save = false;

        let tr_lang = self.tr("界面语言");
        let tr_light = self.tr("浅色");
        let tr_dark = self.tr("深色");
        let tr_theme = self.tr("界面配色主题");
        let tr_scale = self.tr("字体大小");
        let tr_reset_scale = self.tr("恢复 100%");

        settings_group(ui, "界面风格", None, |ui| {
            settings_row(
                ui,
                "appearance_lang",
                tr_lang,
                Some("即时切换界面语言"),
                |ui| {
                    let mut current_lang = crate::i18n::Language::from_code(&self.edit_ui_language);
                    let options: Vec<_> = crate::i18n::Language::ALL
                        .iter()
                        .map(|&l| (l, l.display_name()))
                        .collect();
                    if segmented_pills(ui, &mut current_lang, &options) {
                        self.edit_ui_language = current_lang.code().to_string();
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "appearance_dark",
                "明暗模式",
                Some("切换浅色或深色界面底色"),
                |ui| {
                    let mut dark = self.edit_ui_dark;
                    if segmented_pills(ui, &mut dark, &[(false, tr_light), (true, tr_dark)]) {
                        self.edit_ui_dark = dark;
                        auto_save = true;
                    }
                },
            );

            settings_divider(ui);

            settings_row(
                ui,
                "appearance_theme",
                tr_theme,
                Some("全局强调色"),
                |ui| {
                    ui.with_layout(
                        egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true),
                        |ui| {
                            for theme_spec in theme::THEMES.iter() {
                                let selected = self.edit_ui_theme == theme_spec.id;
                                let accent_col = theme::rgb(theme_spec.accent);
                                let short_name = theme_spec
                                    .name
                                    .split(['（', '('])
                                    .next()
                                    .unwrap_or(theme_spec.name)
                                    .trim();
                                let padding = egui::vec2(9.0, 4.0);
                                let font = egui::FontId::proportional(12.0);
                                let galley = ui.painter().layout_no_wrap(
                                    short_name.to_string(),
                                    font,
                                    if selected {
                                        theme::accent_strong()
                                    } else {
                                        theme::text_primary()
                                    },
                                );
                                let dot_size = 8.0;
                                let gap = 5.0;
                                let desired_size = egui::vec2(
                                    galley.size().x + dot_size + gap + padding.x * 2.0,
                                    galley.size().y.max(dot_size) + padding.y * 2.0,
                                );
                                let (rect, response) =
                                    ui.allocate_exact_size(desired_size, egui::Sense::click());
                                let response = response
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(theme_spec.name);
                                if ui.is_rect_visible(rect) {
                                    let painter = ui.painter();
                                    let bg = if selected {
                                        theme::accent_bg()
                                    } else if response.hovered() {
                                        theme::panel_hover()
                                    } else {
                                        theme::panel()
                                    };
                                    let stroke = if selected {
                                        egui::Stroke::new(1.2_f32, accent_col)
                                    } else {
                                        egui::Stroke::new(1.0_f32, theme::border_subtle())
                                    };
                                    painter.rect(
                                        rect,
                                        egui::CornerRadius::same(7),
                                        bg,
                                        stroke,
                                        egui::StrokeKind::Inside,
                                    );

                                    let dot_center = egui::pos2(
                                        rect.min.x + padding.x + dot_size / 2.0,
                                        rect.center().y,
                                    );
                                    painter.circle_filled(dot_center, dot_size / 2.0, accent_col);
                                    if selected {
                                        painter.circle_stroke(
                                            dot_center,
                                            dot_size / 2.0 + 1.5,
                                            egui::Stroke::new(1.0_f32, accent_col),
                                        );
                                    }

                                    let text_pos = egui::pos2(
                                        dot_center.x + dot_size / 2.0 + gap,
                                        rect.center().y - galley.size().y / 2.0,
                                    );
                                    painter.galley(
                                        text_pos,
                                        galley,
                                        if selected {
                                            theme::accent_strong()
                                        } else {
                                            theme::text_primary()
                                        },
                                    );
                                }
                                if response.clicked() {
                                    self.edit_ui_theme = theme_spec.id.to_string();
                                    auto_save = true;
                                }
                            }
                        },
                    );
                },
            );

            settings_divider(ui);

            let mut slider_geometry = None;
            settings_row(
                ui,
                "appearance_scale",
                tr_scale,
                Some("整体缩放界面比例 (85% - 140%)"),
                |ui| {
                    if (self.edit_ui_scale - 1.0).abs() > 0.001
                        && ui
                            .button(tr_reset_scale)
                            .on_hover_text("回到跟随系统缩放")
                            .clicked()
                    {
                        self.edit_ui_scale = 1.0;
                        auto_save = true;
                    }
                    let mut percent = (self.edit_ui_scale * 100.0).round() as i32;
                    let slider_width = ui.spacing().slider_width;
                    const FONT_SLIDER_RAIL: f32 = 240.0;
                    ui.spacing_mut().slider_width = FONT_SLIDER_RAIL;
                    let response = ui
                        .add(
                            egui::Slider::new(&mut percent, FONT_SCALE_MIN..=FONT_SCALE_MAX)
                                .step_by(5.0)
                                .suffix("%"),
                        )
                        .on_hover_text("85% 到 140%，步长 5%；松手后保存");
                    ui.spacing_mut().slider_width = slider_width;
                    slider_geometry = Some((
                        response.rect,
                        handle_travel_range(ui, &response, FONT_SLIDER_RAIL),
                    ));
                    if response.changed() {
                        self.edit_ui_scale = percent as f32 / 100.0;
                    }
                    if response.drag_stopped() && self.settings_dirty() {
                        self.save_settings();
                    }
                },
            );
            if let Some((rect, travel)) = slider_geometry {
                ui.add_space(FONT_TICK_BAND_HEIGHT);
                paint_font_scale_ticks(ui, rect, travel);
            }
        });

        if auto_save && self.settings_dirty() {
            self.save_settings();
        }
    }
}

/// 手柄中心实际走过的区间。**必须**和 egui 自己算的一致，否则刻度和手柄会错位。
///
/// 两条来自 egui 0.31 源码的事实：① 手柄位置是按**轨道**算的，轨道宽 = `spacing.slider_width`，
/// 而 `ui.add(Slider)` 返回的 response 把右边那段数值文字（"100%"）也算进了宽度 ——
/// 直接拿 `response.rect.x_range()` 会把刻度整体往右推（实测 140% 处偏 48px，
/// 2026-10-15 他报的"点恢复 100% 小球跑到 90 刻度"）；② `handle_radius = 轨道高/2.5`，
/// `HandleShape::Rect` 再乘 `aspect_ratio`。
pub(crate) fn handle_travel_range(
    ui: &Ui,
    response: &egui::Response,
    rail_width: f32,
) -> egui::Rangef {
    let radius = response.rect.height() / 2.5;
    let radius = match ui.style().visuals.handle_shape {
        egui::style::HandleShape::Circle => radius,
        egui::style::HandleShape::Rect { aspect_ratio } => radius * aspect_ratio,
    };
    let left = response.rect.left();
    egui::Rangef::new(left + radius, left + rail_width - radius)
}

/// 每个刻度的 `(百分比, x, 是否长刻度)`。抽成纯函数是因为画出来的东西我看不见 ——
/// 几何只能这样钉成断言。
pub(crate) fn font_scale_ticks(travel: egui::Rangef) -> Vec<(i32, f32, bool)> {
    let span = (FONT_SCALE_MAX - FONT_SCALE_MIN) as f32;
    (FONT_SCALE_MIN..=FONT_SCALE_MAX)
        .step_by(5)
        .map(|value| {
            let ratio = (value - FONT_SCALE_MIN) as f32 / span;
            (
                value,
                egui::lerp(travel.min..=travel.max, ratio),
                matches!(value, 85 | 100 | 120 | 140),
            )
        })
        .collect()
}

/// 把刻度画在滑杆下方那条带里。100 用强调色 —— 那是"跟随系统缩放"的基准点，
/// 一眼要能找回来。
fn paint_font_scale_ticks(ui: &Ui, rect: egui::Rect, travel: egui::Rangef) {
    let painter = ui.painter();
    let top = rect.bottom() + 2.0;
    let color = theme::muted();
    for (value, x, major) in font_scale_ticks(travel) {
        let height = if major { 7.0 } else { 4.0 };
        painter.line_segment(
            [egui::pos2(x, top), egui::pos2(x, top + height)],
            egui::Stroke::new(
                1.0_f32,
                if major {
                    color
                } else {
                    color.gamma_multiply(0.5)
                },
            ),
        );
        if major {
            painter.text(
                egui::pos2(x, top + height + 1.0),
                egui::Align2::CENTER_TOP,
                format!("{value}"),
                egui::FontId::proportional(9.5),
                if value == 100 { theme::accent() } else { color },
            );
        }
    }
}
