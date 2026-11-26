use crate::gui::theme;
use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, Sense, Stroke, Ui, Vec2,
};

/// 分组外标题 + 圆角列表容器，统一设置页与关于页视觉层次。
pub fn settings_group(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    add_contents: impl FnOnce(&mut Ui),
) {
    ui.label(
        RichText::new(title)
            .strong()
            .size(13.0)
            .color(theme::text_primary()),
    );
    if let Some(sub) = subtitle.filter(|s| !s.is_empty()) {
        ui.label(RichText::new(sub).size(11.5).color(theme::muted()));
    }
    ui.add_space(6.0);
    Frame::NONE
        .fill(theme::panel())
        .stroke(theme::card_stroke())
        .shadow(theme::card_shadow())
        .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
        .inner_margin(Margin::symmetric(16, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui);
        });
    ui.add_space(14.0);
}

/// 组内细分隔线，贴合组卡片左右内边距。
pub fn settings_divider(ui: &mut Ui) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 1.0), Sense::hover());
    ui.painter().line_segment(
        [
            egui::pos2(rect.min.x, rect.center().y),
            egui::pos2(rect.max.x, rect.center().y),
        ],
        Stroke::new(1.0, theme::border_subtle()),
    );
}

/// 通用设置行：左侧标题 + 可选单行说明，右侧控件区域右对齐。
pub fn settings_row(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    title: &str,
    hint: Option<&str>,
    control: impl FnOnce(&mut Ui),
) {
    ui.push_id(id_salt, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.set_min_height(28.0);
            let max_label_width = (ui.available_width() * 0.56).max(130.0);
            ui.vertical(|ui| {
                ui.set_max_width(max_label_width);
                ui.label(RichText::new(title).size(13.0).color(theme::text_primary()));
                if let Some(h) = hint.filter(|s| !s.is_empty()) {
                    ui.add(
                        egui::Label::new(RichText::new(h).size(11.5).color(theme::muted())).wrap(),
                    );
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                control(ui);
            });
        });
        ui.add_space(6.0);
    });
}

/// 药丸胶囊拨动开关（左关右开），替代混乱复选框。
pub fn pill_toggle(ui: &mut Ui, value: &mut bool) -> egui::Response {
    let desired = Vec2::new(38.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(desired, Sense::click());
    let mut response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    if ui.is_rect_visible(rect) {
        let on = *value;
        let track_fill = if on {
            theme::accent()
        } else if theme::is_light() {
            Color32::from_rgb(206, 210, 218)
        } else {
            Color32::from_rgb(66, 70, 82)
        };
        let border = if response.hovered() {
            theme::accent().gamma_multiply(0.6)
        } else {
            theme::border_subtle()
        };
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(11), track_fill);
        painter.rect_stroke(
            rect,
            CornerRadius::same(11),
            Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );
        let knob_r = 7.5;
        let knob_x = if on {
            rect.max.x - 11.0
        } else {
            rect.min.x + 11.0
        };
        let knob_fill = if on || theme::is_light() {
            Color32::WHITE
        } else {
            Color32::from_rgb(220, 224, 232)
        };
        painter.circle_filled(egui::pos2(knob_x, rect.center().y), knob_r, knob_fill);
    }
    response
}

/// 行内药丸分段选择器（用于二选一 / 三选一枚举，如 `[ 托盘运行 | 直接退出 ]`）。
pub fn segmented_pills<T: PartialEq + Copy>(
    ui: &mut Ui,
    current: &mut T,
    options: &[(T, &str)],
) -> bool {
    let mut changed = false;
    let font = egui::FontId::proportional(12.0);
    let pad = egui::vec2(10.0, 4.0);
    let item_gap = 2.0_f32;
    let frame_margin = 3.0_f32;

    // 预先量出各分段胶囊尺寸并分配精确外框，避免在 right_to_left 父布局中被拉成全宽长条。
    let mut items = Vec::with_capacity(options.len());
    let mut total_inner_w = 0.0_f32;
    let mut max_pill_h = 22.0_f32;
    for &(value, label) in options {
        let selected = *current == value;
        let text_color = if selected {
            if theme::is_light() {
                theme::text_primary()
            } else {
                Color32::WHITE
            }
        } else {
            theme::text_secondary()
        };
        let galley = ui
            .painter()
            .layout_no_wrap(label.to_string(), font.clone(), text_color);
        let pill_size = egui::vec2(
            galley.size().x + pad.x * 2.0,
            (galley.size().y + pad.y * 2.0).max(22.0),
        );
        total_inner_w += pill_size.x;
        max_pill_h = max_pill_h.max(pill_size.y);
        items.push((value, selected, text_color, galley, pill_size));
    }
    if items.len() > 1 {
        total_inner_w += item_gap * (items.len() - 1) as f32;
    }
    let outer_size = egui::vec2(
        total_inner_w + frame_margin * 2.0,
        max_pill_h + frame_margin * 2.0,
    );

    ui.allocate_ui_with_layout(outer_size, Layout::left_to_right(Align::Center), |ui| {
        Frame::NONE
            .fill(theme::sidebar())
            .stroke(Stroke::new(1.0, theme::border_subtle()))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(frame_margin as i8))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = item_gap;
                for (value, selected, text_color, galley, pill_size) in items {
                    let (rect, resp) = ui.allocate_exact_size(pill_size, Sense::click());
                    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
                    if ui.is_rect_visible(rect) {
                        let (fill, stroke) = if selected {
                            if theme::is_light() {
                                (
                                    Color32::WHITE,
                                    Stroke::new(1.0, Color32::from_black_alpha(24)),
                                )
                            } else {
                                (
                                    Color32::from_rgb(52, 54, 62),
                                    Stroke::new(1.0, Color32::from_white_alpha(28)),
                                )
                            }
                        } else if resp.hovered() {
                            (theme::panel_hover().gamma_multiply(0.5), Stroke::NONE)
                        } else {
                            (Color32::TRANSPARENT, Stroke::NONE)
                        };
                        let painter = ui.painter();
                        if fill != Color32::TRANSPARENT || stroke != Stroke::NONE {
                            painter.rect(
                                rect,
                                CornerRadius::same(6),
                                fill,
                                stroke,
                                egui::StrokeKind::Inside,
                            );
                        }
                        let text_pos = egui::pos2(
                            rect.center().x - galley.size().x / 2.0,
                            rect.center().y - galley.size().y / 2.0,
                        );
                        painter.galley(text_pos, galley, text_color);
                    }
                    if resp.clicked() && !selected {
                        *current = value;
                        changed = true;
                    }
                }
            });
    });
    changed
}

/// 紧凑数字步进器（`[ 输入值 ] [ - ] [ + ]`），统一延迟/端口/并发等参数输入。
pub fn stepper_u32(
    ui: &mut Ui,
    value: &mut u32,
    range: std::ops::RangeInclusive<u32>,
    step: u32,
    suffix: &str,
) -> bool {
    let mut changed = false;
    let min = *range.start();
    let max = *range.end();
    // right_to_left 下按反向顺序添加：先 `+`、再 `-`、最后输入框。
    if ui
        .add_enabled(
            *value < max,
            egui::Button::new("+").min_size(Vec2::new(24.0, 24.0)),
        )
        .clicked()
    {
        *value = value.saturating_add(step).min(max);
        changed = true;
    }
    if ui
        .add_enabled(
            *value > min,
            egui::Button::new("-").min_size(Vec2::new(24.0, 24.0)),
        )
        .clicked()
    {
        *value = value.saturating_sub(step).max(min);
        changed = true;
    }
    let mut drag = egui::DragValue::new(value)
        .range(range)
        .speed(step.max(1) as f64);
    if !suffix.is_empty() {
        drag = drag.suffix(suffix);
    }
    if ui.add_sized([76.0, 24.0], drag).changed() {
        changed = true;
    }
    changed
}
