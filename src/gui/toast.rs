//! 轻量通知条（toast）。
//!
//! 为什么要有它：底部状态栏是"单槽字符串"，全仓库 170+ 处写入点后到者覆盖前者，
//! 用户几乎永远来不及看清一条错误（"订阅源无法保存"报障的根因之一就是
//! 「名称不能为空」只写进了被弹窗挡住的状态栏）。关键错误必须在界面右上角
//! 显式弹出：自动消失、可手动关闭、同类消息短时间去重。
//!
//! 设计取舍：不做队列动画/焦点管理，只做"过期修剪 + 去重 + 右上角覆盖层"，
//! 保持即时模式 UI 的简单性；普通进度信息仍然走状态栏，只有错误类消息入栈。

use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, Color32, Context, CornerRadius, Id, Order, RichText, Vec2};

use crate::gui::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToastKind {
    Error,
    Info,
    Success,
}

impl ToastKind {
    fn ttl(self) -> Duration {
        match self {
            // 错误多留一会儿，给用户截图/读完的时间。
            Self::Error => Duration::from_secs(10),
            Self::Info | Self::Success => Duration::from_secs(6),
        }
    }

    fn accent(self) -> Color32 {
        match self {
            Self::Error => theme::danger(),
            Self::Info => theme::accent(),
            Self::Success => theme::success(),
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Error => "✕",
            Self::Info => "ℹ",
            Self::Success => "✓",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Error => "错误",
            Self::Info => "提示",
            Self::Success => "成功",
        }
    }
}

#[derive(Clone)]
pub struct Toast {
    pub kind: ToastKind,
    pub message: String,
    pub at: Instant,
}

/// 同类同文消息的去重窗口：轮询类错误每秒都可能重复，1.5 秒内视为同一条。
const DEDUPE_WINDOW: Duration = Duration::from_millis(1500);
/// 同屏上限：超出的最老的非错误条目先淘汰，错误最后淘汰。
const MAX_VISIBLE: usize = 4;

#[derive(Default)]
pub struct ToastCenter {
    toasts: Vec<Toast>,
}

impl ToastCenter {
    pub fn push(&mut self, kind: ToastKind, message: impl Into<String>) {
        let message = message.into();
        let now = Instant::now();
        // 去重：最近一条同文消息还在窗口期内就只刷新时间戳，不重复弹。
        if let Some(existing) = self
            .toasts
            .iter_mut()
            .rev()
            .find(|t| t.kind == kind && t.message == message)
        {
            if now.duration_since(existing.at) < DEDUPE_WINDOW {
                existing.at = now;
                return;
            }
        }
        self.toasts.push(Toast {
            kind,
            message,
            at: now,
        });
        self.prune(now);
        if self.toasts.len() > MAX_VISIBLE {
            // 先淘汰最老的普通条目；全是错误时才淘汰最老的错误。
            let plain_idx = self
                .toasts
                .iter()
                .position(|t| t.kind != ToastKind::Error)
                .unwrap_or(0);
            self.toasts.remove(plain_idx);
        }
    }

    /// 纯函数：按 TTL 修剪。单独拆出来可测。
    fn prune(&mut self, now: Instant) {
        self.toasts
            .retain(|t| now.duration_since(t.at) < t.kind.ttl());
    }

    pub fn is_empty(&self) -> bool {
        self.toasts
            .iter()
            .all(|t| Instant::now().duration_since(t.at) >= t.kind.ttl())
    }

    /// 渲染右上角覆盖层。必须在每帧调用；有活跃条目时请求低频重绘让过期平滑。
    pub fn ui(&mut self, ctx: &Context) {
        self.prune(Instant::now());
        if self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(250));
        egui::Area::new(Id::new("vproxy_toasts"))
            .order(Order::Foreground)
            .anchor(Align2::RIGHT_TOP, [-14.0, 52.0])
            .movable(false)
            .interactable(true)
            .show(ctx, |ui| {
                ui.set_min_width(340.0);
                ui.set_max_width(420.0);
                let mut dismissed: Option<usize> = None;
                for (idx, toast) in self.toasts.iter().enumerate() {
                    let accent = toast.kind.accent();
                    let frame = egui::Frame::NONE
                        .fill(theme::panel())
                        .stroke(theme::card_stroke())
                        .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
                        .inner_margin(egui::Margin::same(10))
                        .shadow(theme::card_shadow());
                    frame.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let icon = RichText::new(toast.kind.icon()).strong().color(accent);
                            ui.add_sized(
                                Vec2::new(18.0, 18.0),
                                egui::Label::new(icon)
                                    .selectable(false)
                                    .sense(egui::Sense::hover()),
                            );
                            ui.label(RichText::new(toast.kind.label()).strong().color(accent));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("✕").on_hover_text("关闭这条通知").clicked()
                                    {
                                        dismissed = Some(idx);
                                    }
                                },
                            );
                        });
                        ui.add_space(2.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(&toast.message).color(theme::text_primary()),
                            )
                            .wrap(),
                        );
                    });
                    ui.add_space(6.0);
                }
                if let Some(idx) = dismissed {
                    if idx < self.toasts.len() {
                        self.toasts.remove(idx);
                    }
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn center_with(kind: ToastKind, message: &str) -> ToastCenter {
        let mut center = ToastCenter::default();
        center.push(kind, message);
        center
    }

    #[test]
    fn same_message_within_window_dedupes() {
        let mut center = center_with(ToastKind::Error, "节点连通性验证失败");
        center.push(ToastKind::Error, "节点连通性验证失败");
        assert_eq!(center.toasts.len(), 1);
    }

    #[test]
    fn different_message_pushes_new_toast() {
        let mut center = center_with(ToastKind::Error, "A");
        center.push(ToastKind::Error, "B");
        assert_eq!(center.toasts.len(), 2);
    }

    #[test]
    fn expired_toasts_are_pruned_on_push() {
        let mut center = center_with(ToastKind::Success, "旧消息");
        // 直接把时间戳拨过 TTL，模拟时间流逝。
        center.toasts[0].at = Instant::now() - Duration::from_secs(61);
        center.push(ToastKind::Info, "新消息");
        assert_eq!(center.toasts.len(), 1);
        assert_eq!(center.toasts[0].message, "新消息");
    }

    #[test]
    fn cap_evicts_oldest_plain_first() {
        let mut center = ToastCenter::default();
        for i in 0..MAX_VISIBLE {
            center.push(ToastKind::Success, format!("普通{i}"));
        }
        center.push(ToastKind::Error, "后来的错误");
        assert_eq!(center.toasts.len(), MAX_VISIBLE);
        assert!(
            !center.toasts.iter().any(|t| t.message == "普通0"),
            "最老的普通条目应被先淘汰"
        );
        assert!(
            center.toasts.iter().any(|t| t.message == "后来的错误"),
            "错误应保留"
        );
    }
}
