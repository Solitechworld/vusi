//! Cyberspace visual theme: neon-on-black palette, monospace type ramp, and a
//! reusable animated grid backdrop.

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

// ---- Palette ---------------------------------------------------------------
pub const BG_DEEP: Color32 = Color32::from_rgb(5, 7, 13);
pub const BG_PANEL: Color32 = Color32::from_rgb(11, 15, 26);
pub const BG_INSET: Color32 = Color32::from_rgb(8, 11, 20);
pub const GRID: Color32 = Color32::from_rgb(20, 30, 52);

pub const CYAN: Color32 = Color32::from_rgb(0, 229, 255);
pub const MAGENTA: Color32 = Color32::from_rgb(255, 62, 165);
pub const GREEN: Color32 = Color32::from_rgb(56, 249, 167);
pub const AMBER: Color32 = Color32::from_rgb(255, 179, 71);
pub const RED: Color32 = Color32::from_rgb(255, 59, 92);

pub const TEXT: Color32 = Color32::from_rgb(200, 214, 229);
pub const TEXT_DIM: Color32 = Color32::from_rgb(107, 122, 153);

/// Install the theme (colors, spacing, and a monospace-first type ramp).
pub fn install(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = BG_PANEL;
    visuals.window_fill = BG_PANEL;
    visuals.extreme_bg_color = BG_INSET;
    visuals.faint_bg_color = Color32::from_rgb(14, 19, 32);
    visuals.hyperlink_color = CYAN;
    visuals.selection.bg_fill = Color32::from_rgb(0, 70, 90);
    visuals.selection.stroke = Stroke::new(1.0_f32, CYAN);

    let rounding = Rounding::same(6.0);
    visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_DIM);
    visuals.widgets.noninteractive.rounding = rounding;

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(17, 23, 38);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(17, 23, 38);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(30, 42, 66));
    visuals.widgets.inactive.rounding = rounding;

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(22, 32, 52);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(22, 32, 52);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.2_f32, CYAN);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.2_f32, CYAN);
    visuals.widgets.hovered.rounding = rounding;

    visuals.widgets.active.bg_fill = Color32::from_rgb(0, 60, 78);
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(0, 60, 78);
    visuals.widgets.active.fg_stroke = Stroke::new(1.4_f32, Color32::WHITE);
    visuals.widgets.active.bg_stroke = Stroke::new(1.4_f32, CYAN);
    visuals.widgets.active.rounding = rounding;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    use FontFamily::{Monospace, Proportional};
    style.text_styles = [
        (TextStyle::Heading, FontId::new(21.0, Proportional)),
        (TextStyle::Body, FontId::new(13.5, Monospace)),
        (TextStyle::Monospace, FontId::new(13.0, Monospace)),
        (TextStyle::Button, FontId::new(13.5, Monospace)),
        (TextStyle::Small, FontId::new(11.0, Monospace)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(10.0);
    ctx.set_style(style);
}

/// Paint an animated neon grid + vignette into `rect`. `time` is seconds.
pub fn draw_grid(painter: &egui::Painter, rect: egui::Rect, time: f64) {
    painter.rect_filled(rect, 0.0, BG_DEEP);

    let spacing = 34.0_f32;
    // Slow horizontal drift so the grid reads as "moving through space".
    let drift = ((time * 14.0) as f32) % spacing;

    let faint = Color32::from_rgba_unmultiplied(GRID.r(), GRID.g(), GRID.b(), 130);
    let stroke = Stroke::new(1.0_f32, faint);

    let mut x = rect.left() - drift;
    while x <= rect.right() {
        painter.line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            stroke,
        );
        x += spacing;
    }
    let mut y = rect.top();
    while y <= rect.bottom() {
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            stroke,
        );
        y += spacing;
    }

    // Pulsing scan line.
    let pulse = 0.5 + 0.5 * ((time * 1.4).sin() as f32);
    let scan_y = rect.top() + rect.height() * ((time * 0.06) as f32 % 1.0);
    let scan = Color32::from_rgba_unmultiplied(CYAN.r(), CYAN.g(), CYAN.b(), (40.0 * pulse) as u8);
    painter.line_segment(
        [
            egui::pos2(rect.left(), scan_y),
            egui::pos2(rect.right(), scan_y),
        ],
        Stroke::new(2.0_f32, scan),
    );

    // Corner vignette to sink the edges.
    let dark = Color32::from_rgba_unmultiplied(0, 0, 0, 90);
    painter.rect_filled(
        egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), 8.0)),
        0.0,
        dark,
    );
}

/// A neon "chip" label used for status badges.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32) {
    let bg = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 28);
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0_f32, color))
        .rounding(Rounding::same(4.0))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).monospace().strong());
        });
}
