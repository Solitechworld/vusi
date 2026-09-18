//! vusi-gui — a native, GPU-accelerated "cyberspace" front-end for the `vusi`
//! ECDSA signature-vulnerability analyzer.
//!
//! Rendering goes through eframe's `wgpu` backend, which selects **Metal** on
//! Apple Silicon and T2 Macs automatically. All heavy work runs on a background
//! worker thread (see [`worker`]) so the interface stays fluid, including in
//! continuous-watch and batch modes.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod theme;
mod worker;

use app::VusiApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1220.0, 800.0])
            .with_min_inner_size([960.0, 640.0])
            .with_title("vusi — ECDSA Signature Vulnerability Analyzer"),
        renderer: eframe::Renderer::Wgpu,
        vsync: true,
        ..Default::default()
    };

    eframe::run_native(
        "vusi",
        options,
        Box::new(|cc| Ok(Box::new(VusiApp::new(cc)))),
    )
}
