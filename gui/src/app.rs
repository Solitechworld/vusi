//! The eframe application: layout, state, and wiring of every button to the
//! background worker.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use egui::{Align, Layout, RichText, Rounding, Stroke};
use egui_extras::{Column, TableBuilder};

use vusi_engine::{export_to, AnalysisConfig, AttackKind, Report};

use crate::theme;
use crate::worker::{self, Command, LogLevel, WorkerEvent, WorkerHandle};

const LOG_CAP: usize = 600;
const HISTORY_CAP: usize = 40;

#[derive(PartialEq, Eq, Clone, Copy)]
enum InputMode {
    File,
    Paste,
    Address,
}

pub struct VusiApp {
    worker: WorkerHandle,
    gpu: String,

    // Input
    input_mode: InputMode,
    file_path: Option<PathBuf>,
    paste_text: String,
    // Address fetch (ATXQU pipeline)
    address: String,
    provider: String,
    endpoint: String,
    fetch_parallel: bool,
    fetch_workers: usize,

    // Attack configuration
    attack: AttackKind,
    degree: usize,
    bias_type: String,
    known_bits: usize,
    reduction: String,
    window_block_size: usize,
    window_rounds: usize,
    max_samples_enabled: bool,
    max_samples: usize,
    // Related-nonce attack params
    delta: String,
    bitflip_bits: usize,
    gcd_a_max: u64,
    gcd_b_max: u64,
    bias_min_bits: usize,
    bias_max_bits: usize,

    // Extraction (BTC tx → r,s,z)
    extract_only_verified: bool,
    extracted_json: Option<String>,

    // Output
    autosave_enabled: bool,
    autosave_dir: Option<PathBuf>,

    // Continuous watch
    watch_interval_secs: f32,
    watching: bool,
    busy: bool,

    // Results
    latest: Option<Report>,
    history: VecDeque<Report>,
    log: VecDeque<(LogLevel, String)>,
}

impl VusiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install(&cc.egui_ctx);

        let gpu = cc
            .wgpu_render_state
            .as_ref()
            .map(|rs| {
                let info = rs.adapter.get_info();
                format!("{:?} · {}", info.backend, info.name)
            })
            .unwrap_or_else(|| "CPU (software)".to_string());

        let worker = worker::spawn(cc.egui_ctx.clone());

        let mut app = Self {
            worker,
            gpu,
            input_mode: InputMode::File,
            file_path: None,
            paste_text: String::new(),
            address: String::new(),
            provider: "blockbook".to_string(),
            endpoint: "https://bitcoin.atomicwallet.io/api/v2".to_string(),
            fetch_parallel: false,
            fetch_workers: 16,
            attack: AttackKind::NonceReuse,
            degree: 1,
            bias_type: "lsb".to_string(),
            known_bits: 8,
            reduction: "lll".to_string(),
            window_block_size: 20,
            window_rounds: 2,
            max_samples_enabled: false,
            max_samples: 256,
            delta: "1".to_string(),
            bitflip_bits: 256,
            gcd_a_max: 8,
            gcd_b_max: 256,
            bias_min_bits: 1,
            bias_max_bits: 16,
            extract_only_verified: true,
            extracted_json: None,
            autosave_enabled: false,
            autosave_dir: None,
            watch_interval_secs: 2.0,
            watching: false,
            busy: false,
            latest: None,
            history: VecDeque::new(),
            log: VecDeque::new(),
        };
        app.push_log(
            LogLevel::Info,
            format!("vusi engine online · renderer: {}", app.gpu),
        );
        app.push_log(
            LogLevel::Info,
            "Load a signature set (JSON or CSV: r, s, z, pubkey), pick an attack, and RUN.".into(),
        );
        app
    }

    // ---- helpers -----------------------------------------------------------

    fn push_log(&mut self, level: LogLevel, msg: String) {
        let stamp = chrono::Local::now().format("%H:%M:%S");
        self.log.push_back((level, format!("[{stamp}] {msg}")));
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }

    fn current_config(&self) -> AnalysisConfig {
        AnalysisConfig {
            attack: self.attack,
            degree: self.degree.max(1),
            bias_type: self.bias_type.clone(),
            known_bits: self.known_bits,
            reduction: self.reduction.clone(),
            window_block_size: self.window_block_size.max(1),
            window_rounds: self.window_rounds.max(1),
            max_samples: if self.max_samples_enabled {
                Some(self.max_samples.max(1))
            } else {
                None
            },
            delta: self.delta.clone(),
            bitflip_bits: self.bitflip_bits.max(1),
            gcd_a_max: self.gcd_a_max.max(1),
            gcd_b_max: self.gcd_b_max,
            bias_min_bits: self.bias_min_bits.max(1),
            bias_max_bits: self.bias_max_bits.max(self.bias_min_bits.max(1)),
        }
    }

    /// The directory autosave should write to, defaulting sensibly if enabled
    /// but unset. Returns `None` when autosave is off.
    fn effective_autosave_dir(&mut self) -> Option<PathBuf> {
        if !self.autosave_enabled {
            return None;
        }
        if self.autosave_dir.is_none() {
            let base = self
                .file_path
                .as_ref()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."));
            let dir = base.join("vusi-reports");
            self.push_log(
                LogLevel::Info,
                format!("Autosave folder defaulted to {}", dir.display()),
            );
            self.autosave_dir = Some(dir);
        }
        self.autosave_dir.clone()
    }

    fn dispatch_run(&mut self) {
        if !self.attack.is_available() {
            self.push_log(
                LogLevel::Error,
                format!(
                    "{} is not available in this build (rebuild with --features biased-nonce).",
                    self.attack.label()
                ),
            );
            return;
        }
        let cfg = self.current_config();
        let autosave_dir = self.effective_autosave_dir();

        match self.input_mode {
            InputMode::File => match self.file_path.clone() {
                Some(path) => {
                    self.push_log(LogLevel::Info, format!("Running {} on {}", cfg.attack.label(), path.display()));
                    self.worker.send(Command::AnalyzeFile {
                        path,
                        cfg,
                        autosave_dir,
                    });
                }
                None => self.push_log(LogLevel::Warn, "No file selected. Use LOAD FILE first.".into()),
            },
            InputMode::Paste => {
                if self.paste_text.trim().is_empty() {
                    self.push_log(LogLevel::Warn, "Paste box is empty.".into());
                    return;
                }
                self.push_log(LogLevel::Info, format!("Running {} on pasted data", cfg.attack.label()));
                self.worker.send(Command::AnalyzeText {
                    content: self.paste_text.clone(),
                    source: "<pasted>".to_string(),
                    cfg,
                    autosave_dir,
                });
            }
            InputMode::Address => {
                let addresses: Vec<String> = self
                    .address
                    .split([',', ' ', '\n', '\t', ';'])
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                if addresses.is_empty() {
                    self.push_log(LogLevel::Warn, "Enter a Bitcoin address to scan.".into());
                    return;
                }
                self.push_log(
                    LogLevel::Info,
                    format!(
                        "ATXQU → {}: scanning {} address(es), then extracting + running {}",
                        self.provider,
                        addresses.len(),
                        cfg.attack.label()
                    ),
                );
                self.worker.send(Command::FetchAddress {
                    addresses,
                    provider: self.provider.clone(),
                    endpoint: self.endpoint.clone(),
                    parallel: self.fetch_parallel,
                    workers: self.fetch_workers.max(1),
                    only_verified: self.extract_only_verified,
                    cfg,
                    autosave_dir,
                });
            }
        }
    }

    fn dispatch_batch(&mut self) {
        if !self.attack.is_available() {
            self.push_log(LogLevel::Error, "Selected attack not available in this build.".into());
            return;
        }
        if let Some(dir) = rfd::FileDialog::new().set_title("Select a folder of signature files").pick_folder() {
            let cfg = self.current_config();
            let autosave_dir = self.effective_autosave_dir();
            self.worker.send(Command::BatchDir {
                dir,
                cfg,
                autosave_dir,
            });
        }
    }

    fn toggle_watch(&mut self) {
        if self.watching {
            self.worker.send(Command::StopWatch);
            return;
        }
        if self.input_mode != InputMode::File {
            self.push_log(LogLevel::Warn, "Continuous watch needs a file input (switch to FILE mode).".into());
            return;
        }
        let Some(path) = self.file_path.clone() else {
            self.push_log(LogLevel::Warn, "Load a file before starting continuous watch.".into());
            return;
        };
        if !self.attack.is_available() {
            self.push_log(LogLevel::Error, "Selected attack not available in this build.".into());
            return;
        }
        let cfg = self.current_config();
        let autosave_dir = self.effective_autosave_dir();
        self.worker.send(Command::StartWatch {
            path,
            cfg,
            autosave_dir,
            interval: Duration::from_secs_f32(self.watch_interval_secs.max(0.5)),
        });
    }

    fn dispatch_extract(&mut self) {
        if !self.attack.is_available() {
            self.push_log(LogLevel::Error, "Selected attack not available in this build.".into());
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Extract from a Bitcoin transaction (JSON)")
            .add_filter("Transaction JSON", &["json"])
            .pick_file()
        {
            let cfg = self.current_config();
            let autosave_dir = self.effective_autosave_dir();
            self.push_log(LogLevel::Info, format!("Extracting r,s,z from {}", path.display()));
            self.worker.send(Command::ExtractTx {
                path,
                only_verified: self.extract_only_verified,
                cfg,
                autosave_dir,
            });
        }
    }

    fn save_extraction(&mut self) {
        let Some(json) = self.extracted_json.clone() else {
            self.push_log(LogLevel::Warn, "Nothing extracted yet.".into());
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Save extracted signatures (r,s,z)")
            .add_filter("JSON", &["json"])
            .set_file_name("extracted-signatures.json")
            .save_file()
        {
            match std::fs::write(&path, json) {
                Ok(()) => self.push_log(LogLevel::Good, format!("Saved r,s,z → {}", path.display())),
                Err(e) => self.push_log(LogLevel::Error, format!("Save failed: {e}")),
            }
        }
    }

    fn export_latest(&mut self) {
        let Some(report) = self.latest.clone() else {
            self.push_log(LogLevel::Warn, "Nothing to export yet.".into());
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Export report as JSON")
            .add_filter("JSON", &["json"])
            .set_file_name("vusi-report.json")
            .save_file()
        {
            match export_to(&report, &path) {
                Ok(()) => self.push_log(LogLevel::Good, format!("Exported → {}", path.display())),
                Err(e) => self.push_log(LogLevel::Error, format!("Export failed: {e}")),
            }
        }
    }

    fn handle_event(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Log(level, msg) => self.push_log(level, msg),
            WorkerEvent::Busy(b) => self.busy = b,
            WorkerEvent::Watching(w) => {
                self.watching = w;
            }
            WorkerEvent::Extracted { json, source } => {
                // Keep the full extracted set in memory (for SAVE JSON and for
                // the analysis that already ran on it). Only mirror it into the
                // on-screen text box when it is small: egui re-lays-out the whole
                // string every frame, so dumping a multi-MB blob there can hang
                // or crash the window. Large sets get a short placeholder instead.
                const MAX_PREVIEW_BYTES: usize = 262_144; // 256 KB
                let bytes = json.len();
                if bytes <= MAX_PREVIEW_BYTES {
                    self.paste_text = json.clone();
                    self.input_mode = InputMode::Paste;
                    self.push_log(
                        LogLevel::Good,
                        format!("Loaded extracted signatures from {source} into input."),
                    );
                } else {
                    self.paste_text = format!(
                        "// {:.1} MB of extracted signatures from {source}.\n\
                         // Too large to preview here — the analysis already ran on the\n\
                         // full set (see results below). Use  ⤓ SAVE JSON  to export them.",
                        bytes as f64 / 1_048_576.0
                    );
                    self.push_log(
                        LogLevel::Info,
                        format!(
                            "Extracted set from {source} is large ({:.1} MB) — kept in memory, not shown. Use SAVE JSON to export.",
                            bytes as f64 / 1_048_576.0
                        ),
                    );
                }
                self.extracted_json = Some(json);
            }
            WorkerEvent::Report(report, _saved) => {
                self.history.push_front(report.clone());
                while self.history.len() > HISTORY_CAP {
                    self.history.pop_back();
                }
                self.latest = Some(report);
            }
        }
    }

    // ---- UI sections -------------------------------------------------------

    fn top_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(2.0);
            ui.label(
                RichText::new("◢◤ VUSI")
                    .color(theme::CYAN)
                    .size(22.0)
                    .strong(),
            );
            ui.label(
                RichText::new("ECDSA SIGNATURE VULNERABILITY ANALYZER")
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                theme::chip(ui, &format!("GPU: {}", self.gpu), theme::MAGENTA);
                if self.watching {
                    theme::chip(ui, "● WATCHING", theme::GREEN);
                }
                if self.busy {
                    ui.add(egui::Spinner::new().color(theme::CYAN));
                    theme::chip(ui, "WORKING", theme::AMBER);
                } else {
                    theme::chip(ui, "IDLE", theme::TEXT_DIM);
                }
            });
        });
    }

    fn control_deck(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        section(ui, "INPUT SOURCE", theme::CYAN);
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.input_mode, InputMode::File, "FILE");
            ui.selectable_value(&mut self.input_mode, InputMode::Paste, "PASTE");
            ui.selectable_value(&mut self.input_mode, InputMode::Address, "ADDRESS");
        });

        match self.input_mode {
            InputMode::File => {
                if ui
                    .add(neon_button("⭳  LOAD FILE…", theme::CYAN))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Load signatures")
                        .add_filter("Signatures", &["json", "csv"])
                        .pick_file()
                    {
                        self.push_log(LogLevel::Info, format!("Loaded {}", path.display()));
                        self.file_path = Some(path);
                    }
                }
                let label = self
                    .file_path
                    .as_ref()
                    .map(|p| p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default())
                    .unwrap_or_else(|| "— no file —".to_string());
                ui.label(RichText::new(label).color(theme::TEXT_DIM).small());
            }
            InputMode::Paste => {
                ui.label(RichText::new("Paste JSON array or CSV:").small().color(theme::TEXT_DIM));
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .id_source("paste_scroll")
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.paste_text)
                                .code_editor()
                                .desired_rows(5)
                                .desired_width(f32::INFINITY)
                                .hint_text("[{\"r\":\"…\",\"s\":\"…\",\"z\":\"…\"}]"),
                        );
                    });
            }
            InputMode::Address => {
                ui.label(
                    RichText::new("Scan an address with ATXQU → extract → attack, in one run.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
                ui.add(
                    egui::TextEdit::multiline(&mut self.address)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY)
                        .hint_text("bitcoin address(es) — comma / space / newline separated"),
                );
                labeled(ui, "provider", |ui| {
                    egui::ComboBox::from_id_source("atxqu_provider")
                        .selected_text(&self.provider)
                        .show_ui(ui, |ui| {
                            for p in ["blockbook", "haskoin"] {
                                ui.selectable_value(&mut self.provider, p.to_string(), p);
                            }
                        });
                });
                labeled(ui, "endpoint", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.endpoint)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.fetch_parallel, "parallel")
                        .on_hover_text("List txids then fetch concurrently (for endpoints without bulk pages).");
                    if self.fetch_parallel {
                        labeled(ui, "workers", |ui| {
                            ui.add(egui::DragValue::new(&mut self.fetch_workers).range(1..=128));
                        });
                    }
                });
                ui.label(
                    RichText::new("Requires Python 3 and network access to the endpoint.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
        }

        ui.add_space(6.0);
        section(ui, "EXTRACT · BTC TX → r,s,z", theme::MAGENTA);
        ui.label(
            RichText::new("Pull (r, s, z, pubkey) from a raw transaction, then analyze automatically.")
                .small()
                .color(theme::TEXT_DIM),
        );
        if ui.add(neon_button("⛏ EXTRACT FROM TX…", theme::MAGENTA)).clicked() {
            self.dispatch_extract();
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.extract_only_verified, "verified only")
                .on_hover_text("Keep only signatures that verify against the recomputed sighash.");
            if ui
                .add_enabled(self.extracted_json.is_some(), neon_button("⤓ SAVE JSON", theme::CYAN))
                .clicked()
            {
                self.save_extraction();
            }
        });

        ui.add_space(6.0);
        section(ui, "ATTACK VECTOR", theme::MAGENTA);
        egui::ComboBox::from_id_source("attack")
            .selected_text(self.attack.label())
            .width(ui.available_width())
            .show_ui(ui, |ui| {
                for kind in AttackKind::ALL.iter().copied() {
                    let text = if kind.is_available() {
                        RichText::new(kind.label())
                    } else {
                        RichText::new(format!("{} (unavailable)", kind.label())).color(theme::TEXT_DIM)
                    };
                    ui.selectable_value(&mut self.attack, kind, text);
                }
            });

        match self.attack {
            AttackKind::Polynonce => {
                labeled(ui, "degree", |ui| {
                    ui.add(egui::DragValue::new(&mut self.degree).range(1..=4));
                });
            }
            AttackKind::BiasedNonce => {
                labeled(ui, "bias", |ui| {
                    egui::ComboBox::from_id_source("bias_type")
                        .selected_text(&self.bias_type)
                        .show_ui(ui, |ui| {
                            for b in ["lsb", "msb", "range"] {
                                ui.selectable_value(&mut self.bias_type, b.to_string(), b);
                            }
                        });
                });
                labeled(ui, "known bits", |ui| {
                    ui.add(egui::DragValue::new(&mut self.known_bits).range(1..=256));
                });
                labeled(ui, "reduction", |ui| {
                    egui::ComboBox::from_id_source("reduction")
                        .selected_text(&self.reduction)
                        .show_ui(ui, |ui| {
                            for r in ["lll", "windowed-lll"] {
                                ui.selectable_value(&mut self.reduction, r.to_string(), r);
                            }
                        });
                });
                if self.reduction == "windowed-lll" {
                    labeled(ui, "block", |ui| {
                        ui.add(egui::DragValue::new(&mut self.window_block_size).range(2..=64));
                    });
                    labeled(ui, "rounds", |ui| {
                        ui.add(egui::DragValue::new(&mut self.window_rounds).range(1..=16));
                    });
                }
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.max_samples_enabled, "cap samples");
                    if self.max_samples_enabled {
                        ui.add(egui::DragValue::new(&mut self.max_samples).range(1..=100_000));
                    }
                });
            }
            AttackKind::NonceReuse => {
                ui.label(
                    RichText::new("Detects reused nonces (identical r) and recovers keys.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
            AttackKind::SharedNonce => {
                ui.label(
                    RichText::new("Same nonce reused (identical r) under one key.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
            AttackKind::ReuseR => {
                ui.label(
                    RichText::new("Groups by r alone; flags cross-key r reuse, recovers same-key.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
            }
            AttackKind::DeltaBias => {
                ui.label(
                    RichText::new("Nonces differ by a known Δ: k2 = k1 + Δ.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
                labeled(ui, "delta Δ", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.delta)
                            .desired_width(220.0)
                            .hint_text("decimal, may be negative"),
                    );
                });
            }
            AttackKind::Bitflip => {
                ui.label(
                    RichText::new("Single-bit nonce fault: sweeps Δ = ±2^i.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
                labeled(ui, "max bit", |ui| {
                    ui.add(egui::DragValue::new(&mut self.bitflip_bits).range(1..=256));
                });
            }
            AttackKind::Gcd => {
                ui.label(
                    RichText::new("Unknown small affine relation k2 = a·k1 + b (swept).")
                        .small()
                        .color(theme::TEXT_DIM),
                );
                labeled(ui, "max |a|", |ui| {
                    ui.add(egui::DragValue::new(&mut self.gcd_a_max).range(1..=1024));
                });
                labeled(ui, "max |b|", |ui| {
                    ui.add(egui::DragValue::new(&mut self.gcd_b_max).range(0..=1_000_000));
                });
            }
            AttackKind::NonceBias => {
                ui.label(
                    RichText::new("Generic MSB nonce bias; auto-sweeps the known-bit width.")
                        .small()
                        .color(theme::TEXT_DIM),
                );
                labeled(ui, "min bits", |ui| {
                    ui.add(egui::DragValue::new(&mut self.bias_min_bits).range(1..=255));
                });
                labeled(ui, "max bits", |ui| {
                    ui.add(egui::DragValue::new(&mut self.bias_max_bits).range(1..=255));
                });
                labeled(ui, "reduction", |ui| {
                    egui::ComboBox::from_id_source("reduction_nb")
                        .selected_text(&self.reduction)
                        .show_ui(ui, |ui| {
                            for r in ["lll", "windowed-lll"] {
                                ui.selectable_value(&mut self.reduction, r.to_string(), r);
                            }
                        });
                });
            }
        }

        ui.add_space(6.0);
        section(ui, "EXECUTE", theme::GREEN);
        let run_w = ui.available_width();
        if ui
            .add_sized([run_w, 34.0], neon_button("▶  RUN ANALYSIS", theme::GREEN))
            .clicked()
        {
            self.dispatch_run();
        }
        ui.horizontal(|ui| {
            if ui.add(neon_button("▦ BATCH FOLDER…", theme::CYAN)).clicked() {
                self.dispatch_batch();
            }
        });
        let (watch_label, watch_color) = if self.watching {
            ("◉ STOP WATCH", theme::RED)
        } else {
            ("◉ CONTINUOUS WATCH", theme::AMBER)
        };
        if ui
            .add_sized([run_w, 28.0], neon_button(watch_label, watch_color))
            .clicked()
        {
            self.toggle_watch();
        }
        labeled(ui, "interval (s)", |ui| {
            ui.add(egui::Slider::new(&mut self.watch_interval_secs, 0.5..=30.0).step_by(0.5));
        });

        ui.add_space(6.0);
        section(ui, "OUTPUT", theme::AMBER);
        ui.checkbox(&mut self.autosave_enabled, "Autosave report after each run");
        ui.horizontal(|ui| {
            if ui.add(neon_button("⚑ SET FOLDER…", theme::AMBER)).clicked() {
                if let Some(dir) = rfd::FileDialog::new()
                    .set_title("Autosave folder")
                    .pick_folder()
                {
                    self.push_log(LogLevel::Info, format!("Autosave → {}", dir.display()));
                    self.autosave_dir = Some(dir);
                }
            }
        });
        let dir_label = self
            .autosave_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "— default (vusi-reports next to input) —".to_string());
        ui.label(RichText::new(dir_label).small().color(theme::TEXT_DIM));

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.add(neon_button("⭱ EXPORT", theme::CYAN)).clicked() {
                self.export_latest();
            }
            if ui.add(neon_button("✖ CLEAR", theme::RED)).clicked() {
                self.latest = None;
                self.history.clear();
                self.push_log(LogLevel::Info, "Results cleared.".into());
            }
        });
    }

    fn results_area(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        // Summary tiles
        let (sigs, vulns, keys, attack, source, elapsed) = match &self.latest {
            Some(r) => (
                r.summary.total_signatures,
                r.summary.vulnerabilities_found,
                r.summary.keys_recovered,
                r.attack.clone(),
                r.source.clone(),
                r.elapsed_ms,
            ),
            None => (0, 0, 0, "—".to_string(), "—".to_string(), 0),
        };

        ui.horizontal(|ui| {
            tile(ui, "SIGNATURES", &sigs.to_string(), theme::CYAN);
            tile(
                ui,
                "VULNERABILITIES",
                &vulns.to_string(),
                if vulns > 0 { theme::AMBER } else { theme::TEXT_DIM },
            );
            tile(
                ui,
                "KEYS RECOVERED",
                &keys.to_string(),
                if keys > 0 { theme::GREEN } else { theme::TEXT_DIM },
            );
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("vector: {attack}")).small().color(theme::MAGENTA));
            ui.separator();
            ui.label(RichText::new(format!("source: {source}")).small().color(theme::TEXT_DIM));
            ui.separator();
            ui.label(RichText::new(format!("{elapsed} ms")).small().color(theme::TEXT_DIM));
        });

        ui.add_space(6.0);
        section(ui, "DETECTED VULNERABILITIES", theme::MAGENTA);

        let rows: Vec<_> = self
            .latest
            .as_ref()
            .map(|r| r.vulnerabilities.clone())
            .unwrap_or_default();

        if rows.is_empty() {
            ui.label(
                RichText::new(if self.latest.is_some() {
                    "No vulnerabilities in the latest run."
                } else {
                    "Awaiting analysis…"
                })
                .color(theme::TEXT_DIM),
            );
            return;
        }

        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(26.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::exact(60.0))
            .column(Column::exact(48.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::remainder().at_least(160.0))
            .column(Column::exact(34.0))
            .header(20.0, |mut h| {
                for name in ["#", "TYPE", "CONF", "SIGS", "STATUS", "RECOVERED KEY (hex)", ""] {
                    h.col(|ui| {
                        ui.label(RichText::new(name).color(theme::CYAN).small().strong());
                    });
                }
            })
            .body(|mut body| {
                for (i, v) in rows.iter().enumerate() {
                    body.row(24.0, |mut row| {
                        row.col(|ui| {
                            ui.label(RichText::new((i + 1).to_string()).color(theme::TEXT_DIM));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(&v.vuln_type).color(theme::TEXT));
                        });
                        row.col(|ui| {
                            ui.label(format!("{:.2}", v.confidence));
                        });
                        row.col(|ui| {
                            ui.label(v.signatures_count.to_string());
                        });
                        row.col(|ui| {
                            let (c, t) = if v.recovered_key.is_some() {
                                (theme::GREEN, "RECOVERED")
                            } else {
                                (theme::TEXT_DIM, "unrecov.")
                            };
                            ui.label(RichText::new(t).color(c).strong());
                        });
                        row.col(|ui| match &v.recovered_key {
                            Some(k) => {
                                ui.label(
                                    RichText::new(elide(&k.private_key_hex, 40))
                                        .color(theme::GREEN)
                                        .monospace(),
                                );
                            }
                            None => {
                                ui.label(
                                    RichText::new(v.recovery_reason.clone().unwrap_or_default())
                                        .color(theme::TEXT_DIM)
                                        .small(),
                                );
                            }
                        });
                        row.col(|ui| {
                            if let Some(k) = &v.recovered_key {
                                if ui.small_button("⧉").on_hover_text("Copy private key (hex)").clicked() {
                                    ui.output_mut(|o| o.copied_text = k.private_key_hex.clone());
                                }
                            }
                        });
                    });
                }
            });
    }

    fn log_console(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for (level, line) in &self.log {
                    let color = match level {
                        LogLevel::Info => theme::TEXT_DIM,
                        LogLevel::Good => theme::GREEN,
                        LogLevel::Warn => theme::AMBER,
                        LogLevel::Error => theme::RED,
                    };
                    ui.label(RichText::new(line).color(color).monospace().size(12.0));
                }
            });
    }
}

impl eframe::App for VusiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain worker events.
        let mut events = Vec::new();
        while let Ok(ev) = self.worker.rx.try_recv() {
            events.push(ev);
        }
        for ev in events {
            self.handle_event(ev);
        }

        egui::TopBottomPanel::top("top")
            .frame(egui::Frame::none().fill(theme::BG_PANEL).inner_margin(egui::Margin::symmetric(12.0, 8.0)))
            .show(ctx, |ui| self.top_bar(ui));

        egui::SidePanel::left("controls")
            .resizable(false)
            .exact_width(320.0)
            .frame(egui::Frame::none().fill(theme::BG_PANEL).inner_margin(egui::Margin::same(12.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    self.control_deck(ui);
                });
            });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(150.0)
            .frame(egui::Frame::none().fill(theme::BG_INSET).inner_margin(egui::Margin::same(10.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("▮ CONSOLE").color(theme::CYAN).strong());
                    ui.label(RichText::new("live event log").small().color(theme::TEXT_DIM));
                });
                ui.add_space(2.0);
                self.log_console(ui);
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().inner_margin(egui::Margin::same(14.0)))
            .show(ctx, |ui| {
                // Animated cyberspace backdrop behind everything.
                let time = ui.input(|i| i.time);
                theme::draw_grid(ui.painter(), ui.max_rect(), time);
                self.results_area(ui);
            });

        // Keep the grid animating smoothly (~25 fps) without pinning a core.
        ctx.request_repaint_after(Duration::from_millis(40));
    }
}

// ---- small widget helpers --------------------------------------------------

fn section(ui: &mut egui::Ui, title: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("▚").color(color));
        ui.label(RichText::new(title).color(color).strong().size(13.0));
    });
    let rect = ui.max_rect();
    let y = ui.cursor().top();
    ui.painter().line_segment(
        [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
        Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 60)),
    );
    ui.add_space(4.0);
}

fn labeled(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).small().color(theme::TEXT_DIM));
        add(ui);
    });
}

fn tile(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    egui::Frame::none()
        .fill(theme::BG_INSET)
        .stroke(Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 90)))
        .rounding(Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).small().color(theme::TEXT_DIM));
                ui.label(RichText::new(value).color(color).size(26.0).strong());
            });
        });
}

/// A flat "neon" button (colored text + subtle tinted fill).
fn neon_button(text: &str, color: egui::Color32) -> egui::Button<'static> {
    let fill = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 22);
    egui::Button::new(RichText::new(text.to_owned()).color(color).strong())
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, color))
}

fn elide(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…{}", &s[..max / 2], &s[s.len() - max / 2..])
    }
}
