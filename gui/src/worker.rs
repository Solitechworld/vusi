//! Background worker thread.
//!
//! The UI thread never runs analysis directly. Instead it sends [`Command`]s to
//! a worker thread and drains [`WorkerEvent`]s each frame. This keeps the
//! interface at full frame-rate even while a large batch or a continuous watch
//! loop is churning, and lets "continuous" mode poll a file for changes without
//! blocking anything.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant, SystemTime};

use vusi_engine::{
    analyze_path, analyze_str, autosave, extract_from_tx_json, AnalysisConfig, Report,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Good,
    Warn,
    Error,
}

/// Commands from the UI to the worker.
pub enum Command {
    /// Analyze pasted text.
    AnalyzeText {
        content: String,
        source: String,
        cfg: AnalysisConfig,
        autosave_dir: Option<PathBuf>,
    },
    /// Analyze a single file on disk.
    AnalyzeFile {
        path: PathBuf,
        cfg: AnalysisConfig,
        autosave_dir: Option<PathBuf>,
    },
    /// Analyze every .json/.csv file in a directory.
    BatchDir {
        dir: PathBuf,
        cfg: AnalysisConfig,
        autosave_dir: Option<PathBuf>,
    },
    /// Extract (r,s,z,pubkey) tuples from a raw Bitcoin transaction JSON, load
    /// them as input, and analyze in one step.
    ExtractTx {
        path: PathBuf,
        only_verified: bool,
        cfg: AnalysisConfig,
        autosave_dir: Option<PathBuf>,
    },
    /// Begin watching a file; re-analyze whenever its contents change.
    StartWatch {
        path: PathBuf,
        cfg: AnalysisConfig,
        autosave_dir: Option<PathBuf>,
        interval: Duration,
    },
    StopWatch,
    Shutdown,
}

/// Events from the worker to the UI.
pub enum WorkerEvent {
    Log(LogLevel, String),
    /// A finished report, plus the path it was autosaved to (if any).
    Report(Report, Option<PathBuf>),
    /// Extracted signature tuples as a vusi-ready JSON blob, with a source
    /// label — the UI loads this into the input box.
    Extracted { json: String, source: String },
    /// Worker busy-state changed (drives spinner / disabling of buttons).
    Busy(bool),
    /// Watch mode turned on/off.
    Watching(bool),
}

/// Handle held by the UI. Dropping it shuts the worker down.
pub struct WorkerHandle {
    tx: Sender<Command>,
    pub rx: Receiver<WorkerEvent>,
}

impl WorkerHandle {
    pub fn send(&self, cmd: Command) {
        // If the worker has gone away there is nothing useful to do.
        let _ = self.tx.send(cmd);
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
    }
}

struct WatchState {
    path: PathBuf,
    cfg: AnalysisConfig,
    autosave_dir: Option<PathBuf>,
    interval: Duration,
    last_signature: Option<(SystemTime, u64)>,
    next_poll: Instant,
}

/// Spawn the worker thread. `ctx` is used to wake the UI when events arrive.
pub fn spawn(ctx: egui::Context) -> WorkerHandle {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WorkerEvent>();

    std::thread::Builder::new()
        .name("vusi-worker".into())
        .spawn(move || worker_loop(cmd_rx, evt_tx, ctx))
        .expect("spawn worker thread");

    WorkerHandle {
        tx: cmd_tx,
        rx: evt_rx,
    }
}

fn worker_loop(rx: Receiver<Command>, tx: Sender<WorkerEvent>, ctx: egui::Context) {
    let emit = |ev: WorkerEvent| {
        let _ = tx.send(ev);
        ctx.request_repaint();
    };
    let log = |lvl: LogLevel, msg: String| emit(WorkerEvent::Log(lvl, msg));

    let mut watch: Option<WatchState> = None;

    loop {
        // When watching, wake up periodically to poll; otherwise block.
        let timeout = match &watch {
            Some(w) => w
                .next_poll
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(400)),
            None => Duration::from_millis(750),
        };

        match rx.recv_timeout(timeout) {
            Ok(Command::Shutdown) => break,
            Ok(Command::StopWatch) => {
                if watch.take().is_some() {
                    log(LogLevel::Info, "Continuous watch stopped.".into());
                    emit(WorkerEvent::Watching(false));
                }
            }
            Ok(Command::AnalyzeText {
                content,
                source,
                cfg,
                autosave_dir,
            }) => {
                emit(WorkerEvent::Busy(true));
                run_text(&content, &source, &cfg, autosave_dir.as_deref(), &emit);
                emit(WorkerEvent::Busy(false));
            }
            Ok(Command::AnalyzeFile {
                path,
                cfg,
                autosave_dir,
            }) => {
                emit(WorkerEvent::Busy(true));
                run_file(&path, &cfg, autosave_dir.as_deref(), &emit);
                emit(WorkerEvent::Busy(false));
            }
            Ok(Command::BatchDir {
                dir,
                cfg,
                autosave_dir,
            }) => {
                emit(WorkerEvent::Busy(true));
                run_batch(&dir, &cfg, autosave_dir.as_deref(), &emit);
                emit(WorkerEvent::Busy(false));
            }
            Ok(Command::ExtractTx {
                path,
                only_verified,
                cfg,
                autosave_dir,
            }) => {
                emit(WorkerEvent::Busy(true));
                run_extract(&path, only_verified, &cfg, autosave_dir.as_deref(), &emit);
                emit(WorkerEvent::Busy(false));
            }
            Ok(Command::StartWatch {
                path,
                cfg,
                autosave_dir,
                interval,
            }) => {
                log(
                    LogLevel::Info,
                    format!(
                        "Continuous watch armed on {} (every {:.1}s).",
                        path.display(),
                        interval.as_secs_f32()
                    ),
                );
                emit(WorkerEvent::Watching(true));
                // Run once immediately, then arm polling.
                emit(WorkerEvent::Busy(true));
                let sig = file_signature(&path);
                run_file(&path, &cfg, autosave_dir.as_deref(), &emit);
                emit(WorkerEvent::Busy(false));
                watch = Some(WatchState {
                    path,
                    cfg,
                    autosave_dir,
                    interval,
                    last_signature: sig,
                    next_poll: Instant::now() + interval,
                });
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(w) = watch.as_mut() {
                    if Instant::now() >= w.next_poll {
                        w.next_poll = Instant::now() + w.interval;
                        let sig = file_signature(&w.path);
                        if sig.is_some() && sig != w.last_signature {
                            w.last_signature = sig;
                            log(
                                LogLevel::Info,
                                format!("Change detected in {} — re-analyzing.", w.path.display()),
                            );
                            emit(WorkerEvent::Busy(true));
                            run_file(&w.path, &w.cfg, w.autosave_dir.as_deref(), &emit);
                            emit(WorkerEvent::Busy(false));
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// (mtime, len) fingerprint used to cheaply detect file changes.
fn file_signature(path: &Path) -> Option<(SystemTime, u64)> {
    let md = std::fs::metadata(path).ok()?;
    let mtime = md.modified().ok()?;
    Some((mtime, md.len()))
}

fn deliver<F: Fn(WorkerEvent)>(
    report: Report,
    autosave_dir: Option<&Path>,
    emit: &F,
) {
    let mut saved_path = None;
    if let Some(dir) = autosave_dir {
        match autosave(&report, dir) {
            Ok(p) => {
                emit(WorkerEvent::Log(
                    LogLevel::Good,
                    format!("Autosaved report → {}", p.display()),
                ));
                saved_path = Some(p);
            }
            Err(e) => emit(WorkerEvent::Log(
                LogLevel::Error,
                format!("Autosave failed: {e}"),
            )),
        }
    }

    let summary = &report.summary;
    let level = if summary.keys_recovered > 0 {
        LogLevel::Good
    } else if summary.vulnerabilities_found > 0 {
        LogLevel::Warn
    } else {
        LogLevel::Info
    };
    emit(WorkerEvent::Log(
        level,
        format!(
            "[{}] {} sigs · {} vulns · {} keys · {} ms",
            report.source,
            summary.total_signatures,
            summary.vulnerabilities_found,
            summary.keys_recovered,
            report.elapsed_ms
        ),
    ));
    emit(WorkerEvent::Report(report, saved_path));
}

fn run_text<F: Fn(WorkerEvent)>(
    content: &str,
    source: &str,
    cfg: &AnalysisConfig,
    autosave_dir: Option<&Path>,
    emit: &F,
) {
    match analyze_str(content, source, cfg) {
        Ok(report) => deliver(report, autosave_dir, emit),
        Err(e) => emit(WorkerEvent::Log(LogLevel::Error, format!("Analysis error: {e}"))),
    }
}

fn run_file<F: Fn(WorkerEvent)>(
    path: &Path,
    cfg: &AnalysisConfig,
    autosave_dir: Option<&Path>,
    emit: &F,
) {
    match analyze_path(path, cfg) {
        Ok(report) => deliver(report, autosave_dir, emit),
        Err(e) => emit(WorkerEvent::Log(
            LogLevel::Error,
            format!("Analysis error ({}): {e}", path.display()),
        )),
    }
}

fn run_extract<F: Fn(WorkerEvent)>(
    path: &Path,
    only_verified: bool,
    cfg: &AnalysisConfig,
    autosave_dir: Option<&Path>,
    emit: &F,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            emit(WorkerEvent::Log(
                LogLevel::Error,
                format!("Cannot read {}: {e}", path.display()),
            ));
            return;
        }
    };

    let source = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    let ex = match extract_from_tx_json(&content) {
        Ok(ex) => ex,
        Err(e) => {
            emit(WorkerEvent::Log(LogLevel::Error, format!("Extraction failed: {e}")));
            return;
        }
    };

    let total_sigs = ex.signatures.len();
    let level = if ex.verified == total_sigs && total_sigs > 0 {
        LogLevel::Good
    } else if total_sigs > 0 {
        LogLevel::Warn
    } else {
        LogLevel::Error
    };
    emit(WorkerEvent::Log(
        level,
        format!(
            "Extracted {} signature(s) from {} input(s) · {} verified",
            total_sigs, ex.total_inputs, ex.verified
        ),
    ));
    // Surface up to a few skip reasons so unsupported inputs are visible.
    for reason in ex.skipped.iter().take(6) {
        emit(WorkerEvent::Log(LogLevel::Warn, format!("  skipped {reason}")));
    }
    if ex.skipped.len() > 6 {
        emit(WorkerEvent::Log(
            LogLevel::Warn,
            format!("  …and {} more skipped", ex.skipped.len() - 6),
        ));
    }

    let json = ex.to_vusi_json(only_verified);
    let used = if only_verified { ex.verified } else { total_sigs };

    // Load the extracted tuples into the UI input box.
    emit(WorkerEvent::Extracted {
        json: json.clone(),
        source: source.clone(),
    });

    if used == 0 {
        emit(WorkerEvent::Log(
            LogLevel::Warn,
            "No usable signatures to analyze from this transaction.".into(),
        ));
        return;
    }

    emit(WorkerEvent::Log(
        LogLevel::Info,
        format!("Analyzing {} extracted signature(s)…", used),
    ));
    run_text(&json, &source, cfg, autosave_dir, emit);
}

fn run_batch<F: Fn(WorkerEvent)>(
    dir: &Path,
    cfg: &AnalysisConfig,
    autosave_dir: Option<&Path>,
    emit: &F,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            emit(WorkerEvent::Log(
                LogLevel::Error,
                format!("Cannot read folder {}: {e}", dir.display()),
            ));
            return;
        }
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && matches!(
                    p.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()),
                    Some(ref ext) if ext == "json" || ext == "csv"
                )
        })
        .collect();
    files.sort();

    if files.is_empty() {
        emit(WorkerEvent::Log(
            LogLevel::Warn,
            format!("No .json/.csv files found in {}", dir.display()),
        ));
        return;
    }

    emit(WorkerEvent::Log(
        LogLevel::Info,
        format!("Batch: {} file(s) in {}", files.len(), dir.display()),
    ));
    for path in files {
        run_file(&path, cfg, autosave_dir, emit);
    }
    emit(WorkerEvent::Log(LogLevel::Good, "Batch complete.".into()));
}
