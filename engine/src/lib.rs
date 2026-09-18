//! vusi-engine
//!
//! A thin, UI-agnostic analysis engine that drives the `vusi` ECDSA
//! signature-vulnerability library and produces a serialisable [`Report`].
//!
//! The GUI (and, in principle, any other front-end) uses this crate so that
//! all of the "what does an analysis run mean" logic lives in one tested place
//! and the interface layer only worries about pixels and buttons.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub mod extract;
pub use extract::{extract_from_tx_json, ExtractedSig, Extraction};

use vusi::attack::{Attack, NonceReuseAttack, Vulnerability};
use vusi::math::scalar_to_decimal_string;
use vusi::provider::parse_signatures;
use vusi::signature::Signature;

/// Which attack to run against a signature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackKind {
    /// Same nonce (identical `r`) reused across signatures.
    NonceReuse,
    /// Nonces related by a low-degree polynomial recurrence.
    Polynonce,
    /// Nonces with known biased bits, recovered via lattice reduction.
    BiasedNonce,
}

impl AttackKind {
    pub const ALL: &'static [AttackKind] = &[
        AttackKind::NonceReuse,
        AttackKind::Polynonce,
        AttackKind::BiasedNonce,
    ];

    pub fn label(self) -> &'static str {
        match self {
            AttackKind::NonceReuse => "Nonce Reuse",
            AttackKind::Polynonce => "Polynonce",
            AttackKind::BiasedNonce => "Biased Nonce (lattice)",
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            AttackKind::NonceReuse => "nonce-reuse",
            AttackKind::Polynonce => "polynonce",
            AttackKind::BiasedNonce => "biased-nonce",
        }
    }

    /// Whether this attack is available in the current build.
    pub fn is_available(self) -> bool {
        match self {
            AttackKind::NonceReuse | AttackKind::Polynonce => true,
            AttackKind::BiasedNonce => cfg!(feature = "biased-nonce"),
        }
    }
}

/// All tunable parameters for a single analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub attack: AttackKind,
    /// Polynonce polynomial degree (1 = linear, 2 = quadratic).
    pub degree: usize,
    /// Biased-nonce bias type: `lsb`, `msb`, or `range`.
    pub bias_type: String,
    /// Biased-nonce known bits (or max nonce bits for `range`).
    pub known_bits: usize,
    /// Lattice reduction: `lll` or `windowed-lll`.
    pub reduction: String,
    pub window_block_size: usize,
    pub window_rounds: usize,
    /// Max signatures sampled for biased-nonce recovery.
    pub max_samples: Option<usize>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            attack: AttackKind::NonceReuse,
            degree: 1,
            bias_type: "lsb".to_string(),
            known_bits: 8,
            reduction: "lll".to_string(),
            window_block_size: 20,
            window_rounds: 2,
            max_samples: None,
        }
    }
}

/// A recovered private key, in both decimal and hex form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredKeyOut {
    pub private_key_decimal: String,
    pub private_key_hex: String,
}

/// One detected vulnerability plus (optionally) its recovered key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityOut {
    #[serde(rename = "type")]
    pub vuln_type: String,
    pub confidence: f64,
    pub signatures_count: usize,
    pub pubkey: Option<String>,
    pub r_value: String,
    pub recovered_key: Option<RecoveredKeyOut>,
    pub recovery_status: String,
    pub recovery_reason: Option<String>,
}

/// Aggregate counts for a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Summary {
    pub total_signatures: usize,
    pub vulnerabilities_found: usize,
    pub keys_recovered: usize,
}

/// The full result of one analysis run — this is what gets rendered and
/// what gets autosaved to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Where the signatures came from (file name or `"<pasted>"`).
    pub source: String,
    /// RFC3339 timestamp of when the run completed.
    pub timestamp: String,
    /// Human name of the attack that was run.
    pub attack: String,
    /// Wall-clock duration of the run in milliseconds.
    pub elapsed_ms: u128,
    pub summary: Summary,
    pub vulnerabilities: Vec<VulnerabilityOut>,
}

impl Report {
    pub fn found_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
}

/// Build the concrete `vusi` attack object from a config.
fn build_attack(cfg: &AnalysisConfig) -> Result<Box<dyn Attack>> {
    match cfg.attack {
        AttackKind::NonceReuse => Ok(Box::new(NonceReuseAttack)),
        // `polynonce` is enabled unconditionally on the vusi dependency
        // (see engine/Cargo.toml), so this type is always present.
        AttackKind::Polynonce => Ok(Box::new(vusi::attack::PolynonceAttack::new(cfg.degree))),
        AttackKind::BiasedNonce => build_biased(cfg),
    }
}

#[cfg(feature = "biased-nonce")]
fn build_biased(cfg: &AnalysisConfig) -> Result<Box<dyn Attack>> {
    use vusi::attack::biased_nonce::{BiasType, ReductionAlgorithm};
    use vusi::attack::BiasedNonceAttack;

    let bias_type = match cfg.bias_type.as_str() {
        "lsb" => BiasType::Lsb,
        "msb" => BiasType::Msb,
        "range" => BiasType::Range,
        other => return Err(anyhow!("Unknown bias type: {other}")),
    };
    if bias_type != BiasType::Range && cfg.known_bits < 4 {
        return Err(anyhow!("Known bits must be >= 4 for biased-nonce"));
    }
    if bias_type == BiasType::Range && (cfg.known_bits == 0 || cfg.known_bits > 256) {
        return Err(anyhow!("Range max bits must be between 1 and 256"));
    }
    let reduction = match cfg.reduction.as_str() {
        "lll" => ReductionAlgorithm::Lll,
        "windowed-lll" => ReductionAlgorithm::WindowedLll {
            block_size: cfg.window_block_size,
            rounds: cfg.window_rounds,
        },
        other => return Err(anyhow!("Unknown reduction: {other}")),
    };
    Ok(Box::new(BiasedNonceAttack::new(
        bias_type,
        cfg.known_bits,
        reduction,
        cfg.max_samples,
    )))
}

#[cfg(not(feature = "biased-nonce"))]
fn build_biased(_cfg: &AnalysisConfig) -> Result<Box<dyn Attack>> {
    Err(anyhow!(
        "Biased-nonce attack is not available in this build. Rebuild with the `biased-nonce` feature (needs GMP/MPFR)."
    ))
}

fn to_outputs(vulns: &[Vulnerability], attack: &dyn Attack) -> (Vec<VulnerabilityOut>, usize) {
    let mut out = Vec::with_capacity(vulns.len());
    let mut keys_recovered = 0;

    for vuln in vulns {
        let recovered = attack.recover(vuln);
        let (status, reason, key_out) = if let Some(key) = &recovered {
            keys_recovered += 1;
            (
                "recovered".to_string(),
                None,
                Some(RecoveredKeyOut {
                    private_key_decimal: key.private_key_decimal.clone(),
                    private_key_hex: key.private_key_hex.clone(),
                }),
            )
        } else {
            (
                "unrecoverable".to_string(),
                Some("no exploitable signature pair in group".to_string()),
                None,
            )
        };

        out.push(VulnerabilityOut {
            vuln_type: vuln.attack_type.clone(),
            confidence: vuln.group.confidence,
            signatures_count: vuln.group.signatures.len(),
            pubkey: vuln.group.pubkey.clone(),
            r_value: scalar_to_decimal_string(&vuln.group.r),
            recovered_key: key_out,
            recovery_status: status,
            recovery_reason: reason,
        });
    }

    (out, keys_recovered)
}

/// Run an analysis over already-loaded text (JSON or CSV signature data).
pub fn analyze_str(content: &str, source: &str, cfg: &AnalysisConfig) -> Result<Report> {
    let started = Instant::now();
    let signatures: Vec<Signature> = parse_signatures(content)?;
    let attack = build_attack(cfg)?;
    let vulns = attack.detect(&signatures);
    let (vuln_outputs, keys_recovered) = to_outputs(&vulns, attack.as_ref());

    Ok(Report {
        source: source.to_string(),
        timestamp: chrono::Local::now().to_rfc3339(),
        attack: cfg.attack.label().to_string(),
        elapsed_ms: started.elapsed().as_millis(),
        summary: Summary {
            total_signatures: signatures.len(),
            vulnerabilities_found: vuln_outputs.len(),
            keys_recovered,
        },
        vulnerabilities: vuln_outputs,
    })
}

/// Read a file from disk and analyse it. The file name is used as the report
/// source label.
pub fn analyze_path(path: &Path, cfg: &AnalysisConfig) -> Result<Report> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Could not read {}: {e}", path.display()))?;
    let source = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    analyze_str(&content, &source, cfg)
}

/// A short, filesystem-safe slug of a report source, for autosave filenames.
fn source_slug(source: &str) -> String {
    let stem = Path::new(source)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| source.to_string());
    let slug: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "report".to_string()
    } else {
        slug
    }
}

/// Write a report to `dir` as pretty JSON under a timestamped, source-derived
/// filename, creating `dir` if needed. Returns the path written.
pub fn autosave(report: &Report, dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow!("Could not create autosave dir {}: {e}", dir.display()))?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let filename = format!("vusi_{}_{}.json", source_slug(&report.source), stamp);
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(&path, json)
        .map_err(|e| anyhow!("Could not write autosave {}: {e}", path.display()))?;
    Ok(path)
}

/// Serialise a report to a specific file chosen by the user (Export button).
pub fn export_to(report: &Report, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)
        .map_err(|e| anyhow!("Could not write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two signatures that reuse the same nonce (identical `r`) — the classic
    // recoverable case. Taken from the vusi test fixtures.
    const REUSE_JSON: &str = r#"[
      {
        "r": "6819641642398093696120236467967538361543858578256722584730163952555838220871",
        "s": "5111069398017465712735164463809304352000044522184731945150717785434666956473",
        "z": "4834837306435966184874350434501389872155834069808640791394730023708942795899",
        "pubkey": null
      },
      {
        "r": "6819641642398093696120236467967538361543858578256722584730163952555838220871",
        "s": "31133511789966193434473156682648022965280901634950536313584626906865295404159",
        "z": "108808786585075507407446857551522706228868950080801424952567576192808212665067",
        "pubkey": null
      }
    ]"#;

    // A clean pair: different r values, nothing to recover.
    const CLEAN_JSON: &str = r#"[
      {"r":"123","s":"456","z":"789"},
      {"r":"124","s":"457","z":"790"}
    ]"#;

    #[test]
    fn detects_and_recovers_nonce_reuse() {
        let cfg = AnalysisConfig::default();
        let report = analyze_str(REUSE_JSON, "reuse.json", &cfg).unwrap();
        assert_eq!(report.summary.total_signatures, 2);
        assert_eq!(report.summary.vulnerabilities_found, 1);
        assert_eq!(report.summary.keys_recovered, 1);
        assert!(report.found_vulnerabilities());
        let v = &report.vulnerabilities[0];
        let key = v.recovered_key.as_ref().expect("key recovered");
        assert!(!key.private_key_decimal.is_empty());
        assert!(key.private_key_hex.len() == 64 || key.private_key_hex.len() == 66);
        assert_eq!(v.recovery_status, "recovered");
    }

    #[test]
    fn clean_input_has_no_vulns() {
        let cfg = AnalysisConfig::default();
        let report = analyze_str(CLEAN_JSON, "clean.json", &cfg).unwrap();
        assert_eq!(report.summary.total_signatures, 2);
        assert_eq!(report.summary.vulnerabilities_found, 0);
        assert_eq!(report.summary.keys_recovered, 0);
        assert!(!report.found_vulnerabilities());
    }

    #[test]
    fn csv_input_is_accepted() {
        let csv = "r,s,z,pubkey\n123,456,789,\n124,457,790,\n";
        let cfg = AnalysisConfig::default();
        let report = analyze_str(csv, "in.csv", &cfg).unwrap();
        assert_eq!(report.summary.total_signatures, 2);
    }

    #[test]
    fn bad_input_errors() {
        let cfg = AnalysisConfig::default();
        assert!(analyze_str("not valid", "x", &cfg).is_err());
    }

    #[test]
    fn autosave_and_export_roundtrip() {
        let cfg = AnalysisConfig::default();
        let report = analyze_str(REUSE_JSON, "reuse.json", &cfg).unwrap();

        let dir = std::env::temp_dir().join(format!("vusi_test_{}", std::process::id()));
        let saved = autosave(&report, &dir).unwrap();
        assert!(saved.exists());
        let back: Report =
            serde_json::from_str(&std::fs::read_to_string(&saved).unwrap()).unwrap();
        assert_eq!(back.summary.keys_recovered, 1);

        let export = dir.join("explicit.json");
        export_to(&report, &export).unwrap();
        assert!(export.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_slug_is_safe() {
        assert_eq!(source_slug("/tmp/My Sigs!.json"), "My_Sigs");
        assert_eq!(source_slug("<pasted>"), "pasted");
    }

    #[test]
    fn polynonce_attack_runs() {
        // Just ensure the polynonce path constructs and runs without panicking
        // on clean input (no vuln expected here).
        let cfg = AnalysisConfig {
            attack: AttackKind::Polynonce,
            ..AnalysisConfig::default()
        };
        let report = analyze_str(CLEAN_JSON, "clean.json", &cfg).unwrap();
        assert_eq!(report.summary.total_signatures, 2);
    }
}
