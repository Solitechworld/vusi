//! Command-line companion to the GUI's extractor.
//!
//! Usage:
//!   cargo run -p vusi-engine --example tx_extract -- <tx.json> [out.json]
//!
//! Reads a Bitcoin transaction JSON (single object, array, or a stream of
//! concatenated objects), writes the extracted `(r,s,z,pubkey)` set as a
//! vusi-ready JSON file, and prints a nonce-reuse analysis summary.

use vusi_engine::{analyze_str, extract_from_tx_json, AnalysisConfig};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let input = args.next().unwrap_or_else(|| {
        eprintln!("usage: tx_extract <tx.json> [out.json]");
        std::process::exit(2);
    });
    let out = args.next().unwrap_or_else(|| "extracted.json".to_string());

    let content = std::fs::read_to_string(&input)?;
    let ex = extract_from_tx_json(&content)?;

    println!(
        "inputs={}  extracted={}  verified={}  skipped={}",
        ex.total_inputs,
        ex.signatures.len(),
        ex.verified,
        ex.skipped.len()
    );
    for reason in ex.skipped.iter().take(10) {
        println!("  skip: {reason}");
    }
    if ex.skipped.len() > 10 {
        println!("  …and {} more", ex.skipped.len() - 10);
    }

    let json = ex.to_vusi_json(true);
    std::fs::write(&out, &json)?;
    println!("wrote {out}");

    let report = analyze_str(&json, &input, &AnalysisConfig::default())?;
    println!(
        "nonce-reuse → signatures={}  vulnerabilities={}  keys_recovered={}",
        report.summary.total_signatures,
        report.summary.vulnerabilities_found,
        report.summary.keys_recovered
    );
    for v in &report.vulnerabilities {
        if let Some(k) = &v.recovered_key {
            println!("  RECOVERED KEY (hex): {}", k.private_key_hex);
            if let Some(pk) = &v.pubkey {
                println!("            pubkey  : {pk}");
            }
        }
    }
    Ok(())
}
