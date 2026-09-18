//! Extract ECDSA `(r, s, z, pubkey)` tuples from raw Bitcoin transactions.
//!
//! Given a transaction in the common block-explorer JSON shape (with each
//! input's `sigscript`, prevout `pkscript`, `sequence`, and the tx `version` /
//! `locktime` / `outputs`), this:
//!
//! 1. parses the DER signature out of each input's scriptSig → `(r, s)` and the
//!    sighash type,
//! 2. reconstructs the **legacy P2PKH `SIGHASH_ALL` sighash** for that input →
//!    the message `z` that was actually signed,
//! 3. reads the compressed public key from the scriptSig,
//! 4. **verifies** the signature against the recomputed `z` with `k256`, so a
//!    wrong/unsupported input is caught rather than emitting a bogus `z`.
//!
//! The result serialises straight into the `vusi` input format
//! (`[{"r","s","z","pubkey"}]`), ready to feed the analyzer.
//!
//! Scope: legacy P2PKH inputs signed with `SIGHASH_ALL` (0x01) — the classic
//! reused-nonce target. SegWit (BIP143) and non-`ALL` sighash types are skipped
//! with a reason rather than mis-handled.

use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

/// secp256k1 group order `n`.
fn curve_order() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

#[derive(Debug, Clone, Deserialize)]
struct RawTx {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    locktime: u32,
    #[serde(default)]
    inputs: Vec<RawIn>,
    #[serde(default)]
    outputs: Vec<RawOut>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIn {
    #[serde(default)]
    txid: String,
    #[serde(default)]
    output: u32,
    #[serde(default)]
    sigscript: String,
    #[serde(default)]
    sequence: u32,
    #[serde(default)]
    pkscript: String,
    #[serde(default)]
    witness: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawOut {
    #[serde(default)]
    value: u64,
    #[serde(default)]
    pkscript: String,
}

/// One extracted signature tuple, in the `vusi` input shape (decimal `r,s,z`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSig {
    pub r: String,
    pub s: String,
    pub z: String,
    pub pubkey: String,
    /// Whether the signature verified against the recomputed sighash.
    pub verified: bool,
    /// Source label, e.g. `txid:input_index`.
    pub origin: String,
}

/// Result of an extraction run.
#[derive(Debug, Clone, Default)]
pub struct Extraction {
    pub signatures: Vec<ExtractedSig>,
    pub total_inputs: usize,
    pub verified: usize,
    /// Human-readable reasons for inputs that were skipped.
    pub skipped: Vec<String>,
}

impl Extraction {
    /// Serialise the extracted signatures as a `vusi`-ready JSON array. When
    /// `only_verified` is set, unverified rows are omitted.
    pub fn to_vusi_json(&self, only_verified: bool) -> String {
        #[derive(Serialize)]
        struct Out<'a> {
            r: &'a str,
            s: &'a str,
            z: &'a str,
            pubkey: &'a str,
        }
        let rows: Vec<Out> = self
            .signatures
            .iter()
            .filter(|s| !only_verified || s.verified)
            .map(|s| Out {
                r: &s.r,
                s: &s.s,
                z: &s.z,
                pubkey: &s.pubkey,
            })
            .collect();
        serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
    }
}

// ---- byte helpers ----------------------------------------------------------

fn write_varint(buf: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => buf.push(n as u8),
        0xfd..=0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buf.push(0xfe);
            buf.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            buf.push(0xff);
            buf.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn to_32_be(x: &BigUint) -> [u8; 32] {
    let bytes = x.to_bytes_be();
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

/// Read one script push starting at `*idx`, returning its data and advancing.
fn read_push(script: &[u8], idx: &mut usize) -> Option<Vec<u8>> {
    if *idx >= script.len() {
        return None;
    }
    let opcode = script[*idx];
    *idx += 1;
    let len = match opcode {
        0x01..=0x4b => opcode as usize,
        0x4c => {
            let l = *script.get(*idx)? as usize;
            *idx += 1;
            l
        }
        0x4d => {
            let l = u16::from_le_bytes([*script.get(*idx)?, *script.get(*idx + 1)?]) as usize;
            *idx += 2;
            l
        }
        0x4e => {
            let l = u32::from_le_bytes([
                *script.get(*idx)?,
                *script.get(*idx + 1)?,
                *script.get(*idx + 2)?,
                *script.get(*idx + 3)?,
            ]) as usize;
            *idx += 4;
            l
        }
        _ => return None, // not a simple push (opcode)
    };
    let end = idx.checked_add(len)?;
    if end > script.len() {
        return None;
    }
    let data = script[*idx..end].to_vec();
    *idx = end;
    Some(data)
}

/// Parse a DER-encoded ECDSA signature into `(r, s)` as big integers.
fn parse_der(sig: &[u8]) -> Option<(BigUint, BigUint)> {
    // 0x30 total_len 0x02 r_len R 0x02 s_len S
    if sig.len() < 8 || sig[0] != 0x30 {
        return None;
    }
    let mut i = 2usize;
    if *sig.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let r_len = *sig.get(i)? as usize;
    i += 1;
    let r = sig.get(i..i + r_len)?;
    i += r_len;
    if *sig.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let s_len = *sig.get(i)? as usize;
    i += 1;
    let s = sig.get(i..i + s_len)?;
    Some((BigUint::from_bytes_be(r), BigUint::from_bytes_be(s)))
}

/// Reconstruct the legacy P2PKH `SIGHASH_ALL` message digest for `input_index`.
fn legacy_sighash_all(tx: &RawTx, input_index: usize) -> Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&tx.version.to_le_bytes());

    write_varint(&mut buf, tx.inputs.len());
    for (j, inp) in tx.inputs.iter().enumerate() {
        let mut txid = hex::decode(inp.txid.trim())
            .map_err(|e| anyhow!("input {j}: bad txid hex: {e}"))?;
        if txid.len() != 32 {
            return Err(anyhow!("input {j}: txid is not 32 bytes"));
        }
        txid.reverse(); // display order → internal little-endian
        buf.extend_from_slice(&txid);
        buf.extend_from_slice(&inp.output.to_le_bytes());

        if j == input_index {
            let spk = hex::decode(inp.pkscript.trim())
                .map_err(|e| anyhow!("input {j}: bad pkscript hex: {e}"))?;
            write_varint(&mut buf, spk.len());
            buf.extend_from_slice(&spk);
        } else {
            write_varint(&mut buf, 0);
        }
        buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    write_varint(&mut buf, tx.outputs.len());
    for out in &tx.outputs {
        buf.extend_from_slice(&out.value.to_le_bytes());
        let spk = hex::decode(out.pkscript.trim())
            .map_err(|e| anyhow!("output: bad pkscript hex: {e}"))?;
        write_varint(&mut buf, spk.len());
        buf.extend_from_slice(&spk);
    }

    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // hashtype SIGHASH_ALL, 4 bytes LE

    Ok(double_sha256(&buf))
}

/// ECDSA-verify `(r, s)` over the 32-byte prehash `z` under compressed `pubkey`.
///
/// `s` is normalized to low-S *for the check only* — `k256` rejects high-S
/// signatures by policy (BIP62 malleability), but `(r, s)` and `(r, n-s)`
/// verify to the same point, so a high-S signature is still valid and its `z`
/// is still correct. The caller keeps the original `s` for the output.
fn verifies(r: &BigUint, s: &BigUint, z32: &[u8; 32], pubkey: &[u8]) -> bool {
    let n = curve_order();
    let half = &n >> 1u32;
    let s_low = if s > &half { &n - s } else { s.clone() };
    let r32 = to_32_be(r);
    let s32 = to_32_be(&s_low);
    let sig = match Signature::from_scalars(
        *k256::FieldBytes::from_slice(&r32),
        *k256::FieldBytes::from_slice(&s32),
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    vk.verify_prehash(z32, &sig).is_ok()
}

fn extract_tx(tx: &RawTx, tx_label: &str, out: &mut Extraction) {
    let n = curve_order();
    for (i, inp) in tx.inputs.iter().enumerate() {
        out.total_inputs += 1;
        let origin = format!("{tx_label}:{i}");

        if inp.sigscript.trim().is_empty() {
            if !inp.witness.is_empty() {
                out.skipped
                    .push(format!("{origin}: SegWit input (BIP143 not supported)"));
            } else {
                out.skipped.push(format!("{origin}: empty scriptSig"));
            }
            continue;
        }

        let script = match hex::decode(inp.sigscript.trim()) {
            Ok(b) => b,
            Err(_) => {
                out.skipped.push(format!("{origin}: bad sigscript hex"));
                continue;
            }
        };

        // scriptSig for a P2PKH spend is: <push sig+hashtype> <push pubkey>
        let mut idx = 0usize;
        let sig_push = read_push(&script, &mut idx);
        let key_push = read_push(&script, &mut idx);
        let (sig_and_type, pubkey) = match (sig_push, key_push) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                out.skipped
                    .push(format!("{origin}: not a standard P2PKH scriptSig"));
                continue;
            }
        };

        if sig_and_type.is_empty() {
            out.skipped.push(format!("{origin}: empty signature push"));
            continue;
        }
        let hashtype = *sig_and_type.last().unwrap();
        if hashtype != 0x01 {
            out.skipped
                .push(format!("{origin}: sighash type 0x{hashtype:02x} (only ALL supported)"));
            continue;
        }
        let der = &sig_and_type[..sig_and_type.len() - 1];

        let (r, s) = match parse_der(der) {
            Some(rs) => rs,
            None => {
                out.skipped.push(format!("{origin}: could not parse DER signature"));
                continue;
            }
        };

        let z_hash = match legacy_sighash_all(tx, i) {
            Ok(h) => h,
            Err(e) => {
                out.skipped.push(format!("{origin}: sighash error: {e}"));
                continue;
            }
        };
        let z = BigUint::from_bytes_be(&z_hash) % &n;
        let z32 = to_32_be(&z);

        let r_red = &r % &n;
        let s_red = &s % &n;
        let verified = verifies(&r_red, &s_red, &z32, &pubkey);
        if verified {
            out.verified += 1;
        }

        out.signatures.push(ExtractedSig {
            r: r_red.to_str_radix(10),
            s: s_red.to_str_radix(10),
            z: z.to_str_radix(10),
            pubkey: hex::encode(&pubkey),
            verified,
            origin,
        });
    }
}

/// Extract signatures from a transaction JSON. Accepts any of:
/// - a single transaction object,
/// - a JSON array of transaction objects, or
/// - several transaction objects concatenated back-to-back (whitespace- or
///   newline-separated, i.e. a JSON stream / NDJSON), as many block explorers
///   and dumps produce.
pub fn extract_from_tx_json(content: &str) -> Result<Extraction> {
    let content = content.trim_start_matches('\u{feff}').trim();

    let txs: Vec<RawTx> = if content.starts_with('[') {
        // A single JSON array of transactions.
        serde_json::from_str::<Vec<RawTx>>(content)
            .map_err(|e| anyhow!("Not a recognizable transaction array: {e}"))?
    } else {
        // One or more transaction objects streamed one after another.
        let stream = serde_json::Deserializer::from_str(content).into_iter::<RawTx>();
        let mut list = Vec::new();
        for (n, item) in stream.enumerate() {
            match item {
                Ok(tx) => list.push(tx),
                Err(e) => {
                    return Err(anyhow!(
                        "Not a recognizable transaction JSON (parsing object #{}): {e}",
                        n + 1
                    ))
                }
            }
        }
        list
    };

    if txs.is_empty() {
        return Err(anyhow!("No transactions found in input."));
    }

    let mut out = Extraction::default();
    for (t, tx) in txs.iter().enumerate() {
        if tx.inputs.is_empty() {
            out.skipped.push(format!("tx #{t}: no inputs"));
            continue;
        }
        let label = tx
            .inputs
            .first()
            .map(|_| format!("tx{t}"))
            .unwrap_or_else(|| format!("tx{t}"));
        extract_tx(tx, &label, &mut out);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TX: &str = include_str!("../tests/fixtures/sample_tx.json");

    #[test]
    fn extracts_and_verifies_all_p2pkh_inputs() {
        let ex = extract_from_tx_json(SAMPLE_TX).unwrap();
        assert_eq!(ex.total_inputs, 11, "sample tx has 11 inputs");
        assert_eq!(ex.signatures.len(), 11, "all inputs are P2PKH SIGHASH_ALL");
        // The decisive check: every signature must verify against the sighash
        // we computed. If z were wrong, these would fail.
        assert_eq!(
            ex.verified, 11,
            "all 11 signatures must verify against the recomputed z; skipped={:?}",
            ex.skipped
        );
        for s in &ex.signatures {
            assert!(s.verified);
            assert!(!s.r.is_empty() && !s.s.is_empty() && !s.z.is_empty());
            assert_eq!(s.pubkey.len(), 66); // 33-byte compressed key, hex
        }
    }

    #[test]
    fn output_feeds_the_analyzer() {
        let ex = extract_from_tx_json(SAMPLE_TX).unwrap();
        let json = ex.to_vusi_json(true);
        // Must parse back through the vusi provider without error.
        let sigs = crate::provider::parse_signatures(&json).unwrap();
        assert_eq!(sigs.len(), 11);
    }

    #[test]
    fn parses_concatenated_transactions() {
        // Two transaction objects back-to-back, separated by a blank line —
        // the "JSON stream" shape some explorers dump.
        let streamed = format!("{SAMPLE_TX}\n\n{SAMPLE_TX}");
        let ex = extract_from_tx_json(&streamed).unwrap();
        assert_eq!(ex.total_inputs, 22, "two copies × 11 inputs");
        assert_eq!(ex.verified, 22, "all verify; skipped={:?}", ex.skipped);
    }

    #[test]
    fn rejects_non_tx_json() {
        assert!(extract_from_tx_json(r#"{"foo":"bar"}"#).is_err()
            || extract_from_tx_json(r#"{"foo":"bar"}"#).unwrap().signatures.is_empty());
    }
}
