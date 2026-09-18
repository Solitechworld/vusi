//! Related-nonce attacks.
//!
//! These attacks exploit an **affine relation between the nonces** of two ECDSA
//! signatures made with the *same* private key `d`:
//!
//! ```text
//!     k2 = a * k1 + b   (mod n)
//! ```
//!
//! Writing each nonce in terms of the (unknown) key,
//! `k_i = (z_i + r_i * d) / s_i`, substituting into the relation and solving for
//! `d` gives a closed form:
//!
//! ```text
//!     d = (a*s2*z1 - s1*z2 + b*s1*s2) / (s1*r2 - a*s2*r1)   (mod n)
//! ```
//!
//! This is the two-signature case of *"Breaking ECDSA with Two Affinely Related
//! Nonces"* (Gilchrist, Litos et al., IACR ePrint 2025/705); the classic
//! nonce-reuse attack is simply the special case `a = 1, b = 0`. The resultant /
//! polynomial-GCD elimination of the nonce between the two signing polynomials
//! reduces, in the affine case, to exactly this linear equation in `d`.
//!
//! Concrete modes built on the shared solver [`solve_affine_pair`]:
//!
//! | Mode            | `a`        | `b`               | Notes |
//! |-----------------|------------|-------------------|-------|
//! | Shared nonce    | `1`        | `0`               | same `k` (same `r`) reused |
//! | Reuse-R         | `1`        | `0`               | same `r`, grouped by `r` (incl. cross-key detection) |
//! | Delta bias      | `1`        | `Δ` (known)       | `k2 = k1 + Δ` |
//! | Bitflip (fault) | `1`        | `±2^i` (swept)    | one nonce bit flipped between two signings |
//! | GCD             | swept `a`  | swept `b`         | unknown small affine relation, verified against pubkey |
//!
//! Because the coefficient sweeps (Bitflip, GCD) produce many candidate keys,
//! those modes rely on verification against the known public key (or, failing
//! that, a probabilistic `r`-check across several signatures).

use super::*;
use crate::signature::{group_by_pubkey_ordered, group_by_r_and_pubkey};
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;
use num_bigint::BigUint;
use num_traits::Num;

/// secp256k1 group order `n`.
fn curve_order() -> BigUint {
    BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

/// Reduce a (possibly negative) integer modulo `n` into a [`Scalar`].
fn bigint_to_scalar_mod_n(value: &num_bigint::BigInt, n: &BigUint) -> Option<Scalar> {
    use num_bigint::BigInt;
    use num_traits::Signed;
    let n_signed = BigInt::from(n.clone());
    let mut reduced = value % &n_signed;
    if reduced.is_negative() {
        reduced += &n_signed;
    }
    let magnitude = reduced.to_biguint()?;
    biguint_to_scalar(&magnitude, n)
}

/// Reduce an unsigned integer modulo `n` into a [`Scalar`].
fn biguint_to_scalar(value: &BigUint, n: &BigUint) -> Option<Scalar> {
    let reduced = value % n;
    let bytes = reduced.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut padded = [0u8; 32];
    let offset = 32 - bytes.len();
    padded[offset..].copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(padded.into()))
}

/// Parse a decimal string that may carry a leading `-` into a `Scalar` (mod n).
pub fn parse_signed_delta(s: &str) -> anyhow::Result<Scalar> {
    use num_bigint::BigInt;
    let value = BigInt::from_str_radix(s.trim(), 10)
        .map_err(|e| anyhow::anyhow!("invalid delta '{}': {}", s, e))?;
    bigint_to_scalar_mod_n(&value, &curve_order())
        .ok_or_else(|| anyhow::anyhow!("delta out of range"))
}

/// Solve for the private key `d` from two signatures whose nonces satisfy
/// `k2 = a*k1 + b (mod n)`. Returns `None` when the denominator vanishes.
///
/// `d = (a*s2*z1 - s1*z2 + b*s1*s2) / (s1*r2 - a*s2*r1)`
pub fn solve_affine_pair(
    sig1: &Signature,
    sig2: &Signature,
    a: &Scalar,
    b: &Scalar,
) -> Option<Scalar> {
    let denom = sig1.s * sig2.r - *a * sig2.s * sig1.r;
    if bool::from(denom.is_zero()) {
        return None;
    }
    let denom_inv = Option::<Scalar>::from(denom.invert())?;
    let num = *a * sig2.s * sig1.z - sig1.s * sig2.z + *b * sig1.s * sig2.s;
    Some(num * denom_inv)
}

/// Verified pairwise recovery under `k2 = a*k1 + b`: tries both `s`-polarities
/// (BIP62 low-s/high-s) and returns the first candidate that passes
/// verification (pubkey match, or r-check when no pubkey is known). Used by the
/// coefficient-sweep attacks (bitflip, gcd) where verification is mandatory.
fn try_pair_affine_verified(
    sig1: &Signature,
    sig2: &Signature,
    a: &Scalar,
    b: &Scalar,
    pubkey: &Option<String>,
    verify_sigs: &[Signature],
) -> Option<Scalar> {
    for &s1 in &[sig1.s, -sig1.s] {
        for &s2 in &[sig2.s, -sig2.s] {
            let sa = Signature { s: s1, ..sig1.clone() };
            let sb = Signature { s: s2, ..sig2.clone() };
            if let Some(d) = solve_affine_pair(&sa, &sb, a, b) {
                if !bool::from(d.is_zero()) && verify_candidate_key(&d, pubkey, verify_sigs) {
                    return Some(d);
                }
            }
        }
    }
    None
}


/// Deterministic pairwise recovery for attacks with a *known* relation
/// (shared-nonce, reuse-r, delta-bias). When a public key is known, the result
/// is verified (and the correct `s`-polarity / `b` sign is chosen); when it is
/// not, the algebraic solution is returned unverified — matching the behaviour
/// of [`NonceReuseAttack`], which cannot pin the polarity without a pubkey.
fn recover_pair_deterministic(
    sig1: &Signature,
    sig2: &Signature,
    a: &Scalar,
    bs: &[Scalar],
    pubkey: &Option<String>,
    verify_sigs: &[Signature],
) -> Option<Scalar> {
    if pubkey.is_some() {
        for b in bs {
            if let Some(d) = try_pair_affine_verified(sig1, sig2, a, b, pubkey, verify_sigs) {
                return Some(d);
            }
        }
        return None;
    }
    // No pubkey: return the canonical algebraic solution (original polarity).
    for b in bs {
        if let Some(d) = solve_affine_pair(sig1, sig2, a, b) {
            if !bool::from(d.is_zero()) {
                return Some(d);
            }
        }
    }
    None
}

// ===========================================================================
// Shared-nonce (a = 1, b = 0) — identical nonce, grouped by (r, pubkey)
// ===========================================================================

/// Same nonce reused across signatures from one key (identical `r`).
///
/// Semantically identical recovery to [`NonceReuseAttack`], but presented as a
/// distinct, explicitly-named mode: it groups by `(r, pubkey)` and treats a
/// repeated `r` under the same key as a shared nonce.
pub struct SharedNonceAttack;

impl Attack for SharedNonceAttack {
    fn name(&self) -> &'static str {
        "shared-nonce"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_r_and_pubkey(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= 2)
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        recover_shared_from_group(&vuln.group)
    }
}

fn recover_shared_from_group(group: &SignatureGroup) -> Option<RecoveredKey> {
    let sigs = &group.signatures;
    let one = Scalar::ONE;
    let zero = Scalar::ZERO;
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            if let Some(d) = recover_pair_deterministic(
                &sigs[i],
                &sigs[j],
                &one,
                &[zero],
                &group.pubkey,
                sigs,
            ) {
                return Some(recovered_from_scalar(d, &group.pubkey));
            }
        }
    }
    None
}

// ===========================================================================
// Reuse-R — group by r alone (detects cross-key r-reuse, recovers same-key)
// ===========================================================================

/// Detects reuse of the `r` value across signatures, grouping **by `r` only**.
///
/// This flags reuse even when public keys differ (cross-key `r` reuse, which is
/// itself a red flag), while recovery still requires the signatures to share a
/// key. Groups mixing distinct pubkeys are split per-pubkey for the recovery
/// step.
pub struct ReuseRAttack;

impl Attack for ReuseRAttack {
    fn name(&self) -> &'static str {
        "reuse-r"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        use std::collections::HashMap;
        let mut by_r: HashMap<[u8; 32], Vec<Signature>> = HashMap::new();
        for sig in signatures {
            let r_bytes: [u8; 32] = sig.r.to_bytes().into();
            by_r.entry(r_bytes).or_default().push(sig.clone());
        }
        by_r
            .into_iter()
            .filter(|(_, sigs)| sigs.len() >= 2)
            .map(|(r_bytes, signatures)| {
                let r = Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).unwrap();
                // Confidence 1.0 if every signature shares one pubkey, else 0.6
                // (cross-key reuse — detectable but not directly key-recoverable).
                let distinct: std::collections::HashSet<_> =
                    signatures.iter().map(|s| s.pubkey.clone()).collect();
                let pubkey = if distinct.len() == 1 {
                    signatures[0].pubkey.clone()
                } else {
                    None
                };
                let confidence = if distinct.len() == 1 && pubkey.is_some() {
                    1.0
                } else {
                    0.6
                };
                Vulnerability {
                    attack_type: "reuse-r".to_string(),
                    group: SignatureGroup {
                        r,
                        pubkey,
                        signatures,
                        confidence,
                    },
                }
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        // Recover per same-pubkey sub-group within the r-group.
        use std::collections::HashMap;
        let mut by_pk: HashMap<Option<String>, Vec<Signature>> = HashMap::new();
        for sig in &vuln.group.signatures {
            by_pk.entry(sig.pubkey.clone()).or_default().push(sig.clone());
        }
        for (pubkey, sigs) in by_pk {
            if sigs.len() < 2 {
                continue;
            }
            let sub = SignatureGroup {
                r: vuln.group.r,
                pubkey,
                signatures: sigs,
                confidence: vuln.group.confidence,
            };
            if let Some(key) = recover_shared_from_group(&sub) {
                return Some(key);
            }
        }
        None
    }
}

// ===========================================================================
// Delta bias — a = 1, b = Δ known
// ===========================================================================

/// Recovers the key when two nonces differ by a **known constant** `Δ`
/// (`k2 = k1 + Δ`). Both `+Δ` and `-Δ` are tried, over every signature pair in a
/// key group. `Δ` may also be supplied per-signature via the `kp` field, in
/// which case the pairwise difference `kp_j - kp_i` is used.
pub struct DeltaBiasAttack {
    /// Global delta (mod n). Ignored for pairs where both signatures carry `kp`.
    pub delta: Scalar,
}

impl DeltaBiasAttack {
    pub fn new(delta: Scalar) -> Self {
        Self { delta }
    }
}

impl Attack for DeltaBiasAttack {
    fn name(&self) -> &'static str {
        "delta-bias"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_pubkey_ordered(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= 2)
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        let one = Scalar::ONE;
        for i in 0..sigs.len() {
            for j in (i + 1)..sigs.len() {
                // Prefer per-signature kp difference if both are present.
                let deltas: Vec<Scalar> = match (&sigs[i].kp, &sigs[j].kp) {
                    (Some(ki), Some(kj)) => {
                        let n = curve_order();
                        let di = biguint_to_scalar(ki, &n);
                        let dj = biguint_to_scalar(kj, &n);
                        match (di, dj) {
                            (Some(a), Some(b)) => vec![b - a, a - b],
                            _ => vec![self.delta, -self.delta],
                        }
                    }
                    _ => vec![self.delta, -self.delta],
                };
                if let Some(d) = recover_pair_deterministic(
                    &sigs[i],
                    &sigs[j],
                    &one,
                    &deltas,
                    &vuln.group.pubkey,
                    sigs,
                ) {
                    return Some(recovered_from_scalar(d, &vuln.group.pubkey));
                }
            }
        }
        None
    }
}

// ===========================================================================
// Bitflip (fault attack) — a = 1, b = ±2^i swept
// ===========================================================================

/// Single-bit fault attack: a glitch flips one bit of the nonce between two
/// signings, so the two nonces differ by `±2^i`. Sweeps `i` over
/// `0..max_bits` (default 256) and both signs, verifying each candidate against
/// the public key.
pub struct BitflipAttack {
    pub max_bits: usize,
}

impl BitflipAttack {
    pub fn new(max_bits: usize) -> Self {
        Self {
            max_bits: max_bits.clamp(1, 256),
        }
    }
}

impl Default for BitflipAttack {
    fn default() -> Self {
        Self::new(256)
    }
}

impl Attack for BitflipAttack {
    fn name(&self) -> &'static str {
        "bitflip"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_pubkey_ordered(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= 2)
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        let one = Scalar::ONE;
        let n = curve_order();
        // Precompute the 2^i deltas.
        let deltas: Vec<Scalar> = (0..self.max_bits)
            .filter_map(|i| biguint_to_scalar(&(BigUint::from(1u8) << i), &n))
            .collect();
        for i in 0..sigs.len() {
            for j in (i + 1)..sigs.len() {
                for pow in &deltas {
                    for b in [*pow, -*pow] {
                        if let Some(d) = try_pair_affine_verified(
                            &sigs[i],
                            &sigs[j],
                            &one,
                            &b,
                            &vuln.group.pubkey,
                            sigs,
                        ) {
                            return Some(recovered_from_scalar(d, &vuln.group.pubkey));
                        }
                    }
                }
            }
        }
        None
    }
}

// ===========================================================================
// GCD — sweep unknown small affine coefficients (a, b)
// ===========================================================================

/// Recovers the key when the two nonces satisfy an **unknown small affine
/// relation** `k2 = a*k1 + b`, e.g. a bad linear-congruential PRNG. Sweeps
/// `a` over `1..=a_max` (and their negatives) and `b` over `-b_max..=b_max`,
/// verifying each candidate against the public key.
///
/// The resultant of the two signing polynomials — a polynomial GCD in the
/// nonce — is linear in `d` for a fixed `(a, b)`, which is exactly
/// [`solve_affine_pair`]; this mode searches the coefficient space.
pub struct GcdAttack {
    pub a_max: u64,
    pub b_max: u64,
}

impl GcdAttack {
    pub fn new(a_max: u64, b_max: u64) -> Self {
        Self {
            a_max: a_max.max(1),
            b_max,
        }
    }
}

impl Default for GcdAttack {
    fn default() -> Self {
        // Small by default: catches simple multipliers and offsets cheaply.
        Self::new(8, 256)
    }
}

impl Attack for GcdAttack {
    fn name(&self) -> &'static str {
        "gcd"
    }

    fn min_signatures(&self) -> usize {
        2
    }

    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability> {
        group_by_pubkey_ordered(signatures)
            .into_iter()
            .filter(|g| g.signatures.len() >= 2)
            .map(|group| Vulnerability {
                attack_type: self.name().to_string(),
                group,
            })
            .collect()
    }

    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey> {
        let sigs = &vuln.group.signatures;
        let n = curve_order();
        // Candidate `a` values: ±1..±a_max.
        let mut a_vals: Vec<Scalar> = Vec::new();
        for a in 1..=self.a_max {
            if let Some(sa) = biguint_to_scalar(&BigUint::from(a), &n) {
                a_vals.push(sa);
                a_vals.push(-sa);
            }
        }
        // Candidate `b` values: 0, ±1..±b_max.
        let mut b_vals: Vec<Scalar> = vec![Scalar::ZERO];
        for b in 1..=self.b_max {
            if let Some(sb) = biguint_to_scalar(&BigUint::from(b), &n) {
                b_vals.push(sb);
                b_vals.push(-sb);
            }
        }
        for i in 0..sigs.len() {
            for j in (i + 1)..sigs.len() {
                for a in &a_vals {
                    for b in &b_vals {
                        if let Some(d) =
                            try_pair_affine_verified(&sigs[i], &sigs[j], a, b, &vuln.group.pubkey, sigs)
                        {
                            return Some(recovered_from_scalar(d, &vuln.group.pubkey));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint;

    // n = secp256k1 order
    fn order() -> BigUint {
        curve_order()
    }

    fn scalar_from_dec(s: &str) -> Scalar {
        crate::math::parse_scalar_decimal_strict(s, crate::math::ScalarKind::Z).unwrap()
    }

    fn pubkey_hex(d: &Scalar) -> String {
        let p = ProjectivePoint::GENERATOR * *d;
        let affine: k256::AffinePoint = p.into();
        hex::encode(affine.to_encoded_point(true).as_bytes())
    }

    /// Craft a signature (r, s, z) for private key `d` and nonce `k`.
    /// r = x(k*G) mod n ; s = k^{-1}(z + r*d) ; z arbitrary.
    fn make_sig(d: &Scalar, k: &Scalar, z: &Scalar, pubkey: Option<String>, ts: u64) -> Signature {
        let kg = ProjectivePoint::GENERATOR * *k;
        let affine: k256::AffinePoint = kg.into();
        let point = affine.to_encoded_point(false);
        let x = point.x().unwrap();
        let x_uint = BigUint::from_bytes_be(x);
        let r = biguint_to_scalar(&x_uint, &order()).unwrap();
        let k_inv = Option::<Scalar>::from(k.invert()).unwrap();
        let s = k_inv * (*z + r * *d);
        Signature {
            r,
            s,
            z: *z,
            pubkey,
            timestamp: Some(ts),
            kp: None,
        }
    }

    #[test]
    fn test_solve_affine_matches_nonce_reuse() {
        // a=1, b=0 must reproduce the classic reuse recovery.
        let d = scalar_from_dec("1234567890123456789012345678901234567890");
        let k = scalar_from_dec("42424242424242424242424242424242");
        let z1 = scalar_from_dec("111111111111111111");
        let z2 = scalar_from_dec("222222222222222222");
        let s1 = make_sig(&d, &k, &z1, None, 1);
        let s2 = make_sig(&d, &k, &z2, None, 2);
        let got = solve_affine_pair(&s1, &s2, &Scalar::ONE, &Scalar::ZERO).unwrap();
        assert_eq!(got, d);
    }

    #[test]
    fn test_delta_bias_recovers() {
        let d = scalar_from_dec("98765432109876543210987654321098765432");
        let k1 = scalar_from_dec("55555555555555555555555555");
        let delta = scalar_from_dec("1337");
        let k2 = k1 + delta;
        let pk = pubkey_hex(&d);
        let z1 = scalar_from_dec("777");
        let z2 = scalar_from_dec("888");
        let s1 = make_sig(&d, &k1, &z1, Some(pk.clone()), 1);
        let s2 = make_sig(&d, &k2, &z2, Some(pk.clone()), 2);
        let attack = DeltaBiasAttack::new(delta);
        let vulns = attack.detect(&[s1, s2]);
        assert_eq!(vulns.len(), 1);
        let key = attack.recover(&vulns[0]).expect("delta recovery");
        assert_eq!(key.private_key, d);
    }

    #[test]
    fn test_bitflip_recovers() {
        let d = scalar_from_dec("31415926535897932384626433832795028841");
        let k1 = scalar_from_dec("60000000000000000000000000000");
        // flip bit 17 -> +2^17
        let pow = biguint_to_scalar(&(BigUint::from(1u8) << 17), &order()).unwrap();
        let k2 = k1 + pow;
        let pk = pubkey_hex(&d);
        let s1 = make_sig(&d, &k1, &scalar_from_dec("13"), Some(pk.clone()), 1);
        let s2 = make_sig(&d, &k2, &scalar_from_dec("17"), Some(pk.clone()), 2);
        let attack = BitflipAttack::new(64);
        let vulns = attack.detect(&[s1, s2]);
        let key = attack.recover(&vulns[0]).expect("bitflip recovery");
        assert_eq!(key.private_key, d);
    }

    #[test]
    fn test_gcd_recovers_small_affine() {
        let d = scalar_from_dec("27182818284590452353602874713526624977");
        let k1 = scalar_from_dec("70000000000000000000000");
        // k2 = 3*k1 + 5
        let three = Scalar::from(3u64);
        let five = Scalar::from(5u64);
        let k2 = three * k1 + five;
        let pk = pubkey_hex(&d);
        let s1 = make_sig(&d, &k1, &scalar_from_dec("101"), Some(pk.clone()), 1);
        let s2 = make_sig(&d, &k2, &scalar_from_dec("202"), Some(pk.clone()), 2);
        let attack = GcdAttack::new(8, 16);
        let vulns = attack.detect(&[s1, s2]);
        let key = attack.recover(&vulns[0]).expect("gcd recovery");
        assert_eq!(key.private_key, d);
    }

    #[test]
    fn test_shared_nonce_recovers() {
        let d = scalar_from_dec("16180339887498948482045868343656381177");
        let k = scalar_from_dec("90000000000000000001");
        let pk = pubkey_hex(&d);
        let s1 = make_sig(&d, &k, &scalar_from_dec("5"), Some(pk.clone()), 1);
        let s2 = make_sig(&d, &k, &scalar_from_dec("9"), Some(pk.clone()), 2);
        let attack = SharedNonceAttack;
        let vulns = attack.detect(&[s1, s2]);
        assert_eq!(vulns.len(), 1);
        let key = attack.recover(&vulns[0]).expect("shared recovery");
        assert_eq!(key.private_key, d);
    }

    #[test]
    fn test_reuse_r_cross_key_detection() {
        // Same r under two different keys: detected (confidence 0.6), not recovered.
        let d1 = scalar_from_dec("11111111111111111111111111");
        let d2 = scalar_from_dec("22222222222222222222222222");
        let k = scalar_from_dec("80000000000000000007");
        let pk1 = pubkey_hex(&d1);
        let pk2 = pubkey_hex(&d2);
        let s1 = make_sig(&d1, &k, &scalar_from_dec("5"), Some(pk1), 1);
        let s2 = make_sig(&d2, &k, &scalar_from_dec("9"), Some(pk2), 2);
        let attack = ReuseRAttack;
        let vulns = attack.detect(&[s1, s2]);
        assert_eq!(vulns.len(), 1);
        assert!((vulns[0].group.confidence - 0.6).abs() < 1e-9);
        assert!(attack.recover(&vulns[0]).is_none());
    }
}
