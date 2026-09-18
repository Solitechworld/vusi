//! Attack detection and exploitation traits

use crate::signature::{Signature, SignatureGroup};
use k256::Scalar;

pub mod nonce_reuse;
pub use nonce_reuse::NonceReuseAttack;

#[cfg(feature = "biased-nonce")]
pub mod biased_nonce;
#[cfg(feature = "biased-nonce")]
pub use biased_nonce::{BiasedNonceAttack, NonceBiasAttack};

#[cfg(feature = "polynonce")]
pub mod polynonce;
#[cfg(feature = "polynonce")]
pub use polynonce::PolynonceAttack;

// Related-nonce attacks (affine relation k2 = a*k1 + b). Zero extra deps, always on.
pub mod related_nonce;
pub use related_nonce::{
    BitflipAttack, DeltaBiasAttack, GcdAttack, ReuseRAttack, SharedNonceAttack,
};

pub trait Attack: Send + Sync {
    fn name(&self) -> &'static str;
    fn min_signatures(&self) -> usize;
    fn detect(&self, signatures: &[Signature]) -> Vec<Vulnerability>;
    fn recover(&self, vuln: &Vulnerability) -> Option<RecoveredKey>;
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub attack_type: String,
    pub group: SignatureGroup,
}

#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub private_key: Scalar,
    pub private_key_decimal: String,
    pub private_key_hex: String,
    pub pubkey: Option<String>,
}

// --- Shared verification helpers used by related-nonce attacks ---

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};

/// Returns true if `d * G` matches the given (compressed or uncompressed) pubkey hex.
pub(crate) fn key_matches_pubkey(d: &Scalar, pubkey: &str) -> bool {
    if bool::from(d.is_zero()) {
        return false;
    }
    let computed = ProjectivePoint::GENERATOR * *d;
    let affine: AffinePoint = computed.into();
    let compressed = hex::encode(affine.to_encoded_point(true).as_bytes());
    let uncompressed = hex::encode(affine.to_encoded_point(false).as_bytes());
    let pk = pubkey.to_lowercase();
    pk == compressed || pk == uncompressed
}

/// Probabilistic check when no pubkey is known: verify that `d` reproduces the
/// signature's `r` via `k = (z + r*d)/s`, `r == x(k*G) mod n`.
pub(crate) fn key_matches_sig(d: &Scalar, sig: &Signature) -> bool {
    use num_bigint::BigUint;
    use num_traits::Num;
    if bool::from(d.is_zero()) {
        return false;
    }
    let s_inv = match Option::<Scalar>::from(sig.s.invert()) {
        Some(v) => v,
        None => return false,
    };
    let k = (sig.z + sig.r * *d) * s_inv;
    if bool::from(k.is_zero()) {
        return false;
    }
    let kg = ProjectivePoint::GENERATOR * k;
    let kg_affine: AffinePoint = kg.into();
    let point = kg_affine.to_encoded_point(false);
    let x_bytes = match point.x() {
        Some(x) => x,
        None => return false,
    };
    let n = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();
    let x_uint = BigUint::from_bytes_be(x_bytes);
    let r_uint = &x_uint % &n;
    let sig_r_uint = BigUint::from_bytes_be(&sig.r.to_bytes());
    r_uint == sig_r_uint
}

/// Verify a candidate key against a group: prefer the definitive pubkey check,
/// fall back to the probabilistic r-check across up to 3 signatures.
pub(crate) fn verify_candidate_key(
    d: &Scalar,
    pubkey: &Option<String>,
    sigs: &[Signature],
) -> bool {
    if let Some(pk) = pubkey {
        return key_matches_pubkey(d, pk);
    }
    sigs.iter().take(3).all(|s| key_matches_sig(d, s))
}

/// Build a [`RecoveredKey`] from a scalar and pubkey.
pub(crate) fn recovered_from_scalar(d: Scalar, pubkey: &Option<String>) -> RecoveredKey {
    use crate::math::{scalar_to_decimal_string, scalar_to_hex_string};
    RecoveredKey {
        private_key: d,
        private_key_decimal: scalar_to_decimal_string(&d),
        private_key_hex: scalar_to_hex_string(&d),
        pubkey: pubkey.clone(),
    }
}
