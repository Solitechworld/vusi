//! Generate REAL secp256k1 signature fixtures (r = x(k*G) mod n) for the
//! related-nonce attacks, so the CLI can be exercised end-to-end.
//!
//! Usage: cargo run --example gen_fixtures -- <scenario>
//!   scenarios: delta | bitflip | gcd | reuse

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use num_bigint::BigUint;
use num_traits::Num;

fn n() -> BigUint {
    BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

fn dec(s: &str) -> Scalar {
    let b = BigUint::from_str_radix(s, 10).unwrap() % n();
    let bytes = b.to_bytes_be();
    let mut p = [0u8; 32];
    p[32 - bytes.len()..].copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(p.into())).unwrap()
}

fn to_dec(x: &Scalar) -> String {
    BigUint::from_bytes_be(&x.to_bytes()).to_string()
}

fn pubkey(d: &Scalar) -> String {
    let p = ProjectivePoint::GENERATOR * *d;
    let a: AffinePoint = p.into();
    hex::encode(a.to_encoded_point(true).as_bytes())
}

/// Real signature: r = x(k*G) mod n, s = k^{-1}(z + r*d).
fn sig(d: &Scalar, k: &Scalar, z: &Scalar) -> (Scalar, Scalar) {
    let kg = ProjectivePoint::GENERATOR * *k;
    let a: AffinePoint = kg.into();
    let pt = a.to_encoded_point(false);
    let x = BigUint::from_bytes_be(pt.x().unwrap()) % n();
    let xb = x.to_bytes_be();
    let mut pb = [0u8; 32];
    pb[32 - xb.len()..].copy_from_slice(&xb);
    let r = Option::<Scalar>::from(Scalar::from_repr(pb.into())).unwrap();
    let k_inv = Option::<Scalar>::from(k.invert()).unwrap();
    let s = k_inv * (*z + r * *d);
    (r, s)
}

fn emit(d: &Scalar, pairs: &[(Scalar, Scalar)], zs: &[Scalar]) {
    let pk = pubkey(d);
    println!("[");
    for (i, ((r, s), z)) in pairs.iter().zip(zs).enumerate() {
        let comma = if i + 1 < pairs.len() { "," } else { "" };
        println!(
            "  {{\"r\":\"{}\",\"s\":\"{}\",\"z\":\"{}\",\"pubkey\":\"{}\",\"timestamp\":{}}}{}",
            to_dec(r),
            to_dec(s),
            to_dec(z),
            pk,
            i + 1,
            comma
        );
    }
    println!("]");
}

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_else(|| "delta".into());
    let d = dec("94729509529029384756019283746501928374650192837465019283746501928374");
    let k1 = dec("55555555555555555555555555555555555555555555");
    let z1 = dec("111111111111111111111111");
    let z2 = dec("222222222222222222222222");
    match scenario.as_str() {
        "delta" => {
            let delta = dec("1337");
            let k2 = k1 + delta;
            emit(&d, &[sig(&d, &k1, &z1), sig(&d, &k2, &z2)], &[z1, z2]);
        }
        "bitflip" => {
            let pow = dec("131072"); // 2^17
            let k2 = k1 + pow;
            emit(&d, &[sig(&d, &k1, &z1), sig(&d, &k2, &z2)], &[z1, z2]);
        }
        "gcd" => {
            // k2 = 3*k1 + 5
            let k2 = Scalar::from(3u64) * k1 + Scalar::from(5u64);
            emit(&d, &[sig(&d, &k1, &z1), sig(&d, &k2, &z2)], &[z1, z2]);
        }
        "reuse" => {
            emit(&d, &[sig(&d, &k1, &z1), sig(&d, &k1, &z2)], &[z1, z2]);
        }
        other => {
            eprintln!("unknown scenario: {other}");
            std::process::exit(2);
        }
    }
}
