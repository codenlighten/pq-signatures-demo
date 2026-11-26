//! Sizes and timings of the two algorithms and of the hybrid. Prints one table. Run it pinned to one CPU:
//! `taskset -c 2 cargo run --release --example timings`.

use ed25519_dalek::{Signer as _, Verifier as _};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, Signer as _, Verifier as _};
use hybridsig::{SecretKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use std::hint::black_box;
use std::time::Instant;

const ROUNDS: u32 = 2000;

/// Median, 5th and 95th percentile in microseconds.
fn time(mut work: impl FnMut(u32)) -> (f64, f64, f64) {
    for i in 0..100 {
        work(i);
    }
    let mut samples: Vec<f64> = (0..ROUNDS)
        .map(|i| {
            let start = Instant::now();
            work(i);
            start.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    samples.sort_by(f64::total_cmp);
    let at = |percent: usize| samples[samples.len() * percent / 100];
    (at(50), at(5), at(95))
}

fn row(name: &str, operation: &str, (median, low, high): (f64, f64, f64)) {
    println!("| {name} | {operation} | {median:.1} | {low:.1} to {high:.1} |");
}

fn seed(i: u32, tag: u8) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..4].copy_from_slice(&i.to_le_bytes());
    s
}

fn main() {
    let message = [7u8; 1024];
    println!(
        "Sizes in bytes: Ed25519 public key 32, signature 64; ML-DSA-65 public key {}, signature {}; \
         hybrid public key {PUBLIC_KEY_LEN}, signature {SIGNATURE_LEN}.\n",
        ml_dsa_65::PK_LEN,
        ml_dsa_65::SIG_LEN
    );
    println!("| Scheme | Operation | Median µs | 5th to 95th percentile |\n|---|---|---|---|");

    let ed = ed25519_dalek::SigningKey::from_bytes(&seed(0, 1));
    let ed_signature = ed.sign(&message);
    let made = time(|i| {
        black_box(ed25519_dalek::SigningKey::from_bytes(&seed(i, 1)).verifying_key());
    });
    row("Ed25519", "key generation", made);
    let signed = time(|_| {
        black_box(ed.sign(black_box(&message)));
    });
    row("Ed25519", "sign 1 KiB", signed);
    let checked = time(|_| {
        ed.verifying_key()
            .verify(black_box(&message), &ed_signature)
            .unwrap();
    });
    row("Ed25519", "verify", checked);

    let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed(0, 2));
    let ml_signature = private
        .try_sign_with_seed(&seed(0, 3), &message, b"x")
        .unwrap();
    let made = time(|i| {
        black_box(ml_dsa_65::KG::keygen_from_seed(&seed(i, 2)));
    });
    row("ML-DSA-65", "key generation", made);
    // A different random value each round: signing time varies with it (rejection sampling).
    let signed = time(|i| {
        black_box(private.try_sign_with_seed(&seed(i, 3), black_box(&message), b"x")).unwrap();
    });
    row("ML-DSA-65", "sign 1 KiB", signed);
    let checked = time(|_| {
        assert!(public.verify(black_box(&message), &ml_signature, b"x"));
    });
    row("ML-DSA-65", "verify", checked);

    let key = SecretKey::from_seeds(&seed(0, 1), &seed(0, 2)).unwrap();
    let signature = key.sign(b"x", &message).unwrap();
    let made = time(|i| {
        black_box(SecretKey::from_seeds(&seed(i, 1), &seed(i, 2)).unwrap());
    });
    row("hybrid", "key generation", made);
    let signed = time(|_| {
        black_box(key.sign(b"x", black_box(&message))).unwrap();
    });
    row("hybrid", "sign 1 KiB", signed);
    let checked = time(|_| {
        key.public_key()
            .verify(b"x", black_box(&message), &signature)
            .unwrap();
    });
    row("hybrid", "verify", checked);
}
