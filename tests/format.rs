//! Pins the formats of `SPEC.md`, rebuilt here without the library's own encoding code.

use hybridsig::{
    signed_bytes, PublicKey, SecretKey, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LEN,
};
use sha2::{Digest as _, Sha256};

#[test]
fn sizes_are_as_specified() {
    assert_eq!(
        (PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LEN),
        (1988, 68, 3377)
    );
}

#[test]
fn signed_bytes_layout() {
    let mut want = b"hybrid-sig-v1\0".to_vec();
    want.extend_from_slice(&[7; 32]);
    want.push(3);
    want.extend_from_slice(b"ctxmessage");
    assert_eq!(signed_bytes(&[7; 32], b"ctx", b"message").unwrap(), want);
}

#[test]
fn keys_encode_as_specified_and_stay_the_same_across_releases() {
    let key = SecretKey::from_seeds(&[1; 32], &[2; 32]).unwrap();
    let mut secret = b"HSK1".to_vec();
    secret.extend_from_slice(&[1; 32]);
    secret.extend_from_slice(&[2; 32]);
    assert_eq!(*key.to_bytes(), secret);

    let public = key.public_key().as_bytes();
    assert_eq!(&public[..4], b"HSP1");
    assert_eq!(key.public_key().key_id()[..], Sha256::digest(public)[..]);
    // A pinned value: a library upgrade that changed key derivation would show here.
    assert_eq!(
        hex::encode(key.public_key().key_id()),
        "6c7feee22143ab06efba383f548acd6d2a6af8741b3fe5f819c352ca091a5955"
    );
    let again = PublicKey::from_bytes(public).unwrap();
    assert_eq!(again.key_id(), key.public_key().key_id());
    let reloaded = SecretKey::from_bytes(&secret).unwrap();
    assert_eq!(reloaded.public_key().as_bytes(), public);
}

#[test]
fn a_signature_starts_with_its_magic_and_the_ed25519_half_is_repeatable() {
    let key = SecretKey::from_seeds(&[1; 32], &[2; 32]).unwrap();
    let (a, b) = (key.sign(b"c", b"m").unwrap(), key.sign(b"c", b"m").unwrap());
    assert_eq!(&a[..4], b"HSS1");
    assert_eq!(a.len(), SIGNATURE_LEN);
    assert_eq!(a[4..68], b[4..68], "Ed25519 is deterministic");
    assert_ne!(
        a[68..],
        b[68..],
        "ML-DSA signing is hedged: fresh randomness each time"
    );
}
