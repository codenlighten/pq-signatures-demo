//! The attack matrix: every way of altering, moving or dropping part of a hybrid signature, and the error it
//! must produce. The last tests show what the construction does **not** prevent.

mod common;

use common::seed;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::CompressedEdwardsY;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, Signer as _};
use hybridsig::{
    signed_bytes, Error, PublicKey, SecretKey, DOMAIN, MAX_CONTEXT, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};

const CONTEXT: &[u8] = b"invoice";
const MESSAGE: &[u8] = b"pay 100 to account 7";

fn key(n: u32) -> SecretKey {
    SecretKey::from_seeds(&seed("ed", n), &seed("ml", n)).unwrap()
}

fn signed() -> (SecretKey, Vec<u8>) {
    let key = key(0);
    let signature = key.sign(CONTEXT, MESSAGE).unwrap();
    (key, signature)
}

fn verify(key: &SecretKey, signature: &[u8]) -> Result<(), Error> {
    key.public_key().verify(CONTEXT, MESSAGE, signature)
}

/// A signature made of one signature's Ed25519 half and another's ML-DSA half.
fn splice(ed_from: &[u8], ml_from: &[u8]) -> Vec<u8> {
    [&ed_from[..68], &ml_from[68..]].concat()
}

#[test]
fn a_genuine_signature_verifies() {
    let (key, signature) = signed();
    assert_eq!(verify(&key, &signature), Ok(()));
}

#[test]
fn empty_and_longest_contexts_and_an_empty_message_work() {
    let key = key(0);
    for context in [&b""[..], &[b'x'; MAX_CONTEXT]] {
        let signature = key.sign(context, b"").unwrap();
        assert_eq!(key.public_key().verify(context, b"", &signature), Ok(()));
    }
}

#[test]
fn a_context_of_256_bytes_is_refused_not_truncated() {
    let (key, signature) = signed();
    let long = [b'x'; 256];
    assert_eq!(key.sign(&long, MESSAGE), Err(Error::ContextTooLong(256)));
    assert_eq!(
        key.public_key().verify(&long, MESSAGE, &signature),
        Err(Error::ContextTooLong(256))
    );
}

#[test]
fn another_message_context_or_key_fails() {
    let (key0, signature) = signed();
    let public = key0.public_key();
    assert_eq!(
        public.verify(CONTEXT, b"pay 900 to account 7", &signature),
        Err(Error::Ed25519Invalid)
    );
    assert_eq!(
        public.verify(b"receipt", MESSAGE, &signature),
        Err(Error::Ed25519Invalid)
    );
    assert_eq!(
        public.verify(b"", MESSAGE, &signature),
        Err(Error::Ed25519Invalid)
    );
    assert_eq!(verify(&key(1), &signature), Err(Error::Ed25519Invalid));
}

#[test]
fn the_boundary_between_context_and_message_cannot_be_moved() {
    let key = key(0);
    let signature = key.sign(b"ab", b"cd").unwrap();
    for (context, message) in [(&b"a"[..], &b"bcd"[..]), (b"abc", b"d"), (b"", b"abcd")] {
        assert!(key
            .public_key()
            .verify(context, message, &signature)
            .is_err());
    }
}

#[test]
fn neither_half_can_be_dropped() {
    let (key, signature) = signed();
    for stripped in [&signature[..68], &signature[68..], &signature[..4]] {
        assert!(matches!(verify(&key, stripped), Err(Error::Length { .. })));
    }
    let mut no_ml = signature.clone();
    no_ml[68..].fill(0);
    assert_eq!(verify(&key, &no_ml), Err(Error::MlDsaInvalid));
    let mut no_ed = signature.clone();
    no_ed[4..68].fill(0);
    assert!(verify(&key, &no_ed).is_err());
}

#[test]
fn a_half_from_another_signature_of_the_same_key_fails() {
    let (key, signature) = signed();
    let other = key.sign(CONTEXT, b"a different message").unwrap();
    assert_eq!(
        verify(&key, &splice(&other, &signature)),
        Err(Error::Ed25519Invalid)
    );
    // The case that needs both checks: a good Ed25519 half with a stale ML-DSA half.
    assert_eq!(
        verify(&key, &splice(&signature, &other)),
        Err(Error::MlDsaInvalid)
    );
}

/// Two hybrid keys that share their ML-DSA key. A signature half made under one is useless under the other,
/// because the key id is inside what is signed.
#[test]
fn a_half_cannot_move_to_another_key_that_shares_it() {
    let shared = seed("ml", 0);
    let first = SecretKey::from_seeds(&seed("ed", 0), &shared).unwrap();
    let second = SecretKey::from_seeds(&seed("ed", 1), &shared).unwrap();
    let from_first = first.sign(CONTEXT, MESSAGE).unwrap();
    let from_second = second.sign(CONTEXT, MESSAGE).unwrap();
    // The holder of the second Ed25519 key reuses the first signer's ML-DSA half.
    let forged = splice(&from_second, &from_first);
    assert_eq!(verify(&second, &forged), Err(Error::MlDsaInvalid));
}

#[test]
fn wrong_lengths_and_magic_are_refused() {
    let (key, signature) = signed();
    let longer = [&signature[..], &[0]].concat();
    for bad in [&longer[..], &signature[..SIGNATURE_LEN - 1], &[]] {
        assert!(matches!(verify(&key, bad), Err(Error::Length { .. })));
    }
    let mut magic = signature.clone();
    magic[3] = b'2';
    assert_eq!(verify(&key, &magic), Err(Error::Magic("signature")));
    let public = key.public_key().as_bytes();
    let longer = [&public[..], &[0]].concat();
    for bad in [&longer[..], &public[..PUBLIC_KEY_LEN - 1], &[]] {
        assert!(matches!(
            PublicKey::from_bytes(bad),
            Err(Error::Length { .. })
        ));
    }
    let mut magic = *public;
    magic[0] = b'X';
    assert_eq!(
        PublicKey::from_bytes(&magic).err(),
        Some(Error::Magic("public key"))
    );
}

#[test]
fn changing_any_byte_of_a_signature_is_detected() {
    let (key, signature) = signed();
    for at in 0..SIGNATURE_LEN {
        let mut changed = signature.clone();
        changed[at] ^= 1 << (at % 8);
        assert!(
            verify(&key, &changed).is_err(),
            "byte {at} changed unnoticed"
        );
    }
}

#[test]
fn changing_any_byte_of_a_public_key_is_detected() {
    let (key, signature) = signed();
    for at in 0..PUBLIC_KEY_LEN {
        let mut changed = *key.public_key().as_bytes();
        changed[at] ^= 1 << (at % 8);
        // Refused outright, or loaded as a different key under which nothing verifies.
        if let Ok(public) = PublicKey::from_bytes(&changed) {
            assert!(
                public.verify(CONTEXT, MESSAGE, &signature).is_err(),
                "byte {at}"
            );
        }
    }
}

#[test]
fn a_second_form_of_the_ed25519_scalar_is_refused() {
    // S and S + L satisfy the same equation; only S below the group order L is accepted.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let (key, mut signature) = signed();
    let mut carry = 0u16;
    for (byte, add) in signature[36..68].iter_mut().zip(L) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        *byte = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(verify(&key, &signature), Err(Error::Ed25519Invalid));
}

#[test]
fn bad_points_are_refused_in_the_public_key_and_in_the_signature() {
    let (key, signature) = signed();
    let public = *key.public_key().as_bytes();
    let own = CompressedEdwardsY(public[4..36].try_into().unwrap())
        .decompress()
        .unwrap();
    let r = CompressedEdwardsY(signature[4..36].try_into().unwrap())
        .decompress()
        .unwrap();

    for point in [EIGHT_TORSION[0], EIGHT_TORSION[1], own + EIGHT_TORSION[1]] {
        let mut bad = public;
        bad[4..36].copy_from_slice(point.compress().as_bytes());
        assert_eq!(
            PublicKey::from_bytes(&bad).err(),
            Some(Error::Ed25519Point("public key"))
        );
    }
    for point in [EIGHT_TORSION[0], r + EIGHT_TORSION[1]] {
        let mut bad = signature.clone();
        bad[4..36].copy_from_slice(point.compress().as_bytes());
        assert_eq!(
            verify(&key, &bad),
            Err(Error::Ed25519Point("signature point R"))
        );
    }
}

#[test]
fn secret_key_encodings_are_checked() {
    let bytes = key(0).to_bytes();
    assert!(matches!(
        SecretKey::from_bytes(&bytes[..67]),
        Err(Error::Length { .. })
    ));
    let mut magic = bytes.to_vec();
    magic[0] = b'X';
    assert!(matches!(
        SecretKey::from_bytes(&magic),
        Err(Error::Magic("secret key"))
    ));
}

// --- what the construction does not prevent ---

/// Strong unforgeability is not promised: whoever holds **one** component key can produce a second valid
/// signature for an already signed message. Here only the ML-DSA seed is used to replace that half.
#[test]
fn one_component_key_is_enough_to_make_a_second_signature_of_a_signed_message() {
    let (key, original) = signed();
    let (_, ml_only) = ml_dsa_65::KG::keygen_from_seed(&seed("ml", 0));
    let t = signed_bytes(key.public_key().key_id(), CONTEXT, MESSAGE).unwrap();
    let new_half = ml_only.try_sign_with_seed(&[42; 32], &t, DOMAIN).unwrap();
    let altered = [&original[..68], &new_half[..]].concat();
    assert_ne!(altered, original);
    assert_eq!(verify(&key, &altered), Ok(()));
    // That one key is not enough to sign a message the whole key never signed.
    let t = signed_bytes(key.public_key().key_id(), CONTEXT, b"something new").unwrap();
    let new_half = ml_only.try_sign_with_seed(&[42; 32], &t, DOMAIN).unwrap();
    let forged = [&original[..68], &new_half[..]].concat();
    assert_eq!(
        key.public_key().verify(CONTEXT, b"something new", &forged),
        Err(Error::Ed25519Invalid)
    );
}

/// Binding does not authenticate keys: someone who can swap the verifier's trusted key signs as they like.
#[test]
fn an_attackers_own_key_verifies_the_attackers_signatures() {
    let attacker = key(9);
    let signature = attacker.sign(CONTEXT, MESSAGE).unwrap();
    assert_eq!(verify(&attacker, &signature), Ok(()));
}
