//! The two ML-DSA libraries must agree on keys and accept each other's signatures, and a hybrid signature's
//! halves must be exactly what the specification says they are.

mod common;

use common::seed;
use ed25519_dalek::Verifier as _;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use hybridsig::{signed_bytes, SecretKey, DOMAIN};
use ml_dsa::MlDsa65;

#[test]
fn both_libraries_derive_the_same_keys_and_accept_each_others_signatures() {
    for n in 0..100 {
        let xi = seed("interop key", n);
        let message = seed("interop message", n).repeat(n as usize % 7);
        let context = &seed("interop context", n)[..n as usize % 33];

        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&xi);
        let public_bytes = public.clone().into_bytes();
        let other = ml_dsa::SigningKey::<MlDsa65>::from_seed(&xi.into());
        let other_public = other.expanded_key().verifying_key();
        assert_eq!(
            other_public.encode().to_vec(),
            public_bytes.to_vec(),
            "seed {n}"
        );

        let ours = private
            .try_sign_with_seed(&seed("rnd", n), &message, context)
            .unwrap();
        let decoded = ml_dsa::Signature::<MlDsa65>::decode(&ours.into()).expect("decodes");
        assert!(
            other_public.verify_with_context(&message, context, &decoded),
            "fips204 -> ml-dsa, {n}"
        );

        let theirs = other
            .expanded_key()
            .sign_deterministic(&message, context)
            .unwrap();
        let theirs: [u8; ml_dsa_65::SIG_LEN] = theirs.encode().to_vec().try_into().unwrap();
        assert!(
            public.verify(&message, &theirs, context),
            "ml-dsa -> fips204, {n}"
        );
    }
}

#[test]
fn each_half_is_an_ordinary_signature_over_the_specified_bytes() {
    let key = SecretKey::from_seeds(&seed("ed", 1), &seed("ml", 1)).unwrap();
    let signature = key.sign(b"release", b"version 1.2.3").unwrap();
    let t = signed_bytes(key.public_key().key_id(), b"release", b"version 1.2.3").unwrap();
    let public = key.public_key().as_bytes();

    // The ML-DSA half, checked by the library this crate does not use.
    let ml_public: [u8; ml_dsa_65::PK_LEN] = public[36..].try_into().unwrap();
    let ml_signature: [u8; ml_dsa_65::SIG_LEN] = signature[68..].try_into().unwrap();
    let verifier = ml_dsa::VerifyingKey::<MlDsa65>::decode(&ml_public.into());
    let decoded = ml_dsa::Signature::<MlDsa65>::decode(&ml_signature.into()).unwrap();
    assert!(verifier.verify_with_context(&t, DOMAIN, &decoded));
    assert!(
        !verifier.verify_with_context(&t, b"", &decoded),
        "the FIPS context is part of it"
    );

    // The Ed25519 half verifies as a plain Ed25519 signature over `t`. This is the documented limit
    // (only weak non-separability), asserted so that it cannot change unnoticed.
    let ed_public: [u8; 32] = public[4..36].try_into().unwrap();
    let ed_signature: [u8; 64] = signature[4..68].try_into().unwrap();
    let plain = ed25519_dalek::VerifyingKey::from_bytes(&ed_public).unwrap();
    assert!(plain
        .verify(&t, &ed25519_dalek::Signature::from_bytes(&ed_signature))
        .is_ok());
    assert!(plain
        .verify(
            b"version 1.2.3",
            &ed25519_dalek::Signature::from_bytes(&ed_signature)
        )
        .is_err());
}
