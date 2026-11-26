//! NIST's ACVP vectors for ML-DSA-65 (see `third_party/nist-acvp/NOTICE.md`), run against **both** libraries: `fips204`,
//! which this crate uses, and RustCrypto's `ml-dsa`, which is here only as an independent second opinion.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use ml_dsa::MlDsa65;
use serde_json::Value;

fn cases(mode: &str, expected: usize) -> Vec<Value> {
    let all: Value =
        serde_json::from_str(include_str!("../third_party/nist-acvp/mldsa65.json")).unwrap();
    let cases = all[mode].as_array().unwrap().clone();
    // Exact counts: a filter that silently kept nothing must not look like a pass.
    assert_eq!(cases.len(), expected, "{mode}");
    cases
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap_or_else(|| panic!("no {field}"))).unwrap()
}

fn array<const N: usize>(case: &Value, field: &str) -> [u8; N] {
    bytes(case, field).try_into().expect(field)
}

/// FIPS 204's message framing for the external, pure interface: `0 ‖ len(ctx) ‖ ctx ‖ message`.
fn framed(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = vec![0, u8::try_from(context.len()).unwrap()];
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    out
}

#[test]
fn key_generation_matches_nist_in_both_libraries() {
    for case in cases("keyGen", 25) {
        let seed: [u8; 32] = array(&case, "seed");
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(
            public.into_bytes().to_vec(),
            bytes(&case, "pk"),
            "tc {}",
            case["tcId"]
        );
        assert_eq!(
            private.into_bytes().to_vec(),
            bytes(&case, "sk"),
            "tc {}",
            case["tcId"]
        );

        let other = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed.into());
        let key = other.expanded_key().verifying_key();
        assert_eq!(
            key.encode().to_vec(),
            bytes(&case, "pk"),
            "second library, tc {}",
            case["tcId"]
        );
    }
}

#[test]
#[allow(deprecated)] // the vectors give expanded secret keys, which the second library calls a legacy format
fn signing_matches_nist_byte_for_byte_in_both_libraries() {
    let (mut deterministic, mut hedged) = (0, 0);
    for case in cases("sigGen", 30) {
        let rnd: [u8; 32] = if case["deterministic"].as_bool().unwrap() {
            deterministic += 1;
            [0; 32]
        } else {
            hedged += 1;
            array(&case, "rnd")
        };
        let (message, context) = (bytes(&case, "message"), bytes(&case, "context"));
        let private = ml_dsa_65::PrivateKey::try_from_bytes(array(&case, "sk")).unwrap();
        let signature = private
            .try_sign_with_seed(&rnd, &message, &context)
            .unwrap();
        assert_eq!(
            signature.to_vec(),
            bytes(&case, "signature"),
            "tc {}",
            case["tcId"]
        );

        let expanded: [u8; ml_dsa_65::SK_LEN] = array(&case, "sk");
        let other = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(&expanded.into());
        let signature = other.sign_internal(&[&framed(&context, &message)], &rnd.into());
        assert_eq!(
            signature.encode().to_vec(),
            bytes(&case, "signature"),
            "second library, tc {}",
            case["tcId"]
        );
    }
    assert_eq!((deterministic, hedged), (15, 15));
}

#[test]
fn verification_gives_nists_verdict_in_both_libraries() {
    let mut accepted = 0;
    let all = cases("sigVer", 15);
    for case in &all {
        let want = case["testPassed"].as_bool().unwrap();
        accepted += usize::from(want);
        let (message, context) = (bytes(case, "message"), bytes(case, "context"));
        let public = ml_dsa_65::PublicKey::try_from_bytes(array(case, "pk")).unwrap();
        let signature: [u8; ml_dsa_65::SIG_LEN] = array(case, "signature");
        assert_eq!(
            public.verify(&message, &signature, &context),
            want,
            "tc {}",
            case["tcId"]
        );

        let encoded: [u8; ml_dsa_65::PK_LEN] = array(case, "pk");
        let other = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded.into());
        let got = ml_dsa::Signature::<MlDsa65>::decode(&signature.into())
            .is_some_and(|s| other.verify_with_context(&message, &context, &s));
        assert_eq!(got, want, "second library, tc {}", case["tcId"]);
    }
    assert!(
        accepted > 0 && accepted < all.len(),
        "the vectors must include both verdicts"
    );
}
