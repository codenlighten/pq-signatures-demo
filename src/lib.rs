//! A demonstration hybrid signature: Ed25519 and ML-DSA-65 over the same bytes, and both must verify.
//!
//! The format and its claims are specified in `SPEC.md`. No cryptographic primitive is implemented here; the
//! work of this crate is composing two third-party libraries so that a verifier refuses a signature with a
//! half missing, or with a half that is not valid for the selected key, context and message. It has not been
//! audited.

#![forbid(unsafe_code)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::Signer as _;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use sha2::{Digest as _, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Starts every signed message, and is the FIPS 204 context string.
pub const DOMAIN: &[u8] = b"hybrid-sig-v1";
const PUBLIC_MAGIC: &[u8; 4] = b"HSP1";
const SECRET_MAGIC: &[u8; 4] = b"HSK1";
const SIGNATURE_MAGIC: &[u8; 4] = b"HSS1";
const ED_PUBLIC: usize = 32;
const ED_SIGNATURE: usize = 64;

/// `"HSP1" ‖ Ed25519 public key ‖ ML-DSA-65 public key`
pub const PUBLIC_KEY_LEN: usize = 4 + ED_PUBLIC + ml_dsa_65::PK_LEN;
/// `"HSK1" ‖ Ed25519 seed ‖ ML-DSA-65 seed`
pub const SECRET_KEY_LEN: usize = 4 + 32 + 32;
/// `"HSS1" ‖ Ed25519 signature ‖ ML-DSA-65 signature`
pub const SIGNATURE_LEN: usize = 4 + ED_SIGNATURE + ml_dsa_65::SIG_LEN;
/// The longest application context, in bytes: its length is signed as one byte.
pub const MAX_CONTEXT: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key or signature does not have its exact length.
    Length {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// A key or signature does not start with its magic bytes.
    Magic(&'static str),
    /// An Ed25519 point (the public key or `R`) is outside the accepted set.
    Ed25519Point(&'static str),
    /// The ML-DSA-65 public key does not decode.
    MlDsaKey,
    ContextTooLong(usize),
    /// The operating system's random generator failed. Nothing was signed or generated.
    Randomness,
    Signing,
    /// The Ed25519 half does not verify.
    Ed25519Invalid,
    /// The ML-DSA-65 half does not verify.
    MlDsaInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Length {
                what,
                expected,
                got,
            } => write!(f, "the {what} must be {expected} bytes, not {got}"),
            Error::Magic(what) => write!(f, "this is not a hybrid-sig v1 {what}"),
            Error::Ed25519Point(what) => write!(f, "the Ed25519 {what} is not an accepted point"),
            Error::MlDsaKey => f.write_str("the ML-DSA-65 public key does not decode"),
            Error::ContextTooLong(n) => {
                write!(f, "the context is {n} bytes; the limit is {MAX_CONTEXT}")
            }
            Error::Randomness => f.write_str("the random generator failed"),
            Error::Signing => f.write_str("signing failed"),
            Error::Ed25519Invalid => f.write_str("the Ed25519 signature does not verify"),
            Error::MlDsaInvalid => f.write_str("the ML-DSA-65 signature does not verify"),
        }
    }
}

impl std::error::Error for Error {}

fn exact<'a>(
    bytes: &'a [u8],
    len: usize,
    magic: &[u8; 4],
    what: &'static str,
) -> Result<&'a [u8], Error> {
    if bytes.len() != len {
        return Err(Error::Length {
            what,
            expected: len,
            got: bytes.len(),
        });
    }
    bytes
        .strip_prefix(magic.as_slice())
        .ok_or(Error::Magic(what))
}

/// The accepted Ed25519 points: canonically encoded, in the prime-order subgroup, not the identity.
/// The library's strict verification rejects small-order points; this also rejects points that merely have a
/// small-order component, and second encodings of the same point.
fn check_point(bytes: &[u8; 32], what: &'static str) -> Result<(), Error> {
    let refused = Error::Ed25519Point(what);
    let point = CompressedEdwardsY(*bytes).decompress().ok_or(refused)?;
    if point.compress().to_bytes() != *bytes || point.is_identity() || !point.is_torsion_free() {
        return Err(refused);
    }
    Ok(())
}

/// The bytes both algorithms sign:
/// `DOMAIN ‖ 0x00 ‖ key id ‖ context length (1 byte) ‖ context ‖ message`.
pub fn signed_bytes(key_id: &[u8; 32], context: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u8::try_from(context.len()).map_err(|_| Error::ContextTooLong(context.len()))?;
    let mut t = Vec::with_capacity(DOMAIN.len() + 34 + context.len() + message.len());
    t.extend_from_slice(DOMAIN);
    t.push(0);
    t.extend_from_slice(key_id);
    t.push(length);
    t.extend_from_slice(context);
    t.extend_from_slice(message);
    Ok(t)
}

/// A verifying key. Verify only against a key you already trust; a key sent along with a signature proves
/// nothing.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
    key_id: [u8; 32],
    ed: ed25519_dalek::VerifyingKey,
    ml: ml_dsa_65::PublicKey,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let body = exact(bytes, PUBLIC_KEY_LEN, PUBLIC_MAGIC, "public key")?;
        let (ed, ml) = body.split_at(ED_PUBLIC);
        let ed: [u8; ED_PUBLIC] = ed.try_into().expect("length checked above");
        check_point(&ed, "public key")?;
        let ml: [u8; ml_dsa_65::PK_LEN] = ml.try_into().expect("length checked above");
        Ok(Self {
            bytes: bytes.try_into().expect("length checked above"),
            key_id: Sha256::digest(bytes).into(),
            ed: ed25519_dalek::VerifyingKey::from_bytes(&ed)
                .map_err(|_| Error::Ed25519Point("public key"))?,
            ml: ml_dsa_65::PublicKey::try_from_bytes(ml).map_err(|_| Error::MlDsaKey)?,
        })
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// SHA-256 of the encoded public key.
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Succeeds only if **both** signatures verify, for this key, this context and this message.
    pub fn verify(&self, context: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let body = exact(signature, SIGNATURE_LEN, SIGNATURE_MAGIC, "signature")?;
        let (ed, ml) = body.split_at(ED_SIGNATURE);
        let ed: [u8; ED_SIGNATURE] = ed.try_into().expect("length checked above");
        let r: [u8; 32] = ed[..32].try_into().expect("a signature starts with R");
        check_point(&r, "signature point R")?;
        let ml: [u8; ml_dsa_65::SIG_LEN] = ml.try_into().expect("length checked above");
        let t = signed_bytes(&self.key_id, context, message)?;
        // `verify_strict` also refuses an `S` that is not below the group order.
        self.ed
            .verify_strict(&t, &ed25519_dalek::Signature::from_bytes(&ed))
            .map_err(|_| Error::Ed25519Invalid)?;
        if !self.ml.verify(&t, &ml, DOMAIN) {
            return Err(Error::MlDsaInvalid);
        }
        Ok(())
    }
}

/// A signing key. When it is dropped, its two stored seeds and the two library key objects are wiped (a test
/// checks that these types promise it). Temporary copies on the stack or inside the libraries, and the
/// caller's own buffers, such as the bytes passed to `from_bytes`, are not covered.
pub struct SecretKey {
    ed_seed: Zeroizing<[u8; 32]>,
    ml_seed: Zeroizing<[u8; 32]>,
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa_65::PrivateKey,
    public: PublicKey,
}

type Randomness = fn(&mut [u8]) -> Result<(), Error>;

fn system_randomness(out: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(out).map_err(|_| Error::Randomness)
}

impl SecretKey {
    /// A new key from two independent random seeds.
    pub fn generate() -> Result<Self, Error> {
        Self::generate_with(system_randomness)
    }

    fn generate_with(random: Randomness) -> Result<Self, Error> {
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut ml = Zeroizing::new([0u8; 32]);
        random(ed.as_mut_slice())?;
        random(ml.as_mut_slice())?;
        Self::from_seeds(&ed, &ml)
    }

    /// Rebuilds a key from its seeds. The two must be independent; this cannot be checked.
    pub fn from_seeds(ed_seed: &[u8; 32], ml_seed: &[u8; 32]) -> Result<Self, Error> {
        let ed = ed25519_dalek::SigningKey::from_bytes(ed_seed);
        let (ml_public, ml) = ml_dsa_65::KG::keygen_from_seed(ml_seed);
        let mut encoded = Vec::with_capacity(PUBLIC_KEY_LEN);
        encoded.extend_from_slice(PUBLIC_MAGIC);
        encoded.extend_from_slice(ed.verifying_key().as_bytes());
        encoded.extend_from_slice(&ml_public.into_bytes());
        Ok(Self {
            ed_seed: Zeroizing::new(*ed_seed),
            ml_seed: Zeroizing::new(*ml_seed),
            public: PublicKey::from_bytes(&encoded)?,
            ed,
            ml,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let body = exact(bytes, SECRET_KEY_LEN, SECRET_MAGIC, "secret key")?;
        let (ed, ml) = body.split_at(32);
        Self::from_seeds(
            ed.try_into().expect("length checked above"),
            ml.try_into().expect("length checked above"),
        )
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_KEY_LEN));
        out.extend_from_slice(SECRET_MAGIC);
        out.extend_from_slice(self.ed_seed.as_slice());
        out.extend_from_slice(self.ml_seed.as_slice());
        out
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs with both algorithms. The ML-DSA half uses fresh randomness; if none can be had, nothing is signed.
    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with(system_randomness, context, message)
    }

    fn sign_with(
        &self,
        random: Randomness,
        context: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let t = signed_bytes(&self.public.key_id, context, message)?;
        let mut rnd = Zeroizing::new([0u8; 32]);
        random(rnd.as_mut_slice())?;
        let ml = self
            .ml
            .try_sign_with_seed(&rnd, &t, DOMAIN)
            .map_err(|_| Error::Signing)?;
        let mut signature = Vec::with_capacity(SIGNATURE_LEN);
        signature.extend_from_slice(SIGNATURE_MAGIC);
        signature.extend_from_slice(&self.ed.sign(&t).to_bytes());
        signature.extend_from_slice(&ml);
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The zeroization claim on `SecretKey`, checked by the compiler.
    #[test]
    fn secret_types_wipe_themselves_on_drop() {
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        wipes::<Zeroizing<[u8; 32]>>();
        wipes::<ed25519_dalek::SigningKey>();
        wipes::<ml_dsa_65::PrivateKey>();
    }

    #[test]
    fn a_new_key_has_two_independent_seeds() {
        let (a, b) = (SecretKey::generate().unwrap(), SecretKey::generate().unwrap());
        assert_ne!(*a.ed_seed, *a.ml_seed, "one seed used for both algorithms");
        assert_ne!(*a.ed_seed, *b.ed_seed);
        assert_ne!(*a.ml_seed, *b.ml_seed);
    }

    fn broken(_: &mut [u8]) -> Result<(), Error> {
        Err(Error::Randomness)
    }

    #[test]
    fn no_randomness_means_no_key() {
        assert_eq!(
            SecretKey::generate_with(broken).err(),
            Some(Error::Randomness)
        );
    }

    #[test]
    fn no_randomness_means_no_signature() {
        let key = SecretKey::from_seeds(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(key.sign_with(broken, b"", b"m"), Err(Error::Randomness));
    }

    #[test]
    fn point_policy_refuses_each_kind_of_bad_point() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
        let good = ED25519_BASEPOINT_POINT.compress().to_bytes();
        assert_eq!(check_point(&good, "x"), Ok(()));
        // Every small-order point, the identity included.
        for torsion in EIGHT_TORSION {
            assert!(check_point(&torsion.compress().to_bytes(), "x").is_err());
        }
        // A large-order point with a small-order component: the library's strict check would let it through.
        let mixed = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!mixed.is_small_order());
        assert!(check_point(&mixed.compress().to_bytes(), "x").is_err());
    }

    /// Every non-canonical encoding there is: `y + p` for `y < 19` (either sign bit), and "negative zero" `x`
    /// for the two points with `x = 0`. All are refused. None of them decodes to a prime-order point other than
    /// the identity, so the explicit canonical-encoding rule in `check_point` is redundant with the other two
    /// rules; it is kept so that the policy does not depend on that fact, and no test can isolate it.
    #[test]
    fn every_non_canonical_encoding_is_refused() {
        // p = 2^255 - 19, little-endian: ed ff ... ff 7f
        let above_p = (0u8..19).map(|y| {
            let mut bytes = [0xffu8; 32];
            bytes[0] = 0xed + y;
            bytes[31] = 0x7f;
            bytes
        });
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        let mut all: Vec<[u8; 32]> = above_p.collect();
        all.extend(all.clone().into_iter().map(|mut b| {
            b[31] |= 0x80;
            b
        }));
        for mut x_is_zero in [identity, minus_one] {
            x_is_zero[31] |= 0x80;
            all.push(x_is_zero);
        }

        let mut decoded = 0;
        for bytes in &all {
            assert!(check_point(bytes, "x").is_err(), "accepted {bytes:?}");
            if let Some(point) = CompressedEdwardsY(*bytes).decompress() {
                assert_ne!(
                    point.compress().to_bytes(),
                    *bytes,
                    "not actually non-canonical"
                );
                assert!(point.is_identity() || !point.is_torsion_free());
                decoded += 1;
            }
        }
        assert_eq!(all.len(), 40);
        assert!(
            decoded > 0,
            "nothing decoded: this test would prove nothing"
        );
    }
}
