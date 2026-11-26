use sha2::{Digest as _, Sha256};

/// Repeatable test seeds: SHA-256 of a label and a number.
pub fn seed(label: &str, n: u32) -> [u8; 32] {
    Sha256::new()
        .chain_update(label.as_bytes())
        .chain_update(n.to_le_bytes())
        .finalize()
        .into()
}
