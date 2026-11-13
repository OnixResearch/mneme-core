//! 256-bit content digests as two machine words.
//!
//! Shells convert a 32-byte digest with `u128::from_be_bytes` on each half
//! (`mneme_core::kernel_digest`). That conversion is injective, so equality
//! here is equality of the original digests.

/// A 256-bit digest split into two big-endian 128-bit words.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Digest {
    /// The first sixteen bytes.
    pub hi: u128,
    /// The last sixteen bytes.
    pub lo: u128,
}

/// Whether two digests are the same 256-bit value.
pub fn digest_eq(left: &Digest, right: &Digest) -> bool {
    left.hi == right.hi && left.lo == right.lo
}

/// Whether two optional digests are both absent or both the same value.
pub fn optional_digest_eq(left: &Option<Digest>, right: &Option<Digest>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(found), Some(wanted)) => digest_eq(found, wanted),
        _ => false,
    }
}
