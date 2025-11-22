//! Constants for Ed25519
//!
//! This module contains the group order L and related constants
//! for scalar arithmetic in Ed25519.

/// The order of the edwards25519 group
/// L = 2^252 + 27742317777372353535851937790883648493
pub(crate) const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// L as constant bytes for reduction (little-endian)
#[allow(dead_code)]
pub(crate) const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Barrett reduction parameter μ = floor(2^512 / L)
/// This is precomputed for efficient modular reduction
/// μ ≈ 2^512 / L, stored as 5 limbs (320 bits, extra precision for accuracy)
#[allow(dead_code)]
pub(crate) const BARRETT_MU: [u64; 5] = [
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x0fffffffffffffff,
];

/// Check if a 32-byte little-endian value is less than L
///
/// This is used in signature verification to ensure S < L as required by RFC 8032.
/// Returns true if the value is strictly less than L, false otherwise.
pub(crate) fn is_less_than_l(bytes: &[u8; 32]) -> bool {
    // Convert bytes to u64 limbs (little-endian)
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes([
            bytes[i * 8],
            bytes[i * 8 + 1],
            bytes[i * 8 + 2],
            bytes[i * 8 + 3],
            bytes[i * 8 + 4],
            bytes[i * 8 + 5],
            bytes[i * 8 + 6],
            bytes[i * 8 + 7],
        ]);
    }

    // Compare with L from most significant to least significant limb
    for i in (0..4).rev() {
        if limbs[i] < L[i] {
            return true;
        } else if limbs[i] > L[i] {
            return false;
        }
        // If equal, continue to next limb
    }

    // All limbs are equal, so value == L, which means NOT less than L
    false
}
