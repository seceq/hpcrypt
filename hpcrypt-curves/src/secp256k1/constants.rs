//! secp256k1 (Bitcoin/Ethereum) Constants
//!
//! This module defines the constants for the secp256k1 elliptic curve
//! used by Bitcoin, Ethereum, and many other cryptocurrencies.
//!
//! # Curve Equation
//!
//! y² = x³ + 7 (mod p)
//!
//! This is much simpler than P-256 which has y² = x³ - 3x + b

/// secp256k1 prime modulus p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
///
/// More commonly written as: p = 2^256 - 2^32 - 977
///
/// In hex: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
///
/// Represented as 4 x 64-bit limbs (little-endian):
/// - limbs\[0\] = 0xFFFFFFFEFFFFFC2F
/// - limbs\[1\] = 0xFFFFFFFFFFFFFFFF
/// - limbs\[2\] = 0xFFFFFFFFFFFFFFFF
/// - limbs\[3\] = 0xFFFFFFFFFFFFFFFF
pub const SECP256K1_MODULUS: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 curve parameter a = 0
///
/// The secp256k1 curve equation is y² = x³ + 7, so a = 0
pub const SECP256K1_A: [u64; 4] = [0, 0, 0, 0];

/// secp256k1 curve parameter b = 7
///
/// The secp256k1 curve equation is y² = x³ + 7
pub const SECP256K1_B: [u64; 4] = [7, 0, 0, 0];

/// secp256k1 base point generator G_x coordinate
///
/// In hex: 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
pub const SECP256K1_GX: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

/// secp256k1 base point generator G_y coordinate
///
/// In hex: 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
pub const SECP256K1_GY: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

/// secp256k1 order n (number of points on the curve)
///
/// In hex: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const SECP256K1_ORDER: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// Barrett constant μ for scalar reduction
///
/// μ = ⌊2^512 / n⌋ where n is SECP256K1_ORDER
///
/// This precomputed constant is used in Barrett reduction to efficiently
/// reduce 512-bit products modulo n without division.
///
/// Barrett reduction (HAC Algorithm 14.42) provides 3-4x speedup over BigUint,
/// enabling 20-30% faster scalar operations for secp256k1.
///
/// In hex: 1000000000000000000000000000000014551231950B75FC4402DA1732FC9BEC0
///
/// Represented as 8 x 64-bit limbs (little-endian), though only 5 are non-zero:
pub const BARRETT_MU_SCALAR: [u64; 8] = [
    0x402DA1732FC9BEC0,  // limbs[0]
    0x4551231950B75FC4,  // limbs[1]
    0x0000000000000001,  // limbs[2]
    0x0000000000000000,  // limbs[3]
    0x0000000000000001,  // limbs[4]
    0x0000000000000000,  // limbs[5]
    0x0000000000000000,  // limbs[6]
    0x0000000000000000,  // limbs[7]
];

/// Field element representing zero
pub const ZERO: [u64; 4] = [0, 0, 0, 0];

/// Field element representing one
pub const ONE: [u64; 4] = [1, 0, 0, 0];

/// Field element representing two
pub const TWO: [u64; 4] = [2, 0, 0, 0];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus_structure() {
        // Verify secp256k1 modulus: 2^256 - 2^32 - 977
        // The lowest limb should be 0xFFFFFFFEFFFFFC2F
        assert_eq!(SECP256K1_MODULUS[0], 0xFFFFFFFEFFFFFC2F);
        assert_eq!(SECP256K1_MODULUS[1], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(SECP256K1_MODULUS[2], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(SECP256K1_MODULUS[3], 0xFFFFFFFFFFFFFFFF);
    }

    #[test]
    fn test_curve_a_is_zero() {
        // secp256k1 has a = 0
        assert_eq!(SECP256K1_A, [0, 0, 0, 0]);
    }

    #[test]
    fn test_curve_b_is_seven() {
        // secp256k1 has b = 7
        assert_eq!(SECP256K1_B, [7, 0, 0, 0]);
    }

    #[test]
    fn test_basic_constants() {
        assert_eq!(ZERO, [0, 0, 0, 0]);
        assert_eq!(ONE, [1, 0, 0, 0]);
        assert_eq!(TWO, [2, 0, 0, 0]);
    }
}
