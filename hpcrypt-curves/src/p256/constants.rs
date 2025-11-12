//! P-256 (secp256r1) Constants
//!
//! This module defines the constants for the NIST P-256 elliptic curve
//! as specified in FIPS 186-4.

/// P-256 prime modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1
///
/// In hex: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
///
/// Represented as 4 x 64-bit limbs (little-endian):
/// - limbs\[0\] = 0xFFFFFFFFFFFFFFFF (2^64 - 1)
/// - limbs\[1\] = 0x00000000FFFFFFFF (2^32 - 1)
/// - limbs\[2\] = 0x0000000000000000 (0)
/// - limbs\[3\] = 0xFFFFFFFF00000001 (2^64 - 2^32 + 1)
pub const P256_MODULUS: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

/// P-256 curve parameter a = p - 3
///
/// In hex: FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
pub const P256_A: [u64; 4] = [
    0xFFFFFFFFFFFFFFFC,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

/// P-256 curve parameter b
///
/// In hex: 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
pub const P256_B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

/// P-256 base point generator G_x coordinate
///
/// In hex: 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
pub const P256_GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

/// P-256 base point generator G_y coordinate
///
/// In hex: 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
pub const P256_GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

/// P-256 order n (number of points on the curve)
///
/// In hex: FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
pub const P256_ORDER: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

/// Barrett reduction constant for P-256 scalar arithmetic
///
/// μ = ⌊2^512 / n⌋ where n is P256_ORDER
///
/// This precomputed constant is used in Barrett reduction to efficiently
/// reduce 512-bit products modulo n without division.
///
/// In hex: 100000000FFFFFFFFFFFFFFFEFFFFFFFF43190552DF1A6C21012FFD85EEDF9BFE
///
/// Currently unused - Barrett implementation is disabled.
/// See docs/BARRETT_INVESTIGATION_SESSION3.md
#[allow(dead_code)]
pub const BARRETT_MU_SCALAR: [u64; 8] = [
    0x012FFD85EEDF9BFE,  // limbs[0]
    0x43190552DF1A6C21,  // limbs[1]
    0xFFFFFFFEFFFFFFFF,  // limbs[2]
    0x00000000FFFFFFFF,  // limbs[3]
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

// ============================================================================
// Montgomery Arithmetic Constants
// ============================================================================
//
// Montgomery arithmetic is an efficient technique for performing modular
// multiplication without expensive division operations. It represents field
// elements in a special "Montgomery form" ā = a·R mod p, where R = 2^256.
//
// Operations in Montgomery form:
//   - Multiplication: montgomery_mul(ā, b̄) = (a·b)·R mod p = c̄
//   - Squaring: montgomery_square(ā) = (a²)·R mod p
//
// Conversion:
//   - To Montgomery: ā = montgomery_mul(a, R²)
//   - From Montgomery: a = montgomery_mul(ā, 1)
//
// Performance: Montgomery multiplication is 10-15% faster than standard
// modular multiplication for NIST P-256, as used by OpenSSL and other
// high-performance implementations.

/// Montgomery radix R mod p where R = 2^256
///
/// This constant represents R (the Montgomery radix) reduced modulo p.
/// Used as the Montgomery representation of 1.
///
/// In hex: 00000000FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
pub const MONTGOMERY_R: [u64; 4] = [
    0x0000000000000001,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFE,
];

/// Montgomery R² mod p where R = 2^256
///
/// This constant is used to convert from standard representation
/// to Montgomery representation via: to_montgomery(a) = montgomery_mul(a, R²)
///
/// The conversion works because:
///   montgomery_mul(a, R²) = a · R² · R^(-1) mod p = a · R mod p = ā
///
/// In hex: 00000004FFFFFFFDFFFFFFFFFFFFFFFEFFFFFFFBFFFFFFFF0000000000000003
pub const MONTGOMERY_R2: [u64; 4] = [
    0x0000000000000003,
    0xFFFFFFFBFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
    0x00000004FFFFFFFD,
];

/// Montgomery p' = -p^(-1) mod R where R = 2^256
///
/// This constant is used in the REDC (Montgomery reduction) algorithm.
/// It satisfies the property: p · p' ≡ -1 (mod R)
///
/// REDC uses p' to efficiently compute T · R^(-1) mod p without division.
///
/// In hex: FFFFFFFF00000002000000000000000000000001000000000000000000000001
pub const MONTGOMERY_P_PRIME: [u64; 4] = [
    0x0000000000000001,
    0x0000000100000000,
    0x0000000000000000,
    0xFFFFFFFF00000002,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus_structure() {
        // Verify P-256 modulus has the special form: 2^256 - 2^224 + 2^192 + 2^96 - 1
        assert_eq!(P256_MODULUS[0], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(P256_MODULUS[1], 0x00000000FFFFFFFF);
        assert_eq!(P256_MODULUS[2], 0x0000000000000000);
        assert_eq!(P256_MODULUS[3], 0xFFFFFFFF00000001);
    }

    #[test]
    fn test_curve_a_is_p_minus_3() {
        // a = p - 3, so a should be ...FFFFFFFC in the lowest limb
        assert_eq!(P256_A[0], 0xFFFFFFFFFFFFFFFC);
    }

    #[test]
    fn test_basic_constants() {
        assert_eq!(ZERO, [0, 0, 0, 0]);
        assert_eq!(ONE, [1, 0, 0, 0]);
        assert_eq!(TWO, [2, 0, 0, 0]);
    }
}
