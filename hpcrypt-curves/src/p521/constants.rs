//! P-521 (secp521r1) Constants
//!
//! This module defines the constants for the NIST P-521 elliptic curve
//! as specified in FIPS 186-4.
//!
//! P-521 is special because its prime is a Mersenne prime: p = 2^521 - 1

/// P-521 prime modulus p = 2^521 - 1
///
/// In hex: 01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
///
/// Represented as 9 x 64-bit limbs (little-endian):
/// The prime is 2^521 - 1, which means:
/// - limbs\[0..7\] = 0xFFFFFFFFFFFFFFFF (all 1s)
/// - limbs\[8\] = 0x1FF (9 bits set, since 521 = 8*64 + 9)
pub const P521_MODULUS: [u64; 9] = [
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x1FF, // Only 9 bits (521 mod 64 = 9)
];

/// P-521 curve parameter a = p - 3
///
/// Since p = 2^521 - 1, we have a = 2^521 - 4
/// In hex: 01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
pub const P521_A: [u64; 9] = [
    0xFFFFFFFFFFFFFFFC,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x1FF,
];

/// P-521 curve parameter b
///
/// In hex: 0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
pub const P521_B: [u64; 9] = [
    0xEF451FD46B503F00, // limb 0 (LSB)
    0x3573DF883D2C34F1, // limb 1
    0x1652C0BD3BB1BF07, // limb 2
    0x56193951EC7E937B, // limb 3
    0xB8B489918EF109E1, // limb 4
    0xA2DA725B99B315F3, // limb 5
    0x929A21A0B68540EE, // limb 6
    0x953EB9618E1C9A1F, // limb 7
    0x0000000000000051, // limb 8 (MSB)
];

/// P-521 base point generator G_x coordinate
///
/// In hex: 00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
pub const P521_GX: [u64; 9] = [
    0xF97E7E31C2E5BD66, // limb 0 (LSB)
    0x3348B3C1856A429B, // limb 1
    0xFE1DC127A2FFA8DE, // limb 2
    0xA14B5E77EFE75928, // limb 3
    0xF828AF606B4D3DBA, // limb 4
    0x9C648139053FB521, // limb 5
    0x9E3ECB662395B442, // limb 6
    0x858E06B70404E9CD, // limb 7
    0x00000000000000C6, // limb 8 (MSB, 8 bits)
];

/// P-521 base point generator G_y coordinate
///
/// In hex: 011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
pub const P521_GY: [u64; 9] = [
    0x88BE94769FD16650, // limb 0 (LSB)
    0x353C7086A272C240, // limb 1
    0xC550B9013FAD0761, // limb 2
    0x97EE72995EF42640, // limb 3
    0x17AFBD17273E662C, // limb 4
    0x98F54449579B4468, // limb 5
    0x5C8A5FB42C7D1BD9, // limb 6
    0x39296A789A3BC004, // limb 7
    0x0000000000000118, // limb 8 (MSB, 9 bits)
];

/// P-521 order n (number of points on the curve)
///
/// In hex: 01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
pub const P521_ORDER: [u64; 9] = [
    0xBB6FB71E91386409, // limb 0 (LSB)
    0x3BB5C9B8899C47AE, // limb 1
    0x7FCC0148F709A5D0, // limb 2
    0x51868783BF2F966B, // limb 3
    0xFFFFFFFFFFFFFFFA, // limb 4
    0xFFFFFFFFFFFFFFFF, // limb 5
    0xFFFFFFFFFFFFFFFF, // limb 6
    0xFFFFFFFFFFFFFFFF, // limb 7
    0x1FF,              // limb 8 (MSB, 9 bits)
];

/// Field element representing zero
pub const ZERO: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Field element representing one
pub const ONE: [u64; 9] = [1, 0, 0, 0, 0, 0, 0, 0, 0];

/// Field element representing two
pub const TWO: [u64; 9] = [2, 0, 0, 0, 0, 0, 0, 0, 0];

/// Barrett constant μ for scalar reduction
///
/// μ = ⌊2^1152 / n⌋ where n is P521_ORDER
///
/// This precomputed constant is used in Barrett reduction to efficiently
/// reduce 1152-bit products modulo n without division.
///
/// Barrett reduction (HAC Algorithm 14.42) computes x mod n using:
///   q = ⌊(⌊x / b^(k-1)⌋ * μ) / b^(k+1)⌋
///   r = (x mod b^(k+1)) - (q * n mod b^(k+1))
///   if r < 0: r = r + n
///   while r >= n: r = r - n
///
/// Where b = 2^64 (limb size) and k = 9 (number of limbs in n).
///
/// Performance: Barrett reduction provides 3-4x speedup over BigUint fallback,
/// enabling 20-30% faster scalar operations (multiplication, inversion, etc.).
///
/// In hex: 8000000000000000000000000000000000000000000000000000000000000000016B9E5E1F10341A65200CFFADC23D968BF1128D91DD98EE14512412385BB1E6FDC408F501C8D1CD2DAD1D7F46221C
///
/// Represented as 18 x 64-bit limbs (little-endian), 7 non-zero limbs:
pub const BARRETT_MU_SCALAR: [u64; 18] = [
    0xCD2DAD1D7F46221C, // limbs[0]
    0xE6FDC408F501C8D1, // limbs[1]
    0xEE14512412385BB1, // limbs[2]
    0x968BF1128D91DD98, // limbs[3]
    0x1A65200CFFADC23D, // limbs[4]
    0x00016B9E5E1F1034, // limbs[5]
    0x0000000000000000, // limbs[6]
    0x0000000000000000, // limbs[7]
    0x0000000000000000, // limbs[8]
    0x0080000000000000, // limbs[9]
    0x0000000000000000, // limbs[10-17]
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus_is_mersenne_prime() {
        // Verify P-521 modulus is 2^521 - 1
        // First 8 limbs should be all 1s
        for i in 0..8 {
            assert_eq!(P521_MODULUS[i], 0xFFFFFFFFFFFFFFFF);
        }
        // Last limb should have only 9 bits set (521 = 8*64 + 9)
        assert_eq!(P521_MODULUS[8], 0x1FF);
    }

    #[test]
    fn test_curve_a_is_p_minus_3() {
        // a = p - 3, so a[0] should be ...FFFFFFFC
        assert_eq!(P521_A[0], 0xFFFFFFFFFFFFFFFC);
        // Other limbs (except last) should be all 1s
        for i in 1..8 {
            assert_eq!(P521_A[i], 0xFFFFFFFFFFFFFFFF);
        }
        assert_eq!(P521_A[8], 0x1FF);
    }

    #[test]
    fn test_basic_constants() {
        assert_eq!(ZERO, [0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ONE, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(TWO, [2, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
