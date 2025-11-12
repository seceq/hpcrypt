//! Ed448-Goldilocks curve constants
//!
//! This module defines the curve parameters for Ed448 as specified in RFC 8032.

/// The prime p = 2^448 - 2^224 - 1 (Goldilocks prime)
///
/// This is stored as 8 limbs of 56 bits each (little-endian)
/// p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffe
///     ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
pub const ED448_P: [u64; 8] = [
    0xffffffffffffff, // Limb 0: bits 0-55 (56 bits used)
    0xffffffffffffff, // Limb 1: bits 56-111
    0xffffffffffffff, // Limb 2: bits 112-167
    0xffffffffffffff, // Limb 3: bits 168-223
    0xfffffffffffffe, // Limb 4: bits 224-279 (note: -2^224)
    0xffffffffffffff, // Limb 5: bits 280-335
    0xffffffffffffff, // Limb 6: bits 336-391
    0xffffffffffffff, // Limb 7: bits 392-447
];

/// The curve parameter d = -39081
///
/// In the curve equation: x^2 + y^2 = 1 + d*x^2*y^2
/// d = -39081 mod p
pub const ED448_D: [u64; 8] = [
    0xffffffffff6756, // -39081 mod p (limb 0)
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
    0xfffffffffffffe,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
];

/// Base point order L (the prime order of the base point)
///
/// L = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
///
/// This is a 446-bit prime. The base point has order 4*L (cofactor = 4).
pub const ED448_L: [u64; 8] = [
    0x78c292ab5844f3, // Limb 0
    0xc2728dc58f5523, // Limb 1
    0x49aed63690216c, // Limb 2
    0x7cca23e9c44edb, // Limb 3
    0xffffffffffffff, // Limb 4
    0xffffffffffffff, // Limb 5
    0xffffffffffffff, // Limb 6
    0x3fffffffffffff, // Limb 7 (only 446 bits)
];

/// Base point (generator) X-coordinate
///
/// From RFC 7748 - Corrected coordinates that satisfy the curve equation
/// x = 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
pub const ED448_B_X: [u64; 8] = [
    0x26a82bc70cc05e,  // limb 0
    0x80e18b00938e26,  // limb 1
    0xf72ab66511433b,  // limb 2
    0xa3d3a46412ae1a,  // limb 3
    0x0f1767ea6de324,  // limb 4
    0x36da9e14657047,  // limb 5
    0xed221d15a622bf,  // limb 6
    0x4f1970c66bed0d,  // limb 7
];

/// Base point (generator) Y-coordinate
///
/// From RFC 7748 - Corrected coordinates that satisfy the curve equation
/// y = 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
pub const ED448_B_Y: [u64; 8] = [
    0x08795bf230fa14,  // limb 0
    0x132c4ed7c8ad98,  // limb 1
    0x1ce67c39c4fdbd,  // limb 2
    0x05a0c2d73ad3ff,  // limb 3
    0xa3984087789c1e,  // limb 4
    0xc7624bea73736c,  // limb 5
    0x248876203756c9,  // limb 6
    0x693f46716eb6bc,  // limb 7
];

/// The value 2^224 mod p (used in reduction)
pub const TWO_POW_224: [u64; 8] = [
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_bounds() {
        // Each limb should be at most 56 bits (< 2^56)
        for &limb in &ED448_P {
            assert!(limb < (1u64 << 56));
        }
        for &limb in &ED448_D {
            assert!(limb < (1u64 << 56));
        }
        for &limb in &ED448_L {
            assert!(limb < (1u64 << 56));
        }
    }

    #[test]
    fn test_goldilocks_prime_structure() {
        // Verify that ED448_P represents 2^448 - 2^224 - 1
        // Check limb 4 which should have bit 224 cleared
        assert_eq!(ED448_P[4] & 1, 0); // Bit 224 (first bit of limb 4) should be 0
    }
}
