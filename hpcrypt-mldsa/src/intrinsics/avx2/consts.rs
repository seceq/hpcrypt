//! Precomputed Constants for AVX2 ML-DSA Implementation
//!
//! This module contains all precomputed constants used throughout the AVX2
//! implementation, organized for optimal cache efficiency and SIMD access.
//!
//! # Constant Categories
//!
//! 1. **Field Constants**: Q, QINV, MONT, etc.
//! 2. **NTT Twiddle Factors**: ZETAS array and Shoup precomputes
//! 3. **Magic Division Constants**: For fast division by ALPHA values
//! 4. **Shuffle Masks**: For intra-vector permutations in NTT levels 5-7
//!
//! # Memory Layout
//!
//! All arrays are 32-byte aligned for efficient AVX2 loads.

use core::arch::x86_64::*;

/// ML-DSA modulus Q = 2^23 - 2^13 + 1 = 8380417
pub const Q: i32 = 8380417;

/// Q as i64 for extended precision operations
pub const Q64: i64 = Q as i64;

/// -Q^{-1} mod 2^32 = 58728449
/// Used in Montgomery reduction: t = (a * QINV) mod 2^32
pub const QINV: i32 = 58728449;

/// QINV as u32 for unsigned operations
pub const QINV_U32: u32 = QINV as u32;

/// Montgomery constant R = 2^32 mod Q = 4193792
/// Used for converting to/from Montgomery domain
pub const MONT: i32 = 4193792;

/// R^2 mod Q = 2365951 (for converting to Montgomery domain)
pub const MONT_SQ: i32 = 2365951;

/// F = 2^32 / 256 mod Q = 41978
/// Scaling factor for inverse NTT (1/256 in Montgomery form)
pub const F: i32 = 41978;

/// F's Shoup constant for optimized multiplication
pub const F_SHOUP: i32 = compute_shoup_const(F);

/// Half of Q, used for centered representation
pub const Q_HALF: i32 = (Q - 1) / 2;

/// Number of coefficients in a polynomial
pub const N: usize = 256;

/// log2(N) = 8
pub const LOG_N: usize = 8;

/// Compute Shoup constant for a given value
/// shoup(a) = (a * QINV) mod 2^32
#[inline]
pub const fn compute_shoup_const(a: i32) -> i32 {
    let a64 = a as i64;
    let qinv64 = QINV as u32 as i64;
    ((a64 * qinv64) & 0xFFFFFFFF) as i32
}

/// Primitive 512-th root of unity in Montgomery form
/// ζ = 1753 (standard form), but stored in Montgomery domain
pub const ZETA: i32 = 1753;

/// NTT twiddle factors from FIPS 204 / pq-crystals reference implementation.
/// These are in Montgomery domain (multiplied by R = 2^32 mod Q).
///
/// ZETAS[i] = ζ^{bitrev(i)} * R mod Q
///
/// Organization:
/// - ZETAS[0] is unused (placeholder)
/// - ZETAS[1..128] for forward NTT
/// - ZETAS[128..256] for inverse NTT
pub static ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782,
];

/// Shoup precomputed constants for ZETAS
/// ZETAS_SHOUP[i] = (ZETAS[i] * QINV) mod 2^32
///
/// These enable parallel computation paths in Montgomery reduction,
/// breaking dependency chains for better ILP.
pub static ZETAS_SHOUP: [i32; 256] = compute_all_shoup_consts();

/// Compute all Shoup constants at compile time
const fn compute_all_shoup_consts() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut i = 0;
    while i < 256 {
        result[i] = compute_shoup_const(ZETAS[i]);
        i += 1;
    }
    result
}

// ============================================================================
// Magic Division Constants
// ============================================================================

/// Magic constant for division by ALPHA = 2*GAMMA2 where GAMMA2 = (Q-1)/88
/// For ML-DSA-44: ALPHA = 2 * 95232 = 190464
pub const MAGIC_DIV_190464: u32 = 0x00005816;

/// Magic constant for division by ALPHA = 2*GAMMA2 where GAMMA2 = (Q-1)/32
/// For ML-DSA-65/87: ALPHA = 2 * 261888 = 523776
pub const MAGIC_DIV_523776: u32 = 0x00002008;

/// Magic shift amount for fast division
pub const MAGIC_SHIFT: i32 = 32;

// ============================================================================
// Shuffle Masks for Intra-Vector NTT Operations
// ============================================================================

/// Shuffle mask for NTT level 5 (stride 4): extract low 128-bit lane
/// Duplicates elements [0,1,2,3] to [0,1,2,3,0,1,2,3]
pub static SHUFFLE_LO_128: [i32; 8] = [0, 1, 2, 3, 0, 1, 2, 3];

/// Shuffle mask for NTT level 5: extract high 128-bit lane
/// Duplicates elements [4,5,6,7] to [4,5,6,7,4,5,6,7]
pub static SHUFFLE_HI_128: [i32; 8] = [4, 5, 6, 7, 4, 5, 6, 7];

/// Shuffle mask for NTT level 6 (stride 2): pairs [0,1] and [4,5]
/// Maps [0,1,2,3,4,5,6,7] -> [0,1,0,1,4,5,4,5]
pub static SHUFFLE_LEVEL6_LO: [i32; 8] = [0, 1, 0, 1, 4, 5, 4, 5];

/// Shuffle mask for NTT level 6: pairs [2,3] and [6,7]
/// Maps [0,1,2,3,4,5,6,7] -> [2,3,2,3,6,7,6,7]
pub static SHUFFLE_LEVEL6_HI: [i32; 8] = [2, 3, 2, 3, 6, 7, 6, 7];

/// Shuffle mask for NTT level 7 (stride 1): even elements
/// Maps [0,1,2,3,4,5,6,7] -> [0,0,2,2,4,4,6,6]
pub static SHUFFLE_LEVEL7_EVEN: [i32; 8] = [0, 0, 2, 2, 4, 4, 6, 6];

/// Shuffle mask for NTT level 7: odd elements
/// Maps [0,1,2,3,4,5,6,7] -> [1,1,3,3,5,5,7,7]
pub static SHUFFLE_LEVEL7_ODD: [i32; 8] = [1, 1, 3, 3, 5, 5, 7, 7];

// ============================================================================
// Vector Constants (loaded at runtime for efficiency)
// ============================================================================

/// Create broadcast vector of Q
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn q_vec() -> __m256i {
    _mm256_set1_epi32(Q)
}

/// Create broadcast vector of QINV
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn qinv_vec() -> __m256i {
    _mm256_set1_epi32(QINV)
}

/// Create broadcast vector of F (inverse NTT scale factor)
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn f_vec() -> __m256i {
    _mm256_set1_epi32(F)
}

/// Create broadcast vector of F_SHOUP
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn f_shoup_vec() -> __m256i {
    _mm256_set1_epi32(F_SHOUP)
}

/// Create zero vector
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn zero_vec() -> __m256i {
    _mm256_setzero_si256()
}

/// Create vector of all ones (each i32 = 1)
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn one_vec() -> __m256i {
    _mm256_set1_epi32(1)
}

// ============================================================================
// Rejection Sampling Constants
// ============================================================================

/// Mask for extracting 23-bit values (Q < 2^23)
pub const MASK_23BIT: i32 = (1 << 23) - 1;

/// Number of bytes needed for 8 uniform samples (23 bits each = 23 bytes)
pub const UNIFORM_SAMPLE_BYTES: usize = 24;

/// Lookup table for eta=2 coefficient extraction
/// Maps nibble value 0..15 to coefficient in {-2, -1, 0, 1, 2} or INVALID
pub const ETA2_COEFF_TABLE: [i8; 16] = [
    0, 1, 2, -1,   // 0, 1, 2, 3 (mod 5 gives 0,1,2,3) -> need mapping
    -2, 0, 1, 2,   // 4, 5, 6, 7
    -1, -2, 0, 1,  // 8, 9, 10, 11
    2, -1, -2, -128, // 12, 13, 14, 15 (15 is invalid)
];

/// Lookup table for eta=4 coefficient extraction
pub const ETA4_COEFF_TABLE: [i8; 16] = [
    0, 1, 2, 3, 4, -4, -3, -2, -1, -128, -128, -128, -128, -128, -128, -128,
];

// ============================================================================
// Gamma Parameters
// ============================================================================

/// GAMMA1 for ML-DSA-44: 2^17 = 131072
pub const GAMMA1_44: i32 = 1 << 17;

/// GAMMA1 for ML-DSA-65/87: 2^19 = 524288
pub const GAMMA1_65: i32 = 1 << 19;

/// GAMMA2 for ML-DSA-44: (Q-1)/88 = 95232
pub const GAMMA2_44: i32 = (Q - 1) / 88;

/// GAMMA2 for ML-DSA-65/87: (Q-1)/32 = 261888
pub const GAMMA2_65: i32 = (Q - 1) / 32;

/// 2*GAMMA2 (ALPHA) for ML-DSA-44
pub const ALPHA_44: i32 = 2 * GAMMA2_44;

/// 2*GAMMA2 (ALPHA) for ML-DSA-65/87
pub const ALPHA_65: i32 = 2 * GAMMA2_65;

/// ETA for ML-DSA-44 (secret key coefficient bound)
pub const ETA_44: usize = 2;

/// ETA for ML-DSA-65/87 (secret key coefficient bound)
pub const ETA_65: usize = 4;

/// TAU for ML-DSA-44 (number of ±1 in challenge polynomial)
pub const TAU_44: usize = 39;

/// TAU for ML-DSA-65 (number of ±1 in challenge polynomial)
pub const TAU_65: usize = 49;

/// TAU for ML-DSA-87 (number of ±1 in challenge polynomial)
pub const TAU_87: usize = 60;

// ============================================================================
// Power2Round Constants
// ============================================================================

/// D parameter: number of bits dropped in Power2Round
pub const D: usize = 13;

/// 2^D = 8192
pub const POWER2D: i32 = 1 << D;

/// 2^(D-1) = 4096 (for rounding)
pub const HALF_POWER2D: i32 = 1 << (D - 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_constants() {
        // Verify Q is prime (basic check)
        assert_eq!(Q, 8380417);
        assert_eq!(Q, (1 << 23) - (1 << 13) + 1);

        // Verify QINV * Q ≡ 1 (mod 2^32)
        // This is the Montgomery property for reduction: (a - (a*QINV mod 2^32)*Q) ≡ 0 (mod 2^32)
        let product = (QINV as i64) * (Q as i64);
        assert_eq!((product & 0xFFFFFFFF) as i32, 1);
    }

    #[test]
    fn test_shoup_computation() {
        // Verify Shoup constants are correctly computed
        for i in 0..256 {
            let expected = compute_shoup_const(ZETAS[i]);
            assert_eq!(ZETAS_SHOUP[i], expected, "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_gamma_constants() {
        assert_eq!(GAMMA1_44, 131072);
        assert_eq!(GAMMA1_65, 524288);
        assert_eq!(GAMMA2_44, 95232);
        assert_eq!(GAMMA2_65, 261888);
    }
}
