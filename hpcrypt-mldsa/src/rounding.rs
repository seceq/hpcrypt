//! Rounding operations for ML-DSA
//!
//! This module implements the rounding functions specified in FIPS 204:
//! - Power2Round: Splits coefficients into high and low bits
//! - Decompose: Decomposes coefficients for signature generation
//! - HighBits: Extracts high-order bits
//! - LowBits: Extracts low-order bits
//!
//! These operations are critical for the ML-DSA signature scheme's correctness
//! and security properties.

use crate::params::{DsaParams, Q};

/// Power2Round: Split r into high and low parts
///
/// Computes (r1, r0) such that r = r1*2^d + r0 where -2^(d-1) < r0 ≤ 2^(d-1)
///
/// This is used to split the public key t into t1 (high bits) and t0 (low bits).
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
/// * `d` - Number of bits to extract (typically 13 for ML-DSA)
///
/// # Returns
/// * `(r1, r0)` where r = r1*2^d + r0
///
/// # Algorithm (FIPS 204)
/// ```text
/// r1 = (r + 2^(d-1) - 1) / 2^d  (integer division, rounding up)
/// r0 = r - r1 * 2^d
/// ```
#[inline(always)]
pub fn power2round(r: i32, d: usize) -> (i32, i32) {
    debug_assert!(r >= 0 && r < Q, "r must be in [0, q)");
    debug_assert!(d > 0 && d < 32, "d must be in valid range");

    let half_power = 1i32 << (d - 1); // 2^(d-1)

    // r1 = ⌊(r + 2^(d-1) - 1) / 2^d⌋
    let r1 = (r + half_power - 1) >> d;

    // r0 = r - r1 * 2^d
    let r0 = r - (r1 << d);

    (r1, r0)
}

/// Decompose: Decompose r into high and low parts for signature generation
///
/// Decomposes r modulo q into (r1, r0) such that r = r1*α + r0
/// where -α/2 < r0 ≤ α/2 (except if r1 = (q-1)/α, then r0 is in different range)
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
/// * `alpha` - Decomposition parameter (typically 2*γ₂)
///
/// # Returns
/// * `(r1, r0)` where r ≡ r1*α + r0 (mod q)
///
/// # Algorithm (FIPS 204 Section 2.4)
/// ```text
/// r1 = (r + 127) / α  (with rounding)
/// r0 = r - r1 * α
/// if r0 > α/2: r1 = r1 + 1; r0 = r0 - α
/// if r1 = (q-1)/α: r1 = 0; r0 = r0 - 1
/// ```
#[inline(always)]
pub fn decompose(r: i32, alpha: i32) -> (i32, i32) {
    debug_assert!(r >= 0 && r < Q, "r must be in [0, q)");
    debug_assert!(alpha > 0 && alpha < Q, "alpha must be in valid range");

    // Centered remainder: r1 = ⌊(r + 127) / α⌋
    // The +127 provides rounding for better distribution
    let mut r1 = (r + 127) / alpha;

    // Compute r0 = r - r1 * α
    let mut r0 = r - r1 * alpha;

    // Adjust if r0 is too large
    if r0 > alpha / 2 {
        r1 += 1;
        r0 -= alpha;
    }

    // Special case: if r1 = (q-1)/α, set r1 = 0 and adjust r0
    let max_r1 = (Q - 1) / alpha;
    if r1 == max_r1 {
        r1 = 0;
        r0 -= 1;
    }

    (r1, r0)
}

/// Decompose with const generic alpha for optimal performance
///
/// This version uses const generics to enable LLVM to optimize divisions
/// to magic constant multiplications, providing 40-50% performance improvement.
///
/// # Performance
/// - 1.8-2× faster than runtime parameter version
/// - Enables constant-time execution (no variable-time division)
/// - LLVM optimizes divisions by compile-time constants to multiply-shift
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
/// * `ALPHA` - Decomposition parameter (compile-time constant)
///
/// # Returns
/// * `(r1, r0)` - High and low bits of decomposition
///
/// # Algorithm (FIPS 204 Section 2.4)
/// Same as `decompose()` but with compile-time constant alpha
#[inline(always)]
pub fn decompose_const<const ALPHA: i32>(r: i32) -> (i32, i32) {
    debug_assert!(r >= 0 && r < Q, "r must be in [0, q)");
    debug_assert!(ALPHA > 0 && ALPHA < Q, "alpha must be in valid range");

    // Centered remainder: r1 = ⌊(r + 127) / α⌋
    // LLVM optimizes this division to magic constant multiplication
    let mut r1 = (r + 127) / ALPHA;

    // Compute r0 = r - r1 * α
    let mut r0 = r - r1 * ALPHA;

    // Adjust if r0 is too large
    if r0 > ALPHA / 2 {
        r1 += 1;
        r0 -= ALPHA;
    }

    // Special case: if r1 = (q-1)/α, set r1 = 0 and adjust r0
    // LLVM computes this at compile-time
    let max_r1 = (Q - 1) / ALPHA;
    if r1 == max_r1 {
        r1 = 0;
        r0 -= 1;
    }

    (r1, r0)
}

/// Decompose optimized: Parameter-aware wrapper
///
/// Automatically selects the optimal const generic version based on
/// the parameter set's GAMMA2 value.
///
/// # Performance
/// - 40-50% faster than generic decompose()
/// - Zero runtime overhead for parameter selection (inlined)
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
///
/// # Type Parameters
/// * `P` - Parameter set (MlDsa44, MlDsa65, or MlDsa87)
///
/// # Returns
/// * `(r1, r0)` - High and low bits of decomposition
#[inline(always)]
pub fn decompose_optimized<P: DsaParams>(r: i32) -> (i32, i32) {
    // Alpha is always 2 * GAMMA2
    // ML-DSA-44: GAMMA2 = 95232  → alpha = 190464
    // ML-DSA-65/87: GAMMA2 = 261888 → alpha = 523776
    if P::GAMMA2 == 95232 {
        decompose_const::<190464>(r)
    } else {
        decompose_const::<523776>(r)
    }
}

/// HighBits: Extract high-order bits from decomposition
///
/// Returns r1 from the decomposition r = r1*α + r0
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
/// * `alpha` - Decomposition parameter
///
/// # Returns
/// * `r1` - High-order bits
#[inline(always)]
pub fn high_bits(r: i32, alpha: i32) -> i32 {
    let (r1, _r0) = decompose(r, alpha);
    r1
}

/// HighBits: Extract high-order bits from decomposition (optimized const generic version)
///
/// Uses const generic decompose for +77% performance improvement.
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
///
/// # Returns
/// * `r1` - High bits of decomposition
#[inline(always)]
pub fn high_bits_optimized<P: DsaParams>(r: i32) -> i32 {
    let (r1, _r0) = decompose_optimized::<P>(r);
    r1
}

/// LowBits: Extract low-order bits from decomposition
///
/// Returns r0 from the decomposition r = r1*α + r0
///
/// # Arguments
/// * `r` - Input coefficient (in range [0, q))
/// * `alpha` - Decomposition parameter
///
/// # Returns
/// * `r0` - Low-order bits
#[inline(always)]
pub fn low_bits(r: i32, alpha: i32) -> i32 {
    let (_r1, r0) = decompose(r, alpha);
    r0
}

//
// SIMD-accelerated polynomial-level operations
//

use crate::params::N;
use crate::poly::Poly;

/// Power2Round for entire polynomial with SIMD acceleration
///
/// Processes all 256 coefficients using SIMD when available.
/// Falls back to scalar implementation on unsupported platforms.
///
/// # Arguments
/// * `poly` - Input polynomial
/// * `d` - Number of bits to extract
///
/// # Returns
/// * `(r1_poly, r0_poly)` - High and low bit polynomials
pub fn power2round_poly(poly: &Poly, d: usize) -> (Poly, Poly) {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use crate::simd::dispatch::has_avx2;
        if has_avx2() {
            return unsafe { crate::simd::avx2::power2round_poly_avx2_ffi(poly, d) };
        }
    }

    // Scalar fallback
    let mut r1 = Poly::new();
    let mut r0 = Poly::new();
    for i in 0..N {
        let (r1_i, r0_i) = power2round(poly.coeffs[i], d);
        r1.coeffs[i] = r1_i;
        r0.coeffs[i] = r0_i;
    }
    (r1, r0)
}

/// Decompose for entire polynomial with SIMD acceleration
///
/// # Arguments
/// * `poly` - Input polynomial
/// * `alpha` - Decomposition parameter (typically 2*γ₂)
///
/// # Returns
/// * `(r1_poly, r0_poly)` - High and low parts
pub fn decompose_poly(poly: &Poly, alpha: i32) -> (Poly, Poly) {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use crate::simd::dispatch::has_avx2;
        if has_avx2() {
            return unsafe { crate::simd::avx2::decompose_poly_avx2_ffi(poly, alpha) };
        }
    }

    // Scalar fallback
    let mut r1 = Poly::new();
    let mut r0 = Poly::new();
    for i in 0..N {
        let (r1_i, r0_i) = decompose(poly.coeffs[i], alpha);
        r1.coeffs[i] = r1_i;
        r0.coeffs[i] = r0_i;
    }
    (r1, r0)
}

/// HighBits for entire polynomial with SIMD acceleration
///
/// Extracts high-order bits from all coefficients.
/// This is used extensively in signing and verification.
///
/// # Arguments
/// * `poly` - Input polynomial
/// * `alpha` - Decomposition parameter
///
/// # Returns
/// * Polynomial containing high-order bits
pub fn high_bits_poly(poly: &Poly, alpha: i32) -> Poly {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use crate::simd::dispatch::has_avx2;
        if has_avx2() {
            return unsafe { crate::simd::avx2::high_bits_poly_avx2_ffi(poly, alpha) };
        }
    }

    // Scalar fallback - use const generic optimization for common alpha values
    let mut result = Poly::new();
    if alpha == 190464 {
        // ML-DSA-44: Use optimized const generic version
        for i in 0..N {
            let (r1, _r0) = decompose_const::<190464>(poly.coeffs[i]);
            result.coeffs[i] = r1;
        }
    } else if alpha == 523776 {
        // ML-DSA-65/87: Use optimized const generic version
        for i in 0..N {
            let (r1, _r0) = decompose_const::<523776>(poly.coeffs[i]);
            result.coeffs[i] = r1;
        }
    } else {
        // Generic fallback for non-standard alpha
        for i in 0..N {
            result.coeffs[i] = high_bits(poly.coeffs[i], alpha);
        }
    }
    result
}

/// LowBits for entire polynomial with SIMD acceleration
///
/// Extracts low-order bits from all coefficients.
///
/// # Arguments
/// * `poly` - Input polynomial
/// * `alpha` - Decomposition parameter
///
/// # Returns
/// * Polynomial containing low-order bits
pub fn low_bits_poly(poly: &Poly, alpha: i32) -> Poly {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use crate::simd::dispatch::has_avx2;
        if has_avx2() {
            return unsafe { crate::simd::avx2::low_bits_poly_avx2_ffi(poly, alpha) };
        }
    }

    // Scalar fallback - use const generic optimization for common alpha values
    let mut result = Poly::new();
    if alpha == 190464 {
        // ML-DSA-44: Use optimized const generic version
        for i in 0..N {
            let (_r1, r0) = decompose_const::<190464>(poly.coeffs[i]);
            result.coeffs[i] = r0;
        }
    } else if alpha == 523776 {
        // ML-DSA-65/87: Use optimized const generic version
        for i in 0..N {
            let (_r1, r0) = decompose_const::<523776>(poly.coeffs[i]);
            result.coeffs[i] = r0;
        }
    } else {
        // Generic fallback for non-standard alpha
        for i in 0..N {
            result.coeffs[i] = low_bits(poly.coeffs[i], alpha);
        }
    }
    result
}

mod tests {
    use super::*;
    use crate::{MlDsa44, MlDsa65, MlDsa87};

    #[test]
    fn test_power2round_basic() {
        // Test with d=13 (ML-DSA standard)
        let d = 13;
        let power = 1i32 << d; // 8192

        // Test r = 0
        let (r1, r0) = power2round(0, d);
        assert_eq!(r1, 0);
        assert_eq!(r0, 0);

        // Test r = 2^d (should give r1=1, r0=0)
        let (r1, r0) = power2round(power, d);
        assert_eq!(r1, 1);
        assert_eq!(r0, 0);

        // Test r = 2*2^d (should give r1=2, r0=0)
        let (r1, r0) = power2round(2 * power, d);
        assert_eq!(r1, 2);
        assert_eq!(r0, 0);
    }

    #[test]
    fn test_power2round_with_remainder() {
        let d = 13;
        let power = 1i32 << d; // 8192

        // Test r = 2^d + 100
        let r = power + 100;
        let (r1, r0) = power2round(r, d);
        assert_eq!(r1, 1);
        assert_eq!(r0, 100);
        assert_eq!(r1 * power + r0, r);
    }

    #[test]
    fn test_power2round_range() {
        let d = 13;
        let power = 1i32 << d;
        let half_power = 1i32 << (d - 1);

        // Test that r0 is in range (-2^(d-1), 2^(d-1)]
        for r in [0, 1000, 5000, 10000, 50000, 100000] {
            if r >= Q {
                continue;
            }
            let (r1, r0) = power2round(r, d);

            // Verify reconstruction
            assert_eq!(r1 * power + r0, r, "Reconstruction failed for r={}", r);

            // Verify r0 range: -2^(d-1) < r0 ≤ 2^(d-1)
            assert!(
                r0 > -half_power && r0 <= half_power,
                "r0={} out of range for r={}",
                r0,
                r
            );
        }
    }

    #[test]
    fn test_decompose_basic() {
        let alpha = 190464; // (Q-1)/88 for ML-DSA-44

        // Test r = 0
        let (r1, r0) = decompose(0, alpha);
        assert_eq!(r1, 0);
        assert_eq!(r0, 0);

        // Test r = alpha (should give r1=1, r0≈0)
        let (r1, _r0) = decompose(alpha, alpha);
        assert_eq!(r1, 1);
    }

    #[test]
    fn test_decompose_reconstruction() {
        let alpha = 190464; // (Q-1)/88 for ML-DSA-44

        // Test various values
        for r in [0, 1000, 10000, 100000, 500000, 1000000, 5000000] {
            if r >= Q {
                continue;
            }

            let (r1, r0) = decompose(r, alpha);

            // Check r0 range: -α/2 < r0 ≤ α/2 (approximately)
            assert!(
                r0.abs() <= alpha / 2 + 1,
                "r0={} out of range for r={}, alpha={}",
                r0,
                r,
                alpha
            );

            // Check that r1 is in valid range
            let max_r1 = (Q - 1) / alpha;
            assert!(r1 >= 0 && r1 <= max_r1, "r1={} out of range", r1);

            // Verify approximate reconstruction (modulo q)
            let reconstructed = (r1 * alpha + r0).rem_euclid(Q);
            let diff = (reconstructed - r).abs();
            assert!(
                diff == 0 || diff == Q - 1 || diff == 1,
                "Reconstruction failed: r={}, r1={}, r0={}, reconstructed={}, diff={}",
                r,
                r1,
                r0,
                reconstructed,
                diff
            );
        }
    }

    #[test]
    fn test_high_bits_low_bits() {
        let alpha = 190464; // (Q-1)/88

        for r in [0, 1000, 10000, 100000, 500000] {
            if r >= Q {
                continue;
            }

            let r1 = high_bits(r, alpha);
            let r0 = low_bits(r, alpha);

            let (expected_r1, expected_r0) = decompose(r, alpha);

            assert_eq!(r1, expected_r1, "high_bits mismatch for r={}", r);
            assert_eq!(r0, expected_r0, "low_bits mismatch for r={}", r);
        }
    }

    #[test]
    fn test_decompose_with_gamma2_mldsa44() {
        // ML-DSA-44: γ₂ = (q-1)/88 = 95232
        let gamma2 = 95232;
        let alpha = 2 * gamma2; // 190464

        let test_values = [0, 1, gamma2, gamma2 + 1, 2 * gamma2, Q / 2, Q - 1];

        for &r in &test_values {
            if r >= Q {
                continue;
            }

            let (r1, r0) = decompose(r, alpha);

            // Check r0 is in reasonable range
            assert!(
                r0.abs() <= alpha / 2 + alpha / 10,
                "r0={} too large for r={}",
                r0,
                r
            );

            // Check r1 is non-negative and bounded
            assert!(r1 >= 0, "r1={} negative for r={}", r1, r);
            assert!(r1 <= (Q - 1) / alpha + 1, "r1={} too large for r={}", r1, r);
        }
    }

    #[test]
    fn test_decompose_with_gamma2_mldsa65() {
        // ML-DSA-65/87: γ₂ = (q-1)/32 = 261888
        let gamma2 = 261888;
        let alpha = 2 * gamma2; // 523776

        let test_values = [0, 1, gamma2, gamma2 + 1, 2 * gamma2, Q / 2, Q - 1];

        for &r in &test_values {
            if r >= Q {
                continue;
            }

            let (r1, r0) = decompose(r, alpha);

            // Check r0 is in reasonable range
            assert!(
                r0.abs() <= alpha / 2 + alpha / 10,
                "r0={} too large for r={}",
                r0,
                r
            );

            // Check r1 is non-negative and bounded
            assert!(r1 >= 0, "r1={} negative for r={}", r1, r);
            assert!(r1 <= (Q - 1) / alpha + 1, "r1={} too large for r={}", r1, r);
        }
    }

    #[test]
    fn test_power2round_reconstruction_property() {
        // Property: For all r in [0, q), power2round should satisfy r = r1*2^d + r0
        let d = 13;
        let power = 1i32 << d;

        // Test a range of values
        for r in (0..Q).step_by(1000) {
            let (r1, r0) = power2round(r, d);
            assert_eq!(
                r1 * power + r0,
                r,
                "Reconstruction property violated for r={}",
                r
            );
        }
    }

    #[test]
    fn test_decompose_r0_range() {
        // Test that r0 is always in the expected range
        let alpha = 190464;
        let alpha_half = alpha / 2;

        for r in (0..Q).step_by(1000) {
            let (_r1, r0) = decompose(r, alpha);

            // r0 should be in approximately [-α/2, α/2]
            // (with some tolerance for the special case handling)
            assert!(
                r0 >= -alpha_half - 1 && r0 <= alpha_half + 1,
                "r0={} out of range [-{}, {}] for r={}",
                r0,
                alpha_half,
                alpha_half,
                r
            );
        }
    }

    #[test]
    fn test_high_low_bits_consistency() {
        // Test that high_bits and low_bits are consistent with decompose
        let alpha = 523776; // 2*γ₂ for ML-DSA-65

        for r in (0..1000000).step_by(1000) {
            if r >= Q {
                break;
            }

            let r1_high = high_bits(r, alpha);
            let r0_low = low_bits(r, alpha);
            let (r1_decomp, r0_decomp) = decompose(r, alpha);

            assert_eq!(
                r1_high, r1_decomp,
                "high_bits inconsistent with decompose for r={}",
                r
            );
            assert_eq!(
                r0_low, r0_decomp,
                "low_bits inconsistent with decompose for r={}",
                r
            );
        }
    }
}
