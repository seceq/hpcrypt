//! Multi-Scalar Multiplication (MSM) for P-256
//!
//! This module implements optimized multi-scalar multiplication using the
//! Strauss-Shamir algorithm (also known as Shamir's trick). This algorithm
//! efficiently computes linear combinations of points like k₁·P₁ + k₂·P₂.
//!
//! # Performance
//!
//! The key insight is that computing k₁·P₁ + k₂·P₂ separately requires:
//! - k₁·P₁: ~256 doublings + ~51 additions (with wNAF-4)
//! - k₂·P₂: ~256 doublings + ~51 additions (with wNAF-4)
//! - Total: ~512 doublings + ~102 additions
//!
//! With MSM, we can interleave the operations:
//! - Process both scalars simultaneously
//! - Only ~256 doublings (shared between both scalar muls)
//! - ~102 additions (same as before)
//! - **Expected speedup: ~30%** (save half the doublings)
//!
//! # Algorithm: Interleaved wNAF
//!
//! Instead of basic Shamir's trick with binary representations, we use
//! wNAF for both scalars which reduces additions by ~60%:
//!
//! 1. Compute wNAF representations for both k₁ and k₂
//! 2. Create precomputed tables for P₁ and P₂ (odd multiples)
//! 3. Process both wNAF digits from MSB to LSB:
//!    - Double the accumulator once
//!    - Add from P₁'s table if wNAF₁\[i\] ≠ 0
//!    - Add from P₂'s table if wNAF₂\[i\] ≠ 0
//!
//! # ECDSA Verification Use Case
//!
//! ECDSA verification computes: R = u₁·G + u₂·Q
//! - u₁·G: Uses precomputed generator tables (already optimized)
//! - u₂·Q: Uses wNAF (after our previous optimization)
//! - With MSM: Compute both together for additional ~30% speedup

use super::wnaf::{compute_wnaf, WNafTable, WINDOW_WIDTH};
use super::{AffinePoint, Point};

/// Compute multi-scalar multiplication: k₁·P₁ + k₂·P₂
///
/// This function efficiently computes the linear combination of two points
/// using the interleaved wNAF algorithm.
///
/// # Arguments
///
/// * `scalar1` - First scalar (32 bytes, big-endian)
/// * `point1` - First point
/// * `scalar2` - Second scalar (32 bytes, big-endian)
/// * `point2` - Second point
///
/// # Returns
///
/// The point k₁·P₁ + k₂·P₂
///
/// # Performance
///
/// Approximately 30% faster than computing k₁·P₁ and k₂·P₂ separately
/// due to shared doubling operations.
///
/// # Example
///
/// ```ignore
/// use hpcrypt_curves::p256::{Point, msm_2_points};
///
/// let g = Point::generator();
/// let q = g.double().add(&g); // Some point
///
/// let scalar1 = [0x12; 32];
/// let scalar2 = [0x34; 32];
///
/// // Compute u1*G + u2*Q (ECDSA verification pattern)
/// let result = msm_2_points(&scalar1, &g, &scalar2, &q);
/// ```
pub fn msm_2_points(
    scalar1: &[u8; 48],
    point1: &Point,
    scalar2: &[u8; 48],
    point2: &Point,
) -> Point {
    // Compute wNAF for both scalars
    let wnaf1 = compute_wnaf(scalar1, WINDOW_WIDTH);
    let wnaf2 = compute_wnaf(scalar2, WINDOW_WIDTH);

    // Precompute tables for both points
    let table1 = WNafTable::new(point1);
    let table2 = WNafTable::new(point2);

    // Find the maximum length (they might differ slightly)
    let max_len = wnaf1.len().max(wnaf2.len());

    // Pad shorter wNAF with zeros at the end (MSB side)
    let mut wnaf1_padded = wnaf1;
    let mut wnaf2_padded = wnaf2;

    while wnaf1_padded.len() < max_len {
        wnaf1_padded.push(0);
    }
    while wnaf2_padded.len() < max_len {
        wnaf2_padded.push(0);
    }

    // Process from MSB to LSB (reverse iteration)
    let mut result = Point::infinity();

    for i in (0..max_len).rev() {
        // Double the accumulator (shared operation - this is where we save time!)
        result = result.double();

        // Process first scalar's digit (using mixed addition)
        let digit1 = wnaf1_padded[i];
        if digit1 > 0 {
            result = result.add_affine(table1.lookup(digit1 as usize));
        } else if digit1 < 0 {
            let affine_point = table1.lookup((-digit1) as usize);
            let negated = AffinePoint {
                x: affine_point.x,
                y: affine_point.y.neg(),
            };
            result = result.add_affine(&negated);
        }

        // Process second scalar's digit (using mixed addition)
        let digit2 = wnaf2_padded[i];
        if digit2 > 0 {
            result = result.add_affine(table2.lookup(digit2 as usize));
        } else if digit2 < 0 {
            let affine_point = table2.lookup((-digit2) as usize);
            let negated = AffinePoint {
                x: affine_point.x,
                y: affine_point.y.neg(),
            };
            result = result.add_affine(&negated);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p384::Scalar;

    #[test]
    fn test_msm_correctness_vs_separate() {
        // Test that MSM gives same result as computing k1*P1 + k2*P2 separately
        let g = Point::generator();
        let p = g.double().add(&g); // Some arbitrary point

        let scalar1 = Scalar::from_u64(12345);
        let scalar2 = Scalar::from_u64(67890);

        let scalar1_bytes = scalar1.to_bytes();
        let scalar2_bytes = scalar2.to_bytes();

        // Compute using MSM
        let result_msm = msm_2_points(&scalar1_bytes, &g, &scalar2_bytes, &p);

        // Compute separately
        let k1_p1 = g.scalar_mul(&scalar1_bytes);
        let k2_p2 = p.scalar_mul(&scalar2_bytes);
        let result_separate = k1_p1.add(&k2_p2);

        // Should be equal
        assert_eq!(result_msm, result_separate);
    }

    #[test]
    fn test_msm_with_zero_scalars() {
        let g = Point::generator();
        let p = g.double();

        let zero = Scalar::from_u64(0);
        let one = Scalar::from_u64(1);

        let zero_bytes = zero.to_bytes();
        let one_bytes = one.to_bytes();

        // 0*G + 1*P should equal P
        let result = msm_2_points(&zero_bytes, &g, &one_bytes, &p);
        assert_eq!(result, p);

        // 1*G + 0*P should equal G
        let result = msm_2_points(&one_bytes, &g, &zero_bytes, &p);
        assert_eq!(result, g);

        // 0*G + 0*P should equal infinity
        let result = msm_2_points(&zero_bytes, &g, &zero_bytes, &p);
        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_msm_ecdsa_verification_pattern() {
        // Simulate ECDSA verification: u1*G + u2*Q
        let g = Point::generator();

        // Create a "public key" Q = d*G
        let d = Scalar::from_u64(0x1234567890abcdef);
        let d_bytes = d.to_bytes();
        let q = g.scalar_mul(&d_bytes);

        // Simulate verification scalars u1 and u2
        let u1 = Scalar::from_u64(0xfedcba0987654321);
        let u2 = Scalar::from_u64(0x0123456789abcdef);

        let u1_bytes = u1.to_bytes();
        let u2_bytes = u2.to_bytes();

        // Compute using MSM (what we'll use in ECDSA verify)
        let result_msm = msm_2_points(&u1_bytes, &g, &u2_bytes, &q);

        // Compute separately (current ECDSA verify approach)
        let u1_g = g.scalar_mul(&u1_bytes);
        let u2_q = q.scalar_mul(&u2_bytes);
        let result_separate = u1_g.add(&u2_q);

        // Should match
        assert_eq!(result_msm, result_separate);
    }

    #[test]
    fn test_msm_with_same_point() {
        // Test k1*P + k2*P = (k1 + k2)*P
        let p = Point::generator().double().add(&Point::generator());

        let scalar1 = Scalar::from_u64(100);
        let scalar2 = Scalar::from_u64(200);

        let scalar1_bytes = scalar1.to_bytes();
        let scalar2_bytes = scalar2.to_bytes();

        // Compute using MSM
        let result_msm = msm_2_points(&scalar1_bytes, &p, &scalar2_bytes, &p);

        // Compute as (k1 + k2)*P
        let sum = scalar1.add(&scalar2);
        let sum_bytes = sum.to_bytes();
        let result_sum = p.scalar_mul(&sum_bytes);

        // Should match
        assert_eq!(result_msm, result_sum);
    }

    #[test]
    fn test_msm_large_scalars() {
        // Test with large random-looking scalars
        let g = Point::generator();
        let p = g.double().double().add(&g);

        let scalar1 = Scalar::from_bytes(&[
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ]);

        let scalar2 = Scalar::from_bytes(&[
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
            0x22, 0x11, 0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd, 0xef, 0xcd, 0xab, 0x89,
            0x67, 0x45, 0x23, 0x01, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        ]);

        let scalar1_bytes = scalar1.to_bytes();
        let scalar2_bytes = scalar2.to_bytes();

        // Compute using MSM
        let result_msm = msm_2_points(&scalar1_bytes, &g, &scalar2_bytes, &p);

        // Compute separately
        let k1_p1 = g.scalar_mul(&scalar1_bytes);
        let k2_p2 = p.scalar_mul(&scalar2_bytes);
        let result_separate = k1_p1.add(&k2_p2);

        // Should match
        assert_eq!(result_msm, result_separate);
    }
}
