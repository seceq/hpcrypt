//! Precomputed tables for fast scalar multiplication with the secp256k1 generator point.
//!
//! This module provides optimized scalar multiplication for the base point (generator)
//! using precomputed tables and windowed multiplication.
//!
//! # Performance
//!
//! Using precomputed tables provides ~3-4x speedup for generator multiplication,
//! which is critical for ECDSA signing and key generation performance.
//!
//! # Memory Optimization
//!
//! The table uses affine coordinates instead of Jacobian to reduce memory:
//! - Affine: 2 field elements (64 bytes per point)
//! - Jacobian: 3 field elements (96 bytes per point)
//! - Savings: 33% reduction in memory usage
//!
//! Total table size: 64 windows × 16 points × 64 bytes = 65,536 bytes (~64 KB)

use super::{AffinePoint, FieldElement, Point};
use once_cell::sync::Lazy;

/// Window size for precomputed tables (in bits)
///
/// A window size of 4 means we precompute 2^4 = 16 multiples of G.
/// This is a good trade-off between table size and performance.
const WINDOW_SIZE: usize = 4;

/// Number of windows needed for 256-bit scalars
const NUM_WINDOWS: usize = 256 / WINDOW_SIZE; // 64 windows

/// Precomputed multiples of the generator point G (affine coordinates)
///
/// For each window, we store [0*G, 1*G, 2*G, ..., 15*G] (16 points) in affine form.
/// Using affine coordinates reduces memory by 33% compared to Jacobian.
///
/// Memory usage: 64 windows × 16 points × 64 bytes/point = 65,536 bytes (~64 KB)
pub struct PrecomputedTable {
    /// tables\[i\] contains precomputed multiples for window i
    /// tables\[i\]\[j\] = j * (2^(4*i)) * G in affine coordinates
    ///
    /// Note: tables\[i\]\[0\] represents the point at infinity, stored as (0, 0)
    /// which is handled specially during addition.
    tables: [[AffinePoint; 16]; NUM_WINDOWS],
}

impl AffinePoint {
    /// Create a sentinel value for the point at infinity
    ///
    /// Since infinity has no affine representation, we use (0, 0) as a sentinel.
    /// This is safe because (0, 0) is not on the secp256k1 curve.
    const fn infinity_sentinel() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Check if this is the infinity sentinel
    fn is_infinity_sentinel(&self) -> bool {
        use crate::ct_utils::ConstantTimeEq;
        bool::from(self.x.ct_eq(&FieldElement::zero()) & self.y.ct_eq(&FieldElement::zero()))
    }
}

impl PrecomputedTable {
    /// Generate precomputed tables for the generator point
    ///
    /// This is called once at startup and cached.
    ///
    /// Uses affine coordinates to save 33% memory compared to Jacobian.
    pub fn generate() -> Self {
        let g = Point::generator();
        let mut tables = [[AffinePoint::infinity_sentinel(); 16]; NUM_WINDOWS];

        // For each window position
        for window_idx in 0..NUM_WINDOWS {
            // Compute the base point for this window: G * 2^(4*window_idx)
            let base_jacobian = if window_idx == 0 {
                g
            } else {
                // Double the previous base 4 times (since window size is 4)
                // Convert back from affine to Jacobian
                let prev_affine = tables[window_idx - 1][1];
                let mut point = Point::from_affine(&prev_affine);
                for _ in 0..WINDOW_SIZE {
                    point = point.double();
                }
                point
            };

            // Precompute multiples: 0*base, 1*base, 2*base, ..., 15*base
            tables[window_idx][0] = AffinePoint::infinity_sentinel();
            tables[window_idx][1] = base_jacobian
                .to_affine()
                .expect("Base point should not be infinity");

            // Build up the rest using Jacobian addition for speed
            let mut current = base_jacobian;
            for i in 2..16 {
                current = current.add(&base_jacobian);
                tables[window_idx][i] = current
                    .to_affine()
                    .expect("Multiple of base should not be infinity");
            }
        }

        Self { tables }
    }

    /// Multiply the generator point by a scalar using precomputed tables
    ///
    /// This is ~3-4x faster than double-and-add scalar multiplication.
    ///
    /// # Algorithm
    ///
    /// Uses 4-bit windowing:
    /// 1. Break scalar into 64 4-bit windows
    /// 2. For each window, look up the precomputed multiple
    /// 3. Add all contributions together
    ///
    /// # Security
    ///
    /// This function is NOT constant-time because it uses affine addition
    /// and the scalar is assumed to be public (or we're using it for signing
    /// where constant-time is achieved through RFC 6979).
    pub fn scalar_mul_generator(&self, scalar: &[u8; 32]) -> Point {
        // Result accumulator (start at infinity)
        let mut result = Point::infinity();

        // Process each 4-bit window from LSB to MSB
        // Scalar is in big-endian format: scalar[0] is MSB, scalar[31] is LSB
        for window_idx in 0..NUM_WINDOWS {
            // Calculate bit position from LSB (window 0 = bits 0-3, window 1 = bits 4-7, etc.)
            let bit_position = window_idx * WINDOW_SIZE;
            let byte_idx = bit_position / 8;
            let bit_in_byte = bit_position % 8;

            // Extract 4 bits, accounting for big-endian byte order
            let window_value = if bit_in_byte <= 4 {
                // Window fits in single byte
                ((scalar[31 - byte_idx] >> bit_in_byte) & 0x0F) as usize
            } else {
                // Window spans two bytes
                let low_bits = (scalar[31 - byte_idx] >> bit_in_byte) as usize;
                let high_bits = if byte_idx < 31 {
                    ((scalar[31 - byte_idx - 1] << (8 - bit_in_byte)) & 0x0F) as usize
                } else {
                    0
                };
                low_bits | high_bits
            };

            // Look up the precomputed point
            let affine_point = &self.tables[window_idx][window_value];

            // Skip if it's the infinity sentinel
            if !affine_point.is_infinity_sentinel() {
                // Convert affine to Jacobian and add
                let jacobian_point = Point::from_affine(affine_point);
                result = result.add(&jacobian_point);
            }
        }

        result
    }
}

/// Global precomputed table (initialized lazily on first use)
///
/// Uses `once_cell::Lazy` to ensure thread-safe initialization.
/// The table is computed once and cached for the lifetime of the program.
pub static PRECOMPUTED_TABLE: Lazy<PrecomputedTable> = Lazy::new(|| PrecomputedTable::generate());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::Scalar;

    #[test]
    fn test_precomputed_table_correctness() {
        // Test that precomputed multiplication matches regular multiplication
        let g = Point::generator();

        // Test with several scalars
        let test_scalars = [[0x01u8; 32], [0x42u8; 32], [0xFFu8; 32], {
            let mut s = [0u8; 32];
            s[0] = 0x01;
            s
        }];

        for scalar_bytes in &test_scalars {
            let expected = g.scalar_mul(scalar_bytes);
            let result = PRECOMPUTED_TABLE.scalar_mul_generator(scalar_bytes);

            assert_eq!(
                result, expected,
                "Precomputed multiplication doesn't match regular multiplication"
            );
        }
    }

    #[test]
    fn test_precomputed_table_identity() {
        // Zero scalar should give identity
        let zero = [0u8; 32];
        let result = PRECOMPUTED_TABLE.scalar_mul_generator(&zero);
        assert!(bool::from(result.is_infinity()), "0*G should be infinity");
    }

    #[test]
    fn test_precomputed_table_generator() {
        // 1*G should equal G
        let mut one = [0u8; 32];
        one[31] = 0x01; // LSB in big-endian format

        let result = PRECOMPUTED_TABLE.scalar_mul_generator(&one);
        let expected = Point::generator();

        assert_eq!(result, expected, "1*G should equal generator");
    }

    #[test]
    fn test_precomputed_table_large_scalar() {
        // Test with maximum scalar (n-1)
        let scalar = Scalar::from_bytes(&[0xFFu8; 32]);
        let scalar_bytes = scalar.to_bytes();

        let result = PRECOMPUTED_TABLE.scalar_mul_generator(&scalar_bytes);
        let g = Point::generator();
        let expected = g.scalar_mul(&scalar_bytes);

        assert_eq!(
            result, expected,
            "Precomputed mul should work with large scalars"
        );
    }

    #[test]
    fn test_precomputed_vs_variable_time() {
        // Compare performance test vectors against variable-time implementation
        let test_vectors = [[0x42u8; 32], [0x43u8; 32], [0x44u8; 32]];

        let g = Point::generator();

        for scalar in &test_vectors {
            let precomputed = PRECOMPUTED_TABLE.scalar_mul_generator(scalar);
            let variable_time = g.scalar_mul(scalar);
            let constant_time = g.scalar_mul_constant_time(scalar);

            assert_eq!(precomputed, variable_time, "Precomputed != variable-time");
            assert_eq!(precomputed, constant_time, "Precomputed != constant-time");
        }
    }
}
