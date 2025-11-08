//! Precomputed tables for fast scalar multiplication with the P-384 generator point.
//!
//! This module provides optimized scalar multiplication for the base point (generator)
//! using precomputed tables and windowed multiplication.
//!
//! # Performance
//!
//! Using precomputed tables provides ~5-10x speedup for generator multiplication,
//! which is critical for ECDSA signing performance.
//!
//! # Memory Optimization
//!
//! The table uses affine coordinates instead of Jacobian to reduce memory:
//! - Affine: 2 field elements (96 bytes per point for P-384)
//! - Jacobian: 3 field elements (144 bytes per point)
//! - Savings: 33% reduction in memory usage
//!
//! Total table size: 96 windows × 16 points × 96 bytes = 147,456 bytes (~144 KB)

use super::{AffinePoint, Point};
use once_cell::sync::Lazy;

/// Window size for precomputed tables (in bits)
///
/// A window size of 4 means we precompute 2^4 = 16 multiples of G.
/// This is a good trade-off between table size and performance.
const WINDOW_SIZE: usize = 4;

/// Number of windows needed for 384-bit scalars
const NUM_WINDOWS: usize = 384 / WINDOW_SIZE; // 96 windows

/// Precomputed multiples of the generator point G (affine coordinates)
///
/// For each window, we store [0*G, 1*G, 2*G, ..., 15*G] (16 points) in affine form.
/// Using affine coordinates reduces memory by 33% compared to Jacobian.
///
/// Memory usage: 96 windows × 16 points × 96 bytes/point = 147,456 bytes (~144 KB)
pub struct PrecomputedTable {
    /// tables\[i\] contains precomputed multiples for window i
    /// tables\[i\]\[j\] = j * (2^(4*i)) * G in affine coordinates
    ///
    /// Note: tables\[i\]\[0\] represents the point at infinity, stored as (0, 0)
    /// which is handled specially during addition.
    tables: [[AffinePoint; 16]; NUM_WINDOWS],
}

use super::field::FieldElement;

impl AffinePoint {
    /// Create a sentinel value for the point at infinity
    ///
    /// Since infinity has no affine representation, we use (0, 0) as a sentinel.
    /// This is handled specially during mixed addition.
    const fn infinity_sentinel() -> Self {
        AffinePoint {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }
}

impl PrecomputedTable {
    /// Compute the precomputed table for the generator point
    ///
    /// This is called once during initialization and the result is cached.
    /// The computation happens lazily on first use.
    ///
    /// # Algorithm
    ///
    /// For window i (i = 0 to 95):
    ///   base = 2^(4i) * G
    ///   tables\[i\]\[0\] = infinity (sentinel)
    ///   tables\[i\]\[1\] = base
    ///   tables\[i\]\[2\] = 2 * base
    ///   ...
    ///   tables\[i\]\[15\] = 15 * base
    ///
    /// # Performance
    ///
    /// Table generation takes approximately:
    /// - 96 windows × 15 point additions + 96×4 doublings
    /// - Total: ~1,800 point operations (one-time cost)
    fn new() -> Self {
        let mut tables = [[AffinePoint::infinity_sentinel(); 16]; NUM_WINDOWS];

        let g = Point::generator();

        // For each window
        for window_idx in 0..NUM_WINDOWS {
            // Compute base point for this window: 2^(4*window_idx) * G
            let shift = WINDOW_SIZE * window_idx;
            let mut base = g;

            // Double the base point 'shift' times to get 2^shift * G
            for _ in 0..shift {
                base = base.double();
            }

            // Precompute multiples: 0*base, 1*base, 2*base, ..., 15*base
            // tables[window_idx][0] is already set to infinity sentinel
            let mut accumulator = Point::infinity();

            for multiple in 1..16 {
                accumulator = accumulator.add(&base);

                // Convert to affine for storage
                if let Some(affine) = accumulator.to_affine() {
                    tables[window_idx][multiple] = affine;
                } else {
                    // This should only happen for multiple = 0 (infinity)
                    tables[window_idx][multiple] = AffinePoint::infinity_sentinel();
                }
            }
        }

        PrecomputedTable { tables }
    }

    /// Perform scalar multiplication using the precomputed table: k * G
    ///
    /// This is significantly faster than generic scalar multiplication because:
    /// 1. We process 4 bits at a time (instead of 1 bit)
    /// 2. We use precomputed multiples (no online point additions for multiples)
    /// 3. We use mixed addition (affine + Jacobian → Jacobian)
    ///
    /// # Algorithm
    ///
    /// Windowed multiplication with precomputed table:
    /// ```text
    /// result = infinity
    /// for each 4-bit window in scalar (from MSB to LSB):
    ///     result = result + tables\[window_idx\]\[window_value\]
    /// ```
    ///
    /// The key insight: instead of processing bits one at a time, we process
    /// windows of 4 bits, directly looking up the corresponding multiple.
    ///
    /// # Performance
    ///
    /// - Generic scalar mul: ~384 doublings + ~192 additions (for random scalar)
    /// - Precomputed table: ~96 mixed additions
    /// - Speedup: ~5-10x (mixed addition is cheaper than regular addition)
    ///
    /// # Arguments
    ///
    /// * `scalar` - 384-bit scalar in big-endian byte order
    ///
    /// # Returns
    ///
    /// The point k * G where G is the P-384 generator
    pub fn scalar_mul_generator(&self, scalar: &[u8; 48]) -> Point {
        let mut result = Point::infinity();

        // Process the scalar in 4-bit windows from most significant to least significant
        // Scalar is in big-endian format: byte[0] is most significant

        for window_idx in 0..NUM_WINDOWS {
            // Determine which byte and which nibble (4-bit chunk) to read
            let bit_position = 384 - WINDOW_SIZE * (window_idx + 1);
            let byte_idx = bit_position / 8;
            let bit_offset = bit_position % 8;

            // Extract 4-bit window value
            let window_value = if bit_offset == 4 {
                // Window is entirely in one byte (lower nibble)
                (scalar[byte_idx] & 0x0F) as usize
            } else if bit_offset == 0 {
                // Window is entirely in one byte (upper nibble)
                ((scalar[byte_idx] >> 4) & 0x0F) as usize
            } else {
                // Window spans two bytes
                let high_bits = scalar[byte_idx] & ((1 << (8 - bit_offset)) - 1);
                let low_bits = scalar[byte_idx + 1] >> (8 - (WINDOW_SIZE - (8 - bit_offset)));
                ((high_bits << (WINDOW_SIZE - (8 - bit_offset))) | low_bits) as usize
            };

            // Look up the precomputed point and add it
            // window_idx=0 processes bits 380-383 (4 LSBs) → use tables[0] (base 2^0)
            // window_idx=95 processes bits 0-3 (4 MSBs) → use tables[95] (base 2^380)
            let point_to_add = &self.tables[window_idx][window_value];

            // Mixed addition: add affine point to Jacobian result
            // Skip if window_value is 0 (point at infinity)
            if window_value != 0 {
                result = result.add_affine(point_to_add);
            }
        }

        result
    }
}

impl Point {
    /// Add an affine point to this Jacobian point (mixed addition)
    ///
    /// Mixed addition is faster than Jacobian + Jacobian addition because
    /// the affine point has Z = 1, which eliminates several multiplications.
    ///
    /// Cost: ~8M + 3S (compared to 12M + 4S for full Jacobian addition)
    ///
    /// # Algorithm (Cohen et al.)
    ///
    /// Given P = (X₁, Y₁, Z₁) in Jacobian and Q = (x₂, y₂) in affine:
    /// ```text
    /// U₂ = x₂ * Z₁²
    /// S₂ = y₂ * Z₁³
    /// H = U₂ - X₁
    /// R = S₂ - Y₁
    /// X₃ = R² - H³ - 2*X₁*H²
    /// Y₃ = R*(X₁*H² - X₃) - Y₁*H³
    /// Z₃ = Z₁ * H
    /// ```
    pub(crate) fn add_affine(&self, other: &AffinePoint) -> Point {
        // Handle point at infinity sentinel (0, 0)
        let is_infinity = other.x.is_zero() & other.y.is_zero();
        if bool::from(is_infinity) {
            return *self;
        }

        if bool::from(self.is_infinity()) {
            return Point {
                x: other.x,
                y: other.y,
                z: FieldElement::one(),
            };
        }

        // Mixed addition (affine + Jacobian)
        let z1_squared = self.z.square(); // Z₁²
        let z1_cubed = z1_squared.mul(&self.z); // Z₁³

        let u2 = other.x.mul(&z1_squared); // U₂ = x₂*Z₁²
        let s2 = other.y.mul(&z1_cubed); // S₂ = y₂*Z₁³

        let h = u2.sub(&self.x); // H = U₂ - X₁
        let r = s2.sub(&self.y); // R = S₂ - Y₁

        // Check for point doubling (same point)
        if bool::from(h.is_zero() & r.is_zero()) {
            return self.double();
        }

        let h_squared = h.square(); // H²
        let h_cubed = h_squared.mul(&h); // H³
        let x1_h_squared = self.x.mul(&h_squared); // X₁*H²

        // X₃ = R² - H³ - 2*X₁*H²
        let x3 = r
            .square()
            .sub(&h_cubed)
            .sub(&x1_h_squared)
            .sub(&x1_h_squared);

        // Y₃ = R*(X₁*H² - X₃) - Y₁*H³
        let y3 = r.mul(&x1_h_squared.sub(&x3)).sub(&self.y.mul(&h_cubed));

        // Z₃ = Z₁ * H
        let z3 = self.z.mul(&h);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Global precomputed table for the P-384 generator
///
/// This is computed once on first use and cached for the lifetime of the program.
/// Uses `Lazy` for thread-safe lazy initialization.
pub static PRECOMPUTED_TABLE: Lazy<PrecomputedTable> = Lazy::new(|| PrecomputedTable::new());

/// Fast scalar multiplication with the P-384 generator using precomputed tables
///
/// This is the recommended way to compute k * G for P-384, as it's ~5-10x faster
/// than generic scalar multiplication.
///
/// # Performance
///
/// - First call: includes one-time table generation (~1ms)
/// - Subsequent calls: ~5-10x faster than generic scalar multiplication
///
/// # Arguments
///
/// * `scalar` - 384-bit scalar in big-endian byte order
///
/// # Returns
///
/// The point k * G where G is the P-384 generator
///
/// # Examples
///
/// ```ignore
/// use hpcrypt_curves::p384::precomputed::scalar_mul_generator_fast;
///
/// let scalar = [0x42; 48]; // Some scalar
/// let result = scalar_mul_generator_fast(&scalar);
/// ```
pub fn scalar_mul_generator_fast(scalar: &[u8; 48]) -> Point {
    PRECOMPUTED_TABLE.scalar_mul_generator(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precomputed_table_construction() {
        extern crate std;
        use std::println;

        // Verify table construction is correct
        let table = PrecomputedTable::new();
        let g = Point::generator();

        println!("\n=== Verifying table construction ===");

        // Check tables[0] which should be multiples of 2^0 * G = G
        println!("\nChecking tables[0] (multiples of G):");
        for mult in 1..=3 {
            let expected = {
                let mut acc = Point::infinity();
                for _ in 0..mult {
                    acc = acc.add(&g);
                }
                acc
            };
            let from_table = Point {
                x: table.tables[0][mult].x,
                y: table.tables[0][mult].y,
                z: super::FieldElement::one(),
            };

            // Compare affine coordinates (normalize Jacobian points)
            let expected_affine = expected.to_affine().expect("Point should be valid");
            let from_table_affine = from_table.to_affine().expect("Point should be valid");

            println!(
                "  {}*G: match = {}",
                mult,
                expected_affine.x == from_table_affine.x
                    && expected_affine.y == from_table_affine.y
            );
            assert_eq!(
                expected_affine.x, from_table_affine.x,
                "tables[0][{}] x mismatch",
                mult
            );
            assert_eq!(
                expected_affine.y, from_table_affine.y,
                "tables[0][{}] y mismatch",
                mult
            );
        }

        // Check tables[1] which should be multiples of 2^4 * G = 16*G
        println!("\nChecking tables[1] (multiples of 16*G):");
        let mut base_16g = g;
        for _ in 0..4 {
            base_16g = base_16g.double();
        }
        for mult in 1..=2 {
            let expected = {
                let mut acc = Point::infinity();
                for _ in 0..mult {
                    acc = acc.add(&base_16g);
                }
                acc
            };
            let from_table = Point {
                x: table.tables[1][mult].x,
                y: table.tables[1][mult].y,
                z: super::FieldElement::one(),
            };

            // Compare affine coordinates (normalize Jacobian points)
            let expected_affine = expected.to_affine().expect("Point should be valid");
            let from_table_affine = from_table.to_affine().expect("Point should be valid");

            println!(
                "  {}*16G: match = {}",
                mult,
                expected_affine.x == from_table_affine.x
                    && expected_affine.y == from_table_affine.y
            );
            assert_eq!(
                expected_affine.x, from_table_affine.x,
                "tables[1][{}] x mismatch",
                mult
            );
            assert_eq!(
                expected_affine.y, from_table_affine.y,
                "tables[1][{}] y mismatch",
                mult
            );
        }

        println!("\nTable construction verified!");
    }

    #[test]
    fn test_simple_scalars() {
        extern crate std;
        use std::println;

        let g = Point::generator();

        // Test scalar = 1
        println!("\n=== Testing scalar 1 ===");
        let mut scalar_1 = [0x00; 48];
        scalar_1[47] = 0x01;

        let result_precomputed = scalar_mul_generator_fast(&scalar_1);
        let result_regular = g.scalar_mul(&scalar_1);

        println!("Match: {}", result_precomputed == result_regular);
        assert_eq!(result_precomputed, result_regular, "Failed for scalar 1");

        // Test scalar = 2
        println!("\n=== Testing scalar 2 ===");
        let mut scalar_2 = [0x00; 48];
        scalar_2[47] = 0x02;

        let result_precomputed = scalar_mul_generator_fast(&scalar_2);
        let result_regular = g.scalar_mul(&scalar_2);

        println!("Match: {}", result_precomputed == result_regular);
        assert_eq!(result_precomputed, result_regular, "Failed for scalar 2");

        // Test scalar = 15
        println!("\n=== Testing scalar 15 ===");
        let mut scalar_15 = [0x00; 48];
        scalar_15[47] = 0x0F;

        let result_precomputed = scalar_mul_generator_fast(&scalar_15);
        let result_regular = g.scalar_mul(&scalar_15);

        println!("Match: {}", result_precomputed == result_regular);
        assert_eq!(result_precomputed, result_regular, "Failed for scalar 15");

        // Test scalar = 16
        println!("\n=== Testing scalar 16 ===");
        let mut scalar_16 = [0x00; 48];
        scalar_16[47] = 0x10;

        let result_precomputed = scalar_mul_generator_fast(&scalar_16);
        let result_regular = g.scalar_mul(&scalar_16);

        println!("Match: {}", result_precomputed == result_regular);
        assert_eq!(result_precomputed, result_regular, "Failed for scalar 16");
    }

    #[test]
    fn test_precomputed_table_matches_regular_multiplication() {
        // Test that precomputed table gives the same results as regular scalar multiplication
        let g = Point::generator();

        // Test several scalar values
        let test_scalars = [
            [0x00; 48], // Zero (edge case)
            {
                let mut s = [0x00; 48];
                s[47] = 0x01; // One
                s
            },
            {
                let mut s = [0x00; 48];
                s[47] = 0x02; // Two
                s
            },
            {
                let mut s = [0x00; 48];
                s[47] = 0x0F; // 15
                s
            },
            {
                let mut s = [0x00; 48];
                s[47] = 0x10; // 16
                s
            },
            {
                let mut s = [0x00; 48];
                s[47] = 0xFF; // 255
                s
            },
            [0x42; 48], // Arbitrary value
            [0xFF; 48], // Maximum value (edge case)
        ];

        for scalar in &test_scalars {
            let result_precomputed = scalar_mul_generator_fast(scalar);
            let result_regular = g.scalar_mul(scalar);

            // Compare using affine coordinates (normalize before comparison)
            if bool::from(result_precomputed.is_infinity()) {
                assert!(
                    bool::from(result_regular.is_infinity()),
                    "Precomputed is infinity but regular is not for scalar {:?}",
                    scalar
                );
            } else if bool::from(result_regular.is_infinity()) {
                assert!(
                    bool::from(result_precomputed.is_infinity()),
                    "Regular is infinity but precomputed is not for scalar {:?}",
                    scalar
                );
            } else {
                let precomputed_affine = result_precomputed.to_affine().expect("Valid point");
                let regular_affine = result_regular.to_affine().expect("Valid point");

                assert_eq!(
                    precomputed_affine.x, regular_affine.x,
                    "X coordinates differ for scalar {:?}",
                    scalar
                );
                assert_eq!(
                    precomputed_affine.y, regular_affine.y,
                    "Y coordinates differ for scalar {:?}",
                    scalar
                );
            }
        }
    }

    #[test]
    fn test_precomputed_generator_on_curve() {
        // Verify that precomputed results are valid points on the curve
        let test_scalars = [
            {
                let mut s = [0x00; 48];
                s[47] = 0x01;
                s
            },
            {
                let mut s = [0x00; 48];
                s[47] = 0x42;
                s
            },
            [0x13; 48],
        ];

        for scalar in &test_scalars {
            let result = scalar_mul_generator_fast(scalar);
            assert!(
                bool::from(result.is_on_curve()),
                "Precomputed result is not on curve for scalar {:?}",
                scalar
            );
        }
    }

    #[test]
    fn test_mixed_addition() {
        let g = Point::generator();
        let two_g = g.double();

        // Convert g to affine
        let g_affine = g.to_affine().expect("Generator should convert to affine");

        // Mixed addition: 2G + G (affine)
        let three_g_mixed = two_g.add_affine(&g_affine);

        // Regular addition: 2G + G (Jacobian)
        let three_g_regular = two_g.add(&g);

        assert_eq!(
            three_g_mixed, three_g_regular,
            "Mixed addition should match regular addition"
        );
    }

    #[test]
    fn test_to_affine_and_back() {
        let g = Point::generator();

        // Convert to affine
        let g_affine = g.to_affine().expect("Generator should convert to affine");

        // Convert back to Jacobian
        let g_back = Point {
            x: g_affine.x,
            y: g_affine.y,
            z: FieldElement::one(),
        };

        assert_eq!(g, g_back, "Affine conversion should be reversible");
    }

    #[test]
    fn test_infinity_to_affine() {
        let inf = Point::infinity();
        assert!(
            inf.to_affine().is_none(),
            "Infinity should not convert to affine"
        );
    }
}
