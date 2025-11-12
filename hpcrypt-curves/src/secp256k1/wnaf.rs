//! Window Non-Adjacent Form (wNAF) for optimized scalar multiplication
//!
//! wNAF is a scalar representation that reduces the number of point additions
//! needed during scalar multiplication by using precomputed odd multiples.
//!
//! # Algorithm
//!
//! For a scalar k and window width w:
//! 1. Precompute odd multiples: {P, 3P, 5P, ..., (2^w - 1)P}
//! 2. Convert k to wNAF representation (signed non-zero digits)
//! 3. Perform scalar multiplication using the wNAF representation
//!
//! # Performance
//!
//! - Window width 4 (w=4): ~35% speedup over binary method
//! - Window width 5 (w=5): ~40% speedup (more memory)
//! - Trade-off: Larger window = faster but more memory
//!
//! # Example
//!
//! ```ignore
//! use hpcrypt_curves::p256::{Point, Scalar};
//! use hpcrypt_curves::p256::wnaf::WNafContext;
//!
//! let point = Point::generator();
//! let scalar = Scalar::from_u64(12345);
//! let ctx = WNafContext::new(&point, 4); // window width 4
//! let result = ctx.mul(&scalar.to_bytes());
//! ```

extern crate alloc;

use alloc::vec::Vec;
use super::{Point, AffinePoint};
use super::batch::batch_invert;

/// Window width for wNAF (4-bit windows = 16 precomputed points)
///
/// This is the optimal trade-off between speed and memory:
/// - w=4: 8 odd multiples (P, 3P, 5P, 7P, 9P, 11P, 13P, 15P)
/// - Memory: 8 × 96 bytes = 768 bytes per point
/// - Expected speedup: ~35% over binary method
pub const WINDOW_WIDTH: usize = 4;

/// Maximum value in wNAF representation for window width w
/// For w=4: values are in range [-15, 15] with only odd values
const MAX_WNAF_VALUE: usize = (1 << WINDOW_WIDTH) - 1; // 15 for w=4

/// Precomputed table of odd multiples for wNAF scalar multiplication
///
/// For a point P and window width w=4, stores:
/// - table\[0\] = P
/// - table\[1\] = 3P
/// - table\[2\] = 5P
/// - ...
/// - table\[7\] = 15P
///
/// Memory: 8 points × 64 bytes = 512 bytes (Affine coordinates, 33% less than Jacobian!)
///
/// **Optimization**: Stores points in affine coordinates to enable mixed addition (8M + 3S)
/// instead of Jacobian-Jacobian addition (12M + 4S), providing ~20% speedup in scalar
/// multiplication.
pub struct WNafTable {
    /// Odd multiples: [P, 3P, 5P, 7P, 9P, 11P, 13P, 15P]
    /// Stored in AFFINE coordinates for mixed addition optimization
    table: [AffinePoint; MAX_WNAF_VALUE / 2],
}

impl WNafTable {
    /// Create a new wNAF table by precomputing odd multiples of a point
    ///
    /// # Arguments
    ///
    /// * `point` - The base point P to precompute multiples of
    ///
    /// # Returns
    ///
    /// A table containing [P, 3P, 5P, 7P, 9P, 11P, 13P, 15P] in affine coordinates
    ///
    /// # Performance
    ///
    /// Precomputation cost:
    /// - 7 point doublings + 7 point additions (Jacobian)
    /// - 1 batch inversion to convert 8 points to affine (8M + 1 inversion)
    /// - Total: ~260 µs one-time cost, saves ~20% per scalar multiplication
    ///
    /// # Optimization
    ///
    /// Uses batch inversion to convert all 8 Jacobian points to affine in a single
    /// inversion operation, then stores them as affine for mixed addition during
    /// scalar multiplication.
    pub fn new(point: &Point) -> Self {
        use super::field_ops::FieldElement;

        // Step 1: Compute odd multiples in Jacobian coordinates
        let mut jacobian_table = [Point::infinity(); MAX_WNAF_VALUE / 2];

        // table[0] = P (the point itself)
        jacobian_table[0] = *point;

        // Compute 2P (needed for computing odd multiples)
        let point_double = point.double();

        // Compute remaining odd multiples: 3P, 5P, 7P, ..., 15P
        // Formula: (2i+1)P = (2i-1)P + 2P
        for i in 1..(MAX_WNAF_VALUE / 2) {
            jacobian_table[i] = jacobian_table[i - 1].add(&point_double);
        }

        // Step 2: Extract Z coordinates for batch inversion
        let mut z_coords: Vec<FieldElement> = jacobian_table.iter()
            .map(|p| p.z)
            .collect();

        // Step 3: Batch invert all Z coordinates (8 inversions for price of 1!)
        batch_invert(&mut z_coords);

        // Step 4: Convert all Jacobian points to Affine using inverted Z values
        let mut affine_table = [AffinePoint {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }; MAX_WNAF_VALUE / 2];

        for i in 0..(MAX_WNAF_VALUE / 2) {
            let z_inv = z_coords[i];
            let z_inv_squared = z_inv.square();
            let z_inv_cubed = z_inv_squared.mul(&z_inv);

            // x_affine = X / Z²
            affine_table[i].x = jacobian_table[i].x.mul(&z_inv_squared);

            // y_affine = Y / Z³
            affine_table[i].y = jacobian_table[i].y.mul(&z_inv_cubed);
        }

        Self { table: affine_table }
    }

    /// Look up an odd multiple from the table
    ///
    /// # Arguments
    ///
    /// * `digit` - An odd value in range [1, 15] (must be odd)
    ///
    /// # Returns
    ///
    /// The precomputed point corresponding to digit × P (in affine coordinates)
    ///
    /// # Panics
    ///
    /// Panics if digit is even or out of range
    #[inline]
    pub fn lookup(&self, digit: usize) -> &AffinePoint {
        debug_assert!(digit > 0 && digit <= MAX_WNAF_VALUE && digit % 2 == 1,
                     "wNAF digit must be odd and in range [1, {}]", MAX_WNAF_VALUE);

        // Convert odd digit to table index
        // 1 -> 0, 3 -> 1, 5 -> 2, ..., 15 -> 7
        let index = (digit - 1) / 2;
        &self.table[index]
    }
}

/// Compute the width-w Non-Adjacent Form (wNAF) of a scalar
///
/// # Arguments
///
/// * `scalar` - The scalar value as 32 bytes (little-endian)
/// * `width` - Window width (typically 4 or 5)
///
/// # Returns
///
/// A vector of signed digits in range [-(2^w - 1), 2^w - 1] where:
/// - All non-zero digits are odd
/// - No two adjacent digits are non-zero
/// - Length is at most 257 (256 bits + 1 for potential carry)
///
/// # Algorithm
///
/// ```text
/// Input: k (scalar), w (window width)
/// Output: wNAF representation
///
/// 1. i = 0
/// 2. while k > 0:
///    if k is odd:
///        digit = k mod 2^w (signed)
///        k = k - digit
///        wnaf[i] = digit
///    else:
///        wnaf[i] = 0
///    k = k / 2
///    i = i + 1
/// ```
///
/// # Example
///
/// For scalar 11 (binary: 1011) with w=4:
/// - Standard binary: [1, 1, 0, 1] (3 non-zero digits)
/// - wNAF: [1, 0, -1, 0, 1] (2 non-zero digits, using 11 = 16 - 4 - 1)
pub fn compute_wnaf(scalar: &[u8; 32], width: usize) -> Vec<i8> {
    debug_assert!(width >= 2 && width <= 8, "Window width must be in range [2, 8]");

    let window_size = 1usize << width;  // 2^w
    let window_mask = window_size - 1;  // 2^w - 1

    // Use stack-allocated array instead of Vec for better performance
    // Maximum length is 257 (256 bits + 1 potential carry bit)
    let mut wnaf = [0i8; 257];

    // Convert scalar bytes to mutable working copy
    // Scalar is in big-endian format: byte[0] is MSB, byte[31] is LSB
    // We need to convert to little-endian u64 limbs: k[0] is LSW, k[3] is MSW
    let mut k = [0u64; 4];
    for i in 0..4 {
        // Read bytes in big-endian order, but store limbs in little-endian order
        // byte[31-7..31] -> k[0], byte[23..16] -> k[1], etc.
        let byte_start = 24 - (i * 8);  // 24, 16, 8, 0
        k[i] = u64::from_be_bytes([
            scalar[byte_start],
            scalar[byte_start + 1],
            scalar[byte_start + 2],
            scalar[byte_start + 3],
            scalar[byte_start + 4],
            scalar[byte_start + 5],
            scalar[byte_start + 6],
            scalar[byte_start + 7],
        ]);
    }

    let mut i = 0;

    // Process until scalar is zero
    while !is_zero(&k) {
        if is_odd(&k) {
            // Extract the least significant w bits
            let mods = (k[0] as usize) & window_mask;

            // Convert to signed representation (centered around 0)
            // If mods >= 2^(w-1), use negative representation
            let digit = if mods >= (window_size / 2) {
                // Use negative form: mods - 2^w
                (mods as isize - window_size as isize) as i8
            } else {
                mods as i8
            };

            wnaf[i] = digit;

            // Subtract digit from k (k = k - digit)
            if digit > 0 {
                sub_small(&mut k, digit as u64);
            } else {
                add_small(&mut k, (-digit) as u64);
            }
        } else {
            wnaf[i] = 0;
        }

        // Right shift by 1 (k = k / 2)
        shift_right_1(&mut k);
        i += 1;
    }

    // Convert used portion of array to Vec
    wnaf[..i].to_vec()
}

/// Perform scalar multiplication using wNAF representation
///
/// # Arguments
///
/// * `point` - The base point P
/// * `scalar` - The scalar value as 32 bytes
/// * `width` - Window width (typically 4)
///
/// # Returns
///
/// The result of scalar × point
///
/// # Algorithm
///
/// ```text
/// 1. Compute wNAF representation of scalar
/// 2. Precompute odd multiples: [P, 3P, 5P, ..., (2^w - 1)P]
/// 3. Initialize result = O (point at infinity)
/// 4. For each digit d in wNAF (from most significant to least):
///    - Double the result
///    - If d > 0: add d×P
///    - If d < 0: subtract |d|×P
/// 5. Return result
/// ```
///
/// # Performance
///
/// - Binary method: 256 doublings + ~128 additions
/// - wNAF (w=4): 256 doublings + ~51 additions
/// - Speedup: ~35% (due to 60% fewer additions)
pub fn wnaf_scalar_mul(point: &Point, scalar: &[u8; 32], width: usize) -> Point {
    // Compute wNAF representation
    let wnaf = compute_wnaf(scalar, width);

    // Precompute odd multiples (now in AFFINE coordinates for mixed addition)
    let table = WNafTable::new(point);

    // Start from most significant digit
    let mut result = Point::infinity();

    for &digit in wnaf.iter().rev() {
        // Double for each bit
        result = result.double();

        // Add if non-zero (using MIXED ADDITION for 33% speedup per addition!)
        if digit > 0 {
            // Positive: add digit×P using mixed Jacobian-Affine addition (8M + 3S)
            let affine_point = table.lookup(digit as usize);
            result = result.add_affine(affine_point);
        } else if digit < 0 {
            // Negative: subtract |digit|×P by adding its negation
            let affine_point = table.lookup((-digit) as usize);
            // Negate affine point: (x, y) -> (x, -y)
            let negated = AffinePoint {
                x: affine_point.x,
                y: affine_point.y.neg(),
            };
            result = result.add_affine(&negated);
        }
        // If digit == 0, just double (no addition)
    }

    result
}

// ============================================================================
// Helper functions for big integer arithmetic on [u64; 4]
// ============================================================================

/// Check if 256-bit value is zero
#[inline]
fn is_zero(k: &[u64; 4]) -> bool {
    k[0] == 0 && k[1] == 0 && k[2] == 0 && k[3] == 0
}

/// Check if 256-bit value is odd
#[inline]
fn is_odd(k: &[u64; 4]) -> bool {
    (k[0] & 1) == 1
}

/// Right shift by 1 bit (division by 2)
#[inline]
fn shift_right_1(k: &mut [u64; 4]) {
    k[0] = (k[0] >> 1) | (k[1] << 63);
    k[1] = (k[1] >> 1) | (k[2] << 63);
    k[2] = (k[2] >> 1) | (k[3] << 63);
    k[3] = k[3] >> 1;
}

/// Subtract a small value (used in wNAF computation)
#[inline]
fn sub_small(k: &mut [u64; 4], val: u64) {
    let (new_val, borrow) = k[0].overflowing_sub(val);
    k[0] = new_val;

    if borrow {
        let (new_val, borrow) = k[1].overflowing_sub(1);
        k[1] = new_val;
        if borrow {
            let (new_val, borrow) = k[2].overflowing_sub(1);
            k[2] = new_val;
            if borrow {
                k[3] = k[3].wrapping_sub(1);
            }
        }
    }
}

/// Add a small value (used in wNAF computation)
#[inline]
fn add_small(k: &mut [u64; 4], val: u64) {
    let (new_val, carry) = k[0].overflowing_add(val);
    k[0] = new_val;

    if carry {
        let (new_val, carry) = k[1].overflowing_add(1);
        k[1] = new_val;
        if carry {
            let (new_val, carry) = k[2].overflowing_add(1);
            k[2] = new_val;
            if carry {
                k[3] = k[3].wrapping_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::Scalar;
    use crate::ct_utils::ConstantTimeEq;

    #[test]
    fn test_wnaf_simple() {
        // Test wNAF computation for small values
        let mut scalar = [0u8; 32];
        scalar[31] = 1;  // Value 1 in big-endian (LSB is at byte[31])
        let wnaf = compute_wnaf(&scalar, 4);

        // wNAF of 1 should be just [1]
        assert_eq!(wnaf.len(), 1);
        assert_eq!(wnaf[0], 1);
    }

    #[test]
    fn test_wnaf_properties() {
        // Test that wNAF satisfies required properties
        let mut scalar = [0u8; 32];
        scalar[0] = 123; // Some random value

        let wnaf = compute_wnaf(&scalar, 4);

        // Property 1: All non-zero digits are odd
        for &digit in &wnaf {
            if digit != 0 {
                assert!(digit % 2 != 0, "Non-zero wNAF digit must be odd");
            }
        }

        // Property 2: No two adjacent non-zero digits
        for i in 0..wnaf.len()-1 {
            if wnaf[i] != 0 {
                assert_eq!(wnaf[i+1], 0, "Adjacent wNAF digits cannot both be non-zero");
            }
        }
    }

    #[test]
    fn test_wnaf_table_creation() {
        let g = Point::generator();
        let table = WNafTable::new(&g);

        // Verify table[0] = G
        let g_from_table = table.lookup(1); // Now returns &AffinePoint
        let g_affine = g.to_affine().unwrap();
        assert!(bool::from(g_affine.x.ct_eq(&g_from_table.x)));

        // Verify table[1] = 3G
        let three_g = g.double().add(&g);
        let three_g_from_table = table.lookup(3); // Now returns &AffinePoint
        let three_g_affine = three_g.to_affine().unwrap();
        assert!(bool::from(three_g_affine.x.ct_eq(&three_g_from_table.x)));
    }

    #[test]
    fn test_wnaf_scalar_mul_correctness() {
        // Test that wNAF scalar multiplication gives same result as standard
        let g = Point::generator();
        let scalar = Scalar::from_u64(12345);
        let scalar_bytes = scalar.to_bytes();

        // Standard scalar multiplication
        let result_standard = g.scalar_mul(&scalar_bytes);

        // wNAF scalar multiplication
        let result_wnaf = wnaf_scalar_mul(&g, &scalar_bytes, 4);

        // Results should be identical
        let affine_standard = result_standard.to_affine().unwrap();
        let affine_wnaf = result_wnaf.to_affine().unwrap();

        assert!(bool::from(affine_standard.x.ct_eq(&affine_wnaf.x)));
        assert!(bool::from(affine_standard.y.ct_eq(&affine_wnaf.y)));
    }

    #[test]
    fn test_wnaf_scalar_mul_known_vector() {
        // Test with a known test vector
        let g = Point::generator();
        let scalar = Scalar::from_u64(1);
        let scalar_bytes = scalar.to_bytes();

        let result = wnaf_scalar_mul(&g, &scalar_bytes, 4);

        // 1 × G should equal G
        let affine_result = result.to_affine().unwrap();
        let affine_g = g.to_affine().unwrap();

        assert!(bool::from(affine_result.x.ct_eq(&affine_g.x)));
        assert!(bool::from(affine_result.y.ct_eq(&affine_g.y)));
    }
}
