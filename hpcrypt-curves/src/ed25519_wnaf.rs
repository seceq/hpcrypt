//! Window Non-Adjacent Form (wNAF) for Ed25519 scalar multiplication
//!
//! This module implements w-NAF scalar multiplication for Ed25519, which improves
//! performance by reducing the number of point additions through precomputation.
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
//! - Simple NAF (w=2): ~63.5 µs (baseline)
//! - Window width 4 (w=4): Expected ~48-54 µs (15-25% faster)
//! - Window width 5 (w=5): Expected ~45-51 µs (20-30% faster, more memory)

extern crate alloc;

use alloc::vec::Vec;
use super::ed25519::{EdwardsPoint, Scalar};
use super::field25519::FieldElement;

/// Window width for wNAF scalar multiplication
///
/// Trade-offs:
/// - w=4: 8 odd multiples, ~512 bytes, ~15-25% speedup (DEFAULT)
/// - w=5: 16 odd multiples, ~1 KB, ~20-30% speedup (FAST)
pub const WINDOW_WIDTH: usize = 4;

/// Maximum value in wNAF representation for window width w
/// - w=4: values in range [-15, 15], 8 odd multiples
/// - w=5: values in range [-31, 31], 16 odd multiples
const MAX_WNAF_VALUE: usize = (1 << WINDOW_WIDTH) - 1;

/// Maximum table size (for w=5 which needs most entries)
const MAX_TABLE_SIZE: usize = 16;  // 2^5 / 2 = 16 odd multiples

/// Precomputed table of odd multiples for wNAF scalar multiplication
///
/// For a point P and window width w=4, stores:
/// - table[0] = P
/// - table[1] = 3P
/// - table[2] = 5P
/// - ...
/// - table[7] = 15P
///
/// For w=5, stores up to 16 odd multiples: [P, 3P, 5P, ..., 31P]
///
/// Memory: 8 points (w=4) or 16 points (w=5) × ~96 bytes = ~768-1536 bytes (Niels coordinates)
pub struct WNafTable {
    /// Odd multiples: [P, 3P, 5P, ...]
    /// Stored in NIELS coordinates for fast mixed addition
    table: [super::ed25519::NielsPoint; MAX_TABLE_SIZE],
    /// Number of entries actually used (depends on window width)
    len: usize,
}

impl WNafTable {
    /// Create a new wNAF table by precomputing odd multiples of a point
    ///
    /// # Arguments
    ///
    /// * `point` - The base point P to precompute multiples of
    /// * `width` - Window width (typically 4 or 5)
    ///
    /// # Returns
    ///
    /// A table containing [P, 3P, 5P, ..., (2^w-1)P] in Niels coordinates
    ///
    /// # Performance
    ///
    /// Precomputation cost:
    /// - w=4: 7 point doublings + 7 point additions, 8 conversions to Niels (~2 µs)
    /// - w=5: 15 point doublings + 15 point additions, 16 conversions to Niels (~4 µs)
    pub fn new(point: &EdwardsPoint, width: usize) -> Self {
        use super::ed25519::NielsPoint;

        debug_assert!(width >= 2 && width <= 5, "Window width must be in range [2, 5]");

        let num_entries = (1 << (width - 1));  // 2^(w-1) = number of odd multiples

        // Step 1: Compute odd multiples in extended coordinates
        let mut extended_table = [EdwardsPoint::IDENTITY; MAX_TABLE_SIZE];

        // table[0] = P (the point itself)
        extended_table[0] = *point;

        // Compute 2P (needed for computing odd multiples)
        let point_double = point.double();

        // Compute remaining odd multiples: 3P, 5P, 7P, ..., (2^w-1)P
        // Formula: (2i+1)P = (2i-1)P + 2P
        for i in 1..num_entries {
            extended_table[i] = extended_table[i - 1].add(&point_double);
        }

        // Step 2: Convert all extended points to Niels coordinates (pre-convert once!)
        let mut niels_table = [NielsPoint::IDENTITY; MAX_TABLE_SIZE];

        for i in 0..num_entries {
            niels_table[i] = NielsPoint::from_extended(&extended_table[i]);
        }

        Self {
            table: niels_table,
            len: num_entries,
        }
    }

    /// Look up an odd multiple from the table
    ///
    /// # Arguments
    ///
    /// * `digit` - An odd value in range [1, 2^w-1] (must be odd)
    ///
    /// # Returns
    ///
    /// The precomputed point corresponding to digit × P (in Niels coordinates)
    ///
    /// # Panics
    ///
    /// Panics if digit is even or out of range
    #[inline]
    pub fn lookup(&self, digit: usize) -> &super::ed25519::NielsPoint {
        debug_assert!(digit > 0 && digit % 2 == 1, "wNAF digit must be odd");

        // Convert odd digit to table index
        // 1 -> 0, 3 -> 1, 5 -> 2, ..., 15 -> 7, ..., 31 -> 15
        let index = (digit - 1) / 2;
        debug_assert!(index < self.len, "wNAF digit {} out of range for table size {}", digit, self.len * 2 + 1);
        &self.table[index]
    }
}

/// Compute the width-w Non-Adjacent Form (wNAF) of a scalar
///
/// # Arguments
///
/// * `scalar` - The scalar value as 32 bytes (little-endian for Ed25519)
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
pub fn compute_wnaf(scalar: &[u8; 32], width: usize) -> Vec<i8> {
    debug_assert!(width >= 2 && width <= 8, "Window width must be in range [2, 8]");

    let window_size = 1usize << width;  // 2^w
    let window_mask = window_size - 1;  // 2^w - 1

    // Use stack-allocated array instead of Vec for better performance
    // Maximum length is 257 (256 bits + 1 potential carry bit)
    let mut wnaf = [0i8; 257];

    // Convert scalar bytes to mutable working copy
    // Ed25519 scalars are in little-endian format: byte[0] is LSB, byte[31] is MSB
    let mut k = [0u64; 4];
    for i in 0..4 {
        // Read bytes in little-endian order
        let byte_start = i * 8;
        k[i] = u64::from_le_bytes([
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
/// - Simple NAF (w=2): 256 doublings + ~85 additions
/// - wNAF (w=4): 256 doublings + ~51 additions
/// - Speedup: ~15-25% (due to 40% fewer additions)
pub fn wnaf_scalar_mul(point: &EdwardsPoint, scalar: &[u8; 32], width: usize) -> EdwardsPoint {
    // Compute wNAF representation
    let wnaf = compute_wnaf(scalar, width);

    // Precompute odd multiples (in NIELS coordinates for fast mixed addition)
    let table = WNafTable::new(point, width);

    // Start from most significant digit
    let mut result = EdwardsPoint::IDENTITY;

    for &digit in wnaf.iter().rev() {
        // Double for each bit
        result = result.double();

        // Add if non-zero (using direct NIELS addition for maximum speed)
        if digit > 0 {
            // Positive: add digit×P using pre-converted Niels point
            let niels_point = table.lookup(digit as usize);
            result = result.add_niels(niels_point);
        } else if digit < 0 {
            // Negative: subtract |digit|×P using Niels subtraction
            let niels_point = table.lookup((-digit) as usize);
            result = result.sub_niels(niels_point);
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
    use crate::ed25519::base_point;

    #[test]
    fn test_wnaf_simple() {
        // Test wNAF computation for small values
        let mut scalar = [0u8; 32];
        scalar[0] = 1;  // Value 1 in little-endian (LSB is at byte[0])
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
        let g = base_point();
        let table = WNafTable::new(&g, 4);

        // Verify table[0] = G by using it in an addition
        let niels_g = table.lookup(1);
        let identity = EdwardsPoint::IDENTITY;
        let result = identity.add_niels(niels_g);
        let (result_x, result_y) = result.to_affine();
        let (g_x, g_y) = g.to_affine();

        // Check that identity + G = G
        assert_eq!(result_x.to_bytes(), g_x.to_bytes());
        assert_eq!(result_y.to_bytes(), g_y.to_bytes());

        // Verify table[1] = 3G by using it in an addition
        let three_g = g.double().add(&g);
        let niels_3g = table.lookup(3);
        let result_3g = identity.add_niels(niels_3g);
        let (result_3g_x, result_3g_y) = result_3g.to_affine();
        let (three_g_x, three_g_y) = three_g.to_affine();

        assert_eq!(result_3g_x.to_bytes(), three_g_x.to_bytes());
        assert_eq!(result_3g_y.to_bytes(), three_g_y.to_bytes());
    }

    #[test]
    fn test_wnaf_scalar_mul_correctness() {
        // Test that wNAF scalar multiplication gives same result as standard
        let g = base_point();
        let scalar = [0x42u8; 32];

        // Standard scalar multiplication
        let result_standard = g.scalar_mul(&scalar);

        // wNAF scalar multiplication
        let result_wnaf = wnaf_scalar_mul(&g, &scalar, 4);

        // Results should be identical
        let (x_std, y_std) = result_standard.to_affine();
        let (x_wnaf, y_wnaf) = result_wnaf.to_affine();

        assert_eq!(x_std.to_bytes(), x_wnaf.to_bytes());
        assert_eq!(y_std.to_bytes(), y_wnaf.to_bytes());
    }

    #[test]
    fn test_wnaf_scalar_mul_known_vector() {
        // Test with a known test vector
        let g = base_point();
        let mut scalar = [0u8; 32];
        scalar[0] = 1;  // 1 in little-endian

        let result = wnaf_scalar_mul(&g, &scalar, 4);

        // 1 × G should equal G
        let (result_x, result_y) = result.to_affine();
        let (g_x, g_y) = g.to_affine();

        assert_eq!(result_x.to_bytes(), g_x.to_bytes());
        assert_eq!(result_y.to_bytes(), g_y.to_bytes());
    }
}
