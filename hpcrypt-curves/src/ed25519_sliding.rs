//! Sliding Window Scalar Multiplication for Ed25519
//!
//! This module implements the sliding window method which adapts the window size
//! based on the scalar bit pattern, potentially reducing point additions.
//!
//! # Algorithm
//!
//! Unlike fixed windowing which always uses the same window size (e.g., 4 bits),
//! sliding window:
//! 1. Scans for the next 1 bit
//! 2. Reads up to w bits starting from that 1 bit
//! 3. Looks up the corresponding odd multiple
//! 4. Skips ahead by the window size
//!
//! # Expected Performance
//!
//! - Fewer table lookups than fixed windowing (only on odd windows)
//! - Same precomputation cost as fixed windowing
//! - Claims: 10-20% faster than fixed windowing
//!
//! # Reality Check
//!
//! Based on previous benchmarks:
//! - Simple NAF is already 11.9% faster than 4-bit windowing
//! - Wider windows add overhead that outweighs benefits
//! - Skeptical that sliding windows will help, but let's validate

extern crate alloc;

use super::ed25519::EdwardsPoint;
use alloc::vec::Vec;

/// Sliding window scalar multiplication with configurable window width
///
/// # Arguments
///
/// * `point` - The base point P
/// * `scalar` - The scalar value as 32 bytes
/// * `width` - Window width (typically 4 or 5)
///
/// # Returns
///
/// The result of scalar × point
///
/// # Algorithm
///
/// ```text
/// 1. Precompute odd multiples: [P, 3P, 5P, ..., (2^w - 1)P]
/// 2. Initialize result = O (identity)
/// 3. i = 255 (start from MSB)
/// 4. while i >= 0:
///    if scalar\[i\] == 0:
///        result = double(result)
///        i = i - 1
///    else:
///        // Found a 1 bit, read window
///        j = max(i - w + 1, 0)
///        // Extract w bits from position j to i
///        window_value = extract_bits(scalar, j, i)
///        // Convert to odd value
///        while window_value is even and j < i:
///            window_value = window_value / 2
///            j = j + 1
///        // Double (i - j) times
///        for _ in 0..(i - j):
///            result = double(result)
///        // Add the odd multiple
///        result = result + odd_multiple\[window_value\]
///        i = j - 1
/// 5. Return result
/// ```
pub fn sliding_window_scalar_mul(
    point: &EdwardsPoint,
    scalar: &[u8; 32],
    width: usize,
) -> EdwardsPoint {
    debug_assert!(
        width >= 2 && width <= 5,
        "Window width must be in range [2, 5]"
    );

    // Step 1: Precompute odd multiples: P, 3P, 5P, ..., (2^w - 1)P
    let num_odd = 1 << (width - 1); // 2^(w-1) odd multiples
    let mut odd_multiples = Vec::with_capacity(num_odd);

    odd_multiples.push(*point); // 1P

    if num_odd > 1 {
        let double_p = point.double(); // 2P
        for i in 1..num_odd {
            // (2i+1)P = (2i-1)P + 2P
            odd_multiples.push(odd_multiples[i - 1].add(&double_p));
        }
    }

    // Step 2: Convert scalar to bit array for easier access
    let mut bits = [false; 256];
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            bits[byte_idx * 8 + bit_idx] = ((scalar[byte_idx] >> bit_idx) & 1) == 1;
        }
    }

    // Step 3: Sliding window algorithm
    let mut result = EdwardsPoint::IDENTITY;
    let mut i = 255; // Start from MSB

    while i >= 0 {
        if !bits[i as usize] {
            // Bit is 0: just double
            result = result.double();
            i -= 1;
            if i < 0 {
                break;
            }
        } else {
            // Bit is 1: read a window
            let mut j = if i >= (width as i32 - 1) {
                i - width as i32 + 1
            } else {
                0
            };

            // Extract window value from bits[j..=i]
            let mut window_value = 0usize;
            for k in j..=i {
                if bits[k as usize] {
                    window_value |= 1 << (k - j);
                }
            }

            // Make window value odd by dividing out trailing zeros
            while window_value > 0 && (window_value & 1) == 0 {
                window_value >>= 1;
                j += 1;
            }

            // Double (i - j + 1) times to make room for the entire window
            for _ in 0..(i - j + 1) {
                result = result.double();
            }

            // Add the odd multiple
            if window_value > 0 {
                debug_assert!(window_value % 2 == 1, "Window value must be odd");
                let odd_index = (window_value - 1) / 2;
                if odd_index < odd_multiples.len() {
                    result = result.add(&odd_multiples[odd_index]);
                }
            }

            i = j - 1;
            if i < 0 {
                break;
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::base_point;

    #[test]
    fn test_sliding_window_correctness() {
        let point = base_point();
        let scalar = [0x42u8; 32];

        // Compare with standard scalar multiplication
        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 4);

        assert_eq!(
            result.encode(),
            expected.encode(),
            "Sliding window must produce same result as standard method"
        );
    }

    #[test]
    fn test_sliding_window_width_3() {
        let point = base_point();
        let scalar = [0x12u8; 32];

        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 3);

        assert_eq!(result.encode(), expected.encode());
    }

    #[test]
    fn test_sliding_window_width_5() {
        let point = base_point();
        let scalar = [0xffu8; 32];

        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 5);

        assert_eq!(result.encode(), expected.encode());
    }
}
