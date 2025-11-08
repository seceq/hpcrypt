//! Sliding Window Scalar Multiplication for Ed448
//!
//! This module implements the sliding window method for Ed448, which adapts the window size
//! based on the scalar bit pattern, reducing point additions compared to fixed windowing.
//!
//! Based on the Ed25519 implementation which achieved 35.9% speedup over fixed windowing.

extern crate alloc;
use alloc::vec::Vec;

use super::point::Point;
use super::scalar::Scalar;

/// Sliding window scalar multiplication with configurable window width
///
/// # Arguments
///
/// * `point` - The base point P
/// * `scalar` - The scalar value
/// * `width` - Window width (typically 4 or 5)
///
/// # Returns
///
/// The result of scalar × point
///
/// # Algorithm
///
/// The sliding window method processes the scalar adaptively:
/// 1. Precompute odd multiples: [P, 3P, 5P, ..., (2^w - 1)P]
/// 2. Scan scalar from MSB to LSB
/// 3. When a 1 bit is found, read up to w bits to form a window
/// 4. Ensure window value is odd (skip trailing zeros)
/// 5. Double appropriate number of times and add the odd multiple
///
/// # Performance
///
/// Expected based on Ed25519 results:
/// - Fixed 4-bit windowing: ~112 additions, 448 doublings
/// - Sliding window: ~45 additions, 448 doublings
/// - Expected speedup: 25-35% (based on Ed25519's 35.9% improvement)
pub fn sliding_window_scalar_mul(point: &Point, scalar: &Scalar, width: usize) -> Point {
    debug_assert!(width >= 2 && width <= 5, "Window width must be in range [2, 5]");

    // Step 1: Precompute odd multiples: P, 3P, 5P, ..., (2^w - 1)P
    let num_odd = 1 << (width - 1);  // 2^(w-1) odd multiples
    let mut odd_multiples = Vec::with_capacity(num_odd);

    odd_multiples.push(*point);  // 1P

    if num_odd > 1 {
        let double_p = point.double();  // 2P
        for i in 1..num_odd {
            // (2i+1)P = (2i-1)P + 2P
            odd_multiples.push(odd_multiples[i - 1].add(&double_p));
        }
    }

    // Step 2: Convert scalar to bit array for easier access
    // Ed448 scalars are 57 bytes (456 bits), but we process 448 bits
    let scalar_bytes = scalar.to_bytes();
    let mut bits = [false; 448];

    for byte_idx in 0..56 {  // 56 bytes = 448 bits
        for bit_idx in 0..8 {
            let bit_position = byte_idx * 8 + bit_idx;
            if bit_position < 448 {
                bits[bit_position] = ((scalar_bytes[byte_idx] >> bit_idx) & 1) == 1;
            }
        }
    }

    // Step 3: Sliding window algorithm
    let mut result = Point::identity();
    let mut i = 447;  // Start from MSB (bit 447)

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

    #[test]
    fn test_sliding_window_correctness() {
        let point = Point::generator();
        let mut scalar_bytes = [0x00u8; 57];
        scalar_bytes[0] = 0x42;  // Small scalar that doesn't need reduction
        let scalar = Scalar::from_bytes(&scalar_bytes);

        // Compare with standard scalar multiplication
        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 4);

        assert_eq!(result, expected, "Sliding window must produce same result as standard method");
    }

    #[test]
    fn test_sliding_window_width_3() {
        let point = Point::generator();
        let mut scalar_bytes = [0x00u8; 57];
        scalar_bytes[0] = 0x12;  // Small scalar
        let scalar = Scalar::from_bytes(&scalar_bytes);

        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 3);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sliding_window_width_5() {
        let point = Point::generator();
        let mut scalar_bytes = [0x00u8; 57];
        scalar_bytes[0] = 0xff;  // Small scalar with all bits set in first byte
        let scalar = Scalar::from_bytes(&scalar_bytes);

        let expected = point.scalar_mul(&scalar);
        let result = sliding_window_scalar_mul(&point, &scalar, 5);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sliding_window_zero_scalar() {
        let point = Point::generator();
        let scalar_bytes = [0x00u8; 57];
        let scalar = Scalar::from_bytes(&scalar_bytes);

        let result = sliding_window_scalar_mul(&point, &scalar, 4);
        assert_eq!(result, Point::identity(), "0 × P should be identity");
    }

    #[test]
    fn test_debug_scalar_42() {
        let point = Point::generator();
        let mut scalar_bytes = [0x00u8; 57];
        scalar_bytes[0] = 0x42;
        let scalar = Scalar::from_bytes(&scalar_bytes);

        extern crate std;
        std::println!("\nScalar bytes input: {:?}", &scalar_bytes[0..8]);
        std::println!("Scalar to_bytes: {:?}", &scalar.to_bytes()[0..8]);

        let expected_mul = point.scalar_mul(&scalar);
        let result_sliding = sliding_window_scalar_mul(&point, &scalar, 4);

        std::println!("\nsliding == scalar_mul? {}", result_sliding == expected_mul);

        assert_eq!(result_sliding, expected_mul, "Sliding window failed for scalar=0x42");
    }

    #[test]
    fn test_sliding_window_one_scalar() {
        let point = Point::generator();
        let mut scalar_bytes = [0x00u8; 57];
        scalar_bytes[0] = 0x01;
        let scalar = Scalar::from_bytes(&scalar_bytes);

        let result = sliding_window_scalar_mul(&point, &scalar, 4);
        assert_eq!(result, point, "1 × P should be P");
    }
}
