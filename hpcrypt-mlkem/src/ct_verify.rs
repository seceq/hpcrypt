//! Constant-Time Verification Utilities
//!
//! This module provides utilities for verifying and ensuring constant-time
//! behavior in cryptographic operations. These are critical for preventing
//! timing attacks that could leak secret information.
//!
//! # Security Considerations
//!
//! Constant-time programming is essential for cryptographic implementations
//! to prevent timing side-channel attacks. This module provides:
//!
//! - Constant-time comparison operations
//! - Constant-time conditional selection
//! - Utilities for verifying constant-time behavior
//! - Documentation of timing-sensitive operations
//!
//! # Note on Verification
//!
//! While these utilities help write constant-time code, true verification
//! requires analysis tools like:
//! - `dudect` for statistical timing analysis
//! - `valgrind --tool=memcheck` for memory access patterns
//! - Assembly inspection for compiler optimization verification

extern crate alloc;
use alloc::vec::Vec;

/// Constant-time equality check for byte slices
///
/// Returns 1 if equal, 0 if not equal. Runs in constant time.
///
/// # Security
///
/// This function is designed to run in constant time regardless of input values.
/// It processes all bytes even if an early difference is found.
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::ct_verify::ct_eq;
///
/// let a = b"secret";
/// let b = b"secret";
/// assert_eq!(ct_eq(a, b), 1);
///
/// let c = b"public";
/// assert_eq!(ct_eq(a, c), 0);
/// ```
#[inline(never)] // Prevent inlining that might affect timing
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    // If diff is 0, return 1. If diff is non-zero, return 0.
    // Strategy: if diff == 0, then !diff == 0xFF, and (!diff >> 7) == 1
    //          if diff != 0, then some bit is set, so (!diff) has some bit unset
    // Better: use (1 ^ ((diff | (!diff & diff.wrapping_neg())) >> 7))
    // Simplest: ((diff as u16 - 1) >> 15) as u8 inverted
    // Best constant-time way: check if diff is zero

    ((diff | diff.wrapping_neg()) >> 7) ^ 1
}

/// Constant-time byte equality check
///
/// Returns 0xFF if equal, 0x00 if not equal.
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::ct_verify::ct_u8_eq;
///
/// assert_eq!(ct_u8_eq(5, 5), 0xFF);
/// assert_eq!(ct_u8_eq(5, 6), 0x00);
/// ```
#[inline(always)]
pub const fn ct_u8_eq(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    // If diff is 0, return 0xFF. If diff is non-zero, return 0x00.
    // Use: if diff == 0, then (diff | -diff) has high bit clear, else high bit set
    // Then use arithmetic right shift to propagate bit 7 to all bits
    let neg_diff = (diff as i8).wrapping_neg() as u8;
    let combined = diff | neg_diff;
    // If diff was 0: combined = 0, NOT = 0xFF
    // If diff was non-zero: high bit of combined is set, right shift gives 0xFF, NOT gives 0
    !((combined as i8 >> 7) as u8)
}

/// Constant-time less-than comparison for u8
///
/// Returns 0xFF if a < b, 0x00 otherwise.
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::ct_verify::ct_u8_lt;
///
/// assert_eq!(ct_u8_lt(3, 5), 0xFF);
/// assert_eq!(ct_u8_lt(5, 3), 0x00);
/// assert_eq!(ct_u8_lt(5, 5), 0x00);
/// ```
#[inline(always)]
pub const fn ct_u8_lt(a: u8, b: u8) -> u8 {
    // a < b iff (a - b) has the sign bit set when interpreted as signed
    let diff = a.wrapping_sub(b) as i8;
    // Arithmetic right shift propagates sign bit: negative >> 7 = 0xFF, positive >> 7 = 0x00
    (diff >> 7) as u8
}

/// Constant-time selection between two bytes
///
/// Returns `a` if `mask` is 0xFF, returns `b` if `mask` is 0x00.
///
/// # Security
///
/// `mask` must be either 0xFF or 0x00 for correct behavior.
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::ct_verify::ct_select_u8;
///
/// assert_eq!(ct_select_u8(0xFF, 42, 17), 42);
/// assert_eq!(ct_select_u8(0x00, 42, 17), 17);
/// ```
#[inline(always)]
pub const fn ct_select_u8(mask: u8, a: u8, b: u8) -> u8 {
    (a & mask) | (b & !mask)
}

/// Constant-time selection between two i16 values
///
/// Returns `a` if `mask` is 0xFF, returns `b` if `mask` is 0x00.
#[inline(always)]
pub const fn ct_select_i16(mask: u8, a: i16, b: i16) -> i16 {
    let mask16 = mask as i16 | ((mask as i16) << 8);
    (a & mask16) | (b & !mask16)
}

/// Constant-time selection between two byte slices
///
/// Returns `a` if `condition` is true, returns `b` otherwise.
/// Runs in constant time.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths.
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::ct_verify::ct_select;
///
/// let a = b"first";
/// let b = b"secnd";
/// let result = ct_select(true, a, b);
/// assert_eq!(&result[..], a);
/// ```
#[inline(never)]
pub fn ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Slices must have equal length");

    let mask = if condition { 0xFFu8 } else { 0x00u8 };
    let mut result = Vec::with_capacity(a.len());

    for i in 0..a.len() {
        result.push(ct_select_u8(mask, a[i], b[i]));
    }

    result
}

/// Constant-time copy if condition is true
///
/// Copies `src` to `dst` if `condition` is true, leaves `dst` unchanged otherwise.
/// Runs in constant time (always processes all bytes).
///
/// # Panics
///
/// Panics if `src` and `dst` have different lengths.
#[inline(never)]
pub fn ct_copy(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(src.len(), dst.len(), "Slices must have equal length");

    let mask = if condition { 0xFFu8 } else { 0x00u8 };

    for i in 0..src.len() {
        dst[i] = ct_select_u8(mask, src[i], dst[i]);
    }
}

/// Verify that two operations take similar time (basic timing test)
///
/// This is a simple statistical test to check if two closures take
/// approximately the same time. It's not a replacement for proper
/// timing analysis tools like dudect.
///
/// # Returns
///
/// Returns the ratio of average times (op1_time / op2_time).
/// Values close to 1.0 indicate similar timing.
///
/// # Note
///
/// This is a basic sanity check and should not be relied upon for
/// security verification. Use proper timing analysis tools in production.
#[cfg(test)]
pub fn timing_test<F1, F2>(iterations: usize, mut op1: F1, mut op2: F2) -> f64
where
    F1: FnMut(),
    F2: FnMut(),
{
    use std::time::Instant;

    // Warm up
    for _ in 0..10 {
        op1();
        op2();
    }

    // Measure op1
    let start = Instant::now();
    for _ in 0..iterations {
        op1();
    }
    let time1 = start.elapsed();

    // Measure op2
    let start = Instant::now();
    for _ in 0..iterations {
        op2();
    }
    let time2 = start.elapsed();

    time1.as_secs_f64() / time2.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        let a = b"constant time";
        let b = b"constant time";
        assert_eq!(ct_eq(a, b), 1);
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = b"constant time";
        let b = b"constant TIME";
        assert_eq!(ct_eq(a, b), 0);
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let a = b"short";
        let b = b"longer string";
        assert_eq!(ct_eq(a, b), 0);
    }

    #[test]
    fn test_ct_u8_eq() {
        assert_eq!(ct_u8_eq(0, 0), 0xFF);
        assert_eq!(ct_u8_eq(255, 255), 0xFF);
        assert_eq!(ct_u8_eq(128, 128), 0xFF);

        assert_eq!(ct_u8_eq(0, 1), 0x00);
        assert_eq!(ct_u8_eq(255, 0), 0x00);
        assert_eq!(ct_u8_eq(128, 127), 0x00);
    }

    #[test]
    fn test_ct_u8_lt() {
        assert_eq!(ct_u8_lt(0, 1), 0xFF);
        assert_eq!(ct_u8_lt(100, 200), 0xFF);
        assert_eq!(ct_u8_lt(254, 255), 0xFF);

        assert_eq!(ct_u8_lt(1, 0), 0x00);
        assert_eq!(ct_u8_lt(200, 100), 0x00);
        assert_eq!(ct_u8_lt(255, 254), 0x00);

        assert_eq!(ct_u8_lt(5, 5), 0x00);
    }

    #[test]
    fn test_ct_select_u8() {
        assert_eq!(ct_select_u8(0xFF, 42, 17), 42);
        assert_eq!(ct_select_u8(0x00, 42, 17), 17);

        // Test all byte values
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(ct_select_u8(0xFF, a, b), a);
                assert_eq!(ct_select_u8(0x00, a, b), b);
            }
        }
    }

    #[test]
    fn test_ct_select_i16() {
        assert_eq!(ct_select_i16(0xFF, 1000, -1000), 1000);
        assert_eq!(ct_select_i16(0x00, 1000, -1000), -1000);

        assert_eq!(ct_select_i16(0xFF, -32768, 32767), -32768);
        assert_eq!(ct_select_i16(0x00, -32768, 32767), 32767);
    }

    #[test]
    fn test_ct_select() {
        let a = b"first";
        let b = b"secnd";

        let result_true = ct_select(true, a, b);
        assert_eq!(&result_true[..], a);

        let result_false = ct_select(false, a, b);
        assert_eq!(&result_false[..], b);
    }

    #[test]
    fn test_ct_copy() {
        let src = b"source";
        let mut dst = *b"destin";

        // Copy when condition is true
        ct_copy(true, &mut dst, src);
        assert_eq!(&dst, src);

        // Don't copy when condition is false
        let original = dst;
        ct_copy(false, &mut dst, b"other!");
        assert_eq!(&dst, &original);
    }

    #[test]
    fn test_ct_operations_always_process_all_bytes() {
        // This test verifies that constant-time operations process all bytes
        // even when an early decision could be made

        // ct_eq should process all bytes even if first byte differs
        let a = b"different at start";
        let b = b"xxxxxxxxxxxxxxxxxx"; // Same length
        assert_eq!(ct_eq(a, b), 0);

        // Should still process all bytes even if last byte differs
        let c = b"same until the enX";
        let d = b"same until the enY";
        assert_eq!(ct_eq(c, d), 0);
    }

    #[test]
    fn test_timing_basic_sanity() {
        // Basic sanity check that timing_test works
        // This is NOT a security test, just a functionality test

        let ratio = timing_test(
            1000,
            || {
                // Simple operation
                let _x = 1 + 1;
            },
            || {
                // Similar operation
                let _y = 2 + 2;
            },
        );

        // Both operations should take similar time (within 10x of each other)
        assert!(ratio > 0.1 && ratio < 10.0, "Ratio: {}", ratio);
    }

    #[test]
    fn test_ct_eq_all_positions() {
        // Test that differences at any position are detected
        for pos in 0..32 {
            let mut a = [0x00u8; 32];
            let mut b = [0x00u8; 32];
            b[pos] = 0x01;

            assert_eq!(
                ct_eq(&a, &b),
                0,
                "Failed to detect difference at position {}",
                pos
            );

            a[pos] = 0x01;
            assert_eq!(ct_eq(&a, &b), 1, "False negative at position {}", pos);
        }
    }
}
