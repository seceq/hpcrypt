//! Constant-time operations for ML-DSA
//!
//! Provides constant-time comparison and selection operations to prevent
//! timing side-channel attacks.

/// Constant-time equality comparison for byte slices
///
/// Returns 1 if slices are equal, 0 otherwise.
/// Execution time is independent of where differences occur.
///
/// # Security
///
/// This function is designed to prevent timing side-channels by:
/// - Processing all bytes regardless of early differences
/// - Using bitwise operations instead of branching
/// - Ensuring constant execution time
#[inline]
pub fn ct_compare(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }

    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }

    // Convert to 1 or 0 without branching
    // result == 0 => all bits 0 => output 1
    // result != 0 => some bit 1 => output 0
    ct_eq_zero(result)
}

/// Constant-time check if value equals zero
///
/// Returns 1 if x == 0, returns 0 if x != 0
/// Execution time is independent of input value
#[inline]
const fn ct_eq_zero(x: u8) -> u8 {
    // If x == 0, then !x == 0xFF, so (!x) >> 7 == 1
    // If x != 0, then some bit is set, and the calculation gives 0
    let neg_x = (!x).wrapping_add(1);
    ((neg_x | x) >> 7) ^ 1
}

/// Constant-time selection between two values
///
/// Returns `a` if `select == 1`, returns `b` if `select == 0`
/// Execution time is independent of the select value
///
/// # Arguments
/// * `select` - Must be 0 or 1
/// * `a` - Value to return if select is 1
/// * `b` - Value to return if select is 0
#[inline]
pub const fn ct_select_u32(select: u8, a: u32, b: u32) -> u32 {
    let mask = (select as u32).wrapping_neg(); // 0 => 0x00000000, 1 => 0xFFFFFFFF
    (a & mask) | (b & !mask)
}

/// Constant-time selection between two i32 values
#[inline]
pub const fn ct_select_i32(select: u8, a: i32, b: i32) -> i32 {
    let mask = (select as i32).wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Constant-time less-than comparison
///
/// Returns 1 if a < b, 0 otherwise
/// Execution time is independent of values
#[inline]
pub const fn ct_lt_i32(a: i32, b: i32) -> u8 {
    // Compute a - b and check if sign bit is set
    let diff = a.wrapping_sub(b);
    ((diff >> 31) & 1) as u8
}

/// Constant-time greater-than comparison
///
/// Returns 1 if a > b, 0 otherwise
#[inline]
pub const fn ct_gt_i32(a: i32, b: i32) -> u8 {
    ct_lt_i32(b, a)
}

/// Constant-time absolute value for i32
///
/// Returns |x| in constant time
#[inline]
pub const fn ct_abs_i32(x: i32) -> i32 {
    let mask = x >> 31; // All 1s if negative, all 0s if positive
    (x + mask) ^ mask
}

/// Constant-time conditional swap
///
/// If swap == 1, exchanges a and b
/// If swap == 0, leaves them unchanged
/// Execution time is independent of swap value
#[inline]
pub fn ct_swap_i32(swap: u8, a: &mut i32, b: &mut i32) {
    let mask = (swap as i32).wrapping_neg();
    let diff = (*a ^ *b) & mask;
    *a ^= diff;
    *b ^= diff;
}

mod tests {
    use super::*;

    #[test]
    fn test_ct_compare_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert_eq!(ct_compare(a, b), 1);
    }

    #[test]
    fn test_ct_compare_different() {
        let a = b"hello world";
        let b = b"hello worlD";
        assert_eq!(ct_compare(a, b), 0);
    }

    #[test]
    fn test_ct_compare_different_length() {
        let a = b"hello";
        let b = b"hello world";
        assert_eq!(ct_compare(a, b), 0);
    }

    #[test]
    fn test_ct_eq_zero() {
        assert_eq!(ct_eq_zero(0), 1);
        assert_eq!(ct_eq_zero(1), 0);
        assert_eq!(ct_eq_zero(255), 0);
        assert_eq!(ct_eq_zero(42), 0);
    }

    #[test]
    fn test_ct_select_u32() {
        assert_eq!(ct_select_u32(1, 100, 200), 100);
        assert_eq!(ct_select_u32(0, 100, 200), 200);
    }

    #[test]
    fn test_ct_select_i32() {
        assert_eq!(ct_select_i32(1, -100, 200), -100);
        assert_eq!(ct_select_i32(0, -100, 200), 200);
    }

    #[test]
    fn test_ct_lt_i32() {
        assert_eq!(ct_lt_i32(5, 10), 1);
        assert_eq!(ct_lt_i32(10, 5), 0);
        assert_eq!(ct_lt_i32(5, 5), 0);
        assert_eq!(ct_lt_i32(-5, 5), 1);
    }

    #[test]
    fn test_ct_gt_i32() {
        assert_eq!(ct_gt_i32(10, 5), 1);
        assert_eq!(ct_gt_i32(5, 10), 0);
        assert_eq!(ct_gt_i32(5, 5), 0);
    }

    #[test]
    fn test_ct_abs_i32() {
        assert_eq!(ct_abs_i32(5), 5);
        assert_eq!(ct_abs_i32(-5), 5);
        assert_eq!(ct_abs_i32(0), 0);
        assert_eq!(ct_abs_i32(i32::MAX), i32::MAX);
    }

    #[test]
    fn test_ct_swap_i32() {
        let mut a = 100;
        let mut b = 200;

        ct_swap_i32(1, &mut a, &mut b);
        assert_eq!(a, 200);
        assert_eq!(b, 100);

        ct_swap_i32(0, &mut a, &mut b);
        assert_eq!(a, 200);
        assert_eq!(b, 100);
    }
}
