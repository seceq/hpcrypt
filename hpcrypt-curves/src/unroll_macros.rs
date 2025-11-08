//! Loop Unrolling Macros for Field Operations
//!
//! This module provides declarative macros to generate unrolled loops for
//! multi-precision arithmetic operations. This eliminates loop overhead and
//! allows better compiler optimization.
//!
//! The macros generate code equivalent to manual unrolling but are:
//! - DRY (Don't Repeat Yourself)
//! - Easier to maintain
//! - Consistent across different limb sizes
//! - Less error-prone than copy-paste

/// Unrolled addition with carry propagation for N limbs
///
/// Generates code to add two multi-precision numbers with proper carry propagation.
/// Returns the result and a final overflow flag.
///
/// # Arguments
/// - `$result`: Output array for the sum
/// - `$a`: First input array
/// - `$b`: Second input array
/// - `$N`: Number of limbs (must be a literal: 4, 6, or 9)
///
/// # Example
/// ```ignore
/// let mut result = [0u64; 4];
/// let overflow = unroll_add!(result, a.limbs, b.limbs, 4);
/// ```
macro_rules! unroll_add {
    // 4-limb version (P-256)
    ($result:expr, $a:expr, $b:expr, 4) => {{
        // Limb 0
        let (sum0, c0) = $a[0].overflowing_add($b[0]);
        $result[0] = sum0;
        let carry0 = c0 as u64;

        // Limb 1
        let (sum1, c1_1) = $a[1].overflowing_add($b[1]);
        let (sum1, c1_2) = sum1.overflowing_add(carry0);
        $result[1] = sum1;
        let carry1 = (c1_1 as u64) + (c1_2 as u64);

        // Limb 2
        let (sum2, c2_1) = $a[2].overflowing_add($b[2]);
        let (sum2, c2_2) = sum2.overflowing_add(carry1);
        $result[2] = sum2;
        let carry2 = (c2_1 as u64) + (c2_2 as u64);

        // Limb 3
        let (sum3, c3_1) = $a[3].overflowing_add($b[3]);
        let (sum3, c3_2) = sum3.overflowing_add(carry2);
        $result[3] = sum3;
        let final_carry = (c3_1 as u64) + (c3_2 as u64);

        final_carry != 0
    }};

    // 6-limb version (P-384)
    ($result:expr, $a:expr, $b:expr, 6) => {{
        // Limb 0
        let (sum0, c0) = $a[0].overflowing_add($b[0]);
        $result[0] = sum0;
        let carry0 = c0 as u64;

        // Limb 1
        let (sum1, c1_1) = $a[1].overflowing_add($b[1]);
        let (sum1, c1_2) = sum1.overflowing_add(carry0);
        $result[1] = sum1;
        let carry1 = (c1_1 as u64) + (c1_2 as u64);

        // Limb 2
        let (sum2, c2_1) = $a[2].overflowing_add($b[2]);
        let (sum2, c2_2) = sum2.overflowing_add(carry1);
        $result[2] = sum2;
        let carry2 = (c2_1 as u64) + (c2_2 as u64);

        // Limb 3
        let (sum3, c3_1) = $a[3].overflowing_add($b[3]);
        let (sum3, c3_2) = sum3.overflowing_add(carry2);
        $result[3] = sum3;
        let carry3 = (c3_1 as u64) + (c3_2 as u64);

        // Limb 4
        let (sum4, c4_1) = $a[4].overflowing_add($b[4]);
        let (sum4, c4_2) = sum4.overflowing_add(carry3);
        $result[4] = sum4;
        let carry4 = (c4_1 as u64) + (c4_2 as u64);

        // Limb 5
        let (sum5, c5_1) = $a[5].overflowing_add($b[5]);
        let (sum5, c5_2) = sum5.overflowing_add(carry4);
        $result[5] = sum5;
        let final_carry = (c5_1 as u64) + (c5_2 as u64);

        final_carry != 0
    }};

    // 9-limb version (P-521)
    ($result:expr, $a:expr, $b:expr, 9) => {{
        // Limb 0
        let (sum0, c0) = $a[0].overflowing_add($b[0]);
        $result[0] = sum0;
        let carry0 = c0 as u64;

        // Limb 1
        let (sum1, c1_1) = $a[1].overflowing_add($b[1]);
        let (sum1, c1_2) = sum1.overflowing_add(carry0);
        $result[1] = sum1;
        let carry1 = (c1_1 as u64) + (c1_2 as u64);

        // Limb 2
        let (sum2, c2_1) = $a[2].overflowing_add($b[2]);
        let (sum2, c2_2) = sum2.overflowing_add(carry1);
        $result[2] = sum2;
        let carry2 = (c2_1 as u64) + (c2_2 as u64);

        // Limb 3
        let (sum3, c3_1) = $a[3].overflowing_add($b[3]);
        let (sum3, c3_2) = sum3.overflowing_add(carry2);
        $result[3] = sum3;
        let carry3 = (c3_1 as u64) + (c3_2 as u64);

        // Limb 4
        let (sum4, c4_1) = $a[4].overflowing_add($b[4]);
        let (sum4, c4_2) = sum4.overflowing_add(carry3);
        $result[4] = sum4;
        let carry4 = (c4_1 as u64) + (c4_2 as u64);

        // Limb 5
        let (sum5, c5_1) = $a[5].overflowing_add($b[5]);
        let (sum5, c5_2) = sum5.overflowing_add(carry4);
        $result[5] = sum5;
        let carry5 = (c5_1 as u64) + (c5_2 as u64);

        // Limb 6
        let (sum6, c6_1) = $a[6].overflowing_add($b[6]);
        let (sum6, c6_2) = sum6.overflowing_add(carry5);
        $result[6] = sum6;
        let carry6 = (c6_1 as u64) + (c6_2 as u64);

        // Limb 7
        let (sum7, c7_1) = $a[7].overflowing_add($b[7]);
        let (sum7, c7_2) = sum7.overflowing_add(carry6);
        $result[7] = sum7;
        let carry7 = (c7_1 as u64) + (c7_2 as u64);

        // Limb 8
        let (sum8, c8_1) = $a[8].overflowing_add($b[8]);
        let (sum8, c8_2) = sum8.overflowing_add(carry7);
        $result[8] = sum8;
        let final_carry = (c8_1 as u64) + (c8_2 as u64);

        final_carry != 0
    }};
}

/// Unrolled subtraction with borrow propagation for N limbs
///
/// Generates code to subtract two multi-precision numbers with proper borrow propagation.
/// Returns the result and a final underflow flag.
///
/// # Arguments
/// - `$result`: Output array for the difference
/// - `$a`: First input array (minuend)
/// - `$b`: Second input array (subtrahend)
/// - `$N`: Number of limbs (must be a literal: 4, 6, or 9)
macro_rules! unroll_sub {
    // 4-limb version (P-256)
    ($result:expr, $a:expr, $b:expr, 4) => {{
        // Limb 0
        let (diff0, b0) = $a[0].overflowing_sub($b[0]);
        $result[0] = diff0;
        let borrow0 = b0 as u64;

        // Limb 1
        let (diff1, b1_1) = $a[1].overflowing_sub($b[1]);
        let (diff1, b1_2) = diff1.overflowing_sub(borrow0);
        $result[1] = diff1;
        let borrow1 = (b1_1 as u64) + (b1_2 as u64);

        // Limb 2
        let (diff2, b2_1) = $a[2].overflowing_sub($b[2]);
        let (diff2, b2_2) = diff2.overflowing_sub(borrow1);
        $result[2] = diff2;
        let borrow2 = (b2_1 as u64) + (b2_2 as u64);

        // Limb 3
        let (diff3, b3_1) = $a[3].overflowing_sub($b[3]);
        let (diff3, b3_2) = diff3.overflowing_sub(borrow2);
        $result[3] = diff3;
        let final_borrow = (b3_1 as u64) + (b3_2 as u64);

        final_borrow != 0
    }};

    // 6-limb version (P-384)
    ($result:expr, $a:expr, $b:expr, 6) => {{
        // Limb 0
        let (diff0, b0) = $a[0].overflowing_sub($b[0]);
        $result[0] = diff0;
        let borrow0 = b0 as u64;

        // Limb 1
        let (diff1, b1_1) = $a[1].overflowing_sub($b[1]);
        let (diff1, b1_2) = diff1.overflowing_sub(borrow0);
        $result[1] = diff1;
        let borrow1 = (b1_1 as u64) + (b1_2 as u64);

        // Limb 2
        let (diff2, b2_1) = $a[2].overflowing_sub($b[2]);
        let (diff2, b2_2) = diff2.overflowing_sub(borrow1);
        $result[2] = diff2;
        let borrow2 = (b2_1 as u64) + (b2_2 as u64);

        // Limb 3
        let (diff3, b3_1) = $a[3].overflowing_sub($b[3]);
        let (diff3, b3_2) = diff3.overflowing_sub(borrow2);
        $result[3] = diff3;
        let borrow3 = (b3_1 as u64) + (b3_2 as u64);

        // Limb 4
        let (diff4, b4_1) = $a[4].overflowing_sub($b[4]);
        let (diff4, b4_2) = diff4.overflowing_sub(borrow3);
        $result[4] = diff4;
        let borrow4 = (b4_1 as u64) + (b4_2 as u64);

        // Limb 5
        let (diff5, b5_1) = $a[5].overflowing_sub($b[5]);
        let (diff5, b5_2) = diff5.overflowing_sub(borrow4);
        $result[5] = diff5;
        let final_borrow = (b5_1 as u64) + (b5_2 as u64);

        final_borrow != 0
    }};

    // 9-limb version (P-521)
    ($result:expr, $a:expr, $b:expr, 9) => {{
        // Limb 0
        let (diff0, b0) = $a[0].overflowing_sub($b[0]);
        $result[0] = diff0;
        let borrow0 = b0 as u64;

        // Limb 1
        let (diff1, b1_1) = $a[1].overflowing_sub($b[1]);
        let (diff1, b1_2) = diff1.overflowing_sub(borrow0);
        $result[1] = diff1;
        let borrow1 = (b1_1 as u64) + (b1_2 as u64);

        // Limb 2
        let (diff2, b2_1) = $a[2].overflowing_sub($b[2]);
        let (diff2, b2_2) = diff2.overflowing_sub(borrow1);
        $result[2] = diff2;
        let borrow2 = (b2_1 as u64) + (b2_2 as u64);

        // Limb 3
        let (diff3, b3_1) = $a[3].overflowing_sub($b[3]);
        let (diff3, b3_2) = diff3.overflowing_sub(borrow2);
        $result[3] = diff3;
        let borrow3 = (b3_1 as u64) + (b3_2 as u64);

        // Limb 4
        let (diff4, b4_1) = $a[4].overflowing_sub($b[4]);
        let (diff4, b4_2) = diff4.overflowing_sub(borrow3);
        $result[4] = diff4;
        let borrow4 = (b4_1 as u64) + (b4_2 as u64);

        // Limb 5
        let (diff5, b5_1) = $a[5].overflowing_sub($b[5]);
        let (diff5, b5_2) = diff5.overflowing_sub(borrow4);
        $result[5] = diff5;
        let borrow5 = (b5_1 as u64) + (b5_2 as u64);

        // Limb 6
        let (diff6, b6_1) = $a[6].overflowing_sub($b[6]);
        let (diff6, b6_2) = diff6.overflowing_sub(borrow5);
        $result[6] = diff6;
        let borrow6 = (b6_1 as u64) + (b6_2 as u64);

        // Limb 7
        let (diff7, b7_1) = $a[7].overflowing_sub($b[7]);
        let (diff7, b7_2) = diff7.overflowing_sub(borrow6);
        $result[7] = diff7;
        let borrow7 = (b7_1 as u64) + (b7_2 as u64);

        // Limb 8
        let (diff8, b8_1) = $a[8].overflowing_sub($b[8]);
        let (diff8, b8_2) = diff8.overflowing_sub(borrow7);
        $result[8] = diff8;
        let final_borrow = (b8_1 as u64) + (b8_2 as u64);

        final_borrow != 0
    }};
}

// Re-export macros for use in other modules
pub(crate) use {unroll_add, unroll_sub};

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_unroll_add_4limbs() {
        let a = [1u64, 2, 3, 4];
        let b = [5u64, 6, 7, 8];
        let mut result = [0u64; 4];

        let overflow = unroll_add!(result, a, b, 4);

        assert_eq!(result, [6, 8, 10, 12]);
        assert!(!overflow);
    }

    #[test]
    fn test_unroll_add_6limbs() {
        let a = [1u64, 2, 3, 4, 5, 6];
        let b = [7u64, 8, 9, 10, 11, 12];
        let mut result = [0u64; 6];

        let overflow = unroll_add!(result, a, b, 6);

        assert_eq!(result, [8, 10, 12, 14, 16, 18]);
        assert!(!overflow);
    }

    #[test]
    fn test_unroll_add_9limbs() {
        let a = [1u64, 2, 3, 4, 5, 6, 7, 8, 9];
        let b = [10u64, 11, 12, 13, 14, 15, 16, 17, 18];
        let mut result = [0u64; 9];

        let overflow = unroll_add!(result, a, b, 9);

        assert_eq!(result, [11, 13, 15, 17, 19, 21, 23, 25, 27]);
        assert!(!overflow);
    }

    #[test]
    fn test_unroll_add_with_carry() {
        let a = [u64::MAX, 0, 0, 0];
        let b = [1u64, 0, 0, 0];
        let mut result = [0u64; 4];

        let overflow = unroll_add!(result, a, b, 4);

        assert_eq!(result, [0, 1, 0, 0]);
        assert!(!overflow);
    }

    #[test]
    fn test_unroll_add_with_overflow() {
        let a = [u64::MAX, u64::MAX, u64::MAX, u64::MAX];
        let b = [1u64, 0, 0, 0];
        let mut result = [0u64; 4];

        let overflow = unroll_add!(result, a, b, 4);

        assert_eq!(result, [0, 0, 0, 0]);
        assert!(overflow);
    }

    #[test]
    fn test_unroll_sub_4limbs() {
        let a = [10u64, 9, 8, 7];
        let b = [1u64, 2, 3, 4];
        let mut result = [0u64; 4];

        let underflow = unroll_sub!(result, a, b, 4);

        assert_eq!(result, [9, 7, 5, 3]);
        assert!(!underflow);
    }

    #[test]
    fn test_unroll_sub_with_borrow() {
        let a = [0u64, 1, 0, 0];
        let b = [1u64, 0, 0, 0];
        let mut result = [0u64; 4];

        let underflow = unroll_sub!(result, a, b, 4);

        assert_eq!(result, [u64::MAX, 0, 0, 0]);
        assert!(!underflow);
    }

    #[test]
    fn test_unroll_sub_with_underflow() {
        let a = [0u64, 0, 0, 0];
        let b = [1u64, 0, 0, 0];
        let mut result = [0u64; 4];

        let underflow = unroll_sub!(result, a, b, 4);

        assert_eq!(result, [u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
        assert!(underflow);
    }
}
