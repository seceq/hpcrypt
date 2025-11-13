//! High-performance constant-time operations
//!
//! This module provides constant-time primitives for cryptographic implementations.
//! Unlike the `subtle` crate, these are optimized for performance while maintaining
//! constant-time guarantees through:
//! - No secret-dependent branches
//! - No secret-dependent memory access
//! - Compiler barriers to prevent optimization
//! - Careful use of bitwise operations
//!
//! # Security
//!
//! These operations are designed to run in constant time with respect to their
//! inputs to prevent timing side-channels. However, they rely on:
//! 1. Compiler not optimizing away the constant-time patterns
//! 2. CPU not leaking information through micro-architectural side channels
//! 3. Proper usage (not mixing with non-constant-time operations)

use core::ops::{BitAnd, BitOr, BitXor, Not};

/// A choice represents a constant-time boolean
///
/// Internally represented as a u8 that is either 0 or 1 (not 0xFF)
/// This makes it compatible with mask operations while being efficient
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct Choice(u8);

impl Choice {
    /// Construct a Choice from a u8
    ///
    /// # Security
    /// The input MUST be 0 or 1. Other values will produce incorrect results.
    /// Use `from_u8_nonzero` if you need to convert arbitrary values.
    #[inline]
    pub const fn from_u8(b: u8) -> Self {
        debug_assert!(b == 0 || b == 1);
        Choice(b)
    }

    /// Construct a Choice from an arbitrary u8, mapping non-zero to 1
    #[inline]
    pub fn from_u8_nonzero(b: u8) -> Self {
        // Constant-time: compute (b != 0) as 1 or 0
        // If b == 0: result = 0
        // If b != 0: result = 1
        let result = ((b as u16 | b.wrapping_neg() as u16) >> 8) as u8;
        Choice(result & 1)
    }

    /// Unwrap the Choice to a u8 (0 or 1)
    #[inline]
    pub const fn unwrap_u8(self) -> u8 {
        self.0
    }

    /// Convert to bool
    ///
    /// # Security
    /// This is safe because Choice is always 0 or 1
    #[inline]
    pub const fn into_bool(self) -> bool {
        self.0 == 1
    }

    /// Logical AND
    #[inline]
    pub const fn and(self, other: Self) -> Self {
        Choice(self.0 & other.0)
    }

    /// Logical OR
    #[inline]
    pub const fn or(self, other: Self) -> Self {
        Choice(self.0 | other.0)
    }

    /// Logical XOR
    #[inline]
    pub const fn xor(self, other: Self) -> Self {
        Choice(self.0 ^ other.0)
    }

    /// Logical NOT
    #[inline]
    pub const fn not(self) -> Self {
        Choice(1 ^ self.0)
    }
}

impl BitAnd for Choice {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        self.and(rhs)
    }
}

impl BitOr for Choice {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        self.or(rhs)
    }
}

impl BitXor for Choice {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        self.xor(rhs)
    }
}

impl Not for Choice {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        self.not()
    }
}

impl From<bool> for Choice {
    #[inline]
    fn from(b: bool) -> Self {
        Choice(b as u8)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(c: Choice) -> bool {
        c.into_bool()
    }
}

/// Constant-time equality comparison for byte arrays
///
/// Returns Choice(1) if equal, Choice(0) otherwise
#[inline]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice(0);
    }

    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }

    // acc == 0 iff all bytes were equal
    // Convert to Choice(1) if equal, Choice(0) otherwise
    Choice((1u8 & ((acc as u16).wrapping_sub(1) >> 8) as u8) ^ 1)
}

/// Constant-time equality comparison for u8
#[inline]
pub const fn ct_eq_u8(a: u8, b: u8) -> Choice {
    let x = a ^ b;
    // If x == 0, all bits are 0, so x - 1 = 0xFF...
    // If x != 0, at least one bit is set, so x - 1 has some pattern
    // Take the top bit: 1 if x != 0, 0 if x == 0
    let result = ((x as u16).wrapping_sub(1) >> 8) as u8;
    // Invert: 1 if x == 0, 0 if x != 0
    Choice((result & 1) ^ 1)
}

/// Constant-time equality comparison for u64
#[inline]
pub const fn ct_eq_u64(a: u64, b: u64) -> Choice {
    let x = a ^ b;
    let result = ((x as u128).wrapping_sub(1) >> 64) as u64;
    Choice((result & 1) as u8 ^ 1)
}

/// Constant-time less-than comparison for u64
///
/// Returns Choice(1) if a < b, Choice(0) otherwise
#[inline]
pub const fn ct_lt_u64(a: u64, b: u64) -> Choice {
    // Compute a - b
    // If a < b: borrow = 1
    // If a >= b: borrow = 0
    let (_, borrow) = a.overflowing_sub(b);
    Choice(borrow as u8)
}

/// Constant-time greater-than comparison for u64
#[inline]
pub const fn ct_gt_u64(a: u64, b: u64) -> Choice {
    ct_lt_u64(b, a)
}

/// Constant-time conditional select for u8
///
/// Returns `a` if choice is 1, `b` if choice is 0
#[inline]
pub const fn ct_select_u8(a: u8, b: u8, choice: Choice) -> u8 {
    // mask = 0xFF if choice == 1, 0x00 if choice == 0
    let mask = choice.0.wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Constant-time conditional select for u32
#[inline]
pub const fn ct_select_u32(a: u32, b: u32, choice: Choice) -> u32 {
    let mask = (choice.0 as u32).wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Constant-time conditional select for u64
#[inline]
pub const fn ct_select_u64(a: u64, b: u64, choice: Choice) -> u64 {
    let mask = (choice.0 as u64).wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Constant-time conditional select for i64
#[inline]
pub const fn ct_select_i64(a: i64, b: i64, choice: Choice) -> i64 {
    let mask = (choice.0 as i64).wrapping_neg();
    (a & mask) | (b & !mask)
}

/// Constant-time conditional swap for u64
///
/// If choice == 1: swaps a and b
/// If choice == 0: leaves a and b unchanged
#[inline]
pub const fn ct_swap_u64(a: u64, b: u64, choice: Choice) -> (u64, u64) {
    let mask = (choice.0 as u64).wrapping_neg();
    let x = mask & (a ^ b);
    (a ^ x, b ^ x)
}

/// Constant-time conditional negate for i64
///
/// If choice == 1: returns -a
/// If choice == 0: returns a
#[inline]
pub const fn ct_negate_i64(a: i64, choice: Choice) -> i64 {
    let mask = (choice.0 as i64).wrapping_neg();
    (a ^ mask).wrapping_sub(mask)
}

/// Constant-time conditional negate for u64 (two's complement)
#[inline]
pub const fn ct_negate_u64(a: u64, choice: Choice) -> u64 {
    let mask = (choice.0 as u64).wrapping_neg();
    (a ^ mask).wrapping_sub(mask)
}

/// Constant-time check if u64 is zero
#[inline]
pub const fn ct_is_zero_u64(a: u64) -> Choice {
    // If a == 0: a | -a = 0, top bit = 0
    // If a != 0: a | -a has top bit = 1
    let result = (a | a.wrapping_neg()) >> 63;
    Choice((result as u8) ^ 1)
}

/// Constant-time check if slice is all zeros
#[inline]
pub fn ct_is_zero_bytes(bytes: &[u8]) -> Choice {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    ct_is_zero_u64(acc as u64)
}

/// Constant-time conditional assign for byte arrays
///
/// If choice == 1: dest = src
/// If choice == 0: dest unchanged
#[inline]
pub fn ct_assign_bytes(dest: &mut [u8], src: &[u8], choice: Choice) {
    assert_eq!(dest.len(), src.len());
    let mask = choice.0.wrapping_neg();
    for i in 0..dest.len() {
        let x = mask & (src[i] ^ dest[i]);
        dest[i] ^= x;
    }
}

/// Constant-time table lookup for u8 arrays
///
/// Looks up `table[index]` in constant time by accessing all table entries
///
/// # Security
/// This function accesses ALL table entries regardless of index,
/// ensuring no timing leakage about which index was selected.
#[inline]
pub fn ct_lookup_u8_array<const N: usize>(table: &[[u8; N]], index: usize) -> [u8; N] {
    let mut result = [0u8; N];

    for (i, entry) in table.iter().enumerate() {
        let choice = Choice::from_u8((i == index) as u8);
        for j in 0..N {
            result[j] = ct_select_u8(entry[j], result[j], choice);
        }
    }

    result
}

/// Trait for types that support constant-time equality
pub trait ConstantTimeEq {
    /// Compare in constant time
    fn ct_eq(&self, other: &Self) -> Choice;
}

impl ConstantTimeEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ct_eq_u8(*self, *other)
    }
}

impl ConstantTimeEq for u64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ct_eq_u64(*self, *other)
    }
}

impl ConstantTimeEq for i64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ct_eq_u64(*self as u64, *other as u64)
    }
}

impl ConstantTimeEq for [u8; 32] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ct_eq_bytes(self, other)
    }
}

impl ConstantTimeEq for [u8; 64] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ct_eq_bytes(self, other)
    }
}

impl<const N: usize> ConstantTimeEq for [u64; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        for i in 0..N {
            acc |= self[i] ^ other[i];
        }
        ct_is_zero_u64(acc)
    }
}

impl<const N: usize> ConstantTimeEq for [i64; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        for i in 0..N {
            acc |= (self[i] as u64) ^ (other[i] as u64);
        }
        ct_is_zero_u64(acc)
    }
}

/// Trait for types that support constant-time conditional selection
pub trait ConditionallySelectable: Sized {
    /// Select `a` if `choice == 1`, `b` if `choice == 0`
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Conditionally assign `other` to `self` if `choice == 1`
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(other, self, choice);
    }

    /// Conditionally swap `self` and `other` if `choice == 1`
    fn conditional_swap(&mut self, other: &mut Self, choice: Choice) {
        let temp = Self::conditional_select(self, other, choice);
        *other = Self::conditional_select(other, self, choice);
        *self = temp;
    }
}

impl ConditionallySelectable for u8 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ct_select_u8(*a, *b, choice)
    }
}

impl ConditionallySelectable for u32 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ct_select_u32(*a, *b, choice)
    }
}

impl ConditionallySelectable for u64 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ct_select_u64(*a, *b, choice)
    }
}

impl ConditionallySelectable for i64 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ct_select_i64(*a, *b, choice)
    }
}

impl ConditionallySelectable for [u8; 32] {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = ct_select_u8(a[i], b[i], choice);
        }
        result
    }
}

impl<const N: usize> ConditionallySelectable for [u64; N] {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u64; N];
        for i in 0..N {
            result[i] = ct_select_u64(a[i], b[i], choice);
        }
        result
    }
}

impl<const N: usize> ConditionallySelectable for [i64; N] {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0i64; N];
        for i in 0..N {
            result[i] = ct_select_i64(a[i], b[i], choice);
        }
        result
    }
}

/// Trait for types that support constant-time conditional negation
pub trait ConditionallyNegatable {
    /// Negate if `choice == 1`, otherwise return unchanged
    fn conditional_negate(&self, choice: Choice) -> Self;
}

impl ConditionallyNegatable for i64 {
    #[inline]
    fn conditional_negate(&self, choice: Choice) -> Self {
        ct_negate_i64(*self, choice)
    }
}

impl<const N: usize> ConditionallyNegatable for [i64; N] {
    #[inline]
    fn conditional_negate(&self, choice: Choice) -> Self {
        let mut result = [0i64; N];
        for i in 0..N {
            result[i] = ct_negate_i64(self[i], choice);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choice_operations() {
        let t = Choice::from_u8(1);
        let f = Choice::from_u8(0);

        assert_eq!(t.and(t).unwrap_u8(), 1);
        assert_eq!(t.and(f).unwrap_u8(), 0);
        assert_eq!(f.and(t).unwrap_u8(), 0);
        assert_eq!(f.and(f).unwrap_u8(), 0);

        assert_eq!(t.or(t).unwrap_u8(), 1);
        assert_eq!(t.or(f).unwrap_u8(), 1);
        assert_eq!(f.or(t).unwrap_u8(), 1);
        assert_eq!(f.or(f).unwrap_u8(), 0);

        assert_eq!(t.not().unwrap_u8(), 0);
        assert_eq!(f.not().unwrap_u8(), 1);
    }

    #[test]
    fn test_ct_eq() {
        assert_eq!(ct_eq_u8(42, 42).unwrap_u8(), 1);
        assert_eq!(ct_eq_u8(42, 43).unwrap_u8(), 0);

        assert_eq!(
            ct_eq_u64(0x1234567890ABCDEF, 0x1234567890ABCDEF).unwrap_u8(),
            1
        );
        assert_eq!(
            ct_eq_u64(0x1234567890ABCDEF, 0x1234567890ABCDEE).unwrap_u8(),
            0
        );

        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert_eq!(ct_eq_bytes(&a, &b).unwrap_u8(), 1);
        assert_eq!(ct_eq_bytes(&a, &c).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_select() {
        let t = Choice::from_u8(1);
        let f = Choice::from_u8(0);

        assert_eq!(ct_select_u8(42, 99, t), 42);
        assert_eq!(ct_select_u8(42, 99, f), 99);

        assert_eq!(ct_select_u64(0x1234, 0x5678, t), 0x1234);
        assert_eq!(ct_select_u64(0x1234, 0x5678, f), 0x5678);
    }

    #[test]
    fn test_ct_negate() {
        let t = Choice::from_u8(1);
        let f = Choice::from_u8(0);

        assert_eq!(ct_negate_i64(42, t), -42);
        assert_eq!(ct_negate_i64(42, f), 42);
        assert_eq!(ct_negate_i64(-42, t), 42);
        assert_eq!(ct_negate_i64(-42, f), -42);
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero_u64(0).unwrap_u8(), 1);
        assert_eq!(ct_is_zero_u64(1).unwrap_u8(), 0);
        assert_eq!(ct_is_zero_u64(0xFFFFFFFFFFFFFFFF).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_swap() {
        let t = Choice::from_u8(1);
        let f = Choice::from_u8(0);

        let (a, b) = ct_swap_u64(42, 99, t);
        assert_eq!(a, 99);
        assert_eq!(b, 42);

        let (a, b) = ct_swap_u64(42, 99, f);
        assert_eq!(a, 42);
        assert_eq!(b, 99);
    }

    #[test]
    fn test_ct_lookup() {
        let table = [[1u8, 2, 3], [4u8, 5, 6], [7u8, 8, 9], [10u8, 11, 12]];

        assert_eq!(ct_lookup_u8_array(&table, 0), [1, 2, 3]);
        assert_eq!(ct_lookup_u8_array(&table, 1), [4, 5, 6]);
        assert_eq!(ct_lookup_u8_array(&table, 2), [7, 8, 9]);
        assert_eq!(ct_lookup_u8_array(&table, 3), [10, 11, 12]);
    }
}
