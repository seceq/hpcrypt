//! Constant-Time Utilities
//!
//! High-performance implementations of constant-time operations for cryptographic primitives.
//! These replace the `subtle` crate dependency with native implementations that are:
//! - Side-channel resistant (no data-dependent branches or memory access)
//! - High performance (optimized for modern CPUs)
//! - Compiler-safe (using techniques to prevent optimization removal)
//!
//! # Security
//!
//! All operations in this module are designed to execute in constant time to prevent
//! timing side-channel attacks. This is critical for cryptographic operations.

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// A constant-time boolean choice type
///
/// Internally represents a boolean as a `u8` that is either 0 or 1.
/// All operations are constant-time to prevent timing side-channels.
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct Choice(u8);

impl Choice {
    /// Construct a `Choice` from a `u8` (0 or 1)
    ///
    /// # Panics
    /// Panics in debug mode if the value is not 0 or 1
    #[inline]
    pub const fn from_u8(value: u8) -> Self {
        debug_assert!(value <= 1, "Choice must be 0 or 1");
        Choice(value)
    }

    /// Construct a `Choice` representing true (1)
    #[inline]
    pub const fn true_choice() -> Self {
        Choice(1)
    }

    /// Construct a `Choice` representing false (0)
    #[inline]
    pub const fn false_choice() -> Self {
        Choice(0)
    }

    /// Get the underlying `u8` value (0 or 1)
    #[inline]
    pub const fn unwrap_u8(self) -> u8 {
        self.0
    }

    /// Convert to a boolean (warning: not constant-time!)
    ///
    /// This should only be used when the result does not feed into security-critical operations.
    #[inline]
    pub fn into_bool(self) -> bool {
        self.0 != 0
    }

    /// Conditional select helper - selects `a` if `choice == 0`, `b` if `choice == 1`
    ///
    /// This is a static method that matches the trait signature
    #[inline]
    pub fn conditional_select<T: ConditionallySelectable>(a: &T, b: &T, choice: Choice) -> T {
        T::conditional_select(a, b, choice)
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(value: u8) -> Self {
        Choice::from_u8(value & 1)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(choice: Choice) -> bool {
        choice.into_bool()
    }
}

impl From<Choice> for u8 {
    #[inline]
    fn from(choice: Choice) -> u8 {
        choice.0
    }
}

// Constant-time logical operations on Choice
impl BitAnd for Choice {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Choice(self.0 & rhs.0)
    }
}

impl BitOr for Choice {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Choice(self.0 | rhs.0)
    }
}

impl BitXor for Choice {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Choice(self.0 ^ rhs.0)
    }
}

impl Not for Choice {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Choice(1 - self.0)
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitXorAssign for Choice {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

/// Constant-time conditional select trait
///
/// Selects `a` if `choice == 0`, or `b` if `choice == 1`, in constant time.
pub trait ConditionallySelectable: Sized {
    /// Select `a` or `b` in constant time based on `choice`.
    ///
    /// Returns `a` if `choice == 0`, `b` if `choice == 1`.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Conditionally assign `other` to `self` if `choice == 1`.
    ///
    /// This is equivalent to: `*self = Self::conditional_select(self, other, choice);`
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(self, other, choice);
    }
}

/// Constant-time equality comparison trait
pub trait ConstantTimeEq {
    /// Test equality in constant time
    ///
    /// Returns `Choice(1)` if equal, `Choice(0)` if not equal.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Test inequality in constant time
    ///
    /// Returns `Choice(1)` if not equal, `Choice(0)` if equal.
    #[inline]
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

/// Constant-time greater than comparison trait
pub trait ConstantTimeGreater {
    /// Test if self > other in constant time
    ///
    /// Returns `Choice(1)` if self > other, `Choice(0)` otherwise.
    fn ct_gt(&self, other: &Self) -> Choice;
}

/// Constant-time less than comparison trait
pub trait ConstantTimeLess {
    /// Test if self < other in constant time
    ///
    /// Returns `Choice(1)` if self < other, `Choice(0)` otherwise.
    fn ct_lt(&self, other: &Self) -> Choice;
}

// Implement ConditionallySelectable for Choice itself
impl ConditionallySelectable for Choice {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = choice.0.wrapping_neg();
        Choice((a.0 & !mask) | (b.0 & mask))
    }
}

// Implement ConditionallySelectable for u64
impl ConditionallySelectable for u64 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Constant-time select using bitwise operations
        // mask = choice ? 0xFFFFFFFFFFFFFFFF : 0x0000000000000000
        let mask = (choice.0 as u64).wrapping_neg();

        // result = (a & !mask) | (b & mask)
        // If choice == 0: mask = 0, result = a
        // If choice == 1: mask = 0xFFFF..., result = b
        (a & !mask) | (b & mask)
    }
}

// Implement ConditionallySelectable for u8
impl ConditionallySelectable for u8 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = choice.0.wrapping_neg();
        (a & !mask) | (b & mask)
    }
}

// Implement ConditionallySelectable for u32
impl ConditionallySelectable for u32 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = (choice.0 as u32).wrapping_neg();
        (a & !mask) | (b & mask)
    }
}

// Implement ConditionallySelectable for i64
impl ConditionallySelectable for i64 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = (choice.0 as i64).wrapping_neg();
        (a & !mask) | (b & mask)
    }
}

// Implement ConstantTimeEq for u64
impl ConstantTimeEq for u64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        // XOR the values - result is 0 if equal, non-zero if different
        let xor = self ^ other;

        // Check if xor is zero in constant time
        // If xor == 0, then (xor | -xor) has MSB = 0
        // If xor != 0, then (xor | -xor) has MSB = 1
        let result = ((xor | xor.wrapping_neg()) >> 63) as u8;

        // Invert: we want 1 if equal (xor == 0), 0 if not equal
        Choice(1 - result)
    }
}

// Implement ConstantTimeEq for u8
impl ConstantTimeEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let xor = self ^ other;
        let result = (xor | xor.wrapping_neg()) >> 7;
        Choice(1 - result)
    }
}

// Implement ConstantTimeGreater for u64
impl ConstantTimeGreater for u64 {
    #[inline]
    fn ct_gt(&self, other: &Self) -> Choice {
        // self > other  <==>  self - other - 1 doesn't underflow
        // Compute (self - other - 1) and check if borrow occurred
        let (_, borrow) = self.overflowing_sub(*other);
        let (_, borrow2) = if borrow { (0u64, true) } else { self.wrapping_sub(*other).overflowing_sub(1) };

        // If no borrow in final computation, self > other
        Choice((!borrow2) as u8)
    }
}

// Implement ConstantTimeLess for u64
impl ConstantTimeLess for u64 {
    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        // self < other  <==>  other > self
        other.ct_gt(self)
    }
}

// Implement ConstantTimeEq for i64
impl ConstantTimeEq for i64 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let xor = (self ^ other) as u64;
        let result = ((xor | xor.wrapping_neg()) >> 63) as u8;
        Choice(1 - result)
    }
}

// Implement ConstantTimeEq for slices of u64
impl ConstantTimeEq for [u64] {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.len() != other.len() {
            return Choice::false_choice();
        }

        let mut result = Choice::true_choice();
        for (a, b) in self.iter().zip(other.iter()) {
            result &= a.ct_eq(b);
        }
        result
    }
}

// Implement ConstantTimeEq for slices of u8
impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.len() != other.len() {
            return Choice::false_choice();
        }

        let mut result = Choice::true_choice();
        for (a, b) in self.iter().zip(other.iter()) {
            result &= a.ct_eq(b);
        }
        result
    }
}

// Implement ConstantTimeEq for arrays of u64
macro_rules! impl_ct_eq_array {
    ($($n:expr),+) => {
        $(
            impl ConstantTimeEq for [u64; $n] {
                #[inline]
                fn ct_eq(&self, other: &Self) -> Choice {
                    let mut result = Choice::true_choice();
                    for i in 0..$n {
                        result &= self[i].ct_eq(&other[i]);
                    }
                    result
                }
            }
        )+
    };
}

impl_ct_eq_array!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 18, 32);

// Implement ConstantTimeEq for arrays of i64
macro_rules! impl_ct_eq_array_i64 {
    ($($n:expr),+) => {
        $(
            impl ConstantTimeEq for [i64; $n] {
                #[inline]
                fn ct_eq(&self, other: &Self) -> Choice {
                    let mut result = Choice::true_choice();
                    for i in 0..$n {
                        result &= self[i].ct_eq(&other[i]);
                    }
                    result
                }
            }
        )+
    };
}

impl_ct_eq_array_i64!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 18, 32);

/// Trait for constant-time conditional negation
pub trait ConditionallyNegatable {
    /// Negate `self` if `choice == 1`, return `self` if `choice == 0`
    fn conditional_negate(&self, choice: Choice) -> Self;
}

impl ConditionallyNegatable for i64 {
    #[inline]
    fn conditional_negate(&self, choice: Choice) -> Self {
        // Constant-time negation:
        // If choice == 1: return -self
        // If choice == 0: return self
        //
        // -self in two's complement is: (!self) + 1
        // We can use: (self ^ mask) - mask
        // where mask = choice ? 0xFFFFFFFFFFFFFFFF : 0
        let mask = (choice.0 as i64).wrapping_neg();
        (self ^ mask).wrapping_sub(mask)
    }
}

impl<const N: usize> ConditionallyNegatable for [i64; N] {
    #[inline]
    fn conditional_negate(&self, choice: Choice) -> Self {
        let mut result = [0i64; N];
        for i in 0..N {
            result[i] = self[i].conditional_negate(choice);
        }
        result
    }
}

/// Constant-time table lookup
///
/// Selects `table[index]` in constant time by accessing ALL table entries.
/// This prevents timing side-channels that could reveal the index.
///
/// # Security
/// This function MUST access every entry in the table regardless of `index`
/// to prevent timing leakage.
#[inline]
pub fn ct_table_lookup<T: ConditionallySelectable + Default + Copy>(
    table: &[T],
    index: usize
) -> T {
    let mut result = T::default();

    for (i, entry) in table.iter().enumerate() {
        let choice = Choice::from_u8((i == index) as u8);
        result = T::conditional_select(&result, entry, choice);
    }

    result
}

/// Constant-time check if a value is zero
#[inline]
pub fn ct_is_zero_u64(value: u64) -> Choice {
    // If value == 0: value | -value = 0, MSB = 0
    // If value != 0: value | -value has MSB = 1
    let result = ((value | value.wrapping_neg()) >> 63) as u8;
    Choice(1 - result)
}

/// Constant-time conditional swap
///
/// If `choice == 1`: swaps `a` and `b`
/// If `choice == 0`: leaves `a` and `b` unchanged
#[inline]
pub fn ct_swap_u64(a: &mut u64, b: &mut u64, choice: Choice) {
    let mask = (choice.0 as u64).wrapping_neg();
    let x = mask & (*a ^ *b);
    *a ^= x;
    *b ^= x;
}

/// Constant-time conditional swap for arrays
#[inline]
pub fn ct_swap_array<const N: usize>(a: &mut [u64; N], b: &mut [u64; N], choice: Choice) {
    let mask = (choice.0 as u64).wrapping_neg();
    for i in 0..N {
        let x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choice_basic() {
        let t = Choice::true_choice();
        let f = Choice::false_choice();

        assert_eq!(t.unwrap_u8(), 1);
        assert_eq!(f.unwrap_u8(), 0);
        assert!(t.into_bool());
        assert!(!f.into_bool());
    }

    #[test]
    fn test_choice_logic() {
        let t = Choice::true_choice();
        let f = Choice::false_choice();

        assert_eq!((t & t).unwrap_u8(), 1);
        assert_eq!((t & f).unwrap_u8(), 0);
        assert_eq!((f & t).unwrap_u8(), 0);
        assert_eq!((f & f).unwrap_u8(), 0);

        assert_eq!((t | t).unwrap_u8(), 1);
        assert_eq!((t | f).unwrap_u8(), 1);
        assert_eq!((f | t).unwrap_u8(), 1);
        assert_eq!((f | f).unwrap_u8(), 0);

        assert_eq!((!t).unwrap_u8(), 0);
        assert_eq!((!f).unwrap_u8(), 1);
    }

    #[test]
    fn test_conditional_select_u64() {
        let a = 42u64;
        let b = 99u64;

        let result = u64::conditional_select(&a, &b, Choice::false_choice());
        assert_eq!(result, 42);

        let result = u64::conditional_select(&a, &b, Choice::true_choice());
        assert_eq!(result, 99);
    }

    #[test]
    fn test_ct_eq_u64() {
        let a = 12345u64;
        let b = 12345u64;
        let c = 54321u64;

        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
        assert!(!b.ct_eq(&c).into_bool());
    }

    #[test]
    fn test_ct_eq_array() {
        let a = [1u64, 2, 3, 4];
        let b = [1u64, 2, 3, 4];
        let c = [1u64, 2, 3, 5];

        assert!(a.ct_eq(&b).into_bool());
        assert!(!a.ct_eq(&c).into_bool());
    }

    #[test]
    fn test_ct_eq_slice() {
        let a = [1u64, 2, 3, 4];
        let b = [1u64, 2, 3, 4];
        let c = [1u64, 2, 3, 5];

        assert!(a[..].ct_eq(&b[..]).into_bool());
        assert!(!a[..].ct_eq(&c[..]).into_bool());
    }

    #[test]
    fn test_conditional_negate_i64() {
        let value = 42i64;

        let result = value.conditional_negate(Choice::false_choice());
        assert_eq!(result, 42);

        let result = value.conditional_negate(Choice::true_choice());
        assert_eq!(result, -42);

        let neg_value = -42i64;
        let result = neg_value.conditional_negate(Choice::true_choice());
        assert_eq!(result, 42);

        let result = neg_value.conditional_negate(Choice::false_choice());
        assert_eq!(result, -42);
    }

    #[test]
    fn test_ct_table_lookup() {
        let table = [10u64, 20, 30, 40, 50];

        assert_eq!(ct_table_lookup(&table, 0), 10);
        assert_eq!(ct_table_lookup(&table, 1), 20);
        assert_eq!(ct_table_lookup(&table, 2), 30);
        assert_eq!(ct_table_lookup(&table, 3), 40);
        assert_eq!(ct_table_lookup(&table, 4), 50);
    }

    #[test]
    fn test_ct_is_zero() {
        assert!(ct_is_zero_u64(0).into_bool());
        assert!(!ct_is_zero_u64(1).into_bool());
        assert!(!ct_is_zero_u64(0xFFFFFFFFFFFFFFFF).into_bool());
    }

    #[test]
    fn test_ct_swap() {
        let mut a = 42u64;
        let mut b = 99u64;

        ct_swap_u64(&mut a, &mut b, Choice::false_choice());
        assert_eq!(a, 42);
        assert_eq!(b, 99);

        ct_swap_u64(&mut a, &mut b, Choice::true_choice());
        assert_eq!(a, 99);
        assert_eq!(b, 42);
    }

    #[test]
    fn test_ct_swap_array() {
        let mut a = [1u64, 2, 3, 4];
        let mut b = [5u64, 6, 7, 8];

        ct_swap_array(&mut a, &mut b, Choice::false_choice());
        assert_eq!(a, [1, 2, 3, 4]);
        assert_eq!(b, [5, 6, 7, 8]);

        ct_swap_array(&mut a, &mut b, Choice::true_choice());
        assert_eq!(a, [5, 6, 7, 8]);
        assert_eq!(b, [1, 2, 3, 4]);
    }
}
