//! Constant-time operations
//!
//! This module provides constant-time primitives to prevent timing attacks.
//! All operations execute in time independent of secret values.

use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A type that can be compared in constant time
pub trait CtEqual {
    /// Compare two values in constant time
    fn ct_eq(&self, other: &Self) -> Choice;
}

impl CtEqual for [u8] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self, other)
    }
}

impl<const N: usize> CtEqual for [u8; N] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice())
    }
}

/// A constant-time optional value
///
/// This type represents a value that may or may not be present,
/// but the presence/absence is kept secret from timing attacks.
#[derive(Clone, Copy, Debug)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    /// Create a `CtOption` that is `Some`
    #[inline]
    pub const fn new(value: T, is_some: Choice) -> Self {
        Self { value, is_some }
    }

    /// Returns `Choice::from(1)` if this value is `Some`
    #[inline]
    pub const fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Returns `Choice::from(1)` if this value is `None`
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Unwrap the value or panic
    #[inline]
    pub fn unwrap(self) -> T {
        assert!(bool::from(self.is_some), "unwrap on None value");
        self.value
    }

    /// Map the value if Some
    #[inline]
    pub fn map<U, F>(self, f: F) -> CtOption<U>
    where
        F: FnOnce(T) -> U,
    {
        CtOption {
            value: f(self.value),
            is_some: self.is_some,
        }
    }
}

impl<T: ConditionallySelectable> CtOption<T> {
    /// Returns the contained value or a default
    #[inline]
    pub fn unwrap_or(self, default: T) -> T {
        T::conditional_select(&default, &self.value, self.is_some)
    }

    /// Returns the contained value or computes it from a closure
    #[inline]
    pub fn unwrap_or_else<F>(self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        T::conditional_select(&f(), &self.value, self.is_some)
    }
}

impl<T: Default + ConditionallySelectable> Default for CtOption<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default(), Choice::from(0))
    }
}

/// Constant-time byte operations
pub mod bytes {
    use crate::ct_utils::Choice;

    /// XOR two byte slices in place
    ///
    /// Panics if the slices have different lengths.
    #[inline]
    pub fn xor_inplace(dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }

    /// XOR two byte slices into a destination
    ///
    /// Panics if the slices have different lengths.
    #[inline]
    pub fn xor(dst: &mut [u8], a: &[u8], b: &[u8]) {
        assert_eq!(dst.len(), a.len());
        assert_eq!(dst.len(), b.len());
        for ((d, a), b) in dst.iter_mut().zip(a.iter()).zip(b.iter()) {
            *d = a ^ b;
        }
    }

    /// Conditionally swap two mutable byte slices in constant time
    ///
    /// If `swap` is true, the contents of `a` and `b` are swapped.
    /// This operation is constant-time.
    #[inline]
    pub fn conditional_swap(swap: Choice, a: &mut [u8], b: &mut [u8]) {
        assert_eq!(a.len(), b.len());
        let swap_byte = swap.unwrap_u8() & 1;
        for (a_byte, b_byte) in a.iter_mut().zip(b.iter_mut()) {
            let mask = swap_byte.wrapping_neg();
            let t = (*a_byte ^ *b_byte) & mask;
            *a_byte ^= t;
            *b_byte ^= t;
        }
    }

    /// Copy bytes conditionally in constant time
    ///
    /// If `choice` is true, copies from `src` to `dst`.
    /// Otherwise, `dst` is left unchanged.
    #[inline]
    pub fn conditional_copy(choice: Choice, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mask = (choice.unwrap_u8() & 1).wrapping_neg();
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d = (*d & !mask) | (*s & mask);
        }
    }
}

/// Constant-time arithmetic operations
pub mod arithmetic {
    use crate::ct_utils::Choice;

    /// Add with carry, constant-time
    ///
    /// Returns (result, carry)
    #[inline(always)]
    pub const fn adc(a: u64, b: u64, carry: u8) -> (u64, u8) {
        let sum = (a as u128) + (b as u128) + (carry as u128);
        (sum as u64, (sum >> 64) as u8)
    }

    /// Subtract with borrow, constant-time
    ///
    /// Returns (result, borrow)
    #[inline(always)]
    pub const fn sbb(a: u64, b: u64, borrow: u8) -> (u64, u8) {
        let diff = (a as u128).wrapping_sub(b as u128).wrapping_sub(borrow as u128);
        (diff as u64, ((diff >> 64) & 1) as u8)
    }

    /// Multiply and add with carry, constant-time
    ///
    /// Computes a * b + c, returning low and high words
    #[inline(always)]
    pub const fn mac(a: u64, b: u64, c: u64) -> (u64, u64) {
        let product = (a as u128) * (b as u128) + (c as u128);
        (product as u64, (product >> 64) as u64)
    }

    /// Constant-time less than comparison for u64
    #[inline]
    pub fn ct_lt_u64(a: u64, b: u64) -> Choice {
        let bit = ((a ^ b) | ((a.wrapping_sub(b)) ^ b)) >> 63;
        Choice::from(bit as u8)
    }

    /// Constant-time equality for u64
    #[inline]
    pub fn ct_eq_u64(a: u64, b: u64) -> Choice {
        let diff = a ^ b;
        let diff = diff | diff.wrapping_neg();
        Choice::from(((diff >> 63) ^ 1) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct_utils::Choice;

    #[test]
    fn test_ct_option() {
        let some = CtOption::new(42u32, Choice::from(1));
        assert!(bool::from(some.is_some()));
        assert_eq!(some.unwrap(), 42);

        let none = CtOption::new(42u32, Choice::from(0));
        assert!(bool::from(none.is_none()));
        assert_eq!(none.unwrap_or(99), 99);
    }

    #[test]
    fn test_xor_inplace() {
        let mut dst = [0x11, 0x22, 0x33, 0x44];
        let src = [0x55, 0x66, 0x77, 0x88];
        bytes::xor_inplace(&mut dst, &src);
        assert_eq!(dst, [0x44, 0x44, 0x44, 0xcc]);
    }

    #[test]
    fn test_conditional_swap() {
        let mut a = [1, 2, 3, 4];
        let mut b = [5, 6, 7, 8];

        bytes::conditional_swap(Choice::from(1), &mut a, &mut b);
        assert_eq!(a, [5, 6, 7, 8]);
        assert_eq!(b, [1, 2, 3, 4]);

        bytes::conditional_swap(Choice::from(0), &mut a, &mut b);
        assert_eq!(a, [5, 6, 7, 8]);
        assert_eq!(b, [1, 2, 3, 4]);
    }

    #[test]
    fn test_adc() {
        let (sum, carry) = arithmetic::adc(u64::MAX, 1, 0);
        assert_eq!(sum, 0);
        assert_eq!(carry, 1);

        let (sum, carry) = arithmetic::adc(u64::MAX, u64::MAX, 1);
        assert_eq!(sum, u64::MAX);
        assert_eq!(carry, 1);
    }
}
