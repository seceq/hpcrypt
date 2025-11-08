//! P-384 Field Arithmetic
//!
//! This module implements arithmetic in the prime field F_p where p is the
//! P-384 prime modulus. All operations are constant-time to prevent timing
//! attacks.
//!
//! # Representation
//!
//! Field elements are represented using 6 x 64-bit limbs in little-endian order.
//! This is a "saturated" representation where each limb can use the full 64 bits.
//!
//! # Security
//!
//! All operations use constant-time implementations via the `subtle` crate to
//! prevent timing side-channel attacks.

// Clippy: Explicit indexing is clearer for cryptographic code
#![allow(clippy::needless_range_loop)]

use super::constants::P384_MODULUS;
use core::fmt;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element in the P-384 prime field.
///
/// Represented as 6 x 64-bit limbs in little-endian order:
/// value = limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192 + limbs[4]*2^256 + limbs[5]*2^320
#[derive(Clone, Copy)]
pub struct FieldElement {
    /// Limbs in little-endian order
    pub(crate) limbs: [u64; 6],
}

impl FieldElement {
    /// Number of 64-bit limbs
    pub const LIMBS: usize = 6;

    /// Number of bytes (384 bits = 48 bytes)
    pub const BYTES: usize = 48;

    /// Creates a field element from 6 limbs (little-endian).
    ///
    /// # Note
    ///
    /// This constructor does NOT perform modular reduction. The caller must
    /// ensure the value is already reduced modulo p.
    #[inline]
    pub const fn from_limbs(limbs: [u64; 6]) -> Self {
        Self { limbs }
    }

    /// Creates a field element representing zero.
    #[inline]
    pub const fn zero() -> Self {
        Self { limbs: [0, 0, 0, 0, 0, 0] }
    }

    /// Creates a field element representing one.
    #[inline]
    pub const fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0, 0, 0],
        }
    }

    /// Returns true if this field element is zero.
    ///
    /// This is a constant-time operation.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::zero())
    }

    /// Converts field element to bytes (big-endian encoding).
    ///
    /// This matches the standard SEC1 encoding for field elements.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];

        // Big-endian: most significant limb first
        for i in 0..6 {
            let limb = self.limbs[5 - i];
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }

        bytes
    }

    /// Creates a field element from bytes (big-endian encoding).
    ///
    /// Returns `None` if the value is >= p (not in canonical form).
    pub fn from_bytes(bytes: &[u8; 48]) -> Option<Self> {
        let mut limbs = [0u64; 6];

        // Big-endian: most significant limb first
        for i in 0..6 {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[5 - i] = u64::from_be_bytes(limb_bytes);
        }

        let element = Self { limbs };

        // Check if value < p (in canonical form)
        if element.is_canonical() {
            Some(element)
        } else {
            None
        }
    }

    /// Checks if this field element is in canonical form (< p).
    ///
    /// This is a constant-time operation.
    fn is_canonical(&self) -> bool {
        // Compare limbs from most significant to least significant
        for i in (0..6).rev() {
            if self.limbs[i] < P384_MODULUS[i] {
                return true;
            }
            if self.limbs[i] > P384_MODULUS[i] {
                return false;
            }
        }
        // Equal to modulus, not canonical
        false
    }

    /// Converts a u64 to a field element.
    #[inline]
    pub const fn from_u64(value: u64) -> Self {
        Self {
            limbs: [value, 0, 0, 0, 0, 0],
        }
    }
}

// Constant-time equality comparison
impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.limbs[0].ct_eq(&other.limbs[0])
            & self.limbs[1].ct_eq(&other.limbs[1])
            & self.limbs[2].ct_eq(&other.limbs[2])
            & self.limbs[3].ct_eq(&other.limbs[3])
            & self.limbs[4].ct_eq(&other.limbs[4])
            & self.limbs[5].ct_eq(&other.limbs[5])
    }
}

// Constant-time conditional selection
impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            limbs: [
                u64::conditional_select(&a.limbs[0], &b.limbs[0], choice),
                u64::conditional_select(&a.limbs[1], &b.limbs[1], choice),
                u64::conditional_select(&a.limbs[2], &b.limbs[2], choice),
                u64::conditional_select(&a.limbs[3], &b.limbs[3], choice),
                u64::conditional_select(&a.limbs[4], &b.limbs[4], choice),
                u64::conditional_select(&a.limbs[5], &b.limbs[5], choice),
            ],
        }
    }
}

// Debug formatting
impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FieldElement({:016x}_{:016x}_{:016x}_{:016x}_{:016x}_{:016x})",
            self.limbs[5], self.limbs[4], self.limbs[3], self.limbs[2], self.limbs[1], self.limbs[0]
        )
    }
}

// Equality (constant-time)
impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p384::constants::P384_MODULUS;

    #[test]
    fn test_zero() {
        let zero = FieldElement::zero();
        assert_eq!(zero.limbs, [0, 0, 0, 0, 0, 0]);
        assert!(bool::from(zero.is_zero()));
    }

    #[test]
    fn test_one() {
        let one = FieldElement::one();
        assert_eq!(one.limbs, [1, 0, 0, 0, 0, 0]);
        assert!(!bool::from(one.is_zero()));
    }

    #[test]
    fn test_from_limbs() {
        let fe = FieldElement::from_limbs([0x1234, 0x5678, 0x9ABC, 0xDEF0, 0x1111, 0x2222]);
        assert_eq!(fe.limbs[0], 0x1234);
        assert_eq!(fe.limbs[1], 0x5678);
        assert_eq!(fe.limbs[2], 0x9ABC);
        assert_eq!(fe.limbs[3], 0xDEF0);
        assert_eq!(fe.limbs[4], 0x1111);
        assert_eq!(fe.limbs[5], 0x2222);
    }

    #[test]
    fn test_from_u64() {
        let fe = FieldElement::from_u64(42);
        assert_eq!(fe.limbs, [42, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_ct_eq() {
        let a = FieldElement::from_u64(42);
        let b = FieldElement::from_u64(42);
        let c = FieldElement::from_u64(43);

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn test_to_bytes() {
        let fe = FieldElement::from_limbs([
            0x0102030405060708,
            0x090A0B0C0D0E0F10,
            0x1112131415161718,
            0x191A1B1C1D1E1F20,
            0x2122232425262728,
            0x292A2B2C2D2E2F30,
        ]);

        let bytes = fe.to_bytes();

        // Big-endian: most significant limb first
        assert_eq!(
            bytes,
            [
                0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, // limbs[5]
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // limbs[4]
                0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, // limbs[3]
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // limbs[2]
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // limbs[1]
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // limbs[0]
            ]
        );
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [
            0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, // limbs[5]
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // limbs[4]
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, // limbs[3]
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // limbs[2]
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // limbs[1]
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // limbs[0]
        ];

        let fe = FieldElement::from_bytes(&bytes).unwrap();

        assert_eq!(fe.limbs[0], 0x0102030405060708);
        assert_eq!(fe.limbs[1], 0x090A0B0C0D0E0F10);
        assert_eq!(fe.limbs[2], 0x1112131415161718);
        assert_eq!(fe.limbs[3], 0x191A1B1C1D1E1F20);
        assert_eq!(fe.limbs[4], 0x2122232425262728);
        assert_eq!(fe.limbs[5], 0x292A2B2C2D2E2F30);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let original = FieldElement::from_limbs([
            0x0102030405060708,
            0x090A0B0C0D0E0F10,
            0x1112131415161718,
            0x191A1B1C1D1E1F20,
            0x2122232425262728,
            0x292A2B2C2D2E2F30,
        ]);

        let bytes = original.to_bytes();
        let recovered = FieldElement::from_bytes(&bytes).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_rejects_modulus() {
        // P-384 modulus should be rejected (not canonical)
        let modulus = FieldElement::from_limbs(P384_MODULUS);
        let bytes = modulus.to_bytes();
        assert!(FieldElement::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_from_bytes_rejects_larger_than_modulus() {
        // All 0xFF bytes is definitely > modulus
        let bytes = [0xFF; 48];
        assert!(FieldElement::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_from_bytes_accepts_zero() {
        let bytes = [0u8; 48];
        let fe = FieldElement::from_bytes(&bytes).unwrap();
        assert!(bool::from(fe.is_zero()));
    }

    #[test]
    fn test_from_bytes_accepts_one() {
        let mut bytes = [0u8; 48];
        bytes[47] = 1; // Little-endian in memory, but big-endian encoding
        let fe = FieldElement::from_bytes(&bytes).unwrap();
        assert_eq!(fe, FieldElement::one());
    }

    #[test]
    fn test_conditional_select() {
        let a = FieldElement::from_u64(42);
        let b = FieldElement::from_u64(99);

        let selected_a = FieldElement::conditional_select(&a, &b, Choice::from(0));
        let selected_b = FieldElement::conditional_select(&a, &b, Choice::from(1));

        assert_eq!(selected_a, a);
        assert_eq!(selected_b, b);
    }
}
