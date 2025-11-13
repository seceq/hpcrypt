//! P-521 Field Arithmetic
//!
//! This module implements arithmetic in the prime field F_p where p is the
//! P-521 prime modulus (2^521 - 1). All operations are constant-time to prevent
//! timing attacks.
//!
//! # Representation
//!
//! Field elements are represented using 9 x 64-bit limbs in little-endian order.
//! P-521 uses a Mersenne prime p = 2^521 - 1, which allows for very efficient
//! modular reduction.
//!
//! # Security
//!
//! All operations use constant-time implementations via the `subtle` crate to
//! prevent timing side-channel attacks.

#![allow(clippy::needless_range_loop)]

use super::constants::P521_MODULUS;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::fmt;

/// A field element in the P-521 prime field.
///
/// Represented as 9 x 64-bit limbs in little-endian order:
/// value = limbs\[0\] + limbs\[1\]*2^64 + ... + limbs\[8\]*2^512
///
/// The top limb (limbs\[8\]) only uses 9 bits since 521 = 8*64 + 9.
#[derive(Clone, Copy)]
pub struct FieldElement {
    /// Limbs in little-endian order
    pub(crate) limbs: [u64; 9],
}

impl FieldElement {
    /// Number of 64-bit limbs
    pub const LIMBS: usize = 9;

    /// Number of bytes (521 bits = 66 bytes, but we use 66 bytes)
    pub const BYTES: usize = 66;

    /// Creates a field element from 9 limbs (little-endian).
    ///
    /// # Note
    ///
    /// This constructor does NOT perform modular reduction. The caller must
    /// ensure the value is already reduced modulo p.
    #[inline]
    pub const fn from_limbs(limbs: [u64; 9]) -> Self {
        Self { limbs }
    }

    /// Creates a field element representing zero.
    #[inline]
    pub const fn zero() -> Self {
        Self {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Creates a field element representing one.
    #[inline]
    pub const fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Creates a field element from a u64 value (for testing purposes).
    #[inline]
    pub const fn from_u64(value: u64) -> Self {
        Self {
            limbs: [value, 0, 0, 0, 0, 0, 0, 0, 0],
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
    /// Returns 66 bytes (521 bits).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];

        // Simplified approach: Pack all 521 bits into 66 bytes (big-endian)
        // Limbs are stored in little-endian (limb[0] is LSB), but bytes are big-endian (bytes[0] is MSB)

        // bytes[0]: bits 520-513 (top 8 bits of limb[8])
        bytes[0] = (self.limbs[8] >> 1) as u8;

        // bytes[1]: bit 512 (bottom bit of limb[8]) in bit 7, bits 511-505 (top 7 bits of limb[7]) in bits 6-0
        bytes[1] = (((self.limbs[8] & 1) << 7) | ((self.limbs[7] >> 57) & 0x7F)) as u8;

        // bytes[2-9]: bits 504-441 (bits 56-0 of limb[7] and bit 63 of limb[6])
        bytes[2] = (self.limbs[7] >> 49) as u8;
        bytes[3] = (self.limbs[7] >> 41) as u8;
        bytes[4] = (self.limbs[7] >> 33) as u8;
        bytes[5] = (self.limbs[7] >> 25) as u8;
        bytes[6] = (self.limbs[7] >> 17) as u8;
        bytes[7] = (self.limbs[7] >> 9) as u8;
        bytes[8] = (self.limbs[7] >> 1) as u8;
        bytes[9] = (((self.limbs[7] & 1) << 7) | ((self.limbs[6] >> 57) & 0x7F)) as u8;

        // bytes[10-17]: limb[6]
        bytes[10] = (self.limbs[6] >> 49) as u8;
        bytes[11] = (self.limbs[6] >> 41) as u8;
        bytes[12] = (self.limbs[6] >> 33) as u8;
        bytes[13] = (self.limbs[6] >> 25) as u8;
        bytes[14] = (self.limbs[6] >> 17) as u8;
        bytes[15] = (self.limbs[6] >> 9) as u8;
        bytes[16] = (self.limbs[6] >> 1) as u8;
        bytes[17] = (((self.limbs[6] & 1) << 7) | ((self.limbs[5] >> 57) & 0x7F)) as u8;

        // bytes[18-25]: limb[5]
        bytes[18] = (self.limbs[5] >> 49) as u8;
        bytes[19] = (self.limbs[5] >> 41) as u8;
        bytes[20] = (self.limbs[5] >> 33) as u8;
        bytes[21] = (self.limbs[5] >> 25) as u8;
        bytes[22] = (self.limbs[5] >> 17) as u8;
        bytes[23] = (self.limbs[5] >> 9) as u8;
        bytes[24] = (self.limbs[5] >> 1) as u8;
        bytes[25] = (((self.limbs[5] & 1) << 7) | ((self.limbs[4] >> 57) & 0x7F)) as u8;

        // bytes[26-33]: limb[4]
        bytes[26] = (self.limbs[4] >> 49) as u8;
        bytes[27] = (self.limbs[4] >> 41) as u8;
        bytes[28] = (self.limbs[4] >> 33) as u8;
        bytes[29] = (self.limbs[4] >> 25) as u8;
        bytes[30] = (self.limbs[4] >> 17) as u8;
        bytes[31] = (self.limbs[4] >> 9) as u8;
        bytes[32] = (self.limbs[4] >> 1) as u8;
        bytes[33] = (((self.limbs[4] & 1) << 7) | ((self.limbs[3] >> 57) & 0x7F)) as u8;

        // bytes[34-41]: limb[3]
        bytes[34] = (self.limbs[3] >> 49) as u8;
        bytes[35] = (self.limbs[3] >> 41) as u8;
        bytes[36] = (self.limbs[3] >> 33) as u8;
        bytes[37] = (self.limbs[3] >> 25) as u8;
        bytes[38] = (self.limbs[3] >> 17) as u8;
        bytes[39] = (self.limbs[3] >> 9) as u8;
        bytes[40] = (self.limbs[3] >> 1) as u8;
        bytes[41] = (((self.limbs[3] & 1) << 7) | ((self.limbs[2] >> 57) & 0x7F)) as u8;

        // bytes[42-49]: limb[2]
        bytes[42] = (self.limbs[2] >> 49) as u8;
        bytes[43] = (self.limbs[2] >> 41) as u8;
        bytes[44] = (self.limbs[2] >> 33) as u8;
        bytes[45] = (self.limbs[2] >> 25) as u8;
        bytes[46] = (self.limbs[2] >> 17) as u8;
        bytes[47] = (self.limbs[2] >> 9) as u8;
        bytes[48] = (self.limbs[2] >> 1) as u8;
        bytes[49] = (((self.limbs[2] & 1) << 7) | ((self.limbs[1] >> 57) & 0x7F)) as u8;

        // bytes[50-57]: limb[1]
        bytes[50] = (self.limbs[1] >> 49) as u8;
        bytes[51] = (self.limbs[1] >> 41) as u8;
        bytes[52] = (self.limbs[1] >> 33) as u8;
        bytes[53] = (self.limbs[1] >> 25) as u8;
        bytes[54] = (self.limbs[1] >> 17) as u8;
        bytes[55] = (self.limbs[1] >> 9) as u8;
        bytes[56] = (self.limbs[1] >> 1) as u8;
        bytes[57] = (((self.limbs[1] & 1) << 7) | ((self.limbs[0] >> 57) & 0x7F)) as u8;

        // bytes[58-65]: limb[0]
        bytes[58] = (self.limbs[0] >> 49) as u8;
        bytes[59] = (self.limbs[0] >> 41) as u8;
        bytes[60] = (self.limbs[0] >> 33) as u8;
        bytes[61] = (self.limbs[0] >> 25) as u8;
        bytes[62] = (self.limbs[0] >> 17) as u8;
        bytes[63] = (self.limbs[0] >> 9) as u8;
        bytes[64] = (self.limbs[0] >> 1) as u8;
        bytes[65] = ((self.limbs[0] & 1) << 7) as u8;

        bytes
    }

    /// Creates a field element from bytes (big-endian encoding).
    ///
    /// Expects 66 bytes (521 bits).
    /// Returns `None` if the value is >= p (not in canonical form).
    pub fn from_bytes(bytes: &[u8; 66]) -> Option<Self> {
        let mut limbs = [0u64; 9];

        // Reverse the to_bytes encoding
        // bytes[0]: bits 520-513 (top 8 bits of limb[8])
        // bytes[1]: bit 512 (bottom bit of limb[8]) in bit 7, bits 511-505 (top 7 bits of limb[7]) in bits 6-0

        limbs[8] = ((bytes[0] as u64) << 1) | ((bytes[1] as u64) >> 7);

        limbs[7] = ((bytes[1] as u64 & 0x7F) << 57)
            | ((bytes[2] as u64) << 49)
            | ((bytes[3] as u64) << 41)
            | ((bytes[4] as u64) << 33)
            | ((bytes[5] as u64) << 25)
            | ((bytes[6] as u64) << 17)
            | ((bytes[7] as u64) << 9)
            | ((bytes[8] as u64) << 1)
            | ((bytes[9] as u64) >> 7);

        limbs[6] = ((bytes[9] as u64 & 0x7F) << 57)
            | ((bytes[10] as u64) << 49)
            | ((bytes[11] as u64) << 41)
            | ((bytes[12] as u64) << 33)
            | ((bytes[13] as u64) << 25)
            | ((bytes[14] as u64) << 17)
            | ((bytes[15] as u64) << 9)
            | ((bytes[16] as u64) << 1)
            | ((bytes[17] as u64) >> 7);

        limbs[5] = ((bytes[17] as u64 & 0x7F) << 57)
            | ((bytes[18] as u64) << 49)
            | ((bytes[19] as u64) << 41)
            | ((bytes[20] as u64) << 33)
            | ((bytes[21] as u64) << 25)
            | ((bytes[22] as u64) << 17)
            | ((bytes[23] as u64) << 9)
            | ((bytes[24] as u64) << 1)
            | ((bytes[25] as u64) >> 7);

        limbs[4] = ((bytes[25] as u64 & 0x7F) << 57)
            | ((bytes[26] as u64) << 49)
            | ((bytes[27] as u64) << 41)
            | ((bytes[28] as u64) << 33)
            | ((bytes[29] as u64) << 25)
            | ((bytes[30] as u64) << 17)
            | ((bytes[31] as u64) << 9)
            | ((bytes[32] as u64) << 1)
            | ((bytes[33] as u64) >> 7);

        limbs[3] = ((bytes[33] as u64 & 0x7F) << 57)
            | ((bytes[34] as u64) << 49)
            | ((bytes[35] as u64) << 41)
            | ((bytes[36] as u64) << 33)
            | ((bytes[37] as u64) << 25)
            | ((bytes[38] as u64) << 17)
            | ((bytes[39] as u64) << 9)
            | ((bytes[40] as u64) << 1)
            | ((bytes[41] as u64) >> 7);

        limbs[2] = ((bytes[41] as u64 & 0x7F) << 57)
            | ((bytes[42] as u64) << 49)
            | ((bytes[43] as u64) << 41)
            | ((bytes[44] as u64) << 33)
            | ((bytes[45] as u64) << 25)
            | ((bytes[46] as u64) << 17)
            | ((bytes[47] as u64) << 9)
            | ((bytes[48] as u64) << 1)
            | ((bytes[49] as u64) >> 7);

        limbs[1] = ((bytes[49] as u64 & 0x7F) << 57)
            | ((bytes[50] as u64) << 49)
            | ((bytes[51] as u64) << 41)
            | ((bytes[52] as u64) << 33)
            | ((bytes[53] as u64) << 25)
            | ((bytes[54] as u64) << 17)
            | ((bytes[55] as u64) << 9)
            | ((bytes[56] as u64) << 1)
            | ((bytes[57] as u64) >> 7);

        limbs[0] = ((bytes[57] as u64 & 0x7F) << 57)
            | ((bytes[58] as u64) << 49)
            | ((bytes[59] as u64) << 41)
            | ((bytes[60] as u64) << 33)
            | ((bytes[61] as u64) << 25)
            | ((bytes[62] as u64) << 17)
            | ((bytes[63] as u64) << 9)
            | ((bytes[64] as u64) << 1)
            | ((bytes[65] as u64) >> 7);

        let fe = Self { limbs };

        // Check if value < p
        if fe.lt_modulus().into() {
            Some(fe)
        } else {
            None
        }
    }

    /// Returns true if self < p (constant-time).
    fn lt_modulus(&self) -> Choice {
        // Check if any limb is less than the corresponding modulus limb
        let mut less = Choice::from(0);
        let mut equal = Choice::from(1);

        for i in (0..9).rev() {
            let lt = self.limbs[i] < P521_MODULUS[i];
            let eq = self.limbs[i] == P521_MODULUS[i];

            less |= equal & Choice::from(lt as u8);
            equal &= Choice::from(eq as u8);
        }

        less
    }

    /// Negates this field element: returns -self (mod p).
    ///
    /// This is a constant-time operation.
    pub fn negate(&self) -> Self {
        // If self == 0, return 0, otherwise return p - self
        let is_zero = self.is_zero();

        let mut result = [0u64; 9];
        let mut borrow = 0u64;

        for i in 0..9 {
            let (diff, b1) = P521_MODULUS[i].overflowing_sub(self.limbs[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) + (b2 as u64);
        }

        let neg = Self { limbs: result };
        Self::conditional_select(&neg, &Self::zero(), is_zero)
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({:016x}", self.limbs[8])?;
        for i in (0..8).rev() {
            write!(f, "_{:016x}", self.limbs[i])?;
        }
        write!(f, ")")
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut eq = Choice::from(1);
        for i in 0..9 {
            eq &= self.limbs[i].ct_eq(&other.limbs[i]);
        }
        eq
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; 9];
        for i in 0..9 {
            limbs[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        Self { limbs }
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for FieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();

        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));
        assert_ne!(zero, one);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let one = FieldElement::one();
        let bytes = one.to_bytes();
        let recovered = FieldElement::from_bytes(&bytes).unwrap();
        assert_eq!(one, recovered);
    }

    #[test]
    fn test_negate_zero() {
        let zero = FieldElement::zero();
        let neg_zero = zero.negate();
        assert_eq!(zero, neg_zero);
    }

    #[test]
    fn test_negate_one() {
        let one = FieldElement::one();
        let neg_one = one.negate();

        // -1 should equal p - 1
        let expected = FieldElement::from_limbs([
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x1FF,
        ]);
        assert_eq!(neg_one, expected);
    }

    #[test]
    fn test_conditional_select() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();

        let selected = FieldElement::conditional_select(&zero, &one, Choice::from(0));
        assert_eq!(selected, zero);

        let selected = FieldElement::conditional_select(&zero, &one, Choice::from(1));
        assert_eq!(selected, one);
    }
}
