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
    /// Returns 66 bytes (521 bits in big-endian, with 7 leading zero bits).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];

        // Standard big-endian encoding for 521-bit value:
        // The value is stored in 9 limbs (little-endian):
        //   limbs[0] = bits 0-63
        //   limbs[1] = bits 64-127
        //   ...
        //   limbs[7] = bits 448-511
        //   limbs[8] = bits 512-520 (9 bits)
        //
        // Output 66 bytes in big-endian:
        //   bytes[0] = bits 520-513 (but only 521-513=8 bits used, top bit is bit 520)
        //   bytes[1] = bits 512-505 (but bits 512-520 overlap with limbs[8])
        //   ...
        //   bytes[65] = bits 7-0

        // Handle the 521-bit to 66-byte mapping
        // 521 = 8*65 + 1, so we need to handle the bit alignment carefully
        //
        // In big-endian, bytes[0] contains the MSB.
        // For a 521-bit number fitting in 66 bytes (528 bits), the top 7 bits of byte[0] are padding.
        //
        // Byte layout:
        // bytes[0]: [0 0 0 0 0 0 0 bit520]  (7 padding zeros + bit 520)
        // bytes[1]: [bits 519-512]
        // bytes[2]: [bits 511-504]
        // ...
        // bytes[65]: [bits 7-0]

        // bytes[0]: only bit 520 (MSB of 521-bit number), in the LSB position of the byte
        bytes[0] = ((self.limbs[8] >> 8) & 0x01) as u8;

        // bytes[1]: bits 519-512 (bottom 8 bits of limbs[8])
        bytes[1] = (self.limbs[8] & 0xFF) as u8;

        // bytes[2..10]: limbs[7] (bits 511-448)
        bytes[2] = (self.limbs[7] >> 56) as u8;
        bytes[3] = (self.limbs[7] >> 48) as u8;
        bytes[4] = (self.limbs[7] >> 40) as u8;
        bytes[5] = (self.limbs[7] >> 32) as u8;
        bytes[6] = (self.limbs[7] >> 24) as u8;
        bytes[7] = (self.limbs[7] >> 16) as u8;
        bytes[8] = (self.limbs[7] >> 8) as u8;
        bytes[9] = self.limbs[7] as u8;

        // bytes[10..18]: limbs[6] (bits 447-384)
        bytes[10] = (self.limbs[6] >> 56) as u8;
        bytes[11] = (self.limbs[6] >> 48) as u8;
        bytes[12] = (self.limbs[6] >> 40) as u8;
        bytes[13] = (self.limbs[6] >> 32) as u8;
        bytes[14] = (self.limbs[6] >> 24) as u8;
        bytes[15] = (self.limbs[6] >> 16) as u8;
        bytes[16] = (self.limbs[6] >> 8) as u8;
        bytes[17] = self.limbs[6] as u8;

        // bytes[18..26]: limbs[5] (bits 383-320)
        bytes[18] = (self.limbs[5] >> 56) as u8;
        bytes[19] = (self.limbs[5] >> 48) as u8;
        bytes[20] = (self.limbs[5] >> 40) as u8;
        bytes[21] = (self.limbs[5] >> 32) as u8;
        bytes[22] = (self.limbs[5] >> 24) as u8;
        bytes[23] = (self.limbs[5] >> 16) as u8;
        bytes[24] = (self.limbs[5] >> 8) as u8;
        bytes[25] = self.limbs[5] as u8;

        // bytes[26..34]: limbs[4] (bits 319-256)
        bytes[26] = (self.limbs[4] >> 56) as u8;
        bytes[27] = (self.limbs[4] >> 48) as u8;
        bytes[28] = (self.limbs[4] >> 40) as u8;
        bytes[29] = (self.limbs[4] >> 32) as u8;
        bytes[30] = (self.limbs[4] >> 24) as u8;
        bytes[31] = (self.limbs[4] >> 16) as u8;
        bytes[32] = (self.limbs[4] >> 8) as u8;
        bytes[33] = self.limbs[4] as u8;

        // bytes[34..42]: limbs[3] (bits 255-192)
        bytes[34] = (self.limbs[3] >> 56) as u8;
        bytes[35] = (self.limbs[3] >> 48) as u8;
        bytes[36] = (self.limbs[3] >> 40) as u8;
        bytes[37] = (self.limbs[3] >> 32) as u8;
        bytes[38] = (self.limbs[3] >> 24) as u8;
        bytes[39] = (self.limbs[3] >> 16) as u8;
        bytes[40] = (self.limbs[3] >> 8) as u8;
        bytes[41] = self.limbs[3] as u8;

        // bytes[42..50]: limbs[2] (bits 191-128)
        bytes[42] = (self.limbs[2] >> 56) as u8;
        bytes[43] = (self.limbs[2] >> 48) as u8;
        bytes[44] = (self.limbs[2] >> 40) as u8;
        bytes[45] = (self.limbs[2] >> 32) as u8;
        bytes[46] = (self.limbs[2] >> 24) as u8;
        bytes[47] = (self.limbs[2] >> 16) as u8;
        bytes[48] = (self.limbs[2] >> 8) as u8;
        bytes[49] = self.limbs[2] as u8;

        // bytes[50..58]: limbs[1] (bits 127-64)
        bytes[50] = (self.limbs[1] >> 56) as u8;
        bytes[51] = (self.limbs[1] >> 48) as u8;
        bytes[52] = (self.limbs[1] >> 40) as u8;
        bytes[53] = (self.limbs[1] >> 32) as u8;
        bytes[54] = (self.limbs[1] >> 24) as u8;
        bytes[55] = (self.limbs[1] >> 16) as u8;
        bytes[56] = (self.limbs[1] >> 8) as u8;
        bytes[57] = self.limbs[1] as u8;

        // bytes[58..66]: limbs[0] (bits 63-0)
        bytes[58] = (self.limbs[0] >> 56) as u8;
        bytes[59] = (self.limbs[0] >> 48) as u8;
        bytes[60] = (self.limbs[0] >> 40) as u8;
        bytes[61] = (self.limbs[0] >> 32) as u8;
        bytes[62] = (self.limbs[0] >> 24) as u8;
        bytes[63] = (self.limbs[0] >> 16) as u8;
        bytes[64] = (self.limbs[0] >> 8) as u8;
        bytes[65] = self.limbs[0] as u8;

        bytes
    }

    /// Creates a field element from bytes (big-endian encoding).
    ///
    /// Expects 66 bytes (521 bits in big-endian, with 7 leading zero bits).
    /// Returns `None` if the value is >= p (not in canonical form).
    pub fn from_bytes(bytes: &[u8; 66]) -> Option<Self> {
        let mut limbs = [0u64; 9];

        // Standard big-endian decoding for 521-bit value:
        // Byte layout:
        // bytes[0]: [0 0 0 0 0 0 0 bit520]  (7 padding zeros + bit 520)
        // bytes[1]: [bits 519-512]
        // bytes[2]: [bits 511-504]
        // ...
        // bytes[65]: [bits 7-0]

        // Check that the top 7 bits of bytes[0] are zero (padding)
        if bytes[0] & 0xFE != 0 {
            return None;
        }

        // limbs[8]: bits 520-512 (9 bits)
        // bit 520 is in bytes[0] bit 0, bits 519-512 are in bytes[1]
        limbs[8] = ((bytes[0] as u64 & 0x01) << 8) | (bytes[1] as u64);

        // limbs[7]: bits 511-448 (bytes[2..10])
        limbs[7] = ((bytes[2] as u64) << 56)
            | ((bytes[3] as u64) << 48)
            | ((bytes[4] as u64) << 40)
            | ((bytes[5] as u64) << 32)
            | ((bytes[6] as u64) << 24)
            | ((bytes[7] as u64) << 16)
            | ((bytes[8] as u64) << 8)
            | (bytes[9] as u64);

        // limbs[6]: bits 447-384 (bytes[10..18])
        limbs[6] = ((bytes[10] as u64) << 56)
            | ((bytes[11] as u64) << 48)
            | ((bytes[12] as u64) << 40)
            | ((bytes[13] as u64) << 32)
            | ((bytes[14] as u64) << 24)
            | ((bytes[15] as u64) << 16)
            | ((bytes[16] as u64) << 8)
            | (bytes[17] as u64);

        // limbs[5]: bits 383-320 (bytes[18..26])
        limbs[5] = ((bytes[18] as u64) << 56)
            | ((bytes[19] as u64) << 48)
            | ((bytes[20] as u64) << 40)
            | ((bytes[21] as u64) << 32)
            | ((bytes[22] as u64) << 24)
            | ((bytes[23] as u64) << 16)
            | ((bytes[24] as u64) << 8)
            | (bytes[25] as u64);

        // limbs[4]: bits 319-256 (bytes[26..34])
        limbs[4] = ((bytes[26] as u64) << 56)
            | ((bytes[27] as u64) << 48)
            | ((bytes[28] as u64) << 40)
            | ((bytes[29] as u64) << 32)
            | ((bytes[30] as u64) << 24)
            | ((bytes[31] as u64) << 16)
            | ((bytes[32] as u64) << 8)
            | (bytes[33] as u64);

        // limbs[3]: bits 255-192 (bytes[34..42])
        limbs[3] = ((bytes[34] as u64) << 56)
            | ((bytes[35] as u64) << 48)
            | ((bytes[36] as u64) << 40)
            | ((bytes[37] as u64) << 32)
            | ((bytes[38] as u64) << 24)
            | ((bytes[39] as u64) << 16)
            | ((bytes[40] as u64) << 8)
            | (bytes[41] as u64);

        // limbs[2]: bits 191-128 (bytes[42..50])
        limbs[2] = ((bytes[42] as u64) << 56)
            | ((bytes[43] as u64) << 48)
            | ((bytes[44] as u64) << 40)
            | ((bytes[45] as u64) << 32)
            | ((bytes[46] as u64) << 24)
            | ((bytes[47] as u64) << 16)
            | ((bytes[48] as u64) << 8)
            | (bytes[49] as u64);

        // limbs[1]: bits 127-64 (bytes[50..58])
        limbs[1] = ((bytes[50] as u64) << 56)
            | ((bytes[51] as u64) << 48)
            | ((bytes[52] as u64) << 40)
            | ((bytes[53] as u64) << 32)
            | ((bytes[54] as u64) << 24)
            | ((bytes[55] as u64) << 16)
            | ((bytes[56] as u64) << 8)
            | (bytes[57] as u64);

        // limbs[0]: bits 63-0 (bytes[58..66])
        limbs[0] = ((bytes[58] as u64) << 56)
            | ((bytes[59] as u64) << 48)
            | ((bytes[60] as u64) << 40)
            | ((bytes[61] as u64) << 32)
            | ((bytes[62] as u64) << 24)
            | ((bytes[63] as u64) << 16)
            | ((bytes[64] as u64) << 8)
            | (bytes[65] as u64);

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
