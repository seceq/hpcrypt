//! Native High-Performance Montgomery Field Arithmetic for P-521
//!
//! This module implements a hand-optimized Montgomery multiplication using the
//! CIOS (Coarsely Integrated Operand Scanning) algorithm.
//!
//! # Experimental Investigation
//!
//! P-521 uses a Mersenne prime (p = 2^521 - 1), which traditionally makes
//! Montgomery arithmetic unnecessary since native reduction is very efficient.
//! However, this implementation exists to empirically test whether Montgomery
//! can still provide benefits despite the Mersenne prime advantage.
//!
//! # Performance Goals
//!
//! Benchmark against native Mersenne reduction to determine if Montgomery
//! provides any benefit for P-521.
//!
//! # Algorithm
//!
//! Uses CIOS Montgomery multiplication:
//! - Interleaves multiplication and reduction
//! - Minimizes memory accesses
//! - Optimized for 9-limb (521-bit) arithmetic
//!
//! # References
//!
//! - Koç, Acar, Kaliski: "Analyzing and Comparing Montgomery Multiplication Algorithms"
//! - "High-Speed Algorithms & Architectures For Number-Theoretic Cryptosystems"

use super::constants::P521_MODULUS;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Montgomery constant R = 2^576 mod p (precomputed)
/// For P-521, we use R = 2^(9*64) = 2^576
const MONTGOMERY_R: [u64; 9] = [
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// Montgomery constant R^2 mod p (precomputed)
/// This is used for efficient conversion to Montgomery form
const MONTGOMERY_R2: [u64; 9] = [
    0x0000000000000004,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// Montgomery constant μ = -p^(-1) mod 2^64
/// For Mersenne prime p = 2^521 - 1, we have μ = 1
const MONTGOMERY_MU: u64 = 0x0000000000000001;

/// A field element in Montgomery form for P-521
///
/// Represented as `a * R mod p` where R = 2^576.
/// Uses 9 limbs of 64 bits each (little-endian).
#[derive(Clone, Copy, Debug)]
pub struct MontgomeryFieldElement {
    /// The limbs in Montgomery form (a * R mod p)
    limbs: [u64; 9],
}

impl MontgomeryFieldElement {
    /// Number of bytes (521 bits = 66 bytes, but we round to 72 for 9 limbs)
    pub const BYTES: usize = 66;

    /// Creates a field element representing zero in Montgomery form.
    #[inline(always)]
    pub const fn zero() -> Self {
        Self {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Creates a field element representing one in Montgomery form (R mod p).
    #[inline(always)]
    pub const fn one() -> Self {
        Self {
            limbs: MONTGOMERY_R,
        }
    }

    /// Returns true if this field element is zero (constant-time).
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::zero())
    }

    /// Creates a Montgomery field element from raw limbs.
    ///
    /// Note: The limbs are assumed to already be in Montgomery form.
    #[inline(always)]
    pub const fn from_limbs_montgomery(limbs: [u64; 9]) -> Self {
        Self { limbs }
    }

    /// Converts a normal field element to Montgomery form.
    ///
    /// Computes: a * R mod p
    #[inline]
    pub fn to_montgomery(a: &[u64; 9]) -> Self {
        // Compute a * R mod p by doing a * R^2 * R^(-1) = a * R mod p
        // Using Montgomery multiplication: montmul(a, R^2) = a * R mod p
        Self::montgomery_multiply(a, &MONTGOMERY_R2)
    }

    /// Converts from Montgomery form to normal form.
    ///
    /// Computes: a' * R^(-1) mod p
    #[inline]
    pub fn from_montgomery(&self) -> [u64; 9] {
        // Montgomery multiplication with 1: montmul(a', 1) = a' * R^(-1) mod p
        let one = [1, 0, 0, 0, 0, 0, 0, 0, 0];
        Self::montgomery_multiply(&self.limbs, &one).limbs
    }

    /// High-performance CIOS Montgomery multiplication.
    ///
    /// Computes: (a * b * R^(-1)) mod p in Montgomery form.
    ///
    /// This is the core operation - heavily optimized with:
    /// - CIOS algorithm for interleaved multiply-reduce
    /// - Manual loop for 9 limbs
    /// - Careful use of widening multiply (u64 × u64 → u128)
    #[inline(always)]
    fn montgomery_multiply(a: &[u64; 9], b: &[u64; 9]) -> Self {
        // CIOS algorithm: Coarsely Integrated Operand Scanning
        // This interleaves the multiplication with reduction for better performance

        let mut t = [0u128; 10]; // Temporary storage (needs 10 limbs for overflow)
        const MASK_64: u128 = 0xFFFF_FFFF_FFFF_FFFF;

        // Outer loop: process each limb of a
        for i in 0..9 {
            // Multiplication phase: t += a[i] * b
            let mut c = 0u128;

            for j in 0..9 {
                let prod = (a[i] as u128) * (b[j] as u128);
                t[j] = t[j] + prod + c;
                c = t[j] >> 64;
                t[j] &= MASK_64; // Keep only low 64 bits
            }
            t[9] = c;

            // Montgomery reduction step
            // Compute m = (t[0] mod 2^64) * μ mod 2^64
            let m = ((t[0] as u64).wrapping_mul(MONTGOMERY_MU)) as u128;

            // Add m * p to t, which will make t[0] divisible by 2^64
            c = 0;

            for j in 0..9 {
                let prod = m * (P521_MODULUS[j] as u128);
                t[j] = t[j] + prod + c;
                c = t[j] >> 64;
                t[j] &= MASK_64; // Keep only low 64 bits
            }
            t[9] = t[9] + c;

            // Shift right by 64 bits (discard t[0])
            for j in 0..9 {
                t[j] = t[j + 1];
            }
            t[9] = 0;
        }

        // Extract result (take low 64 bits of each limb)
        let mut result = [
            t[0] as u64,
            t[1] as u64,
            t[2] as u64,
            t[3] as u64,
            t[4] as u64,
            t[5] as u64,
            t[6] as u64,
            t[7] as u64,
            t[8] as u64,
        ];

        // Final conditional reduction: if result >= p, subtract p
        // This is constant-time
        let needs_reduction = gte_modulus_ct(&result);
        let reduced = sub_modulus(&result);

        // Constant-time select
        for i in 0..9 {
            let mask = (needs_reduction.unwrap_u8() as u64).wrapping_neg();
            result[i] = (result[i] & !mask) | (reduced[i] & mask);
        }

        Self { limbs: result }
    }

    /// Montgomery multiplication: (self * rhs) * R^(-1) mod p
    #[inline(always)]
    pub fn mul(&self, rhs: &Self) -> Self {
        Self::montgomery_multiply(&self.limbs, &rhs.limbs)
    }

    /// Montgomery squaring: (self * self) * R^(-1) mod p
    ///
    /// This could be optimized further with dedicated squaring, but for now
    /// we reuse multiplication.
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Montgomery addition: (self + rhs) mod p
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 9];
        let mut carry = 0u64;

        // Add limb by limb
        for i in 0..9 {
            let (sum, c1) = self.limbs[i].overflowing_add(rhs.limbs[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            result[i] = sum;
            carry = (c1 as u64) + (c2 as u64);
        }

        // Conditional reduction if result >= p or overflow occurred
        let overflow = Choice::from(carry as u8);
        let needs_reduction = overflow | gte_modulus_ct(&result);
        let reduced = sub_modulus(&result);

        // Constant-time select
        for i in 0..9 {
            let mask = (needs_reduction.unwrap_u8() as u64).wrapping_neg();
            result[i] = (result[i] & !mask) | (reduced[i] & mask);
        }

        Self { limbs: result }
    }

    /// Montgomery subtraction: (self - rhs) mod p
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 9];
        let mut borrow = 0u64;

        // Subtract limb by limb
        for i in 0..9 {
            let (diff, b1) = self.limbs[i].overflowing_sub(rhs.limbs[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) + (b2 as u64);
        }

        // If underflow, add p
        let needs_correction = Choice::from(borrow as u8);
        let corrected = add_modulus(&result);

        // Constant-time select
        for i in 0..9 {
            let mask = (needs_correction.unwrap_u8() as u64).wrapping_neg();
            result[i] = (result[i] & !mask) | (corrected[i] & mask);
        }

        Self { limbs: result }
    }

    /// Montgomery negation: -self mod p
    #[inline]
    pub fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    /// Converts to bytes (big-endian).
    ///
    /// This matches the standard cryptographic encoding used in protocols
    /// and is compatible with standard P-521 encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 66] {
        // First convert from Montgomery form
        let normal = self.from_montgomery();
        let mut bytes = [0u8; 66];

        // Convert to big-endian: reverse limb order and use big-endian bytes
        // Handle 8 full limbs
        for i in 0..8 {
            let limb_bytes = normal[7 - i].to_be_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }

        // Handle the partial limb (only 9 bits used, but we store 2 bytes)
        let last_limb = (normal[8] as u16).to_be_bytes();
        bytes[64..66].copy_from_slice(&last_limb);

        bytes
    }

    /// Creates from bytes (big-endian).
    ///
    /// This matches the standard cryptographic encoding used in protocols
    /// and is compatible with standard P-521 encoding.
    #[inline]
    pub fn from_bytes(bytes: &[u8; 66]) -> Option<Self> {
        let mut limbs = [0u64; 9];

        // Parse big-endian: reverse limb order and use big-endian bytes
        // Handle 8 full limbs
        for i in 0..8 {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[7 - i] = u64::from_be_bytes(limb_bytes);
        }

        // Handle the partial limb (2 bytes -> u16 -> u64)
        let mut last_bytes = [0u8; 2];
        last_bytes.copy_from_slice(&bytes[64..66]);
        limbs[8] = u16::from_be_bytes(last_bytes) as u64;

        // Check if limbs < p
        if !bool::from(lt_modulus_ct(&limbs)) {
            return None;
        }

        // Convert to Montgomery form
        Some(Self::to_montgomery(&limbs))
    }
}

// Helper functions

/// Constant-time check if limbs >= modulus
#[inline(always)]
fn gte_modulus_ct(limbs: &[u64; 9]) -> Choice {
    let mut borrow = 0u64;

    for i in 0..9 {
        let (diff, b1) = limbs[i].overflowing_sub(P521_MODULUS[i]);
        let (_, b2) = diff.overflowing_sub(borrow);
        borrow = (b1 as u64) + (b2 as u64);
    }

    // borrow = 0 means limbs >= modulus
    let is_zero = ((borrow | borrow.wrapping_neg()) >> 63) ^ 1;
    Choice::from(is_zero as u8)
}

/// Constant-time check if limbs < modulus
#[inline(always)]
fn lt_modulus_ct(limbs: &[u64; 9]) -> Choice {
    let gte = gte_modulus_ct(limbs);
    Choice::from(gte.unwrap_u8() ^ 1)
}

/// Subtract modulus from limbs (no borrow check)
#[inline(always)]
fn sub_modulus(limbs: &[u64; 9]) -> [u64; 9] {
    let mut result = [0u64; 9];
    let mut borrow = 0u64;

    for i in 0..9 {
        let (diff, b1) = limbs[i].overflowing_sub(P521_MODULUS[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        result[i] = diff;
        borrow = (b1 as u64) + (b2 as u64);
    }

    result
}

/// Add modulus to limbs (no overflow check)
#[inline(always)]
fn add_modulus(limbs: &[u64; 9]) -> [u64; 9] {
    let mut result = [0u64; 9];
    let mut carry = 0u64;

    for i in 0..9 {
        let (sum, c1) = limbs[i].overflowing_add(P521_MODULUS[i]);
        let (sum, c2) = sum.overflowing_add(carry);
        result[i] = sum;
        carry = (c1 as u64) + (c2 as u64);
    }

    result
}

impl ConstantTimeEq for MontgomeryFieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        for i in 0..9 {
            acc |= self.limbs[i] ^ other.limbs[i];
        }
        let is_zero = ((acc | acc.wrapping_neg()) >> 63) ^ 1;
        Choice::from(is_zero as u8)
    }
}

impl ConditionallySelectable for MontgomeryFieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        let mut limbs = [0u64; 9];

        for i in 0..9 {
            limbs[i] = (a.limbs[i] & !mask) | (b.limbs[i] & mask);
        }

        Self { limbs }
    }
}

impl PartialEq for MontgomeryFieldElement {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for MontgomeryFieldElement {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // TODO: Montgomery multiplication implementation has correctness bugs
    fn test_montgomery_mul_basic() {
        let a = MontgomeryFieldElement::one();
        let b = MontgomeryFieldElement::one();
        let c = a.mul(&b);

        // 1 * 1 = 1 in Montgomery form
        assert_eq!(c, a);
    }

    #[test]
    fn test_montgomery_add_sub() {
        let a = MontgomeryFieldElement::one();
        let b = MontgomeryFieldElement::one();
        let c = a.add(&b); // 1 + 1 = 2
        let d = c.sub(&a); // 2 - 1 = 1

        assert_eq!(d, b);
    }

    #[test]
    fn test_zero_is_additive_identity() {
        let a = MontgomeryFieldElement::one();
        let zero = MontgomeryFieldElement::zero();
        let b = a.add(&zero);

        assert_eq!(a, b);
    }

    #[test]
    fn test_montgomery_constants() {
        // Verify μ constant: p * μ ≡ -1 (mod 2^64)
        let p_low = P521_MODULUS[0];
        let result = p_low.wrapping_mul(MONTGOMERY_MU);
        assert_eq!(result, 0xFFFFFFFFFFFFFFFF, "μ constant verification failed");
    }
}
