//! Lazy Reduction for Curve25519 Field Arithmetic
//!
//! This module implements lazy reduction for Curve25519 field operations (mod 2^255 - 19).
//! Lazy reduction delays full modular reduction, allowing intermediate values to exceed
//! the modulus temporarily. This significantly improves performance for operation chains.
//!
//! # Strategy
//!
//! - **Additions/Subtractions:** Allow results to temporarily exceed p
//! - **Multiplications:** Always reduce, but can accept unreduced inputs
//! - **Normalize when needed:** Convert to canonical form only when required
//!
//! # Representation
//!
//! Field elements use radix 2^51 representation (5 signed i64 limbs):
//! - Normal form: All limbs in [0, 2^51)
//! - Lazy form: Limbs may exceed 2^51 temporarily (tracked by bounds)
//!
//! # Performance Benefits
//!
//! Expected: 10-15% faster for point operations by reducing the number of
//! full reductions from ~15 per doubling to ~6-8.
//!
//! # Usage
//!
//! ```ignore
//! let a = LazyFieldElement::from_canonical(&canonical_a);
//! let b = LazyFieldElement::from_canonical(&canonical_b);
//! let c = a.add_lazy(&b);  // May exceed p
//! let d = c.add_lazy(&a);  // Still may exceed p
//! let e = d.normalize();   // Now fully reduced
//! ```

use super::field25519::FieldElement;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element that may be in non-canonical (lazy) form
///
/// Allows values to temporarily exceed the modulus 2^255-19,
/// deferring full reduction until normalization is required.
#[derive(Clone, Copy, Debug)]
pub struct LazyFieldElement {
    /// Limbs in radix 2^51 (little-endian)
    /// May have limbs > 2^51 temporarily (lazy form)
    limbs: [i64; 5],
}

impl LazyFieldElement {
    /// Create a lazy field element from canonical form
    #[inline(always)]
    pub fn from_canonical(fe: &FieldElement) -> Self {
        Self { limbs: fe.limbs() }
    }

    /// Create from raw limbs (unchecked - may be non-canonical)
    #[inline(always)]
    pub const fn from_limbs_unchecked(limbs: [i64; 5]) -> Self {
        Self { limbs }
    }

    /// The zero element
    #[inline(always)]
    pub const fn zero() -> Self {
        Self { limbs: [0, 0, 0, 0, 0] }
    }

    /// The one element
    #[inline(always)]
    pub const fn one() -> Self {
        Self { limbs: [1, 0, 0, 0, 0] }
    }

    /// Get the raw limbs
    #[inline(always)]
    pub fn limbs(&self) -> &[i64; 5] {
        &self.limbs
    }

    /// Lazy addition: (self + rhs) without full reduction
    ///
    /// Result may have limbs exceeding 2^51. Safe to call multiple times
    /// before normalization as long as limbs don't overflow i64.
    #[inline]
    pub fn add_lazy(&self, rhs: &Self) -> Self {
        Self {
            limbs: [
                self.limbs[0] + rhs.limbs[0],
                self.limbs[1] + rhs.limbs[1],
                self.limbs[2] + rhs.limbs[2],
                self.limbs[3] + rhs.limbs[3],
                self.limbs[4] + rhs.limbs[4],
            ],
        }
    }

    /// Lazy subtraction: (self - rhs) without full reduction
    ///
    /// Adds 2p to ensure non-negative result, but doesn't reduce modulo p.
    /// Result limbs may exceed 2^51.
    #[inline]
    pub fn sub_lazy(&self, rhs: &Self) -> Self {
        // Add 2p to ensure non-negative
        const TWO_P: [i64; 5] = [
            0x000f_ffff_ffff_ffda,  // 2*(2^51 - 19)
            0x000f_ffff_ffff_fffe,  // 2*(2^51 - 1)
            0x000f_ffff_ffff_fffe,
            0x000f_ffff_ffff_fffe,
            0x000f_ffff_ffff_fffe,
        ];

        Self {
            limbs: [
                TWO_P[0] + self.limbs[0] - rhs.limbs[0],
                TWO_P[1] + self.limbs[1] - rhs.limbs[1],
                TWO_P[2] + self.limbs[2] - rhs.limbs[2],
                TWO_P[3] + self.limbs[3] - rhs.limbs[3],
                TWO_P[4] + self.limbs[4] - rhs.limbs[4],
            ],
        }
    }

    /// Multiply by a small constant without full reduction
    ///
    /// Useful for operations like multiply-by-2, multiply-by-4, etc.
    /// Result is lazily reduced.
    #[inline]
    pub fn mul_small_lazy(&self, k: i64) -> Self {
        Self {
            limbs: [
                self.limbs[0] * k,
                self.limbs[1] * k,
                self.limbs[2] * k,
                self.limbs[3] * k,
                self.limbs[4] * k,
            ],
        }
    }

    /// Partial reduction: reduce limbs modulo 2^51 but not modulo p
    ///
    /// This is cheaper than full reduction. Ensures all limbs fit in 51 bits
    /// but the overall value may still exceed p.
    #[inline]
    pub fn partial_reduce(&mut self) {
        const MASK: i64 = 0x0007_ffff_ffff_ffff;

        // Carry propagation through all limbs
        let mut carry = self.limbs[0] >> 51;
        self.limbs[0] &= MASK;
        self.limbs[1] += carry;

        carry = self.limbs[1] >> 51;
        self.limbs[1] &= MASK;
        self.limbs[2] += carry;

        carry = self.limbs[2] >> 51;
        self.limbs[2] &= MASK;
        self.limbs[3] += carry;

        carry = self.limbs[3] >> 51;
        self.limbs[3] &= MASK;
        self.limbs[4] += carry;

        // Reduce top limb modulo 2^255-19
        carry = self.limbs[4] >> 51;
        self.limbs[4] &= MASK;
        self.limbs[0] += carry * 19;

        // Final carry from limb 0
        carry = self.limbs[0] >> 51;
        self.limbs[0] &= MASK;
        self.limbs[1] += carry;
    }

    /// Full reduction: reduce to canonical form [0, p)
    ///
    /// Converts to a canonical FieldElement. Required before:
    /// - Serialization (to_bytes)
    /// - Comparison (equality testing)
    /// - Final output
    #[inline]
    pub fn normalize(mut self) -> FieldElement {
        // First, do full carry propagation (like partial_reduce but twice)
        const MASK: i64 = 0x0007_ffff_ffff_ffff;

        // Round 1: Carry propagation
        let mut carry = self.limbs[0] >> 51;
        self.limbs[0] &= MASK;
        self.limbs[1] += carry;

        carry = self.limbs[1] >> 51;
        self.limbs[1] &= MASK;
        self.limbs[2] += carry;

        carry = self.limbs[2] >> 51;
        self.limbs[2] &= MASK;
        self.limbs[3] += carry;

        carry = self.limbs[3] >> 51;
        self.limbs[3] &= MASK;
        self.limbs[4] += carry;

        // Reduce top limb modulo 2^255-19
        carry = self.limbs[4] >> 51;
        self.limbs[4] &= MASK;
        self.limbs[0] += carry * 19;

        // Round 2: Propagate carry from limb 0 fully
        carry = self.limbs[0] >> 51;
        self.limbs[0] &= MASK;
        self.limbs[1] += carry;

        carry = self.limbs[1] >> 51;
        self.limbs[1] &= MASK;
        self.limbs[2] += carry;

        carry = self.limbs[2] >> 51;
        self.limbs[2] &= MASK;
        self.limbs[3] += carry;

        carry = self.limbs[3] >> 51;
        self.limbs[3] &= MASK;
        self.limbs[4] += carry;

        // One more reduction if needed
        carry = self.limbs[4] >> 51;
        self.limbs[4] &= MASK;
        self.limbs[0] += carry * 19;

        // Final carry
        carry = self.limbs[0] >> 51;
        self.limbs[0] &= MASK;
        self.limbs[1] += carry;

        // Now canonicalize: ensure result is in [0, p) by subtracting p if needed
        // This is done by checking if h >= p
        // We compute q = 1 if h >= p, else q = 0
        let mut h = self.limbs;

        // Compute carry bit through h + 19
        let mut q = ((h[0] as i128 + 19) >> 51) as i64;
        q = ((h[1] as i128 + q as i128) >> 51) as i64;
        q = ((h[2] as i128 + q as i128) >> 51) as i64;
        q = ((h[3] as i128 + q as i128) >> 51) as i64;
        q = ((h[4] as i128 + q as i128) >> 51) as i64;

        // Subtract p*q by adding 19*q
        h[0] += 19 * q;

        // Propagate carries to remove the 2^255 term
        h[1] += (h[0] as u64 >> 51) as i64;
        h[0] &= MASK;
        h[2] += (h[1] as u64 >> 51) as i64;
        h[1] &= MASK;
        h[3] += (h[2] as u64 >> 51) as i64;
        h[2] &= MASK;
        h[4] += (h[3] as u64 >> 51) as i64;
        h[3] &= MASK;
        h[4] &= MASK;

        FieldElement::from_limbs(h)
    }

    /// Multiply two lazy field elements
    ///
    /// Accepts unreduced inputs, produces a lazily reduced output.
    /// Result is partially reduced (limbs in [0, 2^51)) but may exceed p.
    #[inline]
    pub fn mul_lazy(&self, rhs: &Self) -> Self {
        let a = &self.limbs;
        let b = &rhs.limbs;

        // Use i128 to prevent overflow
        let a0 = a[0] as i128;
        let a1 = a[1] as i128;
        let a2 = a[2] as i128;
        let a3 = a[3] as i128;
        let a4 = a[4] as i128;

        let b0 = b[0] as i128;
        let b1 = b[1] as i128;
        let b2 = b[2] as i128;
        let b3 = b[3] as i128;
        let b4 = b[4] as i128;

        // Precompute 19*b[i] for reduction modulo 2^255-19
        let b1_19 = 19 * b1;
        let b2_19 = 19 * b2;
        let b3_19 = 19 * b3;
        let b4_19 = 19 * b4;

        // Schoolbook multiplication with reduction modulo 2^255-19
        let     r0 = (a0 * b0) + (a1 * b4_19) + (a2 * b3_19) + (a3 * b2_19) + (a4 * b1_19);
        let mut r1 = (a0 * b1) + (a1 * b0)    + (a2 * b4_19) + (a3 * b3_19) + (a4 * b2_19);
        let mut r2 = (a0 * b2) + (a1 * b1)    + (a2 * b0)    + (a3 * b4_19) + (a4 * b3_19);
        let mut r3 = (a0 * b3) + (a1 * b2)    + (a2 * b1)    + (a3 * b0)    + (a4 * b4_19);
        let mut r4 = (a0 * b4) + (a1 * b3)    + (a2 * b2)    + (a3 * b1)    + (a4 * b0);

        const MASK_51: i128 = 0x0007_ffff_ffff_ffff;
        let mut out = [0i64; 5];

        // Carry propagation - following dalek's exact pattern
        r1 += ((r0 >> 51) as i64) as i128;
        out[0] = (r0 & MASK_51) as i64;

        r2 += ((r1 >> 51) as i64) as i128;
        out[1] = (r1 & MASK_51) as i64;

        r3 += ((r2 >> 51) as i64) as i128;
        out[2] = (r2 & MASK_51) as i64;

        r4 += ((r3 >> 51) as i64) as i128;
        out[3] = (r3 & MASK_51) as i64;

        let carry = (r4 >> 51) as i64;
        out[4] = (r4 & MASK_51) as i64;

        // Final reduction
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK_51 as i64;

        Self { limbs: out }
    }

    /// Square a lazy field element
    ///
    /// More efficient than mul_lazy(self, self) due to symmetry.
    #[inline]
    pub fn square_lazy(&self) -> Self {
        let a = &self.limbs;

        let a0_2 = 2 * a[0] as i128;
        let a1_2 = 2 * a[1] as i128;

        let a0 = a[0] as i128;
        let a1 = a[1] as i128;
        let a2 = a[2] as i128;
        let a3 = a[3] as i128;
        let a4 = a[4] as i128;

        let a1_38 = 38 * a1;
        let a2_38 = 38 * a2;
        let a3_19 = 19 * a3;
        let a3_38 = 38 * a3;
        let a4_19 = 19 * a4;

        let     r0 = (a0 * a0) + (a1_38 * a4) + (a2_38 * a3);
        let mut r1 = (a0_2 * a1) + (a2_38 * a4) + (a3_19 * a3);
        let mut r2 = (a0_2 * a2) + (a1 * a1) + (a3_38 * a4);
        let mut r3 = (a0_2 * a3) + (a1_2 * a2) + (a4_19 * a4);
        let mut r4 = (a0_2 * a4) + (a1_2 * a3) + (a2 * a2);

        const MASK_51: i128 = 0x0007_ffff_ffff_ffff;
        let mut out = [0i64; 5];

        // Carry propagation - following dalek's exact pattern
        r1 += ((r0 >> 51) as i64) as i128;
        out[0] = (r0 & MASK_51) as i64;

        r2 += ((r1 >> 51) as i64) as i128;
        out[1] = (r1 & MASK_51) as i64;

        r3 += ((r2 >> 51) as i64) as i128;
        out[2] = (r2 & MASK_51) as i64;

        r4 += ((r3 >> 51) as i64) as i128;
        out[3] = (r3 & MASK_51) as i64;

        let carry = (r4 >> 51) as i64;
        out[4] = (r4 & MASK_51) as i64;

        // Final reduction
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK_51 as i64;

        Self { limbs: out }
    }
}

impl ConstantTimeEq for LazyFieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Must normalize both before comparison
        let a = self.normalize();
        let b = other.normalize();
        a.ct_eq(&b)
    }
}

impl PartialEq for LazyFieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for LazyFieldElement {}

impl ConditionallySelectable for LazyFieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0i64; 5];
        for i in 0..5 {
            result[i] = i64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        Self { limbs: result }
    }

    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        for i in 0..5 {
            self.limbs[i].conditional_assign(&other.limbs[i], choice);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_vs_normal_addition() {
        let a = FieldElement::from_bytes(&[0x42; 32]);
        let b = FieldElement::from_bytes(&[0x7A; 32]);

        // Normal addition
        let result_normal = a.add(&b);

        // Lazy addition
        let a_lazy = LazyFieldElement::from_canonical(&a);
        let b_lazy = LazyFieldElement::from_canonical(&b);
        let result_lazy = a_lazy.add_lazy(&b_lazy).normalize();

        assert_eq!(result_normal, result_lazy);
    }

    #[test]
    fn test_lazy_vs_normal_subtraction() {
        let a = FieldElement::from_bytes(&[0x42; 32]);
        let b = FieldElement::from_bytes(&[0x7A; 32]);

        let result_normal = a.sub(&b);

        let a_lazy = LazyFieldElement::from_canonical(&a);
        let b_lazy = LazyFieldElement::from_canonical(&b);
        let result_lazy = a_lazy.sub_lazy(&b_lazy).normalize();

        assert_eq!(result_normal, result_lazy);
    }

    #[test]
    fn test_lazy_vs_normal_multiplication() {
        let a = FieldElement::from_bytes(&[0x42; 32]);
        let b = FieldElement::from_bytes(&[0x7A; 32]);

        let result_normal = a.mul(&b);

        let a_lazy = LazyFieldElement::from_canonical(&a);
        let b_lazy = LazyFieldElement::from_canonical(&b);
        let result_lazy = a_lazy.mul_lazy(&b_lazy).normalize();

        assert_eq!(result_normal, result_lazy);
    }

    #[test]
    fn test_lazy_addition_chain() {
        // Test that multiple lazy additions produce correct result
        let a = FieldElement::from_bytes(&[0x11; 32]);
        let b = FieldElement::from_bytes(&[0x22; 32]);
        let c = FieldElement::from_bytes(&[0x33; 32]);

        // Normal: a + b + c
        let result_normal = a.add(&b).add(&c);

        // Lazy: a + b + c (defer reduction)
        let a_lazy = LazyFieldElement::from_canonical(&a);
        let b_lazy = LazyFieldElement::from_canonical(&b);
        let c_lazy = LazyFieldElement::from_canonical(&c);
        let result_lazy = a_lazy.add_lazy(&b_lazy).add_lazy(&c_lazy).normalize();

        assert_eq!(result_normal, result_lazy);
    }

    #[test]
    fn test_lazy_mul_add_pattern() {
        // Common pattern: a * b + c
        let a = FieldElement::from_bytes(&[0x42; 32]);
        let b = FieldElement::from_bytes(&[0x7A; 32]);
        let c = FieldElement::from_bytes(&[0x13; 32]);

        let result_normal = a.mul(&b).add(&c);

        let a_lazy = LazyFieldElement::from_canonical(&a);
        let b_lazy = LazyFieldElement::from_canonical(&b);
        let c_lazy = LazyFieldElement::from_canonical(&c);
        let result_lazy = a_lazy.mul_lazy(&b_lazy).add_lazy(&c_lazy).normalize();

        assert_eq!(result_normal, result_lazy);
    }

    #[test]
    fn test_lazy_square() {
        let a = FieldElement::from_bytes(&[0x42; 32]);

        let result_normal = a.square();

        let a_lazy = LazyFieldElement::from_canonical(&a);
        let result_lazy = a_lazy.square_lazy().normalize();

        assert_eq!(result_normal, result_lazy);
    }
}
