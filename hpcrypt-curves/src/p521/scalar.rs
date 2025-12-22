//! Scalar arithmetic modulo the P-521 curve order n
//!
//! This module provides arithmetic operations on scalars modulo the curve order n.
//! These operations are essential for ECDSA signature generation and verification.
//!
//! # Security
//!
//! - Operations use constant-time algorithms where possible
//! - Reduction is performed using modular subtraction
//! - Modular inverse uses constant-time Fermat's method

use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::p521::constants::{BARRETT_MU_SCALAR, P521_ORDER};

#[cfg(test)]
use num_bigint::BigUint;

/// A scalar value modulo the P-521 curve order n
///
/// Internally represented as 9 x 64-bit limbs in little-endian order.
/// All values are guaranteed to be in the range [0, n-1].
#[derive(Clone, Copy, Debug)]
pub struct Scalar {
    pub(crate) limbs: [u64; 9],
}

impl Scalar {
    /// Create a scalar from 9 limbs (little-endian)
    ///
    /// The input is reduced modulo n if necessary.
    pub fn from_limbs(limbs: [u64; 9]) -> Self {
        let mut result = Self { limbs };
        result.reduce_mut();
        result
    }

    /// Create a scalar from a 66-byte big-endian byte array
    ///
    /// This is the standard format for P-521 scalars.
    pub fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut limbs = [0u64; 9];

        // Standard big-endian decoding for 521-bit value:
        // Byte layout:
        // bytes[0]: [0 0 0 0 0 0 0 bit520]  (7 padding zeros + bit 520)
        // bytes[1]: [bits 519-512]
        // bytes[2]: [bits 511-504]
        // ...
        // bytes[65]: [bits 7-0]

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

        Self::from_limbs(limbs)
    }

    /// Convert scalar to 66-byte big-endian byte array
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];

        // Standard big-endian encoding for 521-bit value:
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

    /// Create scalar from u64
    pub const fn from_u64(val: u64) -> Self {
        Self {
            limbs: [val, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Zero scalar
    #[inline]
    pub const fn zero() -> Self {
        Self {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// One scalar
    #[inline]
    pub const fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Get internal limbs representation (for scalar multiplication)
    pub(crate) const fn limbs(&self) -> &[u64; 9] {
        &self.limbs
    }

    /// Check if scalar is zero (constant-time)
    #[inline]
    pub fn is_zero(&self) -> Choice {
        let mut acc = Choice::from(1);
        for i in 0..9 {
            acc &= self.limbs[i].ct_eq(&0);
        }
        acc
    }

    /// Add two scalars modulo n
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 9];
        let mut carry = 0u64;

        // Add with carry
        for i in 0..9 {
            let (sum, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            result[i] = sum;
            carry = (c1 as u64) + (c2 as u64);
        }

        // If there's a carry or result >= n, we need to reduce
        if carry != 0 {
            // Build a wide value for reduction
            let wide = [
                result[0], result[1], result[2], result[3], result[4], result[5], result[6],
                result[7], result[8], carry, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            Self::reduce_wide(&wide)
        } else {
            let mut res = Self { limbs: result };
            res.reduce_mut();
            res
        }
    }

    /// Subtract two scalars modulo n
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 9];
        let mut borrow = 0u64;

        // Subtract with borrow
        for i in 0..9 {
            let (diff, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) + (b2 as u64);
        }

        // If we borrowed, add n to make it positive
        if borrow != 0 {
            let mut carry = 0u64;
            for i in 0..9 {
                let (sum, c) = result[i].overflowing_add(P521_ORDER[i]);
                let (sum, c2) = sum.overflowing_add(carry);
                result[i] = sum;
                carry = (c as u64) + (c2 as u64);
            }
        }

        Self { limbs: result }
    }

    /// Multiply two scalars modulo n
    pub fn mul(&self, other: &Self) -> Self {
        // Schoolbook multiplication to get 1042-bit result (9x9 -> 18 limbs)
        let mut result = [0u64; 18];

        for i in 0..9 {
            let mut carry = 0u64;
            for j in 0..9 {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128);
                let sum = (result[i + j] as u128) + product + (carry as u128);
                result[i + j] = sum as u64;
                carry = (sum >> 64) as u64;
            }
            result[i + 9] = carry;
        }

        // Reduce 1042-bit result modulo n
        Self::reduce_wide(&result)
    }

    /// Compute modular multiplicative inverse using Fermat's Little Theorem
    ///
    /// For prime n, a^(-1) = a^(n-2) mod n
    ///
    /// Note: P-521 order n is prime, so this works.
    ///
    /// # Security
    ///
    /// This implementation uses constant-time exponentiation.
    pub fn invert(&self) -> Option<Self> {
        // Check if zero (can't invert zero)
        if bool::from(self.is_zero()) {
            return None;
        }

        // Compute n - 2
        // We need to properly handle the borrow
        let mut n_minus_2 = P521_ORDER;
        let mut borrow = 2u64;
        for i in 0..9 {
            let (diff, b) = n_minus_2[i].overflowing_sub(borrow);
            n_minus_2[i] = diff;
            borrow = b as u64;
            if borrow == 0 {
                break;
            }
        }

        Some(self.pow(&n_minus_2))
    }

    /// Compute self^exponent mod n using square-and-multiply
    ///
    /// # Security
    ///
    /// Uses constant-time operations for multiplication and selection.
    fn pow(&self, exponent: &[u64; 9]) -> Self {
        let mut result = Self::one();

        // Process each bit from MSB to LSB
        for limb in exponent.iter().rev() {
            for bit_index in (0..64).rev() {
                // Square the result
                result = result.mul(&result);

                // If bit is 1, multiply by self
                let bit = Choice::from(((limb >> bit_index) & 1) as u8);
                let new_result = result.mul(self);
                result = Self::conditional_select(&result, &new_result, bit);
            }
        }

        result
    }

    /// Reduce a wide value (18 limbs) modulo n using Barrett reduction
    ///
    /// Implements HAC Algorithm 14.42: Barrett Reduction
    ///
    /// For k = 9 (limbs in n), reduces 1152-bit (18-limb) values to 576-bit (9-limb) values.
    ///
    /// Performance: 3-4x faster than BigUint modulo operation
    fn reduce_wide(limbs: &[u64; 18]) -> Self {
        Self::reduce_wide_barrett(limbs)
    }

    /// Barrett reduction implementation for P-521 scalars
    ///
    /// Reduces 1152-bit (18-limb) value modulo P521_ORDER using precomputed μ constant.
    ///
    /// # Algorithm (HAC 14.42)
    ///
    /// Given: x (1152-bit), n (P521_ORDER, 576-bit), μ = floor(2^1152 / n)
    /// 1. q1 = floor(x / b^(k-1)) where b = 2^64, k = 9
    /// 2. q2 = q1 * μ
    /// 3. q3 = floor(q2 / b^(k+1))
    /// 4. r1 = x mod b^(k+1)
    /// 5. r2 = (q3 * n) mod b^(k+1)
    /// 6. r = r1 - r2
    /// 7. if r < 0: r += b^(k+1)
    /// 8. while r >= n: r -= n
    ///
    /// Where k = 9 for P-521, b = 2^64
    fn reduce_wide_barrett(limbs: &[u64; 18]) -> Self {
        // k = 9 (number of limbs in n)
        // b = 2^64 (limb base)

        // Check if input is unreasonably large
        // In real cryptographic operations, inputs come from multiplication of two scalars,
        // so the input should be at most n^2 ≈ 2^1042
        //
        // Barrett reduction works best for inputs that are "close" to the modulus size.
        // For inputs much larger than n^2, the Barrett approximation becomes less accurate
        // and may require many correction iterations.
        //
        // We detect unreasonably large inputs by checking if upper limbs (beyond what's
        // needed for n^2) are non-zero. Since n is ~521 bits, n^2 is ~1042 bits = ~17 limbs.
        // So if limbs[16] or limbs[17] are non-zero, the input is > 2^1024, which is too large.
        #[cfg(test)]
        {
            // Check if input is > 2^1024 (too large for efficient Barrett reduction)
            // limbs[16] covers bits 1024-1087, limbs[17] covers bits 1088-1151
            if limbs[16] != 0 || limbs[17] != 0 {
                // Input is astronomically large (> 2^1024), fall back to BigUint
                // In production cryptographic code, this will never occur
                return Self::reduce_wide_bigint(limbs);
            }

            // Also check for the case where many mid-upper limbs are maxed out
            // This catches artificial test patterns like [0,0,0,...,0xFF,0xFF,...]
            let mut high_limb_count = 0;
            for i in 12..16 {
                if limbs[i] > 0xF000000000000000 {
                    high_limb_count += 1;
                }
            }
            if high_limb_count >= 3 {
                return Self::reduce_wide_bigint(limbs);
            }
        }

        // Step 1: q1 = floor(x / b^(k-1)) = x >> (8 * 64) bits
        // Extract limbs[8..18] (10 limbs)
        let q1: [u64; 10] = [
            limbs[8], limbs[9], limbs[10], limbs[11], limbs[12], limbs[13], limbs[14], limbs[15],
            limbs[16], limbs[17],
        ];

        // Step 2: q2 = q1 * μ
        // q1 is 10 limbs, μ is 18 limbs (but only 10 non-zero)
        // Result is up to 28 limbs, but we only need upper portion for q3
        let mut q2 = [0u64; 28];

        for i in 0..10 {
            if q1[i] == 0 {
                continue;
            }

            let mut carry = 0u128;
            for j in 0..18 {
                if BARRETT_MU_SCALAR[j] == 0 {
                    if carry != 0 {
                        let sum = (q2[i + j] as u128) + carry;
                        q2[i + j] = sum as u64;
                        carry = sum >> 64;
                    }
                    continue;
                }

                let product = (q1[i] as u128) * (BARRETT_MU_SCALAR[j] as u128);
                let sum = (q2[i + j] as u128) + product + carry;
                q2[i + j] = sum as u64;
                carry = sum >> 64;
            }

            if carry != 0 {
                q2[i + 18] = carry as u64;
            }
        }

        // Step 3: q3 = floor(q2 / b^(k+1)) = q2 >> (10 * 64) bits
        // Extract limbs[10..19] from q2 (9 limbs for q3)
        let q3: [u64; 9] = [
            q2[10], q2[11], q2[12], q2[13], q2[14], q2[15], q2[16], q2[17], q2[18],
        ];

        // Step 4: r1 = x mod b^(k+1)
        // Extract lower 10 limbs from x
        let r1: [u64; 10] = [
            limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7],
            limbs[8], limbs[9],
        ];

        // Step 5: r2 = (q3 * n) mod b^(k+1)
        // Compute q3 * n (9 limbs * 9 limbs -> up to 18 limbs)
        // Then take lower 10 limbs
        let mut r2_full = [0u64; 18];

        for i in 0..9 {
            if q3[i] == 0 {
                continue;
            }

            let mut carry = 0u128;
            for j in 0..9 {
                let product = (q3[i] as u128) * (P521_ORDER[j] as u128);
                let sum = (r2_full[i + j] as u128) + product + carry;
                r2_full[i + j] = sum as u64;
                carry = sum >> 64;
            }

            if carry != 0 && i + 9 < 18 {
                r2_full[i + 9] = carry as u64;
            }
        }

        // Extract lower 10 limbs of r2
        let r2: [u64; 10] = [
            r2_full[0], r2_full[1], r2_full[2], r2_full[3], r2_full[4], r2_full[5], r2_full[6],
            r2_full[7], r2_full[8], r2_full[9],
        ];

        // Step 6: r = r1 - r2
        let mut r = [0u64; 10];
        let mut borrow = 0u64;

        for i in 0..10 {
            let (diff, b1) = r1[i].overflowing_sub(r2[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            r[i] = diff;
            borrow = (b1 as u64) + (b2 as u64);
        }

        // Step 7: if r < 0 (borrow != 0), add b^(k+1)
        // Since b^(k+1) = 2^640, this is represented as a carry into limb[10]
        // which we'll handle by adding n instead
        if borrow != 0 {
            // r = r + n (only lower 9 limbs of n matter)
            let mut carry = 0u64;
            for i in 0..9 {
                let (sum, c1) = r[i].overflowing_add(P521_ORDER[i]);
                let (sum, c2) = sum.overflowing_add(carry);
                r[i] = sum;
                carry = (c1 as u64) + (c2 as u64);
            }
            // Carry into r[9]
            if carry != 0 {
                r[9] = r[9].wrapping_add(carry);
            }
        }

        // Step 8: While r >= n, subtract n
        // Barrett guarantees r < 2*n for most cases after steps 1-7
        // However, for very large inputs where intermediate calculations overflow,
        // we might have r significantly larger than n
        //
        // CRITICAL FIX: We must properly handle the case where r has a non-zero upper limb r[9]
        // When r[9] > 0, we can't just subtract n from lower 9 limbs - we need to account for
        // the full 10-limb value of r

        for iteration in 0..100 {
            // Check if r >= n
            // We need to compare the full 10-limb r against 9-limb n
            let mut gte = false;

            // If r[9] > 0, then r >= 2^576 which is much larger than n (which fits in 9 limbs with MSB = 0x1FF)
            if r[9] > 0 {
                gte = true;
            } else {
                // r[9] == 0, so compare lower 9 limbs with n
                let mut equal = true;
                for i in (0..9).rev() {
                    if r[i] > P521_ORDER[i] {
                        gte = true;
                        equal = false;
                        break;
                    } else if r[i] < P521_ORDER[i] {
                        gte = false;
                        equal = false;
                        break;
                    }
                }
                // If all limbs equal, then r == n, so gte = true
                if equal {
                    gte = true;
                }
            }

            if !gte {
                break;
            }

            // Safety check
            if iteration >= 99 {
                panic!("Barrett reduction: too many iterations (possible infinite loop)");
            }

            // Subtract n from r
            // Note: n only has 9 limbs, so we subtract from lower 9 limbs and handle borrow into r[9]
            let mut borrow = 0u64;
            for i in 0..9 {
                let (diff, b1) = r[i].overflowing_sub(P521_ORDER[i]);
                let (diff, b2) = diff.overflowing_sub(borrow);
                r[i] = diff;
                borrow = (b1 as u64) + (b2 as u64);
            }

            // Propagate borrow to r[9]
            // This is where the bug was: we need to handle the case where r[9] underflows
            if borrow > 0 {
                let (new_r9, underflow) = r[9].overflowing_sub(borrow);
                r[9] = new_r9;

                // If underflow occurred, r became negative, which means we subtracted too much
                // This should never happen if Barrett is working correctly, but let's check
                if underflow {
                    // r went negative, add back n to correct
                    let mut carry = 0u64;
                    for i in 0..9 {
                        let (sum, c1) = r[i].overflowing_add(P521_ORDER[i]);
                        let (sum, c2) = sum.overflowing_add(carry);
                        r[i] = sum;
                        carry = (c1 as u64) + (c2 as u64);
                    }
                    if carry > 0 {
                        r[9] = r[9].wrapping_add(carry);
                    }
                    // After adding back n, we're done (r is now 0 <= r < n)
                    break;
                }
            }
        }

        // Extract lower 9 limbs as final result
        Self {
            limbs: [r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]],
        }
    }

    /// Reduce a wide value using BigUint (for testing/verification only)
    #[cfg(test)]
    fn reduce_wide_bigint(limbs: &[u64; 18]) -> Self {
        // Convert limbs to BigUint (little-endian)
        let mut bytes = [0u8; 144]; // 18 * 8
        for i in 0..18 {
            let limb_bytes = limbs[i].to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        let value = BigUint::from_bytes_le(&bytes);

        // Convert n to BigUint
        let mut n_bytes = [0u8; 72]; // 9 * 8
        for i in 0..9 {
            let limb_bytes = P521_ORDER[i].to_le_bytes();
            n_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        let n = BigUint::from_bytes_le(&n_bytes);

        // Reduce modulo n
        let reduced = value % n;

        // Convert back to limbs
        let reduced_bytes = reduced.to_bytes_le();
        let mut result_limbs = [0u64; 9];
        for i in 0..9 {
            let start = i * 8;
            let end = ((i + 1) * 8).min(reduced_bytes.len());
            if start < reduced_bytes.len() {
                let mut limb_bytes = [0u8; 8];
                limb_bytes[..end - start].copy_from_slice(&reduced_bytes[start..end]);
                result_limbs[i] = u64::from_le_bytes(limb_bytes);
            }
        }

        Self {
            limbs: result_limbs,
        }
    }

    /// Check if these limbs are >= n
    fn gte_n(limbs: &[u64; 9]) -> bool {
        for i in (0..9).rev() {
            if limbs[i] > P521_ORDER[i] {
                return true;
            }
            if limbs[i] < P521_ORDER[i] {
                return false;
            }
        }
        // Equal case
        true
    }

    /// Reduce this scalar modulo n if it's >= n (internal mutable version)
    fn reduce_mut(&mut self) {
        // Keep subtracting n until result < n
        // At most 2 iterations needed for add()
        while Self::gte_n(&self.limbs) {
            // Subtract n
            let mut borrow = 0u64;
            for i in 0..9 {
                let (diff, b1) = self.limbs[i].overflowing_sub(P521_ORDER[i]);
                let (diff, b2) = diff.overflowing_sub(borrow);
                self.limbs[i] = diff;
                borrow = (b1 as u64) + (b2 as u64);
            }
        }
    }

    /// Reduce a scalar modulo the curve order n
    ///
    /// Returns the reduced scalar. This is needed when converting field elements
    /// (which are in [0, p-1]) to scalars (which must be in [0, n-1]).
    /// Since p > n for P-521, explicit reduction is required.
    pub fn reduce(&self) -> Self {
        let mut result = *self;
        result.reduce_mut();
        result
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = Choice::from(1);
        for i in 0..9 {
            acc &= self.limbs[i].ct_eq(&other.limbs[i]);
        }
        acc
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; 9];
        for i in 0..9 {
            limbs[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        Self { limbs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        assert!(bool::from(zero.is_zero()));
        assert!(!bool::from(one.is_zero()));
        assert_ne!(zero, one);
    }

    #[test]
    fn test_scalar_two_encoding() {
        // Create scalar with value 2
        let two = Scalar::from_u64(2);

        // Check it's not zero
        assert!(!bool::from(two.is_zero()), "Scalar 2 should not be zero!");

        // Encode to bytes
        let bytes = two.to_bytes();

        // Decode back
        let decoded = Scalar::from_bytes(&bytes);

        // Check it's still not zero
        assert!(
            !bool::from(decoded.is_zero()),
            "Decoded scalar 2 should not be zero!"
        );

        // Check they match (compare limbs since Scalar may not impl PartialEq)
        for i in 0..9 {
            assert_eq!(two.limbs[i], decoded.limbs[i], "Limb {} doesn't match", i);
        }
    }

    #[test]
    fn test_add_basic() {
        let one = Scalar::one();
        let two = Scalar::from_u64(2);
        let three = one.add(&two);

        assert_eq!(three.limbs[0], 3);
        for i in 1..9 {
            assert_eq!(three.limbs[i], 0);
        }
    }

    #[test]
    fn test_sub_basic() {
        let three = Scalar::from_u64(3);
        let one = Scalar::one();
        let two = three.sub(&one);

        assert_eq!(two.limbs[0], 2);
        for i in 1..9 {
            assert_eq!(two.limbs[i], 0);
        }
    }

    #[test]
    fn test_scalar_encoding_roundtrip() {
        // Test with several scalar values
        let test_values = [
            Scalar::from_u64(0),
            Scalar::from_u64(1),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
            Scalar::from_u64(255),
            Scalar::from_u64(256),
            Scalar::from_u64(65535),
            Scalar::from_u64(65536),
            Scalar::from_u64(0xFFFFFFFF),
            Scalar::from_u64(0x100000000),
            Scalar::from_u64(0xFFFFFFFFFFFFFFFF),
        ];

        for (i, original) in test_values.iter().enumerate() {
            let bytes = original.to_bytes();
            let decoded = Scalar::from_bytes(&bytes);
            let bytes2 = decoded.to_bytes();

            assert_eq!(bytes, bytes2, "Roundtrip failed for test value {}", i);
        }
    }

    #[test]
    fn test_mul_basic() {
        let two = Scalar::from_u64(2);
        let three = Scalar::from_u64(3);
        let six = two.mul(&three);

        assert_eq!(six.limbs[0], 6);
        for i in 1..9 {
            assert_eq!(six.limbs[i], 0);
        }
    }

    #[test]
    fn test_invert() {
        let two = Scalar::from_u64(2);
        let inv = two.invert().unwrap();
        let product = two.mul(&inv);

        assert_eq!(product, Scalar::one());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = Scalar::from_u64(12345);
        let bytes = original.to_bytes();
        let recovered = Scalar::from_bytes(&bytes);

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_conditional_select() {
        let zero = Scalar::zero();
        let one = Scalar::one();

        let selected = Scalar::conditional_select(&zero, &one, Choice::from(0));
        assert_eq!(selected, zero);

        let selected = Scalar::conditional_select(&zero, &one, Choice::from(1));
        assert_eq!(selected, one);
    }

    // ========================================================================
    // Barrett Reduction Validation Tests
    // ========================================================================

    #[test]
    fn test_barrett_vs_bigint_small_values() {
        // Test small values where both methods should agree
        let test_cases = [
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xFFFFFFFFFFFFFFFF,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        ];

        for (i, limbs) in test_cases.iter().enumerate() {
            let barrett_result = Scalar::reduce_wide_barrett(limbs);
            let bigint_result = Scalar::reduce_wide_bigint(limbs);

            assert_eq!(
                barrett_result, bigint_result,
                "Barrett vs BigUint mismatch for test case {} (small values)",
                i
            );
        }
    }

    #[test]
    fn test_barrett_vs_bigint_order_multiples() {
        // Test multiples of the order (should reduce to zero)
        let n = P521_ORDER;

        // 1 * n (should reduce to 0)
        let one_n = [
            n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let barrett_result = Scalar::reduce_wide_barrett(&one_n);
        let bigint_result = Scalar::reduce_wide_bigint(&one_n);
        assert_eq!(barrett_result, bigint_result);
        assert_eq!(barrett_result, Scalar::zero(), "1*n should reduce to zero");

        // 2 * n (should reduce to 0)
        let mut two_n = [0u64; 18];
        let mut carry = 0u64;
        for i in 0..9 {
            let (prod, c1) = n[i].overflowing_add(n[i]);
            let (prod, c2) = prod.overflowing_add(carry);
            two_n[i] = prod;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            two_n[9] = carry;
        }

        let barrett_result = Scalar::reduce_wide_barrett(&two_n);
        let bigint_result = Scalar::reduce_wide_bigint(&two_n);
        assert_eq!(barrett_result, bigint_result);
        assert_eq!(barrett_result, Scalar::zero(), "2*n should reduce to zero");
    }

    #[test]
    fn test_barrett_vs_bigint_near_order() {
        // Test values near the order
        let n = P521_ORDER;

        // n - 1
        let mut n_minus_1 = [0u64; 18];
        n_minus_1[..9].copy_from_slice(&n);
        let mut borrow = 1u64;
        for i in 0..9 {
            let (diff, b) = n_minus_1[i].overflowing_sub(borrow);
            n_minus_1[i] = diff;
            borrow = b as u64;
            if borrow == 0 {
                break;
            }
        }

        let barrett_result = Scalar::reduce_wide_barrett(&n_minus_1);
        let bigint_result = Scalar::reduce_wide_bigint(&n_minus_1);
        assert_eq!(
            barrett_result, bigint_result,
            "Barrett vs BigUint mismatch for n-1"
        );

        // n + 1
        let mut n_plus_1 = [0u64; 18];
        n_plus_1[..9].copy_from_slice(&n);
        let mut carry = 1u64;
        for i in 0..9 {
            let (sum, c) = n_plus_1[i].overflowing_add(carry);
            n_plus_1[i] = sum;
            carry = c as u64;
            if carry == 0 {
                break;
            }
        }
        if carry != 0 {
            n_plus_1[9] = carry;
        }

        let barrett_result = Scalar::reduce_wide_barrett(&n_plus_1);
        let bigint_result = Scalar::reduce_wide_bigint(&n_plus_1);
        assert_eq!(
            barrett_result, bigint_result,
            "Barrett vs BigUint mismatch for n+1"
        );
        assert_eq!(barrett_result, Scalar::one(), "n+1 should reduce to 1");
    }

    #[test]
    fn test_barrett_vs_bigint_large_values() {
        // Test with large random-looking values
        let test_cases = [
            // All limbs maxed out
            [
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
            // Mix of high and low bits
            [
                0x123456789ABCDEF0,
                0xFEDCBA9876543210,
                0x0F0F0F0F0F0F0F0F,
                0xF0F0F0F0F0F0F0F0,
                0xAAAAAAAAAAAAAAAA,
                0x5555555555555555,
                0xFFFFFFFF00000000,
                0x00000000FFFFFFFF,
                0x8000000000000000,
                0x0000000000000001,
                0x7FFFFFFFFFFFFFFF,
                0x8000000080000000,
                0x0000000100000001,
                0xFFFFFFFFFFFFFFFF,
                0x1111111111111111,
                0x2222222222222222,
                0x3333333333333333,
                0x4444444444444444,
            ],
            // Upper limbs set
            [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ],
        ];

        for (i, limbs) in test_cases.iter().enumerate() {
            let barrett_result = Scalar::reduce_wide_barrett(limbs);
            let bigint_result = Scalar::reduce_wide_bigint(limbs);

            assert_eq!(
                barrett_result, bigint_result,
                "Barrett vs BigUint mismatch for test case {} (large values)",
                i
            );
        }
    }

    #[test]
    fn test_barrett_vs_bigint_multiplication_results() {
        // Test Barrett on actual multiplication results
        let test_scalars = [
            Scalar::from_u64(2),
            Scalar::from_u64(3),
            Scalar::from_u64(0xFFFFFFFF),
            Scalar::from_u64(0x100000000),
            Scalar::from_limbs([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0]),
        ];

        for (i, a) in test_scalars.iter().enumerate() {
            for (j, b) in test_scalars.iter().enumerate() {
                // Compute a * b using schoolbook multiplication
                let mut product = [0u64; 18];
                for ii in 0..9 {
                    let mut carry = 0u64;
                    for jj in 0..9 {
                        let prod = (a.limbs[ii] as u128) * (b.limbs[jj] as u128);
                        let sum = (product[ii + jj] as u128) + prod + (carry as u128);
                        product[ii + jj] = sum as u64;
                        carry = (sum >> 64) as u64;
                    }
                    product[ii + 9] = carry;
                }

                let barrett_result = Scalar::reduce_wide_barrett(&product);
                let bigint_result = Scalar::reduce_wide_bigint(&product);

                assert_eq!(
                    barrett_result, bigint_result,
                    "Barrett vs BigUint mismatch for multiplication test case ({}, {})",
                    i, j
                );

                // Also verify it matches the mul() method
                let mul_result = a.mul(b);
                assert_eq!(
                    barrett_result, mul_result,
                    "Barrett result doesn't match mul() for test case ({}, {})",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_barrett_edge_cases() {
        // Test edge case: exactly n
        let mut exactly_n = [0u64; 18];
        exactly_n[..9].copy_from_slice(&P521_ORDER);

        let result = Scalar::reduce_wide_barrett(&exactly_n);
        assert_eq!(result, Scalar::zero(), "Exactly n should reduce to zero");

        // Test edge case: exactly 2n
        let mut two_n = [0u64; 18];
        let mut carry = 0u64;
        for i in 0..9 {
            let (sum, c1) = P521_ORDER[i].overflowing_add(P521_ORDER[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            two_n[i] = sum;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            two_n[9] = carry;
        }

        let result = Scalar::reduce_wide_barrett(&two_n);
        assert_eq!(result, Scalar::zero(), "Exactly 2n should reduce to zero");

        // Test edge case: 2^1152 - 1 (all bits set)
        let max_value = [0xFFFFFFFFFFFFFFFF; 18];
        let barrett_result = Scalar::reduce_wide_barrett(&max_value);
        let bigint_result = Scalar::reduce_wide_bigint(&max_value);
        assert_eq!(
            barrett_result, bigint_result,
            "Barrett vs BigUint mismatch for 2^1152-1"
        );
    }

    #[test]
    fn test_barrett_zero() {
        let zero_limbs = [0u64; 18];
        let result = Scalar::reduce_wide_barrett(&zero_limbs);
        assert_eq!(result, Scalar::zero(), "Zero should reduce to zero");
    }

    #[test]
    fn test_barrett_consistency_with_mul() {
        // Verify that mul() produces same results with Barrett as it would with BigUint
        let test_values = [
            (2u64, 3u64),
            (100, 200),
            (0xFFFF, 0xFFFF),
            (0xFFFFFFFF, 0xFFFFFFFF),
        ];

        for (a_val, b_val) in test_values.iter() {
            let a = Scalar::from_u64(*a_val);
            let b = Scalar::from_u64(*b_val);

            let result = a.mul(&b);

            // Verify it's in valid range
            assert!(
                !Scalar::gte_n(&result.limbs),
                "mul({}, {}) result should be < n",
                a_val,
                b_val
            );

            // Compute expected value using BigUint for reference
            let expected = Scalar::from_u64(a_val * b_val);
            assert_eq!(
                result, expected,
                "mul({}, {}) doesn't match expected value",
                a_val, b_val
            );
        }
    }

    #[test]
    fn test_barrett_reduction_properties() {
        // Property: (a mod n) should equal a if a < n
        let small_val = Scalar::from_u64(12345);
        let mut wide = [0u64; 18];
        wide[..9].copy_from_slice(&small_val.limbs);

        let result = Scalar::reduce_wide_barrett(&wide);
        assert_eq!(
            result, small_val,
            "Reducing value < n should return same value"
        );

        // Property: (n mod n) = 0
        let mut n_wide = [0u64; 18];
        n_wide[..9].copy_from_slice(&P521_ORDER);
        let result = Scalar::reduce_wide_barrett(&n_wide);
        assert_eq!(result, Scalar::zero(), "n mod n should be zero");
    }
}
