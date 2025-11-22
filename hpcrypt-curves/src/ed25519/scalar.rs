//! Scalar arithmetic for Ed25519
//!
//! This module implements scalar arithmetic modulo the group order L.
//! Scalars are used for operations like scalar multiplication of curve points.

use super::constants::L;

/// Scalar in the edwards25519 group (integers mod L)
/// Represented as 32 bytes in little-endian format
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub [u8; 32]);

impl Scalar {
    /// Create a scalar from bytes (little-endian)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut s = Scalar(bytes);
        s.reduce();
        s
    }

    /// Return the zero scalar
    pub fn zero() -> Self {
        Scalar([0u8; 32])
    }

    /// Create a scalar from a 64-byte hash (reduce mod L)
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        // RFC 8032: Interpret the 64-byte hash as a little-endian integer and reduce mod L

        // Convert hash to wide format (8 x 64-bit limbs)
        let mut wide = [0u64; 8];
        for i in 0..8 {
            wide[i] = u64::from_le_bytes([
                hash[i * 8],
                hash[i * 8 + 1],
                hash[i * 8 + 2],
                hash[i * 8 + 3],
                hash[i * 8 + 4],
                hash[i * 8 + 5],
                hash[i * 8 + 6],
                hash[i * 8 + 7],
            ]);
        }

        // Reduce mod L using our custom reduction
        let bytes = Self::reduce_wide(&wide);
        Scalar(bytes)
    }

    /// Reduce this scalar mod L
    fn reduce(&mut self) {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                self.0[i * 8],
                self.0[i * 8 + 1],
                self.0[i * 8 + 2],
                self.0[i * 8 + 3],
                self.0[i * 8 + 4],
                self.0[i * 8 + 5],
                self.0[i * 8 + 6],
                self.0[i * 8 + 7],
            ]);
        }

        if Self::limbs_gte(&limbs, &L) {
            Self::limbs_sub(&mut limbs, &L);
        }

        for i in 0..4 {
            self.0[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
    }

    /// Add two scalars mod L
    pub fn add(&self, other: &Scalar) -> Scalar {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            let a = u64::from_le_bytes([
                self.0[i * 8],
                self.0[i * 8 + 1],
                self.0[i * 8 + 2],
                self.0[i * 8 + 3],
                self.0[i * 8 + 4],
                self.0[i * 8 + 5],
                self.0[i * 8 + 6],
                self.0[i * 8 + 7],
            ]) as u128;

            let b = u64::from_le_bytes([
                other.0[i * 8],
                other.0[i * 8 + 1],
                other.0[i * 8 + 2],
                other.0[i * 8 + 3],
                other.0[i * 8 + 4],
                other.0[i * 8 + 5],
                other.0[i * 8 + 6],
                other.0[i * 8 + 7],
            ]) as u128;

            let sum = a + b + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        // Reduce if necessary
        if carry > 0 || Self::limbs_gte(&result, &L) {
            Self::limbs_sub(&mut result, &L);
        }

        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&result[i].to_le_bytes());
        }

        Scalar(bytes)
    }

    /// Multiply two scalars mod L
    pub fn mul(&self, other: &Scalar) -> Scalar {
        // Convert to limbs
        let mut a = [0u64; 4];
        let mut b = [0u64; 4];

        for i in 0..4 {
            a[i] = u64::from_le_bytes([
                self.0[i * 8],
                self.0[i * 8 + 1],
                self.0[i * 8 + 2],
                self.0[i * 8 + 3],
                self.0[i * 8 + 4],
                self.0[i * 8 + 5],
                self.0[i * 8 + 6],
                self.0[i * 8 + 7],
            ]);

            b[i] = u64::from_le_bytes([
                other.0[i * 8],
                other.0[i * 8 + 1],
                other.0[i * 8 + 2],
                other.0[i * 8 + 3],
                other.0[i * 8 + 4],
                other.0[i * 8 + 5],
                other.0[i * 8 + 6],
                other.0[i * 8 + 7],
            ]);
        }

        // Multiply: result is up to 512 bits
        let mut wide = [0u64; 8];

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = (a[i] as u128) * (b[j] as u128) + (wide[i + j] as u128) + carry;
                wide[i + j] = product as u64;
                carry = product >> 64;
            }
            wide[i + 4] = carry as u64;
        }

        // Reduce mod L using our custom reduction
        let bytes = Self::reduce_wide(&wide);
        Scalar(bytes)
    }

    /// Check if limbs >= L
    fn limbs_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true // Equal
    }

    /// Subtract b from a (assuming a >= b)
    ///
    /// Constant-time implementation using overflowing_sub to avoid branching.
    fn limbs_sub(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = false;
        for i in 0..4 {
            let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
            let (diff2, borrow2) = diff1.overflowing_sub(borrow as u64);
            a[i] = diff2;
            borrow = borrow1 | borrow2;
        }
    }

    /// Reduce a 512-bit value modulo L using optimized reduction
    ///
    /// This uses a specialized reduction algorithm that is much faster than BigUint.
    /// The algorithm processes the high limbs by multiplying them by precomputed
    /// reduction constants R_i = 2^(64*i) mod L.
    fn reduce_wide(wide: &[u64; 8]) -> [u8; 32] {
        // Precomputed reduction constants: R_i = 2^(256 + 64*i) mod L for i = 0..3
        // L = 2^252 + 27742317777372353535851937790883648493

        // R[0] = 2^256 mod L
        const R0: [u64; 4] = [
            0xd6ec31748d98951d,
            0xc6ef5bf4737dcf70,
            0xfffffffffffffffe,
            0x0fffffffffffffff,
        ];

        // R[1] = 2^320 mod L
        const R1: [u64; 4] = [
            0x5812631a5cf5d3ed,
            0x93b8c838d39a5e06,
            0xb2106215d086329a,
            0x0ffffffffffffffe,
        ];

        // R[2] = 2^384 mod L
        const R2: [u64; 4] = [
            0x39822129a02a6271,
            0xb64a7f435e4fdd95,
            0x7ed9ce5a30a2c131,
            0x02106215d086329a,
        ];

        // R[3] = 2^448 mod L
        const R3: [u64; 4] = [
            0x79daf520a00acb65,
            0xe24babbe38d1d7a9,
            0xb399411b7c309a3d,
            0x0ed9ce5a30a2c131,
        ];

        // Start with low 256 bits
        let mut acc = [wide[0], wide[1], wide[2], wide[3]];

        // Process high limbs: add wide[i] * R[i-4] for i = 4..8
        // Use 5-limb arithmetic to handle overflow
        let mut acc5 = [acc[0], acc[1], acc[2], acc[3], 0u64];

        if wide[4] != 0 {
            acc5 = Scalar::add_mul_limb5(&acc5, wide[4], &R0);
        }
        if wide[5] != 0 {
            acc5 = Scalar::add_mul_limb5(&acc5, wide[5], &R1);
        }
        if wide[6] != 0 {
            acc5 = Scalar::add_mul_limb5(&acc5, wide[6], &R2);
        }
        if wide[7] != 0 {
            acc5 = Scalar::add_mul_limb5(&acc5, wide[7], &R3);
        }

        // Reduce the 5th limb (overflow) by multiplying by R0 and adding back
        // Repeat until overflow is zero (at most 2-3 iterations)
        while acc5[4] != 0 {
            let overflow = acc5[4];
            acc5[4] = 0;
            acc5 = Scalar::add_mul_limb5(&acc5, overflow, &R0);
        }

        // Final reduction: subtract L repeatedly until result < L
        acc = [acc5[0], acc5[1], acc5[2], acc5[3]];
        while Scalar::limbs_gte(&acc, &L) {
            Scalar::limbs_sub(&mut acc, &L);
        }

        // Convert to bytes
        let mut result = [0u8; 32];
        for i in 0..4 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&acc[i].to_le_bytes());
        }

        result
    }

    /// Add (limb * multiplier) to a 5-limb accumulator
    /// Returns the result as [u64; 5]
    fn add_mul_limb5(acc: &[u64; 5], limb: u64, multiplier: &[u64; 4]) -> [u64; 5] {
        let mut result = [0u64; 5];
        let mut carry = 0u128;

        // Add limb * multiplier[i] to acc[i] for i = 0..4
        for i in 0..4 {
            carry = carry + (acc[i] as u128) + (limb as u128) * (multiplier[i] as u128);
            result[i] = carry as u64;
            carry >>= 64;
        }

        // Add remaining carry to the 5th limb
        carry += acc[4] as u128;
        result[4] = carry as u64;

        result
    }

    /// Check if wide >= L
    #[allow(dead_code)]
    fn wide_gte(a: &[u64; 8], b: &[u64; 4]) -> bool {
        // Check if any high limbs are non-zero
        for i in 4..8 {
            if a[i] != 0 {
                return true;
            }
        }

        // Compare low 4 limbs
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true // Equal
    }

    /// Subtract L from wide value
    /// TODO: Currently unused, will be used when replacing num-bigint with Barrett reduction
    #[allow(dead_code)]
    fn wide_sub(a: &mut [u64; 8], b: &[u64; 4]) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = (a[i] as i128) - (b[i] as i128) - borrow;
            if diff < 0 {
                a[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                a[i] = diff as u64;
                borrow = 0;
            }
        }
        // Propagate borrow through high limbs
        for i in 4..8 {
            if borrow == 0 {
                break;
            }
            let diff = (a[i] as i128) - borrow;
            if diff < 0 {
                a[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                a[i] = diff as u64;
                borrow = 0;
            }
        }
    }

    /// Get the bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert scalar to Non-Adjacent Form (NAF) representation
    ///
    /// NAF is a signed digit representation where no two adjacent digits are non-zero.
    /// This property reduces the expected number of non-zero digits (and thus point additions)
    /// by approximately 33% compared to binary representation.
    ///
    /// # Algorithm
    /// For each bit position i from 0 to 255:
    /// - If bit i is 1:
    ///   - If bit i+1 is also 1, set naf\[i\] = -1 and add 1 to position i+1 (carry)
    ///   - Otherwise, set naf\[i\] = 1
    /// - If bit i is 0, set naf\[i\] = 0
    ///
    /// # Returns
    /// Array of 256 signed digits, each in {-1, 0, 1}, represented as i8
    ///
    /// # Performance
    /// This reduces point additions in scalar multiplication by ~33%
    pub fn to_naf(&self) -> [i8; 256] {
        let mut naf = [0i8; 256];
        let mut bytes = self.0;

        // Process each bit from LSB to MSB
        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;

            // Check if current bit is 1
            if (bytes[byte_idx] >> bit_idx) & 1 == 1 {
                // Check if next bit exists and is also 1
                if i < 255 {
                    let next_byte_idx = (i + 1) / 8;
                    let next_bit_idx = (i + 1) % 8;

                    if (bytes[next_byte_idx] >> next_bit_idx) & 1 == 1 {
                        // Two consecutive 1s: use subtraction (naf[i] = -1) and carry
                        naf[i] = -1;

                        // Add 1 to position i+1 (this turns 11... into 10...)
                        // We need to propagate the carry
                        let mut carry_pos = i + 1;
                        loop {
                            let carry_byte_idx = carry_pos / 8;
                            let carry_bit_idx = carry_pos % 8;

                            if carry_byte_idx >= 32 {
                                break; // Overflow protection
                            }

                            // Add 1 to this bit
                            if (bytes[carry_byte_idx] >> carry_bit_idx) & 1 == 0 {
                                // Bit is 0, set it to 1 and we're done
                                bytes[carry_byte_idx] |= 1 << carry_bit_idx;
                                break;
                            } else {
                                // Bit is 1, clear it and continue carry
                                bytes[carry_byte_idx] &= !(1 << carry_bit_idx);
                                carry_pos += 1;
                                if carry_pos >= 256 {
                                    break; // Don't overflow array
                                }
                            }
                        }
                    } else {
                        // Current bit is 1, next bit is 0: just use 1
                        naf[i] = 1;
                    }
                } else {
                    // Last bit, just use 1
                    naf[i] = 1;
                }
            }
            // If current bit is 0, naf[i] remains 0
        }

        naf
    }
}
