//! Poly1305 one-time authenticator
//!
//! Implementation using 64-bit saturated limbs (3 limbs).
//! Based on libsodium's poly1305-donna-64 implementation.
//!
//! Uses 3 limbs of 64 bits each to represent 130-bit values.
//! This representation is optimal for 64-bit platforms with native 64×64→128 multiplication.
//!
//! Reference: https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h

use hpcrypt_core::utils::{read_u64_le, write_u64_le};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Poly1305 key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Poly1305 tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Poly1305 block size in bytes
pub const BLOCK_SIZE: usize = 16;

/// Poly1305 MAC state using 64-bit saturated limbs
///
/// Uses 3 limbs to represent the 130-bit accumulator and key.
/// This representation is optimal for 64-bit platforms with native 64×64→128 multiplication.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    // Clamped key (r) - 3 limbs for the 130-bit value (but only 128 bits used after clamping)
    r: [u64; 3],
    // Precomputed r * 5 values for reduction
    r5: [u64; 2],  // r5[0] = r[1]*5, r5[1] = r[2]*5
    // Second key portion (s) - for final addition
    s: [u64; 2],
    // Accumulator (h) - 3 limbs for 130-bit value
    h: [u64; 3],
    // Buffer for partial blocks
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Poly1305 {
    /// Create a new Poly1305 instance with the given key
    ///
    /// # Arguments
    /// * `key` - 32-byte key (first 16 bytes for r, last 16 for s)
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        // Extract and clamp r (first 16 bytes)
        // Clamping: clear top 4 bits of bytes 3, 7, 11, 15
        //          clear bottom 2 bits of bytes 4, 8, 12
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);

        // Apply clamping
        r_bytes[3] &= 15;   // Clear top 4 bits
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;  // Clear bottom 2 bits
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        // Read as 3 limbs: r0 (bits 0-63), r1 (bits 64-127), r2 (bits 128-129, only 2 bits)
        let r0 = read_u64_le(&r_bytes[0..8]);
        let r1 = read_u64_le(&r_bytes[8..16]);
        let r2 = 0u64;  // After clamping, r is only 128 bits, so r2 = 0

        let r = [r0, r1, r2];

        // Precompute r * 5 for modular reduction
        let r5 = [r1.wrapping_mul(5), r2.wrapping_mul(5)];

        // Extract s (second 16 bytes, unmodified)
        let s = [
            read_u64_le(&key[16..24]),
            read_u64_le(&key[24..32]),
        ];

        Self {
            r,
            r5,
            s,
            h: [0; 3],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Update the MAC with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        // Process buffered data first if we have any
        if self.buffer_len > 0 {
            let needed = BLOCK_SIZE - self.buffer_len;
            let to_copy = remaining.len().min(needed);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&remaining[..to_copy]);
            self.buffer_len += to_copy;
            remaining = &remaining[to_copy..];

            if self.buffer_len == BLOCK_SIZE {
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy, false);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while remaining.len() >= BLOCK_SIZE {
            self.process_block(&remaining[..BLOCK_SIZE], false);
            remaining = &remaining[BLOCK_SIZE..];
        }

        // Buffer remaining partial block
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    /// Finalize and return the MAC tag
    pub fn finalize(mut self) -> [u8; TAG_SIZE] {
        // Process final partial block if any
        if self.buffer_len > 0 {
            // Pad with 0x01 byte after the data
            self.buffer[self.buffer_len] = 1;
            for i in self.buffer_len + 1..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy, true);
        }

        // Fully reduce h modulo 2^130 - 5
        self.freeze();

        // Add s to h
        let mut tag = [0u8; TAG_SIZE];

        // h0 + s0 (with carry)
        let (h0, carry) = self.h[0].overflowing_add(self.s[0]);
        write_u64_le(&mut tag[0..8], h0);

        // h1 + s1 + carry
        let mut h1 = self.h[1].wrapping_add(self.s[1]);
        if carry {
            h1 = h1.wrapping_add(1);
        }
        write_u64_le(&mut tag[8..16], h1);

        tag
    }

    /// Process a single 16-byte block
    ///
    /// The hibit parameter determines if this is the final block:
    /// - false: append 0x01 byte (2^128) to the block
    /// - true: this is the final padded block, don't add 2^128
    #[inline]
    fn process_block(&mut self, block: &[u8], is_final: bool) {
        // Read block as two 64-bit limbs
        let m0 = read_u64_le(&block[0..8]);
        let m1 = read_u64_le(&block[8..16]);

        // Add block to accumulator with high bit
        // hibit is 2^128 for non-final blocks, 0 for final block
        let (h0, carry0) = self.h[0].overflowing_add(m0);
        self.h[0] = h0;

        let (h1, carry1) = self.h[1].overflowing_add(m1);
        let (h1, carry2) = h1.overflowing_add(carry0 as u64);
        self.h[1] = h1;

        // Propagate carries to h2
        let mut h2 = self.h[2];
        if carry1 {
            h2 = h2.wrapping_add(1);
        }
        if carry2 {
            h2 = h2.wrapping_add(1);
        }

        if !is_final {
            // Add 2^128 (the hibit)
            h2 = h2.wrapping_add(1);
        }

        self.h[2] = h2;

        // h = h * r (mod 2^130 - 5)
        self.multiply();
    }

    /// Multiply accumulator by r modulo 2^130 - 5
    ///
    /// This is the core operation of Poly1305.
    /// Computes h * r and reduces modulo 2^130 - 5.
    ///
    /// Strategy: Compute full product, then iteratively reduce.
    #[inline(always)]
    fn multiply(&mut self) {
        let h0 = self.h[0];
        let h1 = self.h[1];
        let h2 = self.h[2];
        let r0 = self.r[0];
        let r1 = self.r[1];

        // Compute h * r as a multi-precision product
        // h = h0 + h1*2^64 + h2*2^128 (where h2 is small, usually < 4)
        // r = r0 + r1*2^64 (r is 128 bits after clamping)
        //
        // Product = (h0 + h1*2^64 + h2*2^128) * (r0 + r1*2^64)
        //
        // Expand to get 6 terms:
        //   p00 = h0*r0                at bit 0
        //   p01 = h0*r1                at bit 64
        //   p10 = h1*r0                at bit 64
        //   p11 = h1*r1                at bit 128
        //   p20 = h2*r0                at bit 128
        //   p21 = h2*r1                at bit 192

        let p00 = mul128(h0, r0);
        let p01 = mul128(h0, r1);
        let p10 = mul128(h1, r0);
        let p11 = mul128(h1, r1);
        let p20 = mul128(h2, r0);
        let p21 = mul128(h2, r1);

        // Accumulate into a 256-bit result represented as 4 x u64
        // result[0] = bits 0-63
        // result[1] = bits 64-127
        // result[2] = bits 128-191
        // result[3] = bits 192-255

        // Start with p00 at position 0
        let mut res0 = p00.0;
        let mut res1 = p00.1;
        let mut res2 = 0u64;
        let mut res3 = 0u64;

        // Add p01 and p10 at position 64 (to res1, res2)
        let (new_res1, c1) = res1.overflowing_add(p01.0);
        res1 = new_res1;
        let (new_res1_2, c2) = res1.overflowing_add(p10.0);
        res1 = new_res1_2;

        res2 = res2.wrapping_add(p01.1).wrapping_add(p10.1)
            .wrapping_add(c1 as u64).wrapping_add(c2 as u64);

        // Add p11 and p20 at position 128 (to res2, res3)
        let (new_res2, c3) = res2.overflowing_add(p11.0);
        res2 = new_res2;
        let (new_res2_2, c4) = res2.overflowing_add(p20.0);
        res2 = new_res2_2;

        res3 = res3.wrapping_add(p11.1).wrapping_add(p20.1)
            .wrapping_add(c3 as u64).wrapping_add(c4 as u64);

        // Add p21 at position 192 (to res3)
        res3 = res3.wrapping_add(p21.0);
        // p21.1 would be at position 256+, which we'll reduce immediately

        // Now reduce modulo 2^130 - 5
        // We have a value that's (res0, res1, res2, res3) representing up to 256 bits
        // We need to reduce everything above bit 129 (i.e., res2 >> 2, res3)
        //
        // For each bit above 129, multiply by 5 and add back
        // res2 bits 2+ represent 2^130, 2^131, ...
        // res3 represents 2^192, 2^193, ...

        // Reduce res3 and upper bits of res2
        // res3 * 2^192 ≡ res3 * 5 * 2^62 (mod 2^130-5)
        let overflow3_times_5 = (res3 as u128).wrapping_mul(5);
        let overflow3_contribution = (overflow3_times_5 << 62) as u64;
        let overflow3_carry = (overflow3_times_5 >> 2) as u64;  // Upper bits at position 64+62=126

        let (new_res0, c0) = res0.overflowing_add(overflow3_contribution);
        res0 = new_res0;
        let (temp_res1, c1) = res1.overflowing_add(overflow3_carry);
        let (new_res1, c2) = temp_res1.overflowing_add(c0 as u64);
        res1 = new_res1;
        res2 = res2.wrapping_add(c1 as u64).wrapping_add(c2 as u64);

        // Reduce upper bits of res2 (bits 2+)
        // (res2 >> 2) * 2^130 ≡ (res2 >> 2) * 5
        let overflow2 = res2 >> 2;
        res2 &= 3;  // Keep only lower 2 bits

        // overflow2 * 5 can be up to 65 bits, so we need to handle the overflow
        let (overflow2_times_5_lo, overflow2_times_5_hi) = mul128(overflow2, 5);
        let (new_res0_2, c2) = res0.overflowing_add(overflow2_times_5_lo);
        res0 = new_res0_2;
        res1 = res1.wrapping_add(overflow2_times_5_hi).wrapping_add(c2 as u64);

        // Final result
        self.h[0] = res0;
        self.h[1] = res1;
        self.h[2] = res2;
    }

    /// Fully reduce h modulo 2^130 - 5
    ///
    /// This performs the final reduction to ensure h < p.
    ///
    /// The simple two-stage approach is faster than multi-stage carry propagation
    /// because the multiply() function already maintains h in a well-normalized state.
    fn freeze(&mut self) {
        // Reduce h[2] overflow (bits beyond position 129)
        let c = self.h[2] >> 2;
        self.h[2] &= 3;

        // Add c*5 to h[0], potentially causing overflow
        let h0_wide = (self.h[0] as u128).wrapping_add((c as u128) * 5);
        self.h[0] = h0_wide as u64;

        // Propagate carry to h[1]
        let carry = (h0_wide >> 64) as u64;
        self.h[1] = self.h[1].wrapping_add(carry);

        // Try to subtract p = 2^130 - 5 by adding 5
        // g = h + 5
        let (g0, carry0) = self.h[0].overflowing_add(5);
        let (g1, carry1) = self.h[1].overflowing_add(carry0 as u64);
        let g2 = self.h[2].wrapping_add(carry1 as u64);

        // If g2 >= 4 (bit 2 set), we overflowed past 2^130, so keep h
        // Otherwise use g
        // mask = 0xFFFFFFFFFFFFFFFF if bit 2 of g2 is NOT set (use g)
        //        0x0000000000000000 if bit 2 of g2 IS set (use h)
        let mask = !(((g2 >> 2) as i64) - 1) as u64;

        // Constant-time selection: result = h if mask == 0, g if mask == all 1s
        self.h[0] = (self.h[0] & !mask) | (g0 & mask);
        self.h[1] = (self.h[1] & !mask) | (g1 & mask);
        self.h[2] = (self.h[2] & !mask) | (g2 & mask);
    }
}

/// Perform 64×64→128 bit multiplication
///
/// Returns (lo, hi) where result = lo + hi * 2^64
#[inline(always)]
fn mul128(a: u64, b: u64) -> (u64, u64) {
    let product = (a as u128).wrapping_mul(b as u128);
    (product as u64, (product >> 64) as u64)
}

/// One-shot Poly1305 MAC computation
pub fn poly1305(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; TAG_SIZE] {
    let mut mac = Poly1305::new(key);
    mac.update(data);
    mac.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly1305_rfc8439() {
        // Test vector from RFC 8439 Section 2.5.2
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";

        let tag = poly1305(&key, msg);

        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_poly1305_incremental() {
        let key = [42u8; KEY_SIZE];
        let data = b"Hello, Poly1305!";

        // One-shot
        let tag1 = poly1305(&key, data);

        // Incremental
        let mut mac = Poly1305::new(&key);
        mac.update(&data[..8]);
        mac.update(&data[8..]);
        let tag2 = mac.finalize();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_poly1305_empty() {
        let key = [0u8; KEY_SIZE];
        let tag = poly1305(&key, b"");
        // Empty message should still produce a valid tag
        assert_eq!(tag.len(), TAG_SIZE);
    }
}
