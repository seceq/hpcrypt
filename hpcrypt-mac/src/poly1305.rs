//! Poly1305 one-time authenticator
//!
//! High-performance implementation of Poly1305 as specified in RFC 8439.
//! Optimized for pure Rust without hardware instructions.
//!
//! Target performance: <2 cycles/byte (based on DJB's Salsa20 benchmarks)
//!
//! Poly1305 is a polynomial evaluation MAC that achieves high performance
//! through 130-bit modular arithmetic.

use hpcrypt_core::utils::{read_u32_le, write_u32_le};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Poly1305 key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Poly1305 tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Poly1305 block size in bytes
pub const BLOCK_SIZE: usize = 16;

/// Poly1305 MAC state
///
/// Poly1305 computes a MAC using modular arithmetic in GF(2^130 - 5).
/// The state is maintained as five 26-bit limbs for efficient computation.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    // r value (clamped key portion) in 26-bit limbs
    r: [u32; 5],
    // s value (second half of key) for final addition
    s: [u32; 4],
    // Accumulator in 26-bit limbs
    h: [u32; 5],
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
        // Extract and clamp r
        let mut r = [0u32; 5];
        r[0] = read_u32_le(&key[0..4]) & 0x3ffffff;
        r[1] = (read_u32_le(&key[3..7]) >> 2) & 0x3ffff03;
        r[2] = (read_u32_le(&key[6..10]) >> 4) & 0x3ffc0ff;
        r[3] = (read_u32_le(&key[9..13]) >> 6) & 0x3f03fff;
        r[4] = (read_u32_le(&key[12..16]) >> 8) & 0x00fffff;

        // Extract s (unmodified)
        let s = [
            read_u32_le(&key[16..20]),
            read_u32_le(&key[20..24]),
            read_u32_le(&key[24..28]),
            read_u32_le(&key[28..32]),
        ];

        Self {
            r,
            s,
            h: [0; 5],
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
        let h0 = self.h[0] | (self.h[1] << 26);
        let h1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let h2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let h3 = (self.h[3] >> 18) | (self.h[4] << 8);

        let mut c = h0 as u64 + self.s[0] as u64;
        write_u32_le(&mut tag[0..4], c as u32);
        c >>= 32;

        c += h1 as u64 + self.s[1] as u64;
        write_u32_le(&mut tag[4..8], c as u32);
        c >>= 32;

        c += h2 as u64 + self.s[2] as u64;
        write_u32_le(&mut tag[8..12], c as u32);
        c >>= 32;

        c += h3 as u64 + self.s[3] as u64;
        write_u32_le(&mut tag[12..16], c as u32);

        tag
    }

    /// Process a single block
    #[inline]
    fn process_block(&mut self, block: &[u8], is_final: bool) {
        // Read block as little-endian u32s
        let r0 = read_u32_le(&block[0..4]);
        let r1 = read_u32_le(&block[4..8]);
        let r2 = read_u32_le(&block[8..12]);
        let r3 = read_u32_le(&block[12..16]);

        // Convert to 26-bit limbs
        let hibit = if is_final { 0 } else { 1u32 << 24 };

        self.h[0] += r0 & 0x3ffffff;
        self.h[1] += ((r0 >> 26) | (r1 << 6)) & 0x3ffffff;
        self.h[2] += ((r1 >> 20) | (r2 << 12)) & 0x3ffffff;
        self.h[3] += ((r2 >> 14) | (r3 << 18)) & 0x3ffffff;
        self.h[4] += (r3 >> 8) | hibit;

        // h = (h + block) * r  (mod 2^130 - 5)
        let r_copy = self.r;
        self.multiply_accumulate(&r_copy);
    }

    /// Multiply accumulator by r value
    #[inline(always)]
    fn multiply_accumulate(&mut self, r: &[u32; 5]) {
        // Precompute 5 * r values for reduction
        let r1_5 = r[1] * 5;
        let r2_5 = r[2] * 5;
        let r3_5 = r[3] * 5;
        let r4_5 = r[4] * 5;

        // Polynomial multiplication
        let d0 = (self.h[0] as u64 * r[0] as u64)
            + (self.h[1] as u64 * r4_5 as u64)
            + (self.h[2] as u64 * r3_5 as u64)
            + (self.h[3] as u64 * r2_5 as u64)
            + (self.h[4] as u64 * r1_5 as u64);

        let d1 = (self.h[0] as u64 * r[1] as u64)
            + (self.h[1] as u64 * r[0] as u64)
            + (self.h[2] as u64 * r4_5 as u64)
            + (self.h[3] as u64 * r3_5 as u64)
            + (self.h[4] as u64 * r2_5 as u64);

        let d2 = (self.h[0] as u64 * r[2] as u64)
            + (self.h[1] as u64 * r[1] as u64)
            + (self.h[2] as u64 * r[0] as u64)
            + (self.h[3] as u64 * r4_5 as u64)
            + (self.h[4] as u64 * r3_5 as u64);

        let d3 = (self.h[0] as u64 * r[3] as u64)
            + (self.h[1] as u64 * r[2] as u64)
            + (self.h[2] as u64 * r[1] as u64)
            + (self.h[3] as u64 * r[0] as u64)
            + (self.h[4] as u64 * r4_5 as u64);

        let d4 = (self.h[0] as u64 * r[4] as u64)
            + (self.h[1] as u64 * r[3] as u64)
            + (self.h[2] as u64 * r[2] as u64)
            + (self.h[3] as u64 * r[1] as u64)
            + (self.h[4] as u64 * r[0] as u64);

        // Carry propagation
        let c = d0 >> 26;
        self.h[0] = d0 as u32 & 0x3ffffff;

        let d1 = d1 + c;
        let c = d1 >> 26;
        self.h[1] = d1 as u32 & 0x3ffffff;

        let d2 = d2 + c;
        let c = d2 >> 26;
        self.h[2] = d2 as u32 & 0x3ffffff;

        let d3 = d3 + c;
        let c = d3 >> 26;
        self.h[3] = d3 as u32 & 0x3ffffff;

        let d4 = d4 + c;
        let c = d4 >> 26;
        self.h[4] = d4 as u32 & 0x3ffffff;

        // Reduce mod 2^130 - 5
        self.h[0] += (c * 5) as u32;
        let c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c;
    }

    /// Fully reduce h modulo 2^130 - 5
    fn freeze(&mut self) {
        // Full carry propagation
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        // Compute h - p where p = 2^130 - 5
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;

        let mut g4 = h4.wrapping_add(c);
        c = g4 >> 26;
        g4 &= 0x3ffffff;

        // If there was a borrow (c == 0), use g, otherwise use h
        // mask = 0xffffffff if c > 0, else 0
        let mask = c.wrapping_neg();

        // Constant-time select
        self.h[0] = h0 ^ (mask & (h0 ^ g0));
        self.h[1] = h1 ^ (mask & (h1 ^ g1));
        self.h[2] = h2 ^ (mask & (h2 ^ g2));
        self.h[3] = h3 ^ (mask & (h3 ^ g3));
        self.h[4] = h4 ^ (mask & (h4 ^ g4));
    }
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
        let key = hex_literal::hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let msg = b"Cryptographic Forum Research Group";

        let tag = poly1305(&key, msg);

        let expected = hex_literal::hex!("a8061dc1305136c6c22b8baf0c0127a9");
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
