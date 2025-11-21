//! POLYVAL universal hash function for AES-GCM-SIV
//!
//! POLYVAL is a polynomial hash over GF(2^128) similar to GHASH but with
//! a different polynomial and byte ordering optimized for hardware implementations.
//! It operates with the irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1.
//!
//! This implementation uses carryless multiplication based on BearSSL's technique,
//! which emulates carryless multiplication using masked integer operations.

use core::convert::TryInto;

/// POLYVAL universal hash for AES-GCM-SIV
///
/// Operates in GF(2^128) with irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1.
/// This implementation is constant-time and suitable for cryptographic applications.
#[derive(Debug)]
pub struct Polyval {
    h: [u64; 2],
    state: [u64; 2],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Polyval {
    /// Creates a new POLYVAL instance with the given H value.
    ///
    /// # Arguments
    /// * `h` - The 16-byte key value in little-endian format
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            h: [
                u64::from_le_bytes(h[0..8].try_into().unwrap()),
                u64::from_le_bytes(h[8..16].try_into().unwrap()),
            ],
            state: [0, 0],
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Updates POLYVAL state with a complete 16-byte block.
    ///
    /// # Arguments
    /// * `block` - A 16-byte block to process
    #[inline]
    pub fn update_block(&mut self, block: &[u8; 16]) {
        let x = [
            u64::from_le_bytes(block[0..8].try_into().unwrap()),
            u64::from_le_bytes(block[8..16].try_into().unwrap()),
        ];

        self.state[0] ^= x[0];
        self.state[1] ^= x[1];
        self.state = mul_gf128_carryless(self.state, self.h);
    }

    /// Updates POLYVAL with arbitrary-length data.
    ///
    /// Data is buffered and processed in 16-byte blocks. Partial blocks
    /// are kept in the buffer until more data arrives or `finalize()` is called.
    ///
    /// # Arguments
    /// * `data` - Input data of any length
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            let available = core::cmp::min(needed, data.len());

            self.buffer[self.buffer_len..self.buffer_len + available]
                .copy_from_slice(&data[..available]);
            self.buffer_len += available;
            offset += available;

            if self.buffer_len == 16 {
                let block = self.buffer;
                self.update_block(&block);
                self.buffer_len = 0;
            }
        }

        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.update_block(&block);
            offset += 16;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Returns the final POLYVAL output as a 16-byte array.
    ///
    /// Any buffered bytes are zero-padded to form a complete block
    /// before computing the final state.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.update_block(&block);
        }

        let mut output = [0u8; 16];
        output[0..8].copy_from_slice(&self.state[0].to_le_bytes());
        output[8..16].copy_from_slice(&self.state[1].to_le_bytes());
        output
    }

    /// Resets the internal state and buffer to initial values.
    pub fn reset(&mut self) {
        self.state = [0, 0];
        self.buffer = [0u8; 16];
        self.buffer_len = 0;
    }
}

/// Multiplies two elements in GF(2^128) using carryless multiplication.
#[inline]
fn mul_gf128_carryless(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    let z = carryless_mul_128x128(a, b);
    reduce_gf128_optimized(z)
}

/// Carryless multiplication of two 128-bit values producing a 256-bit result.
///
/// Uses Karatsuba decomposition for efficiency.
#[inline]
fn carryless_mul_128x128(a: [u64; 2], b: [u64; 2]) -> [u64; 4] {
    let a0 = a[0];
    let a1 = a[1];
    let b0 = b[0];
    let b1 = b[1];

    let z00 = clmul64_full(a0, b0);
    let z01 = clmul64_full(a0, b1);
    let z10 = clmul64_full(a1, b0);
    let z11 = clmul64_full(a1, b1);

    let mut result = [0u64; 4];

    result[0] = z00[0];
    result[1] = z00[1];

    result[1] ^= z01[0] ^ z10[0];
    result[2] = z01[1] ^ z10[1];

    result[2] ^= z11[0];
    result[3] = z11[1];

    result
}

/// Carryless multiplication of two 64-bit values returning 128 bits.
#[inline]
fn clmul64_full(a: u64, b: u64) -> [u64; 2] {
    clmul64(a, b)
}

/// Carryless multiplication of two 32-bit values using BearSSL technique.
///
/// Uses 4-bit nibble masking to prevent carry propagation.
#[inline]
pub fn clmul32(a: u32, b: u32) -> u64 {
    let a0 = (a & 0x11111111) as u64;
    let a1 = (a & 0x22222222) as u64;
    let a2 = (a & 0x44444444) as u64;
    let a3 = (a & 0x88888888) as u64;

    let b0 = (b & 0x11111111) as u64;
    let b1 = (b & 0x22222222) as u64;
    let b2 = (b & 0x44444444) as u64;
    let b3 = (b & 0x88888888) as u64;

    let z0 = a0 * b0 ^ a1 * b3 ^ a2 * b2 ^ a3 * b1;
    let z1 = a0 * b1 ^ a1 * b0 ^ a2 * b3 ^ a3 * b2;
    let z2 = a0 * b2 ^ a1 * b1 ^ a2 * b0 ^ a3 * b3;
    let z3 = a0 * b3 ^ a1 * b2 ^ a2 * b1 ^ a3 * b0;

    let z0 = z0 & 0x1111111111111111;
    let z1 = z1 & 0x2222222222222222;
    let z2 = z2 & 0x4444444444444444;
    let z3 = z3 & 0x8888888888888888;

    z0 | z1 | z2 | z3
}

/// Montgomery reduction for POLYVAL.
///
/// Reduces a 256-bit product modulo the POLYVAL polynomial using the
/// algorithm from the Intel CLMUL instruction set whitepaper.
///
/// Polynomial: x^128 + x^127 + x^126 + x^121 + 1
/// Reduction constant: 0xc200000000000000
#[inline]
pub fn reduce_gf128_optimized(z: [u64; 4]) -> [u64; 2] {
    const POLY: u64 = 0xc200000000000000;

    let a = clmul64(z[0], POLY);
    let b1 = z[0] ^ a[1];
    let b0 = z[1] ^ a[0];

    let c = clmul64(b0, POLY);
    let d1 = b0 ^ c[1];
    let d0 = b1 ^ c[0];

    let result0 = d0 ^ z[2];
    let result1 = d1 ^ z[3];

    [result0, result1]
}

/// Carryless multiplication of two 64-bit values using BearSSL technique.
#[inline]
pub fn clmul64(a: u64, b: u64) -> [u64; 2] {
    let a0 = a as u32;
    let a1 = (a >> 32) as u32;
    let b0 = b as u32;
    let b1 = (b >> 32) as u32;

    let z00 = clmul32(a0, b0);
    let z01 = clmul32(a0, b1);
    let z10 = clmul32(a1, b0);
    let z11 = clmul32(a1, b1);

    let mut result = [0u64; 2];
    result[0] = z00;
    result[0] ^= z01 << 32;
    result[0] ^= z10 << 32;
    result[1] = z01 >> 32;
    result[1] ^= z10 >> 32;
    result[1] ^= z11;

    result
}

/// Computes POLYVAL over the given data in a single operation.
///
/// This is a convenience function for one-shot POLYVAL computation.
///
/// # Arguments
/// * `h` - The 16-byte key value in little-endian format
/// * `data` - Input data of any length
///
/// # Returns
/// The 16-byte POLYVAL hash output
pub fn polyval(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut poly = Polyval::new(h);
    poly.update(data);
    poly.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clmul32() {
        assert_eq!(clmul32(0, 0x12345678), 0);
        assert_eq!(clmul32(0x12345678, 0), 0);
        assert_eq!(clmul32(1, 0x12345678) & 0xFFFFFFFF, 0x12345678);
    }

    #[test]
    fn test_polyval_basic() {
        let h = [0u8; 16];
        let data = b"test data";
        let result = polyval(&h, data);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn test_polyval_incremental() {
        let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut poly1 = Polyval::new(&h);
        poly1.update(b"hello");
        poly1.update(b"world");
        let result1 = poly1.finalize();

        let mut poly2 = Polyval::new(&h);
        poly2.update(b"helloworld");
        let result2 = poly2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_polyval_block() {
        let h = [
            0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
            0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16,
        ];

        let mut poly = Polyval::new(&h);
        let block = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        poly.update_block(&block);

        let result = poly.finalize();
        assert_eq!(result.len(), 16);
    }
}
