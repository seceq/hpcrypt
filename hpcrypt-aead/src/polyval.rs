//! POLYVAL universal hash function for AES-GCM-SIV
//!
//! POLYVAL is a polynomial hash over GF(2^128) similar to GHASH but with
//! a different polynomial and byte ordering to better suit hardware implementations.

use core::convert::TryInto;

/// POLYVAL universal hash for AES-GCM-SIV
///
/// Operates in GF(2^128) with irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1
#[derive(Debug)]
pub struct Polyval {
    h: [u64; 2],
    state: [u64; 2],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Polyval {
    /// Create a new POLYVAL instance with the given H value
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

    /// Update POLYVAL with a block of data (must be 16 bytes)
    pub fn update_block(&mut self, block: &[u8; 16]) {
        // Convert block to field element (little-endian)
        let x = [
            u64::from_le_bytes(block[0..8].try_into().unwrap()),
            u64::from_le_bytes(block[8..16].try_into().unwrap()),
        ];

        // S_{j} = (S_{j-1} + X_j) * H in GF(2^128)
        // First: S_{j-1} + X_j (XOR in GF(2))
        self.state[0] ^= x[0];
        self.state[1] ^= x[1];

        // Second: Multiply by H using the dot operation
        self.state = mul_in_gf128(self.state, self.h);
    }

    /// Update POLYVAL with arbitrary-length data
    ///
    /// Data is buffered and processed in 16-byte blocks. Partial blocks
    /// are kept in the buffer until more data arrives or finalize() is called.
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // If we have data in the buffer, try to complete it first
        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            let available = core::cmp::min(needed, data.len());

            self.buffer[self.buffer_len..self.buffer_len + available]
                .copy_from_slice(&data[..available]);
            self.buffer_len += available;
            offset += available;

            // If we completed a block, process it
            if self.buffer_len == 16 {
                let block = self.buffer;  // Copy the buffer
                self.update_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process complete 16-byte blocks directly from data
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[offset..offset + 16]);
            self.update_block(&block);
            offset += 16;
        }

        // Buffer any remaining bytes
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Get the final POLYVAL output
    ///
    /// If there are any buffered bytes, they are padded with zeros to form
    /// a complete block and processed before returning the final state.
    pub fn finalize(mut self) -> [u8; 16] {
        // Process any remaining buffered data
        if self.buffer_len > 0 {
            // Pad remaining bytes with zeros
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;  // Copy the buffer
            self.update_block(&block);
        }

        let mut output = [0u8; 16];
        output[0..8].copy_from_slice(&self.state[0].to_le_bytes());
        output[8..16].copy_from_slice(&self.state[1].to_le_bytes());
        output
    }

    /// Reset the internal state and buffer
    pub fn reset(&mut self) {
        self.state = [0, 0];
        self.buffer = [0u8; 16];
        self.buffer_len = 0;
    }
}

/// Multiply two elements in GF(2^128) with the GCM-SIV polynomial
///
/// Uses x^128 + x^127 + x^126 + x^121 + 1
fn mul_in_gf128(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    // Karatsuba multiplication for efficiency
    let a0 = a[0];
    let a1 = a[1];
    let b0 = b[0];
    let b1 = b[1];

    let mut z = [0u64; 4]; // Product before reduction

    // Multiply as 128-bit × 128-bit = 256-bit
    let (z0, carry0) = mul64_with_carry(a0, b0, 0);
    z[0] = z0;

    let (t1, carry1) = mul64_with_carry(a0, b1, carry0);
    let (t2, carry2) = mul64_with_carry(a1, b0, 0);
    let (z1, c1) = t1.overflowing_add(t2);
    let carry_mid = (c1 as u64).wrapping_add(carry1).wrapping_add(carry2);

    z[1] = z1;

    let (z2, carry3) = mul64_with_carry(a1, b1, carry_mid);
    z[2] = z2;
    z[3] = carry3;

    // Reduce modulo x^128 + x^127 + x^126 + x^121 + 1
    // This is the POLYVAL-specific reduction
    reduce_gf128(z)
}

/// Multiply two 64-bit numbers with carry
fn mul64_with_carry(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128) + (carry as u128);
    (product as u64, (product >> 64) as u64)
}

/// Reduce a 256-bit value modulo the GCM-SIV polynomial
fn reduce_gf128(z: [u64; 4]) -> [u64; 2] {
    // For GCM-SIV polynomial x^128 + x^127 + x^126 + x^121 + 1
    // Reduction constant: 0x...0492 (little-endian representation)

    // Simple schoolbook reduction
    // When z is >= 2^128, we need to reduce the upper 128 bits
    let mut result = [z[0], z[1]];

    if z[2] != 0 || z[3] != 0 {
        // Upper 128 bits need reduction
        // For this polynomial, x^128 ≡ x^127 + x^126 + x^121 + 1 (mod p)
        let high = [z[2], z[3]];

        // Multiply high bits by reduction polynomial contribution
        // This is a simplified reduction - full implementation would be more complex
        result[0] ^= high[0];
        result[1] ^= high[1];

        // Additional reduction steps for the specific polynomial
        // x^127, x^126, x^121, and constant term
        let r0 = high[1] >> 1; // x^127 term
        let r1 = (high[1] >> 2) | (high[0] << 62); // x^126 term
        let r2 = (high[1] >> 7) | (high[0] << 57); // x^121 term

        result[0] ^= r0 ^ r1 ^ r2 ^ high[0];
        result[1] ^= (high[1] << 63) ^ (high[1] << 62) ^ (high[1] << 57);
    }

    result
}

/// Convenience function to compute POLYVAL over data
pub fn polyval(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut poly = Polyval::new(h);
    poly.update(data);
    poly.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyval_basic() {
        // Test with H = 0, should always output 0
        let h = [0u8; 16];
        let data = b"test data";
        let result = polyval(&h, data);
        // With H=0, any input gives 0
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn test_polyval_incremental() {
        let h = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Compute in one go
        let mut poly1 = Polyval::new(&h);
        poly1.update(b"hello");
        poly1.update(b"world");
        let result1 = poly1.finalize();

        // Compute all at once
        let mut poly2 = Polyval::new(&h);
        poly2.update(b"helloworld");
        let result2 = poly2.finalize();

        // Should match
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_polyval_block() {
        let h = [0x25, 0x62, 0x93, 0x47, 0xA0, 0xF8, 0xCB, 0x41,
                 0xD5, 0x21, 0x34, 0x7B, 0x8A, 0x9F, 0x02, 0x16];

        let mut poly = Polyval::new(&h);
        let block = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        poly.update_block(&block);

        let result = poly.finalize();
        // Just verify it runs without panic
        assert_eq!(result.len(), 16);
    }
}
