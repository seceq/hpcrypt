//! SHA-1 hash function implementation
//!
//! **WARNING**: SHA-1 is cryptographically broken and should not be used for
//! security-critical applications. It is provided here for compatibility with
//! legacy protocols (like SRP-6a which uses SHA-1 per RFC 5054).
//!
//! Consider using SHA-256, SHA-384, or SHA-512 for new applications.

use core::convert::TryInto;

const K: [u32; 4] = [
    0x5A827999, // 0  <= t <= 19
    0x6ED9EBA1, // 20 <= t <= 39
    0x8F1BBCDC, // 40 <= t <= 59
    0xCA62C1D6, // 60 <= t <= 79
];

/// SHA-1 hasher
pub struct Sha1 {
    h: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    /// Create a new SHA-1 hasher
    pub fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        while !remaining.is_empty() {
            let to_copy = core::cmp::min(64 - self.buffer_len, remaining.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&remaining[..to_copy]);
            self.buffer_len += to_copy;
            remaining = &remaining[to_copy..];

            if self.buffer_len == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
                self.total_len += 512; // 64 bytes * 8 bits
            }
        }
    }

    /// Finalize the hash and return the digest
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len + (self.buffer_len as u64 * 8);

        // Append padding
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough space for length, pad to end and process
        if self.buffer_len > 56 {
            while self.buffer_len < 64 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        // Pad with zeros until we reach byte 56
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // Append length as 64-bit big-endian
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buffer.clone();
        self.process_block(&final_block);

        // Convert hash to bytes
        let mut output = [0u8; 20];
        for (i, &h) in self.h.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        output
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];

        // Prepare message schedule
        for t in 0..16 {
            w[t] = u32::from_be_bytes(block[t * 4..(t + 1) * 4].try_into().unwrap());
        }

        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Main loop
        for t in 0..80 {
            let f = match t {
                0..=19 => (b & c) | ((!b) & d),
                20..=39 => b ^ c ^ d,
                40..=59 => (b & c) | (b & d) | (c & d),
                60..=79 => b ^ c ^ d,
                _ => unreachable!(),
            };

            let k = match t {
                0..=19 => K[0],
                20..=39 => K[1],
                40..=59 => K[2],
                60..=79 => K[3],
                _ => unreachable!(),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Add to hash
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to compute SHA-1 hash
///
/// **WARNING**: SHA-1 is broken! Only use for legacy compatibility.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        let hash = sha1(b"");
        let expected = hex_literal::hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        let expected = hex_literal::hex!("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_long() {
        let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = hex_literal::hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_incremental() {
        let mut hasher = Sha1::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let hash = hasher.finalize();

        let hash_direct = sha1(b"abcdef");
        assert_eq!(hash, hash_direct);
    }
}
