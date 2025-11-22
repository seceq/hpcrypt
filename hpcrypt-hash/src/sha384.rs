//! SHA-384 (Secure Hash Algorithm 384-bit)
//!
//! SHA-384 is a variant of SHA-512 with different initial values
//! and truncated output to 384 bits (48 bytes).
//!
//! Specified in FIPS 180-4.

/// SHA-384 block size in bytes (same as SHA-512: 1024 bits = 128 bytes)
pub const BLOCK_LEN: usize = 128;

/// SHA-384 output size in bytes (384 bits = 48 bytes)
pub const OUTPUT_LEN: usize = 48;

/// SHA-384 hasher state
#[derive(Clone)]
pub struct Sha384 {
    /// Internal state (8 x 64-bit words, same as SHA-512)
    state: [u64; 8],
    /// Message buffer
    buffer: [u8; BLOCK_LEN],
    /// Number of bytes in buffer
    buffer_len: usize,
    /// Total message length in bytes
    total_len: u64,
}

impl Sha384 {
    /// Create a new SHA-384 hasher
    pub fn new() -> Self {
        Self {
            // SHA-384 initial values (different from SHA-512)
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0u8; BLOCK_LEN],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;

        while !data.is_empty() {
            let available = BLOCK_LEN - self.buffer_len;
            let to_copy = data.len().min(available);

            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            self.total_len += to_copy as u64;
            data = &data[to_copy..];

            if self.buffer_len == BLOCK_LEN {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize and return the hash (384 bits = 48 bytes)
    pub fn finalize(mut self) -> [u8; 48] {
        // Padding: add 1 bit followed by zeros, then length
        let bit_len = self.total_len.wrapping_mul(8);

        // Append 0x80 byte (10000000 in binary)
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough room for length (16 bytes), pad and process block
        if self.buffer_len > BLOCK_LEN - 16 {
            self.buffer[self.buffer_len..BLOCK_LEN].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer.fill(0);
            self.buffer_len = 0;
        }

        // Pad with zeros up to length field
        self.buffer[self.buffer_len..BLOCK_LEN - 16].fill(0);

        // Append length in bits as 128-bit big-endian (upper 64 bits are 0)
        self.buffer[BLOCK_LEN - 16..BLOCK_LEN - 8].copy_from_slice(&0u64.to_be_bytes());
        self.buffer[BLOCK_LEN - 8..BLOCK_LEN].copy_from_slice(&bit_len.to_be_bytes());

        // Process final block
        let block = self.buffer;
        self.process_block(&block);

        // Output first 48 bytes (6 words) of state
        let mut output = [0u8; 48];
        for i in 0..6 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_be_bytes());
        }
        output
    }

    /// Process a single 1024-bit block
    #[inline(always)]
    fn process_block(&mut self, block: &[u8]) {
        // Same as SHA-512 compression function
        const K: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];

        // Circular buffer optimization: use only 16 entries instead of 80
        let mut w = [0u64; 16];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }

        // Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop with on-the-fly message schedule
        for i in 0..80 {
            // Compute next message schedule word on-the-fly (after first 16)
            if i >= 16 {
                let s0 = w[(i - 15) & 15].rotate_right(1)
                    ^ w[(i - 15) & 15].rotate_right(8)
                    ^ (w[(i - 15) & 15] >> 7);
                let s1 = w[(i - 2) & 15].rotate_right(19)
                    ^ w[(i - 2) & 15].rotate_right(61)
                    ^ (w[(i - 2) & 15] >> 6);
                w[i & 15] = w[(i - 16) & 15]
                    .wrapping_add(s0)
                    .wrapping_add(w[(i - 7) & 15])
                    .wrapping_add(s1);
            }

            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            // Optimized Ch function: g ^ (e & (f ^ g))
            let ch = g ^ (e & (f ^ g));
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i & 15]);

            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            // Optimized Maj function: (a & b) | (c & (a | b))
            let maj = (a & b) | (c & (a | b));
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-384 hash
pub fn sha384(data: &[u8]) -> [u8; OUTPUT_LEN] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let hasher = Sha384::new();
        let hash = hasher.finalize();

        // SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
        let expected = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_abc() {
        let mut hasher = Sha384::new();
        hasher.update(b"abc");
        let hash = hasher.finalize();

        // SHA-384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
            0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
            0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
            0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_long() {
        let mut hasher = Sha384::new();
        hasher.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let hash = hasher.finalize();

        // SHA-384("abcdefgh...") = 09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039
        let expected = [
            0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd,
            0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86,
            0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3,
            0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39,
        ];

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_incremental() {
        let mut hasher = Sha384::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let hash = hasher.finalize();

        let mut hasher2 = Sha384::new();
        hasher2.update(b"abcdef");
        let hash2 = hasher2.finalize();

        assert_eq!(hash, hash2);
    }
}
