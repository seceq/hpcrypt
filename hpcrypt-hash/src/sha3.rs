//! SHA-3 (Keccak) - Secure Hash Algorithm 3
//!
//! Based on the Keccak sponge construction, standardized in FIPS 202.
//! Supports SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

#![allow(clippy::needless_range_loop)]

/// SHA3-224 output size in bytes
pub const SHA3_224_OUTPUT_SIZE: usize = 28;
/// SHA3-256 output size in bytes
pub const SHA3_256_OUTPUT_SIZE: usize = 32;
/// SHA3-384 output size in bytes
pub const SHA3_384_OUTPUT_SIZE: usize = 48;
/// SHA3-512 output size in bytes
pub const SHA3_512_OUTPUT_SIZE: usize = 64;

/// Keccak state size in 64-bit words
const STATE_SIZE: usize = 25;

/// Round constants for Keccak-f[1600]
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for Keccak-f[1600]
const ROTATION_OFFSETS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// SHA3-256 hasher
#[derive(Clone)]
pub struct Sha3_256 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 136], // rate = 1088 bits = 136 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256 {
    /// Create a new SHA3-256 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 136],
            buffer_len: 0,
            rate: 136, // 1600 - 2*256 = 1088 bits = 136 bytes
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer if partial
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks
        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the digest
    pub fn finalize(mut self) -> [u8; SHA3_256_OUTPUT_SIZE] {
        // SHA-3 padding: append 0x06, pad with zeros, final byte is 0x80
        self.buffer[self.buffer_len] = 0x06;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;

        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);

        // Squeeze
        let mut output = [0u8; SHA3_256_OUTPUT_SIZE];
        for i in 0..4 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }

        output
    }

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        // XOR block into state
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }

        // Apply Keccak-f permutation
        keccak_f(&mut self.state);
    }

    /// Compute SHA3-256 of data in one call
    pub fn digest(data: &[u8]) -> [u8; SHA3_256_OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHA3-512 hasher
#[derive(Clone)]
pub struct Sha3_512 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 72], // rate = 576 bits = 72 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512 {
    /// Create a new SHA3-512 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 72],
            buffer_len: 0,
            rate: 72, // 1600 - 2*512 = 576 bits = 72 bytes
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }

        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the digest
    pub fn finalize(mut self) -> [u8; SHA3_512_OUTPUT_SIZE] {
        self.buffer[self.buffer_len] = 0x06;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;

        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);

        let mut output = [0u8; SHA3_512_OUTPUT_SIZE];
        for i in 0..8 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }

        output
    }

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }

        keccak_f(&mut self.state);
    }

    /// Compute SHA3-512 of data in one call
    pub fn digest(data: &[u8]) -> [u8; SHA3_512_OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHA3-224 hasher
#[derive(Clone)]
pub struct Sha3_224 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 144], // rate = 1152 bits = 144 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_224 {
    /// Create a new SHA3-224 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 144],
            buffer_len: 0,
            rate: 144, // 1600 - 2*224 = 1152 bits = 144 bytes
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }
        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the digest
    pub fn finalize(mut self) -> [u8; SHA3_224_OUTPUT_SIZE] {
        self.buffer[self.buffer_len] = 0x06;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;
        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);
        let mut output = [0u8; SHA3_224_OUTPUT_SIZE];
        for i in 0..3 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        output[24..28].copy_from_slice(&self.state[3].to_le_bytes()[..4]);
        output
    }

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }

    /// Compute SHA3-224 of data in one call
    pub fn digest(data: &[u8]) -> [u8; SHA3_224_OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHA3-384 hasher
#[derive(Clone)]
pub struct Sha3_384 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 104], // rate = 832 bits = 104 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Sha3_384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_384 {
    /// Create a new SHA3-384 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 104],
            buffer_len: 0,
            rate: 104, // 1600 - 2*384 = 832 bits = 104 bytes
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }
        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the digest
    pub fn finalize(mut self) -> [u8; SHA3_384_OUTPUT_SIZE] {
        self.buffer[self.buffer_len] = 0x06;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;
        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);
        let mut output = [0u8; SHA3_384_OUTPUT_SIZE];
        for i in 0..6 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        output
    }

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }

    /// Compute SHA3-384 of data in one call
    pub fn digest(data: &[u8]) -> [u8; SHA3_384_OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// SHAKE128 - Extendable Output Function
#[derive(Clone)]
pub struct Shake128 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 168], // rate = 1344 bits = 168 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake128 {
    /// Create a new SHAKE128 XOF
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 168],
            buffer_len: 0,
            rate: 168, // 1600 - 2*128 = 1344 bits = 168 bytes
        }
    }

    /// Update with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }
        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and squeeze output of arbitrary length
    pub fn finalize(mut self, output: &mut [u8]) {
        // SHAKE padding: 0x1F
        self.buffer[self.buffer_len] = 0x1F;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;
        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);

        // Squeeze
        let mut offset = 0;
        while offset < output.len() {
            let to_copy = core::cmp::min(self.rate, output.len() - offset);
            for i in 0..to_copy {
                let word_idx = i / 8;
                let byte_idx = i % 8;
                output[offset + i] = self.state[word_idx].to_le_bytes()[byte_idx];
            }
            offset += to_copy;
            if offset < output.len() {
                keccak_f(&mut self.state);
            }
        }
    }

    /// Absorb a block
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

/// SHAKE256 - Extendable Output Function
#[derive(Clone)]
pub struct Shake256 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 136], // rate = 1088 bits = 136 bytes
    buffer_len: usize,
    rate: usize,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    /// Create a new SHAKE256 XOF
    pub fn new() -> Self {
        Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 136],
            buffer_len: 0,
            rate: 136, // 1600 - 2*256 = 1088 bits = 136 bytes
        }
    }

    /// Update with input data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.rate - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
            if self.buffer_len == self.rate {
                let rate = self.rate;
                let buffer = self.buffer;
                self.absorb_block(&buffer[..rate]);
                self.buffer_len = 0;
            }
        }
        while offset + self.rate <= data.len() {
            self.absorb_block(&data[offset..offset + self.rate]);
            offset += self.rate;
        }
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and squeeze output of arbitrary length
    pub fn finalize(mut self, output: &mut [u8]) {
        // SHAKE padding: 0x1F
        self.buffer[self.buffer_len] = 0x1F;
        for i in self.buffer_len + 1..self.rate {
            self.buffer[i] = 0;
        }
        self.buffer[self.rate - 1] |= 0x80;
        let rate = self.rate;
        let buffer = self.buffer;
        self.absorb_block(&buffer[..rate]);

        // Squeeze
        let mut offset = 0;
        while offset < output.len() {
            let to_copy = core::cmp::min(self.rate, output.len() - offset);
            for i in 0..to_copy {
                let word_idx = i / 8;
                let byte_idx = i % 8;
                output[offset + i] = self.state[word_idx].to_le_bytes()[byte_idx];
            }
            offset += to_copy;
            if offset < output.len() {
                keccak_f(&mut self.state);
            }
        }
    }

    /// Absorb a block
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

/// Keccak-f[1600] permutation
fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // Rho and Pi steps combined
        let mut b = [0u64; 25];
        b[0] = state[0];

        let mut x = 1;
        let mut y = 0;
        for i in 0..24 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(ROTATION_OFFSETS[i]);
            let temp = y;
            y = (2 * x + 3 * y) % 5;
            x = temp;
        }

        // Chi step
        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = b[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // Iota step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = Sha3_256::digest(b"");
        let expected =
            hex_literal::hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_256_abc() {
        let hash = Sha3_256::digest(b"abc");
        let expected =
            hex_literal::hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_256_long() {
        let hash = Sha3_256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected =
            hex_literal::hex!("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_512_empty() {
        let hash = Sha3_512::digest(b"");
        let expected = hex_literal::hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_512_abc() {
        let hash = Sha3_512::digest(b"abc");
        let expected = hex_literal::hex!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_256_incremental() {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        let hash = hasher.finalize();

        let expected =
            hex_literal::hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_224_empty() {
        let hash = Sha3_224::digest(b"");
        let expected = hex_literal::hex!("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha3_384_empty() {
        let hash = Sha3_384::digest(b"");
        let expected = hex_literal::hex!(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
             c3713831264adb47fb6bd1e058d5f004"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_shake128() {
        let mut hasher = Shake128::new();
        hasher.update(b"abc");
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);

        let expected = hex_literal::hex!(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );
        assert_eq!(output, expected);
    }

    #[test]
    fn test_shake256() {
        let mut hasher = Shake256::new();
        hasher.update(b"abc");
        let mut output = [0u8; 64];
        hasher.finalize(&mut output);

        let expected = hex_literal::hex!(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
             d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
        assert_eq!(output, expected);
    }
}
