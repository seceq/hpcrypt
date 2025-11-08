//! KMAC - Keccak Message Authentication Code
//!
//! Based on NIST SP 800-185: SHA-3 Derived Functions
//! KMAC provides variable-length message authentication using the Keccak/SHA-3 sponge construction.
//!
//! KMAC is built on top of cSHAKE (customizable SHAKE), which allows domain separation
//! through function name and customization strings.

#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Keccak state size in 64-bit words
const STATE_SIZE: usize = 25;

/// Round constants for Keccak-f[1600] (from sha3.rs)
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for Keccak-f[1600] (from sha3.rs)
const ROTATION_OFFSETS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Pi lane permutation indices (from sha3.rs)
const PI_LANE: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f[1600] permutation
fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..24 {
        // θ (theta) step
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

        // ρ (rho) and π (pi) steps
        let mut current = state[1];
        for i in 0..24 {
            let (x, y) = (PI_LANE[i] % 5, PI_LANE[i] / 5);
            let temp = state[x + 5 * y];
            state[x + 5 * y] = current.rotate_left(ROTATION_OFFSETS[i]);
            current = temp;
        }

        // χ (chi) step
        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι (iota) step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Encode a string as NIST SP 800-185 byte string (left_encode(len) || S)
#[cfg(feature = "alloc")]
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut result = left_encode(s.len() * 8); // length in bits
    result.extend_from_slice(s);
    result
}

/// Left encode - encode integer as bytes with length prefix on the left
#[cfg(feature = "alloc")]
fn left_encode(value: usize) -> Vec<u8> {
    if value == 0 {
        return vec![1, 0];
    }

    // Calculate number of bytes needed
    let mut n = value;
    let mut num_bytes = 0;
    while n > 0 {
        num_bytes += 1;
        n >>= 8;
    }

    let mut result = vec![num_bytes as u8];
    for i in (0..num_bytes).rev() {
        result.push(((value >> (i * 8)) & 0xFF) as u8);
    }

    result
}

/// Right encode - encode integer as bytes with length suffix on the right
#[cfg(feature = "alloc")]
fn right_encode(value: usize) -> Vec<u8> {
    if value == 0 {
        return vec![0, 1];
    }

    // Calculate number of bytes needed
    let mut n = value;
    let mut num_bytes = 0;
    while n > 0 {
        num_bytes += 1;
        n >>= 8;
    }

    let mut result = Vec::new();
    for i in (0..num_bytes).rev() {
        result.push(((value >> (i * 8)) & 0xFF) as u8);
    }
    result.push(num_bytes as u8);

    result
}

/// Encode bytes as NIST SP 800-185 byte string for cSHAKE
#[cfg(feature = "alloc")]
fn bytepad(input: &[u8], rate: usize) -> Vec<u8> {
    let mut result = left_encode(rate);
    result.extend_from_slice(input);

    // Pad to rate bytes
    while result.len() % rate != 0 {
        result.push(0);
    }

    result
}

/// cSHAKE128 - Customizable SHAKE128
///
/// This is the foundation for KMAC128. It allows customization through
/// function name (N) and customization string (S).
#[derive(Clone)]
pub struct CShake128 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 168], // rate = 1344 bits = 168 bytes
    buffer_len: usize,
    rate: usize,
    is_custom: bool,
}

impl CShake128 {
    /// Create a new cSHAKE128 instance
    ///
    /// # Arguments
    /// * `function_name` - Function name (N) for domain separation
    /// * `customization` - Customization string (S)
    #[cfg(feature = "alloc")]
    pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
        let mut hasher = Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 168],
            buffer_len: 0,
            rate: 168, // 1600 - 2*128 = 1344 bits = 168 bytes
            is_custom: !function_name.is_empty() || !customization.is_empty(),
        };

        // If customized, absorb the prefix
        if hasher.is_custom {
            let mut prefix = encode_string(function_name);
            prefix.extend_from_slice(&encode_string(customization));
            let padded = bytepad(&prefix, hasher.rate);
            hasher.update(&padded);
        }

        hasher
    }

    /// Update with input data
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

    /// Finalize and squeeze output of arbitrary length
    pub fn finalize(mut self, output: &mut [u8]) {
        // cSHAKE padding (or SHAKE if not customized)
        let pad_byte = if self.is_custom { 0x04 } else { 0x1F };

        self.buffer[self.buffer_len] = pad_byte;
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

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

/// cSHAKE256 - Customizable SHAKE256
///
/// This is the foundation for KMAC256. It allows customization through
/// function name (N) and customization string (S).
#[derive(Clone)]
pub struct CShake256 {
    state: [u64; STATE_SIZE],
    buffer: [u8; 136], // rate = 1088 bits = 136 bytes
    buffer_len: usize,
    rate: usize,
    is_custom: bool,
}

impl CShake256 {
    /// Create a new cSHAKE256 instance
    ///
    /// # Arguments
    /// * `function_name` - Function name (N) for domain separation
    /// * `customization` - Customization string (S)
    #[cfg(feature = "alloc")]
    pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
        let mut hasher = Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; 136],
            buffer_len: 0,
            rate: 136, // 1600 - 2*256 = 1088 bits = 136 bytes
            is_custom: !function_name.is_empty() || !customization.is_empty(),
        };

        // If customized, absorb the prefix
        if hasher.is_custom {
            let mut prefix = encode_string(function_name);
            prefix.extend_from_slice(&encode_string(customization));
            let padded = bytepad(&prefix, hasher.rate);
            hasher.update(&padded);
        }

        hasher
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
        // cSHAKE padding (or SHAKE if not customized)
        let pad_byte = if self.is_custom { 0x04 } else { 0x1F };

        self.buffer[self.buffer_len] = pad_byte;
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

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

/// KMAC128 - Keccak Message Authentication Code with 128-bit security
///
/// KMAC is a PRF and keyed hash function based on Keccak. It provides
/// variable-length output and is suitable for message authentication,
/// key derivation, and randomness extraction.
///
/// # Example
/// ```
/// use hpcrypt_hash::Kmac128;
///
/// let key = b"my secret key";
/// let message = b"hello world";
/// let customization = b""; // optional
///
/// // Generate 32-byte MAC
/// let mac = Kmac128::mac(key, message, customization, 32);
/// ```
#[derive(Clone)]
pub struct Kmac128 {
    cshake: CShake128,
}

impl Kmac128 {
    /// Create a new KMAC128 instance
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `customization` - Optional customization string for domain separation
    #[cfg(feature = "alloc")]
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        let mut kmac = Self {
            cshake: CShake128::new(b"KMAC", customization),
        };

        // Absorb key: bytepad(encode_string(K), rate) || X || right_encode(L)
        let encoded_key = bytepad(&encode_string(key), 168);
        kmac.cshake.update(&encoded_key);

        kmac
    }

    /// Update with message data
    pub fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }

    /// Finalize and produce MAC of specified output length
    ///
    /// # Arguments
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        // Append right_encode(output_len in bits)
        let suffix = right_encode(output_len * 8);
        self.cshake.update(&suffix);

        // Squeeze output
        let mut output = vec![0u8; output_len];
        self.cshake.finalize(&mut output);
        output
    }

    /// Compute KMAC128 in one call
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `message` - The message to authenticate
    /// * `customization` - Optional customization string
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    pub fn mac(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
        let mut kmac = Self::new(key, customization);
        kmac.update(message);
        kmac.finalize(output_len)
    }
}

/// KMAC256 - Keccak Message Authentication Code with 256-bit security
///
/// KMAC is a PRF and keyed hash function based on Keccak. It provides
/// variable-length output and is suitable for message authentication,
/// key derivation, and randomness extraction.
///
/// # Example
/// ```
/// use hpcrypt_hash::Kmac256;
///
/// let key = b"my secret key";
/// let message = b"hello world";
/// let customization = b""; // optional
///
/// // Generate 64-byte MAC
/// let mac = Kmac256::mac(key, message, customization, 64);
/// ```
#[derive(Clone)]
pub struct Kmac256 {
    cshake: CShake256,
}

impl Kmac256 {
    /// Create a new KMAC256 instance
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `customization` - Optional customization string for domain separation
    #[cfg(feature = "alloc")]
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        let mut kmac = Self {
            cshake: CShake256::new(b"KMAC", customization),
        };

        // Absorb key: bytepad(encode_string(K), rate) || X || right_encode(L)
        let encoded_key = bytepad(&encode_string(key), 136);
        kmac.cshake.update(&encoded_key);

        kmac
    }

    /// Update with message data
    pub fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }

    /// Finalize and produce MAC of specified output length
    ///
    /// # Arguments
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        // Append right_encode(output_len in bits)
        let suffix = right_encode(output_len * 8);
        self.cshake.update(&suffix);

        // Squeeze output
        let mut output = vec![0u8; output_len];
        self.cshake.finalize(&mut output);
        output
    }

    /// Compute KMAC256 in one call
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `message` - The message to authenticate
    /// * `customization` - Optional customization string
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    pub fn mac(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
        let mut kmac = Self::new(key, customization);
        kmac.update(message);
        kmac.finalize(output_len)
    }
}

/// Convenience functions for one-shot KMAC computation
#[cfg(feature = "alloc")]
pub fn kmac128(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
    Kmac128::mac(key, message, customization, output_len)
}

#[cfg(feature = "alloc")]
pub fn kmac256(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
    Kmac256::mac(key, message, customization, output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_encode() {
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(left_encode(255), vec![1, 255]);
        assert_eq!(left_encode(256), vec![2, 1, 0]);
        assert_eq!(left_encode(65535), vec![2, 255, 255]);
    }

    #[test]
    fn test_right_encode() {
        assert_eq!(right_encode(0), vec![0, 1]);
        assert_eq!(right_encode(255), vec![255, 1]);
        assert_eq!(right_encode(256), vec![1, 0, 2]);
        assert_eq!(right_encode(65535), vec![255, 255, 2]);
    }

    #[test]
    fn test_kmac128_basic() {
        // Basic smoke test
        let key = b"my secret key";
        let message = b"hello world";
        let mac = kmac128(key, message, b"", 32);
        assert_eq!(mac.len(), 32);

        // Same input should produce same output
        let mac2 = kmac128(key, message, b"", 32);
        assert_eq!(mac, mac2);

        // Different key should produce different output
        let mac3 = kmac128(b"different key", message, b"", 32);
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_kmac256_basic() {
        // Basic smoke test
        let key = b"my secret key";
        let message = b"hello world";
        let mac = kmac256(key, message, b"", 64);
        assert_eq!(mac.len(), 64);

        // Same input should produce same output
        let mac2 = kmac256(key, message, b"", 64);
        assert_eq!(mac, mac2);

        // Different key should produce different output
        let mac3 = kmac256(b"different key", message, b"", 64);
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_kmac_variable_output_length() {
        let key = b"test";
        let message = b"data";

        // Test different output lengths
        for len in [16, 32, 64, 128] {
            let mac = kmac128(key, message, b"", len);
            assert_eq!(mac.len(), len);
        }
    }

    #[test]
    fn test_kmac_customization() {
        let key = b"key";
        let message = b"message";

        // Different customization strings should produce different MACs
        let mac1 = kmac128(key, message, b"", 32);
        let mac2 = kmac128(key, message, b"custom1", 32);
        let mac3 = kmac128(key, message, b"custom2", 32);

        assert_ne!(mac1, mac2);
        assert_ne!(mac1, mac3);
        assert_ne!(mac2, mac3);
    }

    // NIST SP 800-185 test vectors
    #[test]
    fn test_kmac128_nist_sample_1() {
        use hex_literal::hex;
        // Sample #1 from NIST SP 800-185
        let key = &hex!("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let data = &hex!("00010203");
        let customization = b"";

        let mac = kmac128(key, data, customization, 32);
        let expected = hex!("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");

        assert_eq!(&mac[..], &expected[..]);
    }

    #[test]
    fn test_kmac256_nist_sample_1() {
        use hex_literal::hex;
        // Sample #4 from NIST SP 800-185
        let key = &hex!("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        let data = &hex!("00010203");
        let customization = b"My Tagged Application";

        let mac = kmac256(key, data, customization, 64);
        let expected = hex!("20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");

        assert_eq!(&mac[..], &expected[..]);
    }
}
