//! ChaCha20 stream cipher
//!
//! High-performance implementation of ChaCha20 as specified in RFC 8439.
//! Optimized for Rust without requiring hardware instructions.
//!
//! Target performance: 2.8-4 cycles/byte (based on Salsa20 benchmarks)

use hpcrypt_core::utils::{read_u32_le, write_u32_le};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ChaCha20 key size in bytes
pub const KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96-bit nonce for ChaCha20)
pub const NONCE_SIZE: usize = 12;

/// ChaCha20 block size in bytes
pub const BLOCK_SIZE: usize = 64;

/// ChaCha20 state (16 u32 words)
const STATE_WORDS: usize = 16;

/// ChaCha20 stream cipher
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20 {
    state: [u32; STATE_WORDS],
    keystream: [u8; BLOCK_SIZE],
    keystream_pos: usize,
}

impl ChaCha20 {
    /// Create a new ChaCha20 instance with key and nonce
    ///
    /// # Arguments
    /// * `key` - 256-bit key
    /// * `nonce` - 96-bit nonce
    /// * `counter` - Initial block counter (usually 0 or 1)
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], counter: u32) -> Self {
        let mut state = [0u32; STATE_WORDS];

        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] = read_u32_le(&key[i * 4..]);
        }

        // Counter (1 word)
        state[12] = counter;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = read_u32_le(&nonce[i * 4..]);
        }

        Self {
            state,
            keystream: [0u8; BLOCK_SIZE],
            keystream_pos: BLOCK_SIZE, // Force generation on first use
        }
    }

    /// Apply keystream to data (encryption/decryption are the same)
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.keystream_pos >= BLOCK_SIZE {
                self.generate_block();
                self.keystream_pos = 0;
            }
            *byte ^= self.keystream[self.keystream_pos];
            self.keystream_pos += 1;
        }
    }

    /// Encrypt data in place
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Seek to a specific block position
    pub fn seek(&mut self, block_counter: u32) {
        self.state[12] = block_counter;
        self.keystream_pos = BLOCK_SIZE; // Force regeneration
    }

    /// Generate one block of keystream
    fn generate_block(&mut self) {
        let mut working_state = self.state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut working_state, 0, 4, 8, 12);
            quarter_round(&mut working_state, 1, 5, 9, 13);
            quarter_round(&mut working_state, 2, 6, 10, 14);
            quarter_round(&mut working_state, 3, 7, 11, 15);

            // Diagonal rounds
            quarter_round(&mut working_state, 0, 5, 10, 15);
            quarter_round(&mut working_state, 1, 6, 11, 12);
            quarter_round(&mut working_state, 2, 7, 8, 13);
            quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        // Add initial state
        #[allow(clippy::needless_range_loop)]
        for i in 0..STATE_WORDS {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }

        // Serialize to bytes (little-endian)
        #[allow(clippy::needless_range_loop)]
        for i in 0..STATE_WORDS {
            write_u32_le(&mut self.keystream[i * 4..], working_state[i]);
        }

        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
    }
}

/// ChaCha20 quarter round
///
/// This is the core operation of ChaCha20. We use explicit inlining
/// and wrapping operations for maximum performance.
#[inline(always)]
fn quarter_round(state: &mut [u32; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
    // a += b; d ^= a; d <<<= 16;
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    // c += d; b ^= c; b <<<= 12;
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    // a += b; d ^= a; d <<<= 8;
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    // c += d; b ^= c; b <<<= 7;
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// XChaCha20 - ChaCha20 with extended nonce
///
/// Uses HChaCha20 to derive a subkey, allowing for 192-bit nonces
#[derive(Debug)]
pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    /// XChaCha20 nonce size (192 bits)
    pub const NONCE_SIZE: usize = 24;

    /// Create a new XChaCha20 instance
    ///
    /// # Arguments
    /// * `key` - 256-bit key
    /// * `nonce` - 192-bit nonce
    /// * `counter` - Initial block counter (usually 0 or 1)
    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; Self::NONCE_SIZE], counter: u32) -> Self {
        // Derive subkey using HChaCha20
        let subkey = hchacha20(key, &nonce[..16].try_into().unwrap());

        // Use last 8 bytes of nonce as ChaCha20 nonce
        let mut chacha_nonce = [0u8; NONCE_SIZE];
        chacha_nonce[4..12].copy_from_slice(&nonce[16..24]);

        Self {
            inner: ChaCha20::new(&subkey, &chacha_nonce, counter),
        }
    }

    /// Encrypt data in place
    #[inline]
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.inner.encrypt(data);
    }

    /// Decrypt data in place
    #[inline]
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.inner.decrypt(data);
    }
}

/// HChaCha20 - Hash function used for XChaCha20 key derivation
fn hchacha20(key: &[u8; KEY_SIZE], input: &[u8; 16]) -> [u8; KEY_SIZE] {
    let mut state = [0u32; STATE_WORDS];

    // Constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for i in 0..8 {
        state[4 + i] = read_u32_le(&key[i * 4..]);
    }

    // Input
    for i in 0..4 {
        state[12 + i] = read_u32_le(&input[i * 4..]);
    }

    // 20 rounds
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Return state[0..4] || state[12..16]
    let mut output = [0u8; KEY_SIZE];
    for i in 0..4 {
        write_u32_le(&mut output[i * 4..], state[i]);
    }
    for i in 0..4 {
        write_u32_le(&mut output[16 + i * 4..], state[12 + i]);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_rfc8439() {
        // Test vector from RFC 8439 Section 2.4.2
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1;

        let mut chacha = ChaCha20::new(&key, &nonce, counter);

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ciphertext = plaintext.to_vec();
        chacha.encrypt(&mut ciphertext);

        let expected = hex_literal::hex!(
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b357"
            "1639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e"
            "52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );

        assert_eq!(&ciphertext[..], &expected[..]);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = [42u8; KEY_SIZE];
        let nonce = [1u8; NONCE_SIZE];
        let plaintext = b"Hello, ChaCha20!";

        let mut ciphertext = plaintext.to_vec();
        let mut chacha = ChaCha20::new(&key, &nonce, 0);
        chacha.encrypt(&mut ciphertext);

        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mut decrypted = ciphertext.clone();
        let mut chacha = ChaCha20::new(&key, &nonce, 0);
        chacha.decrypt(&mut decrypted);

        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
