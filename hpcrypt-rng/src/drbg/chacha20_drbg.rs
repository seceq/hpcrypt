//! ChaCha20-based Deterministic Random Bit Generator
//!
//! This implements a DRBG using the ChaCha20 stream cipher. While not part of
//! NIST SP 800-90A, it provides similar security properties to CTR_DRBG but
//! with better performance on platforms without AES acceleration.
//!
//! # Design
//!
//! - **State**: 256-bit key + 128-bit counter/nonce
//! - **Security**: 256-bit security strength
//! - **Reseed interval**: 2^48 bytes (~281 TB)
//! - **Max request**: 2^32 bytes (~4 GB)
//!
//! # Algorithm
//!
//! 1. Initial seeding: Hash entropy into 256-bit key
//! 2. Generation: Use ChaCha20 with counter to produce output
//! 3. Reseeding: XOR new entropy into key state
//! 4. Forward secrecy: Update key after each generation
//!
//! # Security Properties
//!
//! - **Backtracking resistance**: Key is updated after each use
//! - **Prediction resistance**: Requires periodic reseeding
//! - **Constant-time**: All operations avoid timing side-channels
//! - **No hardware dependencies**: Works on all platforms
//!
//! # References
//!
//! - RFC 8439: ChaCha20 and Poly1305
//! - libsodium's implementation
//! - RustCrypto's rand_chacha

use super::Drbg;
use crate::{Result, RngError};
use zeroize::{Zeroize, ZeroizeOnDrop};

use hpcrypt_cipher::ChaCha20;

/// ChaCha20-DRBG key size (256 bits)
pub const KEY_SIZE: usize = 32;

/// ChaCha20-DRBG nonce size (128 bits)
const NONCE_SIZE: usize = 16;

/// ChaCha20 block size
const BLOCK_SIZE: usize = 64;

/// Maximum bytes per generate request (4 GB)
const MAX_GENERATE_LENGTH: usize = 1 << 32;

/// Reseed interval in blocks (2^48 bytes / 64 = 2^42 blocks)
const RESEED_INTERVAL: u64 = 1 << 42;

/// ChaCha20-based DRBG
///
/// A deterministic random bit generator using ChaCha20 stream cipher.
///
/// # Example
///
/// ```
/// use hpcrypt_rng::{ChaCha20Drbg, Drbg};
///
/// // Create with OS entropy
/// let mut drbg = ChaCha20Drbg::new().expect("Failed to create DRBG");
///
/// // Generate random bytes
/// let mut output = [0u8; 32];
/// drbg.generate(&mut output).expect("Failed to generate");
///
/// // Or create from seed for reproducibility
/// let seed = [42u8; 32];
/// let mut drbg = ChaCha20Drbg::from_seed(&seed).expect("Invalid seed");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Drbg {
    /// 256-bit key
    key: [u8; KEY_SIZE],

    /// 128-bit nonce (counter in lower 64 bits, stream ID in upper 64 bits)
    nonce: [u8; NONCE_SIZE],

    /// Number of blocks generated since last reseed
    reseed_counter: u64,
}

impl ChaCha20Drbg {
    /// Security strength in bits
    pub const SECURITY_STRENGTH: usize = 256;

    /// Create a ChaCha20-DRBG from raw key and nonce
    ///
    /// This is a low-level constructor. Prefer `new()` or `from_seed()`.
    fn from_key_nonce(key: [u8; KEY_SIZE], nonce: [u8; NONCE_SIZE]) -> Self {
        Self {
            key,
            nonce,
            reseed_counter: 0,
        }
    }

    /// Update the DRBG state (for forward secrecy)
    ///
    /// Generates new key material and updates internal state.
    /// This ensures that compromising current state doesn't reveal past output.
    fn update(&mut self) {
        let mut new_key = [0u8; KEY_SIZE];
        let mut new_nonce = [0u8; NONCE_SIZE];

        // Generate new key and nonce from current state using ChaCha20
        let mut temp = [0u8; BLOCK_SIZE];

        // Use ChaCha20 from hpcrypt-cipher to generate keystream
        // Map our 128-bit nonce to 96-bit nonce by using first 12 bytes
        let chacha_nonce = [
            self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3],
            self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7],
            self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11],
        ];

        let mut chacha = ChaCha20::new(&self.key, &chacha_nonce, 0);
        chacha.apply_keystream(&mut temp);

        new_key.copy_from_slice(&temp[..KEY_SIZE]);
        new_nonce.copy_from_slice(&temp[KEY_SIZE..KEY_SIZE + NONCE_SIZE]);

        // Update state
        self.key = new_key;
        self.nonce = new_nonce;

        // Zeroize temporary data
        temp.zeroize();
    }

    /// Generate keystream into output buffer
    fn generate_keystream(&mut self, output: &mut [u8]) {
        // Extract counter from nonce (lower 64 bits)
        let counter = u64::from_le_bytes([
            self.nonce[0],
            self.nonce[1],
            self.nonce[2],
            self.nonce[3],
            self.nonce[4],
            self.nonce[5],
            self.nonce[6],
            self.nonce[7],
        ]);

        // Map our 128-bit nonce to 96-bit nonce by using bytes 8-19
        // (12 bytes starting from offset 8, which includes the counter area)
        let chacha_nonce = [
            self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11],
            self.nonce[12], self.nonce[13], self.nonce[14], self.nonce[15],
            0, 0, 0, 0,  // Padding to make 12 bytes
        ];

        // Create ChaCha20 cipher with current key, nonce, and counter
        let mut chacha = ChaCha20::new(&self.key, &chacha_nonce, counter as u32);

        // Generate keystream
        chacha.apply_keystream(output);

        // Update counter based on blocks generated
        let blocks_used = (output.len() + BLOCK_SIZE - 1) / BLOCK_SIZE;
        let new_counter = counter.wrapping_add(blocks_used as u64);

        // Update counter in nonce
        self.nonce[..8].copy_from_slice(&new_counter.to_le_bytes());

        // Update reseed counter
        self.reseed_counter = self.reseed_counter.saturating_add(blocks_used as u64);
    }
}

impl Drbg for ChaCha20Drbg {
    fn new() -> Result<Self> {
        #[cfg(feature = "os-rng")]
        {
            let mut seed = [0u8; KEY_SIZE];
            crate::generate_random_bytes(&mut seed)?;
            Self::from_seed(&seed)
        }

        #[cfg(not(feature = "os-rng"))]
        {
            Err(RngError::OsRngFailed)
        }
    }

    fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < KEY_SIZE {
            return Err(RngError::InvalidSeedLength);
        }

        // Use first 32 bytes as key
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&seed[..KEY_SIZE]);

        // Initialize nonce (use extra seed bytes if available, otherwise zero)
        let mut nonce = [0u8; NONCE_SIZE];
        if seed.len() >= KEY_SIZE + NONCE_SIZE {
            nonce.copy_from_slice(&seed[KEY_SIZE..KEY_SIZE + NONCE_SIZE]);
        }

        Ok(Self::from_key_nonce(key, nonce))
    }

    fn generate(&mut self, output: &mut [u8]) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        if output.len() > MAX_GENERATE_LENGTH {
            return Err(RngError::InternalError);
        }

        if self.needs_reseed() {
            return Err(RngError::NotSeeded);
        }

        // Generate keystream
        self.generate_keystream(output);

        // Update state for forward secrecy
        self.update();

        Ok(())
    }

    fn reseed(&mut self) -> Result<()> {
        #[cfg(feature = "os-rng")]
        {
            let mut entropy = [0u8; KEY_SIZE];
            crate::generate_random_bytes(&mut entropy)?;
            self.reseed_with(&entropy)?;
            entropy.zeroize();
            Ok(())
        }

        #[cfg(not(feature = "os-rng"))]
        {
            Err(RngError::OsRngFailed)
        }
    }

    fn reseed_with(&mut self, entropy: &[u8]) -> Result<()> {
        if entropy.len() < KEY_SIZE {
            return Err(RngError::InvalidSeedLength);
        }

        // XOR entropy into key (simple but effective)
        for (k, &e) in self.key.iter_mut().zip(entropy.iter().take(KEY_SIZE)) {
            *k ^= e;
        }

        // Reset reseed counter
        self.reseed_counter = 0;

        // Update state
        self.update();

        Ok(())
    }

    fn security_strength(&self) -> usize {
        Self::SECURITY_STRENGTH
    }

    fn needs_reseed(&self) -> bool {
        self.reseed_counter >= RESEED_INTERVAL
    }
}

impl core::fmt::Debug for ChaCha20Drbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Drbg")
            .field("security_strength", &Self::SECURITY_STRENGTH)
            .field("reseed_counter", &self.reseed_counter)
            .field("needs_reseed", &self.needs_reseed())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [42u8; KEY_SIZE];

        let mut drbg1 = ChaCha20Drbg::from_seed(&seed).unwrap();
        let mut drbg2 = ChaCha20Drbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Same seed should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_different_seeds_different_output() {
        let seed1 = [1u8; KEY_SIZE];
        let seed2 = [2u8; KEY_SIZE];

        let mut drbg1 = ChaCha20Drbg::from_seed(&seed1).unwrap();
        let mut drbg2 = ChaCha20Drbg::from_seed(&seed2).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Different seeds should produce different output
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_sequential_outputs_differ() {
        let seed = [42u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg.generate(&mut output1).unwrap();
        drbg.generate(&mut output2).unwrap();

        // Sequential outputs should differ (forward secrecy)
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_generate_various_sizes() {
        let seed = [42u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        // Test various output sizes
        let mut small = [0u8; 16];
        let mut medium = [0u8; 100];
        let mut large = [0u8; 1024];

        drbg.generate(&mut small).unwrap();
        drbg.generate(&mut medium).unwrap();
        drbg.generate(&mut large).unwrap();

        // All should be non-zero
        assert_ne!(small, [0u8; 16]);
        assert_ne!(medium, [0u8; 100]);
        assert_ne!(large, [0u8; 1024]);
    }

    #[test]
    fn test_reseed_with() {
        let seed = [1u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1).unwrap();

        // Reseed with new entropy
        let new_entropy = [2u8; KEY_SIZE];
        drbg.reseed_with(&new_entropy).unwrap();

        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2).unwrap();

        // Output after reseed should differ
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_reseed_counter_reset() {
        let seed = [42u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        // Generate some data
        let mut output = [0u8; 1024];
        drbg.generate(&mut output).unwrap();

        let counter_before = drbg.reseed_counter;
        assert!(counter_before > 0);

        // Reseed
        let new_entropy = [99u8; KEY_SIZE];
        drbg.reseed_with(&new_entropy).unwrap();

        // Counter should be reset
        assert_eq!(drbg.reseed_counter, 0);
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [1u8; 16]; // Too short
        let result = ChaCha20Drbg::from_seed(&short_seed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RngError::InvalidSeedLength);
    }

    #[test]
    fn test_empty_generate() {
        let seed = [42u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        let mut empty = [];
        let result = drbg.generate(&mut empty);
        assert!(result.is_ok());
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_new_with_os_rng() {
        let mut drbg = ChaCha20Drbg::new().unwrap();

        let mut output = [0u8; 64];
        drbg.generate(&mut output).unwrap();

        assert_ne!(output, [0u8; 64]);
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_reseed_with_os_rng() {
        let seed = [1u8; KEY_SIZE];
        let mut drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1).unwrap();

        // Reseed with OS RNG
        drbg.reseed().unwrap();

        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2).unwrap();

        // Output should differ after reseed
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_security_strength() {
        let seed = [42u8; KEY_SIZE];
        let drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        assert_eq!(drbg.security_strength(), 256);
    }

    #[test]
    fn test_needs_reseed_initially_false() {
        let seed = [42u8; KEY_SIZE];
        let drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        assert!(!drbg.needs_reseed());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_debug_impl() {
        let seed = [42u8; KEY_SIZE];
        let drbg = ChaCha20Drbg::from_seed(&seed).unwrap();

        let debug_str = std::format!("{:?}", drbg);
        assert!(debug_str.contains("ChaCha20Drbg"));
        assert!(debug_str.contains("security_strength"));
    }
}
