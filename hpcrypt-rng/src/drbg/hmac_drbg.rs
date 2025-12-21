//! HMAC_DRBG (HMAC-based Deterministic Random Bit Generator)
//!
//! NIST SP 800-90A compliant DRBG using HMAC-SHA256.
//! This is one of the approved DRBGs for cryptographic applications.
//!
//! # Production Ready
//!
//! This implementation uses HMAC-SHA256 from `hpcrypt-hash`, providing:
//! - **NIST SP 800-90A Rev. 1 compliance**
//! - **FIPS 140-2/3 approved algorithm**
//! - **Simpler than CTR_DRBG** (no block cipher needed)
//! - **Widely deployed** (used in TLS, OpenSSL, etc.)
//!
//! # Design
//!
//! - **Algorithm**: HMAC-SHA256
//! - **Security**: 256-bit security strength
//! - **State**: Key (K) + Value (V), both 256 bits
//! - **Reseed interval**: 2^48 requests
//! - **Max request**: 2^19 bits (64 KB)
//!
//! # NIST SP 800-90A Compliance
//!
//! This implementation follows NIST SP 800-90A Rev. 1:
//! - Section 10.1.2: HMAC_DRBG algorithm
//! - FIPS 140-2/3 approved
//! - No derivation function required for full entropy input
//!
//! # Algorithm Overview
//!
//! 1. **Instantiate**: Initialize K and V from seed
//! 2. **Generate**: Use HMAC to generate output, update K and V
//! 3. **Update**: Mix additional data into K and V using HMAC
//! 4. **Reseed**: Update state with fresh entropy
//!
//! # References
//!
//! - NIST SP 800-90A Rev. 1 (2015) Section 10.1.2
//! - FIPS 140-2/3 approved DRBG
//! - Used in: OpenSSL, BoringSSL, TLS, etc.

extern crate alloc;

use super::Drbg;
use crate::{Result, RngError};
use zeroize::{Zeroize, ZeroizeOnDrop};

use hpcrypt_mac::{HmacSha256, Mac};

/// Output length of HMAC-SHA256 (256 bits)
const OUTLEN: usize = 32;

/// Maximum bytes per generate request (2^19 bits = 64 KB)
const MAX_GENERATE_LENGTH: usize = 1 << 16;

/// Reseed interval in requests (2^48)
const RESEED_INTERVAL: u64 = 1 << 48;

/// HMAC_DRBG using HMAC-SHA256
///
/// A NIST SP 800-90A compliant deterministic random bit generator.
///
/// # Example
///
/// ```
/// use hpcrypt_rng::{HmacDrbg, Drbg};
///
/// // Create with OS entropy
/// let mut drbg = HmacDrbg::new().expect("Failed to create DRBG");
///
/// // Generate random bytes
/// let mut output = [0u8; 32];
/// drbg.generate(&mut output).expect("Failed to generate");
///
/// // Or create from seed for reproducibility
/// let seed = [42u8; 32];
/// let mut drbg = HmacDrbg::from_seed(&seed).expect("Invalid seed");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacDrbg {
    /// HMAC key (K) - 256 bits
    k: [u8; OUTLEN],

    /// Internal state value (V) - 256 bits
    v: [u8; OUTLEN],

    /// Reseed counter (requests since last reseed)
    reseed_counter: u64,
}

impl HmacDrbg {
    /// Security strength in bits
    pub const SECURITY_STRENGTH: usize = 256;

    /// HMAC_DRBG_Update function (NIST SP 800-90A Section 10.1.2.2)
    ///
    /// Updates the internal state (K, V) using provided data.
    fn update(&mut self, provided_data: Option<&[u8]>) {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut data = alloc::vec::Vec::with_capacity(OUTLEN + 1 + provided_data.map(|d| d.len()).unwrap_or(0));
        data.extend_from_slice(&self.v);
        data.push(0x00);
        if let Some(pd) = provided_data {
            data.extend_from_slice(pd);
        }

        self.k = HmacSha256::compute(&self.k, &data);

        // V = HMAC(K, V)
        self.v = HmacSha256::compute(&self.k, &self.v);

        // If provided_data is present, do another update
        if provided_data.is_some() {
            // K = HMAC(K, V || 0x01 || provided_data)
            let mut data = alloc::vec::Vec::with_capacity(OUTLEN + 1 + provided_data.map(|d| d.len()).unwrap_or(0));
            data.extend_from_slice(&self.v);
            data.push(0x01);
            if let Some(pd) = provided_data {
                data.extend_from_slice(pd);
            }

            self.k = HmacSha256::compute(&self.k, &data);

            // V = HMAC(K, V)
            self.v = HmacSha256::compute(&self.k, &self.v);
        }

        // Zeroize temporary data
        data.zeroize();
    }

    /// HMAC_DRBG_Instantiate function (NIST SP 800-90A Section 10.1.2.3)
    fn instantiate(seed: &[u8]) -> Self {
        // 1. seed_material = seed
        // 2. Key = 0x00 00...00 (outlen bits)
        let k = [0u8; OUTLEN];

        // 3. V = 0x01 01...01 (outlen bits)
        let v = [0x01u8; OUTLEN];

        // Create initial DRBG state
        let mut drbg = Self {
            k,
            v,
            reseed_counter: 1,
        };

        // 4. (Key, V) = HMAC_DRBG_Update(seed_material, Key, V)
        drbg.update(Some(seed));

        // 5. reseed_counter = 1
        drbg.reseed_counter = 1;

        drbg
    }
}

impl Drbg for HmacDrbg {
    fn new() -> Result<Self> {
        #[cfg(feature = "os-rng")]
        {
            let mut seed = [0u8; OUTLEN];
            crate::generate_random_bytes(&mut seed)?;
            Ok(Self::instantiate(&seed))
        }

        #[cfg(not(feature = "os-rng"))]
        {
            Err(RngError::OsRngFailed)
        }
    }

    fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < OUTLEN {
            return Err(RngError::InvalidSeedLength);
        }

        Ok(Self::instantiate(seed))
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

        // HMAC_DRBG_Generate (NIST SP 800-90A Section 10.1.2.5)

        // Generate requested bits
        let mut offset = 0;
        let mut remaining = output.len();

        while remaining > 0 {
            // V = HMAC(K, V)
            self.v = HmacSha256::compute(&self.k, &self.v);

            let to_copy = core::cmp::min(remaining, OUTLEN);
            output[offset..offset + to_copy].copy_from_slice(&self.v[..to_copy]);

            offset += to_copy;
            remaining -= to_copy;
        }

        // Update state
        self.update(None);

        // Increment reseed counter
        self.reseed_counter = self.reseed_counter.saturating_add(1);

        Ok(())
    }

    fn reseed(&mut self) -> Result<()> {
        #[cfg(feature = "os-rng")]
        {
            let mut entropy = [0u8; OUTLEN];
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
        if entropy.len() < OUTLEN {
            return Err(RngError::InvalidSeedLength);
        }

        // HMAC_DRBG_Reseed (NIST SP 800-90A Section 10.1.2.4)
        // 1. seed_material = entropy_input
        // 2. (Key, V) = HMAC_DRBG_Update(seed_material, Key, V)
        self.update(Some(entropy));

        // 3. reseed_counter = 1
        self.reseed_counter = 1;

        Ok(())
    }

    fn security_strength(&self) -> usize {
        Self::SECURITY_STRENGTH
    }

    fn needs_reseed(&self) -> bool {
        self.reseed_counter >= RESEED_INTERVAL
    }
}

impl core::fmt::Debug for HmacDrbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HmacDrbg")
            .field("algorithm", &"HMAC-SHA256")
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
        let seed = [42u8; OUTLEN];

        let mut drbg1 = HmacDrbg::from_seed(&seed).unwrap();
        let mut drbg2 = HmacDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Same seed should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_different_seeds_different_output() {
        let seed1 = [1u8; OUTLEN];
        let seed2 = [2u8; OUTLEN];

        let mut drbg1 = HmacDrbg::from_seed(&seed1).unwrap();
        let mut drbg2 = HmacDrbg::from_seed(&seed2).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Different seeds should produce different output
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_sequential_outputs_differ() {
        let seed = [42u8; OUTLEN];
        let mut drbg = HmacDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg.generate(&mut output1).unwrap();
        drbg.generate(&mut output2).unwrap();

        // Sequential outputs should differ
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_generate_various_sizes() {
        let seed = [42u8; OUTLEN];
        let mut drbg = HmacDrbg::from_seed(&seed).unwrap();

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
        let seed = [1u8; OUTLEN];
        let mut drbg = HmacDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1).unwrap();

        // Reseed with new entropy
        let new_entropy = [2u8; OUTLEN];
        drbg.reseed_with(&new_entropy).unwrap();

        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2).unwrap();

        // Output after reseed should differ
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_reseed_counter_reset() {
        let seed = [42u8; OUTLEN];
        let mut drbg = HmacDrbg::from_seed(&seed).unwrap();

        // Generate some data
        let mut output = [0u8; 1024];
        drbg.generate(&mut output).unwrap();

        let counter_before = drbg.reseed_counter;
        assert!(counter_before > 1);

        // Reseed
        let new_entropy = [99u8; OUTLEN];
        drbg.reseed_with(&new_entropy).unwrap();

        // Counter should be reset to 1
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [1u8; 16]; // Too short
        let result = HmacDrbg::from_seed(&short_seed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RngError::InvalidSeedLength);
    }

    #[test]
    fn test_empty_generate() {
        let seed = [42u8; OUTLEN];
        let mut drbg = HmacDrbg::from_seed(&seed).unwrap();

        let mut empty = [];
        let result = drbg.generate(&mut empty);
        assert!(result.is_ok());
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_new_with_os_rng() {
        let mut drbg = HmacDrbg::new().unwrap();

        let mut output = [0u8; 64];
        drbg.generate(&mut output).unwrap();

        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_security_strength() {
        let seed = [42u8; OUTLEN];
        let drbg = HmacDrbg::from_seed(&seed).unwrap();

        assert_eq!(drbg.security_strength(), 256);
    }

    #[test]
    fn test_needs_reseed_initially_false() {
        let seed = [42u8; OUTLEN];
        let drbg = HmacDrbg::from_seed(&seed).unwrap();

        assert!(!drbg.needs_reseed());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_debug_impl() {
        let seed = [42u8; OUTLEN];
        let drbg = HmacDrbg::from_seed(&seed).unwrap();

        let debug_str = std::format!("{:?}", drbg);
        assert!(debug_str.contains("HmacDrbg"));
        assert!(debug_str.contains("HMAC-SHA256"));
    }
}
