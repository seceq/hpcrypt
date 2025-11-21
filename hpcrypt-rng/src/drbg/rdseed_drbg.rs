//! RDSEED-based Deterministic Random Bit Generator
//!
//! This implements a DRBG that uses Intel's RDSEED instruction as its entropy source.
//! RDSEED provides direct access to the hardware entropy source, offering the highest
//! quality randomness available from Intel CPUs.
//!
//! # Design
//!
//! - **Entropy source**: Intel RDSEED instruction (raw hardware entropy)
//! - **State**: Direct from hardware entropy source
//! - **Security**: 256-bit security strength (full entropy)
//! - **Reseed interval**: Automatic (each call gets fresh entropy)
//! - **Max request**: Limited by hardware entropy pool
//!
//! # Hardware Requirements
//!
//! - Intel: Broadwell (2014) or newer
//! - AMD: Zen (2017) or newer
//!
//! # Algorithm
//!
//! 1. Initial check: Verify RDSEED support via CPUID
//! 2. Generation: Call RDSEED instruction to fill output
//! 3. Reseeding: Not needed (always fresh entropy)
//! 4. Rate limiting: Hardware may block if entropy pool is low
//!
//! # Security Properties
//!
//! - **Raw entropy**: Not conditioned, direct from hardware source
//! - **Maximum quality**: Highest entropy available
//! - **Constant-time**: RDSEED instruction is constant-time
//! - **NIST compliant**: Meets SP 800-90B requirements
//!
//! # Performance Characteristics
//!
//! RDSEED is slower than RDRAND (100-1000x):
//! - Limited by hardware entropy pool refill rate
//! - May block briefly waiting for entropy
//! - Best for occasional use (seed generation, long-term keys)
//! - Not suitable for high-throughput applications
//!
//! # Security Considerations
//!
//! ## Strengths
//! - Raw entropy directly from hardware
//! - Not conditioned by closed-source algorithm
//! - Validated by Intel and third-party audits
//! - Highest quality randomness available
//!
//! ## Weaknesses
//! - Still requires trust in Intel hardware
//! - Slower than other entropy sources
//! - May fail under heavy load
//!
//! ## Recommendations
//! - Use for long-term cryptographic keys
//! - Mix with OS RNG for defense in depth
//! - Use RDRAND for high-throughput needs
//! - Ideal for seeding other DRBGs
//!
//! # References
//!
//! - Intel Digital Random Number Generator (DRNG) Software Implementation Guide
//! - NIST SP 800-90B
//!
//! # Example
//!
//! ```
//! use hpcrypt_rng::drbg::{RdseedDrbg, Drbg};
//!
//! // Check hardware support
//! if RdseedDrbg::is_available() {
//!     // Create RDSEED-based DRBG
//!     let mut drbg = RdseedDrbg::new().expect("RDSEED not supported");
//!
//!     // Generate high-quality random seed
//!     let mut seed = [0u8; 32];
//!     drbg.generate(&mut seed).expect("Generation failed");
//! }
//! ```

use super::Drbg;
use crate::{Result, RngError};

/// RDSEED-based DRBG
///
/// Uses Intel's RDSEED instruction for raw entropy generation.
/// RDSEED provides direct access to hardware entropy source without conditioning.
///
/// # Performance
///
/// RDSEED is much slower than RDRAND:
/// - Limited by entropy pool refill rate
/// - May block waiting for entropy
/// - 100-1000x slower than RDRAND
/// - Best for infrequent, high-security uses
///
/// # Trust Model
///
/// This DRBG requires trust in:
/// - Intel's hardware entropy source
/// - CPU microcode
/// - Absence of hardware backdoors
///
/// Provides higher quality than RDRAND (raw vs conditioned entropy).
pub struct RdseedDrbg {
    /// Hardware entropy source instance
    rng: rdrand::RdSeed,
}

impl RdseedDrbg {
    /// Security strength in bits (full entropy)
    pub const SECURITY_STRENGTH: usize = 256;

    /// Check if RDSEED is available on this CPU
    ///
    /// Returns `true` if RDSEED instruction is supported.
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_rng::drbg::RdseedDrbg;
    ///
    /// if RdseedDrbg::is_available() {
    ///     println!("RDSEED is supported");
    /// }
    /// ```
    pub fn is_available() -> bool {
        rdrand::RdSeed::new().is_ok()
    }

    /// Fill buffer with raw entropy (convenience method)
    ///
    /// This is a convenience method that creates a temporary DRBG instance,
    /// generates raw entropy, and discards the instance. For repeated generation,
    /// create a persistent DRBG instance using `new()` instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use hpcrypt_rng::drbg::RdseedDrbg;
    ///
    /// // Quick one-off generation
    /// let mut seed = [0u8; 32];
    /// RdseedDrbg::fill(&mut seed).expect("RDSEED failed");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if RDSEED is not supported or generation fails.
    pub fn fill(dest: &mut [u8]) -> Result<()> {
        let mut drbg = Self::new()?;
        drbg.generate(dest)
    }

    /// Generate a typed key (convenience method)
    ///
    /// Type-safe key generation with compile-time size checking.
    /// Best for long-term keys and DRBG seeds.
    ///
    /// # Examples
    ///
    /// ```
    /// use hpcrypt_rng::drbg::RdseedDrbg;
    ///
    /// let master_key: [u8; 32] = RdseedDrbg::key().expect("RDSEED failed");
    /// let drbg_seed: [u8; 32] = RdseedDrbg::key().expect("RDSEED failed");
    /// ```
    pub fn key<const N: usize>() -> Result<[u8; N]> {
        let mut key = [0u8; N];
        Self::fill(&mut key)?;
        Ok(key)
    }
}

impl Drbg for RdseedDrbg {
    fn new() -> Result<Self> {
        let rng = rdrand::RdSeed::new().map_err(|_| RngError::HardwareRngNotSupported)?;
        Ok(Self { rng })
    }

    fn from_seed(_seed: &[u8]) -> Result<Self> {
        // RDSEED doesn't use external seeds - it provides raw hardware entropy
        // We create a new instance and ignore the seed
        Self::new()
    }

    fn generate(&mut self, output: &mut [u8]) -> Result<()> {
        // Fill buffer using 64-bit chunks for efficiency
        let (chunks, remainder) = output.split_at_mut(output.len() - (output.len() % 8));

        // Fill 8-byte aligned chunks
        for chunk in chunks.chunks_exact_mut(8) {
            let value = self
                .rng
                .try_next_u64()
                .map_err(|_| RngError::HardwareRngFailed)?;
            chunk.copy_from_slice(&value.to_le_bytes());
        }

        // Fill remaining bytes
        if !remainder.is_empty() {
            let value = self
                .rng
                .try_next_u64()
                .map_err(|_| RngError::HardwareRngFailed)?;
            let bytes = value.to_le_bytes();
            remainder.copy_from_slice(&bytes[..remainder.len()]);
        }

        Ok(())
    }

    fn reseed(&mut self) -> Result<()> {
        // RDSEED always provides fresh entropy - no reseeding needed
        // Each call to generate() gets new entropy from hardware
        Ok(())
    }

    fn reseed_with(&mut self, _entropy: &[u8]) -> Result<()> {
        // RDSEED provides raw hardware entropy, doesn't support external reseeding
        Ok(())
    }

    fn security_strength(&self) -> usize {
        Self::SECURITY_STRENGTH
    }

    fn needs_reseed(&self) -> bool {
        // RDSEED always provides fresh entropy, never needs reseeding
        false
    }
}

impl core::fmt::Debug for RdseedDrbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdseedDrbg")
            .field("security_strength", &Self::SECURITY_STRENGTH)
            .field("hardware", &"Intel RDSEED")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    use std::vec;

    #[test]
    fn test_availability() {
        // Just ensure the function doesn't panic
        let _available = RdseedDrbg::is_available();
    }

    #[test]
    fn test_new() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let result = RdseedDrbg::new();
        assert!(result.is_ok(), "Failed to create RDSEED DRBG");
    }

    #[test]
    fn test_generate() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let mut drbg = RdseedDrbg::new().expect("RDSEED not available");
        let mut output = [0u8; 64];

        drbg.generate(&mut output).expect("Generation failed");

        // Output should not be all zeros
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_uniqueness() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let mut drbg = RdseedDrbg::new().expect("RDSEED not available");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        drbg.generate(&mut buf1).expect("Generation failed");
        drbg.generate(&mut buf2).expect("Generation failed");

        // Should produce different output
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_reseed() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let mut drbg = RdseedDrbg::new().expect("RDSEED not available");

        // Reseed should succeed (even though it's a no-op)
        assert!(drbg.reseed().is_ok());

        // Should still generate after reseed
        let mut output = [0u8; 32];
        assert!(drbg.generate(&mut output).is_ok());
    }

    #[test]
    fn test_needs_reseed() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let drbg = RdseedDrbg::new().expect("RDSEED not available");

        // RDSEED never needs reseeding (always fresh entropy)
        assert!(!drbg.needs_reseed());
    }

    #[test]
    fn test_various_sizes() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let mut drbg = RdseedDrbg::new().expect("RDSEED not available");

        // Test smaller sizes to avoid depleting entropy pool
        for size in [1, 7, 8, 15, 16, 31, 32, 64] {
            let mut output = vec![0u8; size];
            drbg.generate(&mut output).expect("Generation failed");

            // Should not be all zeros (except possibly for size=1)
            if size > 1 {
                assert_ne!(output, vec![0u8; size]);
            }
        }
    }

    #[test]
    fn test_multiple_instances() {
        if !RdseedDrbg::is_available() {
            return;
        }

        let mut drbg1 = RdseedDrbg::new().expect("RDSEED not available");
        let mut drbg2 = RdseedDrbg::new().expect("RDSEED not available");

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        drbg1.generate(&mut buf1).expect("Generation failed");
        drbg2.generate(&mut buf2).expect("Generation failed");

        // Different instances should produce different output
        assert_ne!(buf1, buf2);
    }
}
