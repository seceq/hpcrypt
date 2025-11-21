//! Deterministic Random Bit Generators (DRBGs)
//!
//! This module provides cryptographically secure deterministic random number
//! generators suitable for testing, reproducibility, and environments where
//! seeded randomness is required.
//!
//! # Security Warning
//!
//! DRBGs are deterministic - given the same seed, they produce the same output.
//! For production cryptographic keys, use the OS RNG (`generate_random_bytes`).
//! Only use DRBGs when you specifically need:
//! - Reproducible randomness for testing
//! - Seeded randomness for specific protocols
//! - Entropy expansion from a trusted seed
//!
//! # Available DRBGs
//!
//! - **ChaCha20-DRBG**: Fast, constant-time, based on ChaCha20 stream cipher
//! - **CTR_DRBG**: NIST SP 800-90A compliant, AES-256-CTR based (FIPS approved)
//! - **HMAC_DRBG**: NIST SP 800-90A compliant, HMAC-SHA256 based (FIPS approved)
//! - **HASH_DRBG**: NIST SP 800-90A compliant, SHA-256 based (FIPS approved)
//! - **RDRAND-DRBG**: Hardware-based, Intel RDRAND instruction (x86_64 only)
//! - **RDSEED-DRBG**: Hardware entropy, Intel RDSEED instruction (x86_64 only)

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "chacha20-drbg")]
pub mod chacha20_drbg;
#[cfg(feature = "ctr-drbg")]
pub mod ctr_drbg;
#[cfg(feature = "hmac-drbg")]
pub mod hmac_drbg;
#[cfg(feature = "hash-drbg")]
pub mod hash_drbg;
#[cfg(feature = "rdrand-drbg")]
pub mod rdrand_drbg;
#[cfg(feature = "rdseed-drbg")]
pub mod rdseed_drbg;

#[cfg(feature = "chacha20-drbg")]
pub use chacha20_drbg::ChaCha20Drbg;
#[cfg(feature = "ctr-drbg")]
pub use ctr_drbg::CtrDrbg;
#[cfg(feature = "hmac-drbg")]
pub use hmac_drbg::HmacDrbg;
#[cfg(feature = "hash-drbg")]
pub use hash_drbg::HashDrbg;
#[cfg(feature = "rdrand-drbg")]
pub use rdrand_drbg::RdrandDrbg;
#[cfg(feature = "rdseed-drbg")]
pub use rdseed_drbg::RdseedDrbg;

use crate::Result;

/// Common trait for all DRBG implementations
///
/// This trait provides a uniform interface for deterministic random bit generators.
/// All DRBGs can be created from entropy, generate random bytes, and be reseeded.
pub trait Drbg {
    /// Create a new DRBG instance seeded with OS entropy
    ///
    /// This uses the operating system's CSPRNG to seed the DRBG,
    /// providing cryptographically secure initial state.
    ///
    /// # Errors
    ///
    /// Returns error if OS RNG fails or seed length is invalid.
    fn new() -> Result<Self>
    where
        Self: Sized;

    /// Create a DRBG from a specific seed (deterministic)
    ///
    /// Given the same seed, the DRBG will always produce the same sequence.
    /// This is useful for:
    /// - Reproducible tests
    /// - Deterministic key derivation
    /// - Protocols requiring seeded randomness
    ///
    /// # Security
    ///
    /// The seed must have sufficient entropy (typically 32 bytes minimum).
    /// Never use a predictable or low-entropy seed for cryptographic purposes.
    ///
    /// # Errors
    ///
    /// Returns error if seed length is invalid.
    fn from_seed(seed: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Generate random bytes
    ///
    /// Fills the output buffer with cryptographically secure random bytes
    /// derived from the DRBG's current state.
    ///
    /// # Security
    ///
    /// The DRBG should be reseeded periodically or after generating a large
    /// amount of output (implementation-specific limits apply).
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Reseed is required
    /// - Request length exceeds maximum
    /// - Internal state is invalid
    fn generate(&mut self, output: &mut [u8]) -> Result<()>;

    /// Reseed the DRBG with fresh OS entropy
    ///
    /// Mixes new entropy from the operating system into the DRBG state.
    /// This should be called periodically to maintain forward secrecy.
    ///
    /// # Errors
    ///
    /// Returns error if OS RNG fails.
    fn reseed(&mut self) -> Result<()>;

    /// Reseed with specific entropy input
    ///
    /// Allows manual reseeding with custom entropy. Useful for:
    /// - Protocol-specific entropy injection
    /// - Hierarchical key derivation
    /// - Testing with known entropy
    ///
    /// # Security
    ///
    /// The entropy input should have sufficient randomness. Low-entropy
    /// inputs will compromise the DRBG's security.
    ///
    /// # Errors
    ///
    /// Returns error if entropy length is invalid.
    fn reseed_with(&mut self, entropy: &[u8]) -> Result<()>;

    /// Get the security strength in bits
    ///
    /// Returns the cryptographic security level of this DRBG.
    /// Common values: 128, 192, 256 bits.
    fn security_strength(&self) -> usize;

    /// Check if reseed is required
    ///
    /// Returns true if the DRBG has reached its reseed interval or
    /// generated the maximum number of bytes.
    fn needs_reseed(&self) -> bool;

    // ========================================================================
    // NIST SP 800-90A Compliant Methods
    // ========================================================================

    /// Instantiate DRBG with separate entropy, nonce, and personalization (NIST SP 800-90A)
    ///
    /// This is the NIST-compliant instantiation method that takes three separate inputs:
    /// - `entropy`: Primary entropy input (length depends on security strength)
    /// - `nonce`: Non-repeating value for uniqueness (typically 16 bytes)
    /// - `personalization`: Optional string for domain separation (can be empty)
    ///
    /// This method combines these inputs according to NIST SP 800-90A requirements
    /// to create a properly initialized DRBG instance.
    ///
    /// # Security
    ///
    /// - Entropy must have full security strength (e.g., 32 bytes for 256-bit security)
    /// - Nonce must be unique across instantiations with the same entropy
    /// - Personalization string provides domain separation
    ///
    /// # Default Implementation
    ///
    /// The default implementation concatenates inputs for compatibility with `from_seed()`.
    /// NIST-compliant implementations should override this with proper derivation.
    ///
    /// # Errors
    ///
    /// Returns error if entropy/nonce/personalization lengths are invalid.
    fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // Default: concatenate all inputs (simple compatibility shim)
        // NIST-compliant implementations should override with proper KDF
        #[cfg(feature = "std")]
        let mut seed = std::vec::Vec::new();
        #[cfg(not(feature = "std"))]
        let mut seed = alloc::vec::Vec::new();

        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);
        Self::from_seed(&seed)
    }

    /// Generate random bytes with additional input (NIST SP 800-90A)
    ///
    /// This NIST-compliant generate method accepts per-request additional input
    /// that gets mixed into the state before generation. This provides:
    /// - Application-specific randomization
    /// - Additional entropy injection
    /// - Protocol-specific domain separation
    ///
    /// # Parameters
    ///
    /// - `output`: Buffer to fill with random bytes
    /// - `additional`: Additional input to mix (can be empty for no additional input)
    ///
    /// # Default Implementation
    ///
    /// The default implementation ignores additional input for compatibility.
    /// NIST-compliant implementations should override this.
    ///
    /// # Errors
    ///
    /// Returns error if reseed required or request too large.
    fn generate_with_additional(
        &mut self,
        output: &mut [u8],
        _additional: &[u8],
    ) -> Result<()> {
        // Default: ignore additional input for compatibility
        // NIST-compliant implementations should mix it in
        self.generate(output)
    }

    /// Reseed with entropy and additional input (NIST SP 800-90A)
    ///
    /// This NIST-compliant reseed method accepts both fresh entropy and
    /// optional additional input for comprehensive state update.
    ///
    /// # Parameters
    ///
    /// - `entropy`: Fresh entropy input for reseeding
    /// - `additional`: Additional input to mix (can be empty)
    ///
    /// # Default Implementation
    ///
    /// The default implementation concatenates inputs for compatibility.
    /// NIST-compliant implementations should override with proper derivation.
    ///
    /// # Errors
    ///
    /// Returns error if entropy length is invalid.
    fn reseed_with_additional(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<()> {
        // Default: concatenate entropy and additional input
        // NIST-compliant implementations should use proper mixing
        if additional.is_empty() {
            self.reseed_with(entropy)
        } else {
            #[cfg(feature = "std")]
            let mut combined = std::vec::Vec::new();
            #[cfg(not(feature = "std"))]
            let mut combined = alloc::vec::Vec::new();

            combined.extend_from_slice(entropy);
            combined.extend_from_slice(additional);
            self.reseed_with(&combined)
        }
    }

    /// Check if this DRBG supports prediction resistance
    ///
    /// Prediction resistance means the DRBG automatically reseeds with
    /// fresh entropy before each generate request, providing forward secrecy.
    ///
    /// # Returns
    ///
    /// - `true`: DRBG supports and uses prediction resistance
    /// - `false`: DRBG does not automatically reseed (default)
    fn supports_prediction_resistance(&self) -> bool {
        false // Default: no prediction resistance
    }

    /// Generate with prediction resistance (NIST SP 800-90A)
    ///
    /// This method reseeds with fresh entropy before generating output,
    /// providing forward secrecy. Even if the DRBG state is later compromised,
    /// previously generated values cannot be recovered.
    ///
    /// # Parameters
    ///
    /// - `output`: Buffer to fill with random bytes
    /// - `entropy`: Fresh entropy for reseeding (must be at least security_strength bits)
    /// - `additional`: Optional additional input to mix
    ///
    /// # NIST SP 800-90A Compliance
    ///
    /// Per NIST SP 800-90A Section 9.3.1, prediction resistance requests:
    /// 1. Reseed with fresh entropy and additional input
    /// 2. Generate the requested output
    ///
    /// # Errors
    ///
    /// Returns error if entropy length is invalid or generation fails.
    #[cfg(feature = "std")]
    fn generate_with_prediction_resistance(
        &mut self,
        output: &mut [u8],
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<()> {
        // Step 1: Reseed with fresh entropy and additional input
        self.reseed_with_additional(entropy, additional)?;

        // Step 2: Generate output (with additional input per NIST)
        self.generate_with_additional(output, additional)
    }
}
