//! Test API for CAVP/ACVP validation testing
//!
//! This module provides a deterministic interface for NIST CAVP/ACVP test vectors.
//! It is designed specifically for validation testing and should NOT be used in production.
//!
//! # CAVP Test Requirements
//!
//! NIST test vectors require:
//! - Deterministic key generation from specific seed formats (d || z, 64 bytes total)
//! - Deterministic encapsulation with explicit randomness (m, 32 bytes)
//! - Exact reproducibility of all operations
//!
//! # Differences from Production API
//!
//! The production API uses a single 32-byte seed for key generation, while CAVP tests
//! provide separate d (32 bytes) and z (32 bytes) values. This test API bridges that gap.

#![cfg(feature = "cavp")]

extern crate alloc;
use alloc::vec::Vec;

use crate::decaps;
use crate::encaps;
use crate::keygen::ml_kem_keygen_internal;
use crate::params::Params;

/// Error type for CAVP test operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CavpError {
    /// Invalid seed length (expected 64 bytes for keygen)
    InvalidSeedLength,
    /// Invalid randomness length (expected 32 bytes for encapsulation)
    InvalidRandomnessLength,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid ciphertext
    InvalidCiphertext,
}

/// Encapsulation key (public key)
pub type EncapsulationKey = Vec<u8>;

/// Decapsulation key (private key)
pub type DecapsulationKey = Vec<u8>;

/// Ciphertext
pub type Ciphertext = Vec<u8>;

/// Shared secret (always 32 bytes)
pub type SharedSecret = [u8; 32];

/// Core KEM operations for CAVP testing
///
/// This trait provides deterministic operations required by NIST test vectors.
/// Implementations are provided for all ML-KEM parameter sets.
pub trait KemCore: Params {
    /// Generate a key pair deterministically from a 64-byte seed
    ///
    /// # Arguments
    ///
    /// * `seed` - 64-byte seed (d || z format as per CAVP)
    ///
    /// # Returns
    ///
    /// A tuple of (encapsulation_key, decapsulation_key) on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidSeedLength` if seed is not exactly 64 bytes
    fn generate_deterministic(seed: &[u8]) -> Result<(EncapsulationKey, DecapsulationKey), CavpError>
    where
        Self: Sized,
    {
        if seed.len() != 64 {
            return Err(CavpError::InvalidSeedLength);
        }

        // Split seed into d and z (32 bytes each)
        let d = &seed[0..32];
        let z = &seed[32..64];

        // Call internal keygen with split seeds
        let keys = ml_kem_keygen_internal::<Self>(d, z);

        Ok((keys.ek, keys.dk))
    }

    /// Encapsulate deterministically with explicit randomness
    ///
    /// # Arguments
    ///
    /// * `ek` - Encapsulation (public) key bytes
    /// * `m` - 32-byte random value for deterministic encapsulation
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret) on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidRandomnessLength` if m is not exactly 32 bytes
    fn encapsulate_deterministic(ek: &[u8], m: &[u8]) -> Result<(Ciphertext, SharedSecret), CavpError>
    where
        Self: Sized,
    {
        if m.len() != 32 {
            return Err(CavpError::InvalidRandomnessLength);
        }

        // Convert m to array
        let mut m_array = [0u8; 32];
        m_array.copy_from_slice(m);

        // Call encapsulation with explicit randomness
        let result = encaps::ml_kem_encaps::<Self>(ek, Some(&m_array));

        Ok((result.ciphertext, result.shared_secret))
    }

    /// Decapsulate a ciphertext to recover the shared secret
    ///
    /// # Arguments
    ///
    /// * `dk` - Decapsulation (private) key bytes
    /// * `ct` - Ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret (always 32 bytes)
    ///
    /// # Notes
    ///
    /// This function always succeeds and returns a value due to implicit rejection.
    /// Invalid ciphertexts produce pseudorandom outputs (by design).
    fn decapsulate(dk: &[u8], ct: &[u8]) -> Result<SharedSecret, CavpError>
    where
        Self: Sized,
    {
        let shared_secret = decaps::ml_kem_decaps::<Self>(dk, ct);
        Ok(shared_secret)
    }
}

// Implement KemCore for all ML-KEM parameter sets
impl KemCore for crate::params::MlKem512 {}
impl KemCore for crate::params::MlKem768 {}
impl KemCore for crate::params::MlKem1024 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem1024, MlKem512, MlKem768};

    #[test]
    fn test_deterministic_keygen_mlkem512() {
        let seed = [0x42u8; 64];
        let result = MlKem512::generate_deterministic(&seed);
        assert!(result.is_ok());

        let (ek, dk) = result.unwrap();
        assert_eq!(ek.len(), MlKem512::EK_SIZE);
        assert_eq!(dk.len(), MlKem512::DK_SIZE);

        // Verify determinism
        let (ek2, dk2) = MlKem512::generate_deterministic(&seed).unwrap();
        assert_eq!(ek, ek2);
        assert_eq!(dk, dk2);
    }

    #[test]
    fn test_deterministic_keygen_mlkem768() {
        let seed = [0x42u8; 64];
        let (ek, dk) = MlKem768::generate_deterministic(&seed).unwrap();
        assert_eq!(ek.len(), MlKem768::EK_SIZE);
        assert_eq!(dk.len(), MlKem768::DK_SIZE);
    }

    #[test]
    fn test_deterministic_encapsulation() {
        let seed = [0x42u8; 64];
        let (ek, dk) = MlKem768::generate_deterministic(&seed).unwrap();

        let m = [0x99u8; 32];
        let (ct, ss1) = MlKem768::encapsulate_deterministic(&ek, &m).unwrap();

        // Verify determinism
        let (ct2, ss2) = MlKem768::encapsulate_deterministic(&ek, &m).unwrap();
        assert_eq!(ct, ct2);
        assert_eq!(ss1, ss2);

        // Verify decapsulation
        let ss3 = MlKem768::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss3);
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [0u8; 32];
        let result = MlKem768::generate_deterministic(&short_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));

        let long_seed = [0u8; 128];
        let result = MlKem768::generate_deterministic(&long_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));
    }

    #[test]
    fn test_invalid_randomness_length() {
        let seed = [0x42u8; 64];
        let (ek, _) = MlKem768::generate_deterministic(&seed).unwrap();

        let short_m = [0u8; 16];
        let result = MlKem768::encapsulate_deterministic(&ek, &short_m);
        assert_eq!(result, Err(CavpError::InvalidRandomnessLength));
    }

    #[test]
    fn test_all_parameter_sets() {
        let seed = [0x42u8; 64];
        let m = [0x99u8; 32];

        // ML-KEM-512
        let (ek512, dk512) = MlKem512::generate_deterministic(&seed).unwrap();
        let (ct512, ss512) = MlKem512::encapsulate_deterministic(&ek512, &m).unwrap();
        let ss512_dec = MlKem512::decapsulate(&dk512, &ct512).unwrap();
        assert_eq!(ss512, ss512_dec);

        // ML-KEM-768
        let (ek768, dk768) = MlKem768::generate_deterministic(&seed).unwrap();
        let (ct768, ss768) = MlKem768::encapsulate_deterministic(&ek768, &m).unwrap();
        let ss768_dec = MlKem768::decapsulate(&dk768, &ct768).unwrap();
        assert_eq!(ss768, ss768_dec);

        // ML-KEM-1024
        let (ek1024, dk1024) = MlKem1024::generate_deterministic(&seed).unwrap();
        let (ct1024, ss1024) = MlKem1024::encapsulate_deterministic(&ek1024, &m).unwrap();
        let ss1024_dec = MlKem1024::decapsulate(&dk1024, &ct1024).unwrap();
        assert_eq!(ss1024, ss1024_dec);
    }
}
