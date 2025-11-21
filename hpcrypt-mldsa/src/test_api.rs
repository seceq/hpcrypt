//! Test API for CAVP/ACVP validation testing
//!
//! This module provides a deterministic interface for NIST CAVP/ACVP test vectors.
//! It is designed specifically for validation testing and should NOT be used in production.
//!
//! # CAVP Test Requirements
//!
//! NIST test vectors require:
//! - Deterministic key generation from a 32-byte seed
//! - Deterministic signature generation (both deterministic and hedged/randomized modes)
//! - Signature verification with specific test cases (valid and invalid signatures)
//! - Exact reproducibility of all operations
//!
//! # Differences from Production API
//!
//! This test API exposes low-level deterministic operations required by CAVP tests,
//! whereas the production API may use additional security features like hedged signatures.

#![cfg(feature = "cavp")]

extern crate alloc;
use alloc::vec::Vec;

use crate::params::DsaParams;
use crate::keygen;
use crate::sign;
use crate::verify;
use crate::serialize;

/// Error type for CAVP test operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CavpError {
    /// Invalid seed length (expected 32 bytes)
    InvalidSeedLength,
    /// Invalid randomness length (expected 32 bytes for randomized signing)
    InvalidRandomnessLength,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid signature
    InvalidSignature,
    /// Signing operation failed
    SigningFailed,
}

/// Public key (verification key)
pub type PublicKey = Vec<u8>;

/// Secret key (signing key)
pub type SecretKey = Vec<u8>;

/// Signature bytes
pub type Signature = Vec<u8>;

/// Core signature scheme operations for CAVP testing
///
/// This trait provides deterministic operations required by NIST test vectors.
/// Implementations are provided for all ML-DSA parameter sets.
pub trait SignatureScheme: DsaParams {
    /// Generate a key pair deterministically from a 32-byte seed
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for deterministic key generation
    ///
    /// # Returns
    ///
    /// A tuple of (public_key, secret_key) on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidSeedLength` if seed is not exactly 32 bytes
    fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), CavpError>
    where
        Self: Sized,
    {
        if seed.len() != 32 {
            return Err(CavpError::InvalidSeedLength);
        }

        // Convert to array
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        // Generate keypair using deterministic keygen
        let (pk, sk) = keygen::keygen_from_seed::<Self>(&seed_array);

        // Serialize keys to bytes
        let pk_bytes = serialize::serialize_public_key(&pk);
        let sk_bytes = serialize::serialize_secret_key(&sk);

        Ok((pk_bytes, sk_bytes))
    }

    /// Sign a message deterministically (pure deterministic mode)
    ///
    /// This uses the deterministic signing mode where the signature depends
    /// only on the secret key and message (no additional randomness).
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    ///
    /// # Errors
    ///
    /// Returns `SigningFailed` if signing fails
    fn sign_deterministic(sk: &[u8], message: &[u8]) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        // Deserialize secret key from bytes
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Use zero randomness for pure deterministic mode
        let zero_rnd = [0u8; 32];

        // Sign and serialize
        let signature = sign::sign_deterministic::<Self>(&secret_key, message, &zero_rnd)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Sign a message with explicit randomness (hedged/randomized mode)
    ///
    /// This uses randomized signing mode where additional randomness is mixed
    /// into the signature generation process.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign
    /// * `rnd` - 32-byte random value
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidRandomnessLength` if rnd is not 32 bytes
    /// Returns `SigningFailed` if signing fails
    fn sign_with_randomness(sk: &[u8], message: &[u8], rnd: &[u8]) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        if rnd.len() != 32 {
            return Err(CavpError::InvalidRandomnessLength);
        }

        // Deserialize secret key from bytes
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Convert randomness to array
        let mut rnd_array = [0u8; 32];
        rnd_array.copy_from_slice(rnd);

        // Sign and serialize
        let signature = sign::sign_deterministic::<Self>(&secret_key, message, &rnd_array)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Verify a signature
    ///
    /// # Arguments
    ///
    /// * `pk` - Public (verification) key bytes
    /// * `message` - Message that was signed
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool
    where
        Self: Sized,
    {
        // Deserialize public key and signature
        let public_key = match serialize::deserialize_public_key::<Self>(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match serialize::deserialize_signature::<Self>(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verify::verify::<Self>(&public_key, message, &sig)
    }
}

// Implement SignatureScheme for all ML-DSA parameter sets
impl SignatureScheme for crate::params::MlDsa44 {}
impl SignatureScheme for crate::params::MlDsa65 {}
impl SignatureScheme for crate::params::MlDsa87 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlDsa44, MlDsa65, MlDsa87};

    #[test]
    fn test_deterministic_keygen_mldsa44() {
        let seed = [0x42u8; 32];
        let result = MlDsa44::generate_deterministic(&seed);
        assert!(result.is_ok());

        let (pk, sk) = result.unwrap();
        assert_eq!(pk.len(), MlDsa44::PK_SIZE);
        assert_eq!(sk.len(), MlDsa44::SK_SIZE);

        // Verify determinism
        let (pk2, sk2) = MlDsa44::generate_deterministic(&seed).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_deterministic_keygen_mldsa65() {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::generate_deterministic(&seed).unwrap();
        assert_eq!(pk.len(), MlDsa65::PK_SIZE);
        assert_eq!(sk.len(), MlDsa65::SK_SIZE);
    }

    #[test]
    fn test_deterministic_keygen_mldsa87() {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa87::generate_deterministic(&seed).unwrap();
        assert_eq!(pk.len(), MlDsa87::PK_SIZE);
        assert_eq!(sk.len(), MlDsa87::SK_SIZE);
    }

    #[test]
    fn test_sign_verify_deterministic() {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::generate_deterministic(&seed).unwrap();

        let message = b"Test message for signing";
        let sig = MlDsa65::sign_deterministic(&sk, message).unwrap();

        // Verify determinism
        let sig2 = MlDsa65::sign_deterministic(&sk, message).unwrap();
        assert_eq!(sig, sig2);

        // Verify signature
        assert!(MlDsa65::verify(&pk, message, &sig));

        // Verify rejection of invalid signature
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 1;
        assert!(!MlDsa65::verify(&pk, message, &bad_sig));
    }

    #[test]
    fn test_sign_with_randomness() {
        let seed = [0x42u8; 32];
        let (pk, sk) = MlDsa65::generate_deterministic(&seed).unwrap();

        let message = b"Test message for randomized signing";
        let rnd = [0x99u8; 32];
        let sig = MlDsa65::sign_with_randomness(&sk, message, &rnd).unwrap();

        // Verify signature is valid
        assert!(MlDsa65::verify(&pk, message, &sig));

        // Verify determinism with same randomness
        let sig2 = MlDsa65::sign_with_randomness(&sk, message, &rnd).unwrap();
        assert_eq!(sig, sig2);

        // Verify different randomness produces different signature
        let rnd2 = [0xAAu8; 32];
        let sig3 = MlDsa65::sign_with_randomness(&sk, message, &rnd2).unwrap();
        assert_ne!(sig, sig3);
        assert!(MlDsa65::verify(&pk, message, &sig3));
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [0u8; 16];
        let result = MlDsa65::generate_deterministic(&short_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));

        let long_seed = [0u8; 64];
        let result = MlDsa65::generate_deterministic(&long_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));
    }

    #[test]
    fn test_invalid_randomness_length() {
        let seed = [0x42u8; 32];
        let (_, sk) = MlDsa65::generate_deterministic(&seed).unwrap();

        let message = b"Test message";
        let short_rnd = [0u8; 16];
        let result = MlDsa65::sign_with_randomness(&sk, message, &short_rnd);
        assert_eq!(result, Err(CavpError::InvalidRandomnessLength));
    }

    #[test]
    fn test_all_parameter_sets() {
        let seed = [0x42u8; 32];
        let message = b"Test message for all parameter sets";

        // ML-DSA-44
        let (pk44, sk44) = MlDsa44::generate_deterministic(&seed).unwrap();
        let sig44 = MlDsa44::sign_deterministic(&sk44, message).unwrap();
        assert!(MlDsa44::verify(&pk44, message, &sig44));

        // ML-DSA-65
        let (pk65, sk65) = MlDsa65::generate_deterministic(&seed).unwrap();
        let sig65 = MlDsa65::sign_deterministic(&sk65, message).unwrap();
        assert!(MlDsa65::verify(&pk65, message, &sig65));

        // ML-DSA-87
        let (pk87, sk87) = MlDsa87::generate_deterministic(&seed).unwrap();
        let sig87 = MlDsa87::sign_deterministic(&sk87, message).unwrap();
        assert!(MlDsa87::verify(&pk87, message, &sig87));
    }
}
