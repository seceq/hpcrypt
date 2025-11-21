//! Test API for CAVP/ACVP validation testing
//!
//! This module provides a deterministic interface for NIST CAVP/ACVP test vectors.
//! It is designed specifically for validation testing and should NOT be used in production.
//!
//! # CAVP Test Requirements
//!
//! NIST test vectors require:
//! - Deterministic key generation from specific seed formats (sk.seed || sk.prf || pk.seed)
//! - Deterministic signature generation (pure deterministic mode)
//! - Randomized signature generation with explicit randomness
//! - Signature verification with specific test cases (valid and invalid signatures)
//! - Exact reproducibility of all operations
//!
//! # Differences from Production API
//!
//! CAVP tests provide the full 3*N-byte seed structure (sk.seed || sk.prf || pk.seed)
//! directly, whereas the production API may generate these components internally.

#![cfg(feature = "cavp")]

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::params::ParameterSet;
use crate::slhdsa::{KeyPair, verify};

/// Error type for CAVP test operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CavpError {
    /// Invalid seed length (expected 3*N bytes where N is parameter-set specific)
    InvalidSeedLength,
    /// Invalid randomness length (expected N bytes for randomized signing)
    InvalidRandomnessLength,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid signature
    InvalidSignature,
    /// Signing operation failed
    SigningFailed,
    /// Key generation failed
    KeyGenFailed,
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
/// Implementations are provided for all SLH-DSA parameter sets.
pub trait SignatureScheme: ParameterSet {
    /// Generate a key pair deterministically from seed material
    ///
    /// The seed should be formatted as: sk.seed || sk.prf || pk.seed (3*N bytes total)
    /// where N is the security parameter for this parameter set.
    ///
    /// # Arguments
    ///
    /// * `seed` - Combined seed (3*N bytes: sk.seed || sk.prf || pk.seed)
    ///
    /// # Returns
    ///
    /// A tuple of (public_key, secret_key) on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidSeedLength` if seed is not exactly 3*N bytes
    fn generate_deterministic(seed: &[u8]) -> Result<(PublicKey, SecretKey), CavpError>
    where
        Self: Sized,
    {
        let expected_len = 3 * Self::N;
        if seed.len() != expected_len {
            return Err(CavpError::InvalidSeedLength);
        }

        // Split seed into components
        let sk_seed = &seed[0..Self::N];
        let sk_prf = &seed[Self::N..2 * Self::N];
        let pk_seed = &seed[2 * Self::N..3 * Self::N];

        // Generate keypair using internal deterministic function
        let keypair = KeyPair::<Self>::from_seed_components(sk_seed, sk_prf, pk_seed)
            .map_err(|_| CavpError::KeyGenFailed)?;

        Ok((keypair.public_key.to_bytes(), keypair.secret_key.to_bytes()))
    }

    /// Sign a message deterministically (pure deterministic mode)
    ///
    /// This uses pure deterministic signing where the signature depends
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
        // Parse secret key
        let secret_key = crate::slhdsa::SecretKey::<Self>::from_bytes(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Sign deterministically using None for opt_rand (pure deterministic mode)
        let signature = crate::slhdsa::sign_with_opt_rand(&secret_key, message, None)
            .map_err(|_| CavpError::SigningFailed)?;

        Ok(signature)
    }

    /// Sign a message with explicit randomness (randomized mode)
    ///
    /// This uses randomized signing mode where additional randomness is mixed
    /// into the signature generation process via the optRand parameter.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign
    /// * `opt_rand` - N-byte random value (where N is parameter-set specific)
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    ///
    /// # Errors
    ///
    /// Returns `InvalidRandomnessLength` if opt_rand is not N bytes
    /// Returns `SigningFailed` if signing fails
    fn sign_with_randomness(sk: &[u8], message: &[u8], opt_rand: &[u8]) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        if opt_rand.len() != Self::N {
            return Err(CavpError::InvalidRandomnessLength);
        }

        // Parse secret key
        let secret_key = crate::slhdsa::SecretKey::<Self>::from_bytes(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Sign with explicit randomness
        let signature = crate::slhdsa::sign_with_opt_rand(&secret_key, message, Some(opt_rand))
            .map_err(|_| CavpError::SigningFailed)?;

        Ok(signature)
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
        // Parse public key
        let public_key = match crate::slhdsa::PublicKey::<Self>::from_bytes(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Verify signature
        verify(&public_key, message, signature)
    }
}

// Implement SignatureScheme for all SLH-DSA parameter sets
impl SignatureScheme for crate::params::Sha2_128s {}
impl SignatureScheme for crate::params::Sha2_128f {}
impl SignatureScheme for crate::params::Sha2_192s {}
impl SignatureScheme for crate::params::Sha2_192f {}
impl SignatureScheme for crate::params::Sha2_256s {}
impl SignatureScheme for crate::params::Sha2_256f {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Sha2_128s, Sha2_128f, Sha2_192s};

    #[test]
    fn test_deterministic_keygen_sha2_128s() {
        let seed = vec![0x42u8; 3 * Sha2_128s::N];
        let result = Sha2_128s::generate_deterministic(&seed);
        assert!(result.is_ok());

        let (pk, sk) = result.unwrap();
        assert_eq!(pk.len(), Sha2_128s::PK_BYTES);
        assert_eq!(sk.len(), Sha2_128s::SK_BYTES);

        // Verify determinism
        let (pk2, sk2) = Sha2_128s::generate_deterministic(&seed).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sk, sk2);
    }

    #[test]
    fn test_deterministic_keygen_sha2_128f() {
        let seed = vec![0x42u8; 3 * Sha2_128f::N];
        let (pk, sk) = Sha2_128f::generate_deterministic(&seed).unwrap();
        assert_eq!(pk.len(), Sha2_128f::PK_BYTES);
        assert_eq!(sk.len(), Sha2_128f::SK_BYTES);
    }

    #[test]
    fn test_sign_verify_deterministic() {
        let seed = vec![0x42u8; 3 * Sha2_128s::N];
        let (pk, sk) = Sha2_128s::generate_deterministic(&seed).unwrap();

        let message = b"Test message for signing";
        let sig = Sha2_128s::sign_deterministic(&sk, message).unwrap();

        // Verify determinism
        let sig2 = Sha2_128s::sign_deterministic(&sk, message).unwrap();
        assert_eq!(sig, sig2);

        // Verify signature
        assert!(Sha2_128s::verify(&pk, message, &sig));
    }

    #[test]
    fn test_sign_with_randomness() {
        let seed = vec![0x42u8; 3 * Sha2_128s::N];
        let (pk, sk) = Sha2_128s::generate_deterministic(&seed).unwrap();

        let message = b"Test message for randomized signing";
        let opt_rand = vec![0x99u8; Sha2_128s::N];
        let sig = Sha2_128s::sign_with_randomness(&sk, message, &opt_rand).unwrap();

        // Verify signature is valid
        assert!(Sha2_128s::verify(&pk, message, &sig));

        // Verify determinism with same randomness
        let sig2 = Sha2_128s::sign_with_randomness(&sk, message, &opt_rand).unwrap();
        assert_eq!(sig, sig2);

        // Verify different randomness produces different signature
        let opt_rand2 = vec![0xAAu8; Sha2_128s::N];
        let sig3 = Sha2_128s::sign_with_randomness(&sk, message, &opt_rand2).unwrap();
        assert_ne!(sig, sig3);
        assert!(Sha2_128s::verify(&pk, message, &sig3));
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = vec![0u8; Sha2_128s::N];
        let result = Sha2_128s::generate_deterministic(&short_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));

        let long_seed = vec![0u8; 4 * Sha2_128s::N];
        let result = Sha2_128s::generate_deterministic(&long_seed);
        assert_eq!(result, Err(CavpError::InvalidSeedLength));
    }

    #[test]
    fn test_invalid_randomness_length() {
        let seed = vec![0x42u8; 3 * Sha2_128s::N];
        let (_, sk) = Sha2_128s::generate_deterministic(&seed).unwrap();

        let message = b"Test message";
        let short_rand = vec![0u8; Sha2_128s::N / 2];
        let result = Sha2_128s::sign_with_randomness(&sk, message, &short_rand);
        assert_eq!(result, Err(CavpError::InvalidRandomnessLength));
    }

    #[test]
    fn test_multiple_parameter_sets() {
        let message = b"Test message for multiple parameter sets";

        // SHA2-128s
        let seed_128s = vec![0x42u8; 3 * Sha2_128s::N];
        let (pk_128s, sk_128s) = Sha2_128s::generate_deterministic(&seed_128s).unwrap();
        let sig_128s = Sha2_128s::sign_deterministic(&sk_128s, message).unwrap();
        assert!(Sha2_128s::verify(&pk_128s, message, &sig_128s));

        // SHA2-128f
        let seed_128f = vec![0x42u8; 3 * Sha2_128f::N];
        let (pk_128f, sk_128f) = Sha2_128f::generate_deterministic(&seed_128f).unwrap();
        let sig_128f = Sha2_128f::sign_deterministic(&sk_128f, message).unwrap();
        assert!(Sha2_128f::verify(&pk_128f, message, &sig_128f));

        // SHA2-192s
        let seed_192s = vec![0x42u8; 3 * Sha2_192s::N];
        let (pk_192s, sk_192s) = Sha2_192s::generate_deterministic(&seed_192s).unwrap();
        let sig_192s = Sha2_192s::sign_deterministic(&sk_192s, message).unwrap();
        assert!(Sha2_192s::verify(&pk_192s, message, &sig_192s));
    }
}
