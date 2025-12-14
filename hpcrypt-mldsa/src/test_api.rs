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
//!
//! # FIPS 204 Interface Types
//!
//! - **External Interface**: Uses context encoding: M = 0x00 || len(ctx) || ctx || M'
//! - **Internal Interface**: Uses raw message directly (for internal interface tests)

#![cfg(feature = "cavp")]

extern crate alloc;
use alloc::vec::Vec;

use crate::keygen;
use crate::params::DsaParams;
use crate::prehash::{HashAlgorithm, encode_hash_ml_dsa_message};
use crate::serialize;
use crate::sign;
use crate::verify;

/// Maximum context string length as per FIPS 204
pub const MAX_CONTEXT_LENGTH: usize = 255;

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
    /// Context string exceeds maximum length (255 bytes)
    ContextTooLong,
}

/// Encode message with context string as per FIPS 204 external interface
///
/// Format: 0x00 || len(ctx) || ctx || message
fn encode_message_with_context(message: &[u8], context: &[u8]) -> Result<Vec<u8>, CavpError> {
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(CavpError::ContextTooLong);
    }

    // Allocate: 1 byte (0x00) + 1 byte (len) + context + message
    let mut encoded = Vec::with_capacity(2 + context.len() + message.len());

    // FIPS 204 encoding: 0x00 || len(ctx) || ctx || M
    encoded.push(0x00);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(message);

    Ok(encoded)
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

        // Sign using FIPS-compliant function (no early rejection optimization)
        // This ensures deterministic behavior required by CAVP test vectors
        let signature = sign::sign_deterministic_fips::<Self>(&secret_key, message, &zero_rnd)
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

        // Sign using FIPS-compliant function (no early rejection optimization)
        // This ensures deterministic behavior required by CAVP test vectors
        let signature = sign::sign_deterministic_fips::<Self>(&secret_key, message, &rnd_array)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Verify a signature (internal interface - no context encoding)
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

    // ========================================================================
    // EXTERNAL INTERFACE (with context encoding per FIPS 204)
    // Message encoding: M = 0x00 || len(ctx) || ctx || M'
    // ========================================================================

    /// Sign a message with context (FIPS 204 external interface, deterministic mode)
    ///
    /// Encodes message as: 0x00 || len(ctx) || ctx || message
    /// Uses zero randomness for pure deterministic mode.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign (M')
    /// * `context` - Context string (max 255 bytes)
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    fn sign_with_context(sk: &[u8], message: &[u8], context: &[u8]) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        // Encode message with context per FIPS 204: 0x00 || len(ctx) || ctx || M'
        let encoded_message = encode_message_with_context(message, context)?;

        // Deserialize secret key
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Use zero randomness for pure deterministic mode
        let zero_rnd = [0u8; 32];

        // Sign using FIPS-compliant function
        let signature = sign::sign_deterministic_fips::<Self>(&secret_key, &encoded_message, &zero_rnd)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Sign a message with context and explicit randomness (FIPS 204 external interface)
    ///
    /// Encodes message as: 0x00 || len(ctx) || ctx || message
    /// Uses provided randomness for hedged/randomized mode.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign (M')
    /// * `context` - Context string (max 255 bytes)
    /// * `rnd` - 32-byte random value
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    fn sign_with_context_and_randomness(
        sk: &[u8],
        message: &[u8],
        context: &[u8],
        rnd: &[u8],
    ) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        if rnd.len() != 32 {
            return Err(CavpError::InvalidRandomnessLength);
        }

        // Encode message with context per FIPS 204: 0x00 || len(ctx) || ctx || M'
        let encoded_message = encode_message_with_context(message, context)?;

        // Deserialize secret key
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Convert randomness to array
        let mut rnd_array = [0u8; 32];
        rnd_array.copy_from_slice(rnd);

        // Sign using FIPS-compliant function
        let signature = sign::sign_deterministic_fips::<Self>(&secret_key, &encoded_message, &rnd_array)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Verify a signature with context (FIPS 204 external interface)
    ///
    /// Encodes message as: 0x00 || len(ctx) || ctx || message
    ///
    /// # Arguments
    ///
    /// * `pk` - Public (verification) key bytes
    /// * `message` - Original message (M')
    /// * `context` - Context string (must match signing context)
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    fn verify_with_context(pk: &[u8], message: &[u8], context: &[u8], signature: &[u8]) -> bool
    where
        Self: Sized,
    {
        // Encode message with context per FIPS 204: 0x00 || len(ctx) || ctx || M'
        let encoded_message = match encode_message_with_context(message, context) {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Deserialize public key and signature
        let public_key = match serialize::deserialize_public_key::<Self>(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match serialize::deserialize_signature::<Self>(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verify::verify::<Self>(&public_key, &encoded_message, &sig)
    }

    // ========================================================================
    // INTERNAL INTERFACE WITH PRE-COMPUTED μ
    // For ACVP internal interface tests where μ is provided directly
    // ========================================================================

    /// Sign with pre-computed μ (internal interface with pre-computed hash)
    ///
    /// This function accepts the 64-byte message hash μ directly, bypassing the
    /// μ = H(tr || M) computation. Used for ACVP internal interface tests.
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `mu` - Pre-computed 64-byte message hash
    /// * `rnd` - Optional 32-byte randomness (zeros for deterministic)
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    fn sign_with_mu(sk: &[u8], mu: &[u8], rnd: Option<&[u8]>) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        if mu.len() != 64 {
            return Err(CavpError::SigningFailed);
        }

        // Deserialize secret key
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Convert mu to array
        let mut mu_array = [0u8; 64];
        mu_array.copy_from_slice(mu);

        // Use provided rnd or zeros for deterministic mode
        let rnd_array = match rnd {
            Some(r) if r.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(r);
                arr
            }
            Some(_) => return Err(CavpError::InvalidRandomnessLength),
            None => [0u8; 32],
        };

        // Sign using FIPS-compliant function with pre-computed μ
        let signature = sign::sign_with_mu_fips::<Self>(&secret_key, &mu_array, &rnd_array)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Verify a signature with pre-computed μ (internal interface)
    ///
    /// This function accepts the 64-byte message hash μ directly, bypassing the
    /// μ = H(tr || M) computation. Used for ACVP internal interface tests.
    ///
    /// # Arguments
    ///
    /// * `pk` - Public (verification) key bytes
    /// * `mu` - Pre-computed 64-byte message hash
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    fn verify_with_mu(pk: &[u8], mu: &[u8], signature: &[u8]) -> bool
    where
        Self: Sized,
    {
        if mu.len() != 64 {
            return false;
        }

        // Deserialize public key and signature
        let public_key = match serialize::deserialize_public_key::<Self>(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match serialize::deserialize_signature::<Self>(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Convert mu to array
        let mut mu_array = [0u8; 64];
        mu_array.copy_from_slice(mu);

        // Use internal verification with pre-computed μ
        verify::verify_with_mu::<Self>(&public_key, &mu_array, &sig)
    }

    // ========================================================================
    // HASHML-DSA (PRE-HASH MODE) - FIPS 204 Section 5.4
    // Message encoding: M' = 0x01 || len(ctx) || ctx || OID || PH(M)
    // ========================================================================

    /// Sign a message using HashML-DSA (pre-hash mode)
    ///
    /// This implements Algorithm 4 from FIPS 204 Section 5.4.
    /// The message is first hashed with the specified hash algorithm,
    /// then the signature is computed over:
    /// M' = 0x01 || len(ctx) || ctx || OID || PH(M)
    ///
    /// # Arguments
    ///
    /// * `sk` - Secret (signing) key bytes
    /// * `message` - Message to sign (will be pre-hashed)
    /// * `context` - Context string (max 255 bytes)
    /// * `hash_alg_name` - ACVP hash algorithm name (e.g., "SHA2-256", "SHA3-512")
    /// * `rnd` - Optional 32-byte randomness (zeros for deterministic)
    ///
    /// # Returns
    ///
    /// The signature bytes on success
    fn sign_hash_ml_dsa(
        sk: &[u8],
        message: &[u8],
        context: &[u8],
        hash_alg_name: &str,
        rnd: Option<&[u8]>,
    ) -> Result<Signature, CavpError>
    where
        Self: Sized,
    {
        // Parse hash algorithm
        let hash_alg = HashAlgorithm::from_acvp_name(hash_alg_name)
            .ok_or(CavpError::SigningFailed)?;

        // Encode message: 0x01 || len(ctx) || ctx || OID || PH(M)
        let encoded_message = encode_hash_ml_dsa_message(message, context, hash_alg)
            .map_err(|_| CavpError::ContextTooLong)?;

        // Deserialize secret key
        let secret_key = serialize::deserialize_secret_key::<Self>(sk)
            .map_err(|_| CavpError::InvalidSecretKey)?;

        // Use provided rnd or zeros for deterministic mode
        let rnd_array = match rnd {
            Some(r) if r.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(r);
                arr
            }
            Some(_) => return Err(CavpError::InvalidRandomnessLength),
            None => [0u8; 32],
        };

        // Sign using FIPS-compliant function
        let signature = sign::sign_deterministic_fips::<Self>(&secret_key, &encoded_message, &rnd_array)
            .ok_or(CavpError::SigningFailed)?;

        Ok(serialize::serialize_signature(&signature))
    }

    /// Verify a HashML-DSA signature (pre-hash mode)
    ///
    /// This implements Algorithm 5 from FIPS 204 Section 5.4.
    /// The message is first hashed with the specified hash algorithm,
    /// then verification is performed over:
    /// M' = 0x01 || len(ctx) || ctx || OID || PH(M)
    ///
    /// # Arguments
    ///
    /// * `pk` - Public (verification) key bytes
    /// * `message` - Original message (will be pre-hashed)
    /// * `context` - Context string (must match signing context)
    /// * `hash_alg_name` - ACVP hash algorithm name (e.g., "SHA2-256", "SHA3-512")
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    fn verify_hash_ml_dsa(
        pk: &[u8],
        message: &[u8],
        context: &[u8],
        hash_alg_name: &str,
        signature: &[u8],
    ) -> bool
    where
        Self: Sized,
    {
        // Parse hash algorithm
        let hash_alg = match HashAlgorithm::from_acvp_name(hash_alg_name) {
            Some(alg) => alg,
            None => return false,
        };

        // Encode message: 0x01 || len(ctx) || ctx || OID || PH(M)
        let encoded_message = match encode_hash_ml_dsa_message(message, context, hash_alg) {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Deserialize public key and signature
        let public_key = match serialize::deserialize_public_key::<Self>(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match serialize::deserialize_signature::<Self>(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verify::verify::<Self>(&public_key, &encoded_message, &sig)
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
