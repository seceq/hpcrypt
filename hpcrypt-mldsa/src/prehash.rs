//! Hash ML-DSA - Pre-hashing mode for large messages
//!
//! This module implements HashML-DSA as specified in FIPS 204 Section 5.4.
//! Pre-hashing is useful for:
//! - Signing very large messages that don't fit in memory
//! - Incremental/streaming message processing
//! - Applications that already hash data before signing
//!
//! # Security Requirements (FIPS 204 Section 5.4)
//!
//! The hash function must be an approved hash function or XOF providing at least
//! λ bits of classical security strength against both collision and second preimage
//! attacks:
//! - ML-DSA-44: SHA-256 or stronger (128-bit security)
//! - ML-DSA-65: SHA-384 or stronger (192-bit security)
//! - ML-DSA-87: SHA-512 (256-bit security)
//!
//! # Example
//!
//! ```no_run
//! use mldsa::params::MlDsa65;
//! use mldsa::keygen::keygen;
//! use mldsa::prehash::{sign_prehashed_sha512, verify_prehashed_sha512};
//!
//! let (pk, sk) = keygen::<MlDsa65>();
//!
//! // For large messages, hash first then sign the hash
//! let large_message = vec![0u8; 1_000_000]; // 1 MB message
//! let sig = sign_prehashed_sha512(&sk, &large_message).unwrap();
//!
//! // Verify
//! let valid = verify_prehashed_sha512(&pk, &large_message, &sig);
//! assert!(valid);
//! ```

extern crate alloc;
use alloc::vec::Vec;

use hpcrypt_hash::{Sha3_256, Sha3_384, Sha3_512};

use crate::keygen::{PublicKey, SecretKey};
use crate::params::DsaParams;
use crate::sign::{sign, sign_deterministic, Signature};
use crate::verify::verify;

/// Context string for HashML-DSA as per FIPS 204
const HASH_ML_DSA_CONTEXT: &[u8] = b"HashML-DSA";

/// Sign a message using HashML-DSA with SHA3-256 pre-hashing
///
/// Suitable for ML-DSA-44 (128-bit security level).
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message of any length (will be hashed with SHA3-256)
///
/// # Returns
/// * Signature or None if signing fails
///
/// # Security Note
/// SHA3-256 provides 128-bit classical security against collision and
/// second preimage attacks, matching ML-DSA-44 security level.
pub fn sign_prehashed_sha256<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
) -> Option<Signature<P>> {
    // Compute SHA3-256 hash of message
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 32);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Sign the constructed message using standard ML-DSA
    sign(sk, &hash_ml_dsa_message)
}

/// Verify a HashML-DSA signature with SHA3-256 pre-hashing
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message (will be hashed with SHA3-256)
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_prehashed_sha256<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    signature: &Signature<P>,
) -> bool {
    // Compute SHA3-256 hash of message
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 32);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Verify using standard ML-DSA
    verify(pk, &hash_ml_dsa_message, signature)
}

/// Sign a message using HashML-DSA with SHA3-384 pre-hashing
///
/// Suitable for ML-DSA-65 (192-bit security level).
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message of any length (will be hashed with SHA3-384)
///
/// # Returns
/// * Signature or None if signing fails
///
/// # Security Note
/// SHA3-384 provides 192-bit classical security against collision and
/// second preimage attacks, matching ML-DSA-65 security level.
pub fn sign_prehashed_sha384<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
) -> Option<Signature<P>> {
    // Compute SHA3-384 hash of message
    let mut hasher = Sha3_384::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 48);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Sign the constructed message using standard ML-DSA
    sign(sk, &hash_ml_dsa_message)
}

/// Verify a HashML-DSA signature with SHA3-384 pre-hashing
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message (will be hashed with SHA3-384)
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_prehashed_sha384<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    signature: &Signature<P>,
) -> bool {
    // Compute SHA3-384 hash of message
    let mut hasher = Sha3_384::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 48);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Verify using standard ML-DSA
    verify(pk, &hash_ml_dsa_message, signature)
}

/// Sign a message using HashML-DSA with SHA3-512 pre-hashing
///
/// Suitable for ML-DSA-87 (256-bit security level).
/// This is the most common HashML-DSA variant and the only one with
/// standardized OIDs in current specifications.
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message of any length (will be hashed with SHA3-512)
///
/// # Returns
/// * Signature or None if signing fails
///
/// # Security Note
/// SHA3-512 provides 256-bit classical security against collision and
/// second preimage attacks, matching ML-DSA-87 security level.
pub fn sign_prehashed_sha512<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
) -> Option<Signature<P>> {
    // Compute SHA3-512 hash of message
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 64);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Sign the constructed message using standard ML-DSA
    sign(sk, &hash_ml_dsa_message)
}

/// Verify a HashML-DSA signature with SHA3-512 pre-hashing
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message (will be hashed with SHA3-512)
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_prehashed_sha512<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    signature: &Signature<P>,
) -> bool {
    // Compute SHA3-512 hash of message
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 64);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Verify using standard ML-DSA
    verify(pk, &hash_ml_dsa_message, signature)
}

/// Sign a message deterministically using HashML-DSA with SHA3-512 pre-hashing
///
/// This is the deterministic variant of HashML-DSA, useful for testing.
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message of any length (will be hashed with SHA3-512)
/// * `rnd` - 32-byte deterministic randomness seed
///
/// # Returns
/// * Signature or None if signing fails
pub fn sign_prehashed_sha512_deterministic<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    rnd: &[u8; 32],
) -> Option<Signature<P>> {
    // Compute SHA3-512 hash of message
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    // Construct HashML-DSA message: context || hash
    let mut hash_ml_dsa_message = Vec::with_capacity(HASH_ML_DSA_CONTEXT.len() + 64);
    hash_ml_dsa_message.extend_from_slice(HASH_ML_DSA_CONTEXT);
    hash_ml_dsa_message.extend_from_slice(&message_hash);

    // Sign deterministically
    sign_deterministic(sk, &hash_ml_dsa_message, rnd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::keygen::keygen;
    use crate::params::MlDsa65;

    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_prehashed_sha512_basic() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test message for HashML-DSA";
        let sig = sign_prehashed_sha512(&sk, message).expect("Signing failed");

        let valid = verify_prehashed_sha512(&pk, message, &sig);
        assert!(valid, "Valid HashML-DSA signature should verify");
    }

    #[test]
    fn test_prehashed_sha512_large_message() {
        let (pk, sk) = keygen::<MlDsa65>();

        // Test with a large message (1 MB)
        let large_message = vec![0x42u8; 1_000_000];
        let sig = sign_prehashed_sha512(&sk, &large_message).expect("Signing failed");

        let valid = verify_prehashed_sha512(&pk, &large_message, &sig);
        assert!(
            valid,
            "Valid HashML-DSA signature on large message should verify"
        );
    }

    #[test]
    fn test_prehashed_sha512_wrong_message() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message1 = b"Original message";
        let message2 = b"Different message";

        let sig = sign_prehashed_sha512(&sk, message1).expect("Signing failed");

        let valid = verify_prehashed_sha512(&pk, message2, &sig);
        assert!(!valid, "Signature on different message should not verify");
    }

    #[test]
    fn test_prehashed_sha384() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test SHA3-384 pre-hashing";
        let sig = sign_prehashed_sha384(&sk, message).expect("Signing failed");

        let valid = verify_prehashed_sha384(&pk, message, &sig);
        assert!(valid, "Valid SHA3-384 HashML-DSA signature should verify");
    }

    #[test]
    fn test_prehashed_sha256() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test SHA3-256 pre-hashing";
        let sig = sign_prehashed_sha256(&sk, message).expect("Signing failed");

        let valid = verify_prehashed_sha256(&pk, message, &sig);
        assert!(valid, "Valid SHA3-256 HashML-DSA signature should verify");
    }

    #[test]
    fn test_prehashed_deterministic() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Deterministic HashML-DSA test";
        let rnd = [99u8; 32];

        let sig1 = sign_prehashed_sha512_deterministic(&sk, message, &rnd).expect("Signing failed");
        let sig2 = sign_prehashed_sha512_deterministic(&sk, message, &rnd).expect("Signing failed");

        // Deterministic signing should produce identical signatures
        assert_eq!(
            sig1.c_tilde, sig2.c_tilde,
            "Deterministic signatures should be identical"
        );

        let valid = verify_prehashed_sha512(&pk, message, &sig1);
        assert!(valid, "Deterministic HashML-DSA signature should verify");
    }
}
