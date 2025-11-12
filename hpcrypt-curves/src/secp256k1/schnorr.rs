//! Schnorr Signatures (BIP 340)
//!
//! Implementation of Schnorr signatures for Bitcoin as specified in BIP 340.
//!
//! # Overview
//!
//! BIP 340 specifies a Schnorr signature scheme for the secp256k1 elliptic curve.
//! Key features:
//! - 64-byte signatures (32-byte R point x-coordinate + 32-byte s scalar)
//! - 32-byte X-only public keys (implicit even Y-coordinate)
//! - Deterministic nonce generation
//! - Provable security in the random oracle model
//! - Batch verification support
//! - Simpler than ECDSA
//!
//! # Security
//!
//! - Signatures are non-malleable
//! - Nonce is deterministically derived from secret key and message
//! - Uses tagged SHA-256 hashing to prevent cross-protocol attacks

extern crate alloc;
use alloc::vec::Vec;

use super::point::Point;
use super::scalar::Scalar;
use hpcrypt_hash::sha256::Sha256;

/// Schnorr signature (64 bytes: 32-byte R || 32-byte s)
pub type Signature = [u8; 64];

/// Schnorr public key (32 bytes: X-coordinate only)
pub type PublicKey = [u8; 32];

/// Schnorr private key (32 bytes)
pub type PrivateKey = [u8; 32];

/// BIP 340 domain separation tags
const TAG_AUX: &[u8] = b"BIP0340/aux";
const TAG_NONCE: &[u8] = b"BIP0340/nonce";
const TAG_CHALLENGE: &[u8] = b"BIP0340/challenge";

/// Generate a public key from a private key
///
/// # Arguments
/// * `secret_key` - 32-byte private key
///
/// # Returns
/// 32-byte X-only public key
pub fn public_key(secret_key: &PrivateKey) -> PublicKey {
    let p = Point::generator().scalar_mul(secret_key);

    // Return X-coordinate only (BIP 340 uses X-only public keys)
    let affine = p.to_affine().expect("Generator scalar multiplication cannot be infinity");
    affine.x.to_bytes()
}

/// Sign a message using BIP 340 Schnorr signatures
///
/// # Arguments
/// * `secret_key` - 32-byte private key
/// * `message` - Message to sign (any length)
/// * `aux_rand` - 32 bytes of auxiliary randomness (can be all zeros for deterministic)
///
/// # Returns
/// 64-byte Schnorr signature
pub fn sign(secret_key: &PrivateKey, message: &[u8], aux_rand: &[u8; 32]) -> Signature {
    // Parse secret key as scalar
    let d_scalar = Scalar::from_bytes(secret_key);

    // Compute public key point P = d⋅G
    let p = Point::generator().scalar_mul(secret_key);
    let p_affine = p.to_affine().expect("Generator scalar multiplication cannot be infinity");

    // If P.y is odd, negate d (BIP 340: implicit even Y)
    // Note: to_bytes() returns big-endian, so LSB is at the end
    let mut d = d_scalar;
    if p_affine.y.to_bytes()[31] & 1 == 1 {
        d = d.negate();
    }

    // Compute t = d ⊕ hash_BIP0340/aux(aux_rand)
    let aux_hash = tagged_hash(TAG_AUX, aux_rand);
    let mut t = d.to_bytes();
    for i in 0..32 {
        t[i] ^= aux_hash[i];
    }

    // Compute rand = hash_BIP0340/nonce(t || P.x || m)
    let px_bytes = p_affine.x.to_bytes();
    let mut nonce_input = Vec::with_capacity(32 + 32 + message.len());
    nonce_input.extend_from_slice(&t);
    nonce_input.extend_from_slice(&px_bytes);
    nonce_input.extend_from_slice(message);
    let rand = tagged_hash(TAG_NONCE, &nonce_input);

    // Compute k' = int(rand) mod n
    let k_scalar = Scalar::from_bytes(&rand);

    // Compute R = k'⋅G
    let r = Point::generator().scalar_mul(&rand);
    let r_affine = r.to_affine().expect("Generator scalar multiplication cannot be infinity");

    // If R.y is odd, negate k (BIP 340: implicit even Y)
    // Note: to_bytes() returns big-endian, so LSB is at the end
    let mut k = k_scalar;
    if r_affine.y.to_bytes()[31] & 1 == 1 {
        k = k.negate();
    }

    // Compute e = hash_BIP0340/challenge(R.x || P.x || m) mod n
    let rx_bytes = r_affine.x.to_bytes();
    let mut challenge_input = Vec::with_capacity(32 + 32 + message.len());
    challenge_input.extend_from_slice(&rx_bytes);
    challenge_input.extend_from_slice(&px_bytes);
    challenge_input.extend_from_slice(message);
    let e_bytes = tagged_hash(TAG_CHALLENGE, &challenge_input);
    let e = Scalar::from_bytes(&e_bytes);

    // Compute s = (k + e⋅d) mod n
    let ed = e.mul(&d);
    let s = k.add(&ed);

    // Signature is R.x || s
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx_bytes);
    sig[32..].copy_from_slice(&s.to_bytes());

    sig
}

/// Verify a Schnorr signature
///
/// # Arguments
/// * `public_key` - 32-byte X-only public key
/// * `message` - Message that was signed
/// * `signature` - 64-byte signature to verify
///
/// # Returns
/// `true` if signature is valid, `false` otherwise
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // Parse public key as X-coordinate and lift to point
    let px_bytes = &public_key[..];
    let p = match Point::lift_x(px_bytes) {
        Some(point) => point,
        None => return false,
    };

    // Parse signature as (r, s)
    let r_bytes = &signature[..32];
    let s_bytes = &signature[32..];

    // Parse s as scalar
    let s = Scalar::from_bytes(&<[u8; 32]>::try_from(s_bytes).unwrap());

    // Validate s is non-zero
    if bool::from(s.is_zero()) {
        return false;
    }

    // Compute e = hash_BIP0340/challenge(r || P.x || m) mod n
    let px_bytes = {
        let affine = p.to_affine().expect("Public key point cannot be infinity");
        affine.x.to_bytes()
    };
    let mut challenge_input = Vec::with_capacity(32 + 32 + message.len());
    challenge_input.extend_from_slice(r_bytes);
    challenge_input.extend_from_slice(&px_bytes);
    challenge_input.extend_from_slice(message);
    let e_bytes = tagged_hash(TAG_CHALLENGE, &challenge_input);
    let e = Scalar::from_bytes(&e_bytes);

    // Compute R = s⋅G - e⋅P
    let s_bytes_array = s.to_bytes();
    let e_bytes_array = e.to_bytes();
    let sg = Point::generator().scalar_mul(&s_bytes_array);
    let ep = p.scalar_mul(&e_bytes_array);
    let r_point = sg.add(&ep.negate());

    // Check R is not infinity
    if r_point.is_identity() {
        return false;
    }

    // Get R's affine coordinates
    let r_affine = match r_point.to_affine() {
        Some(affine) => affine,
        None => return false, // R is infinity, verification fails
    };

    // Check R.y is even (implicit in BIP 340)
    // Note: to_bytes() returns big-endian, so LSB is at the end
    if r_affine.y.to_bytes()[31] & 1 == 1 {
        return false;
    }

    // Check R.x == r
    let rx_bytes = r_affine.x.to_bytes();
    rx_bytes == *r_bytes
}

/// Tagged SHA-256 hash as defined in BIP 340
///
/// hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x)
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // Compute tag_hash = SHA256(tag)
    let tag_hash = {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.finalize()
    };

    // Compute SHA256(tag_hash || tag_hash || data)
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        // Test that tagged hash produces different outputs for different tags
        let data = b"test data";
        let hash1 = tagged_hash(b"tag1", data);
        let hash2 = tagged_hash(b"tag2", data);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_public_key_generation() {
        // Test public key generation from a private key
        let secret_key = [1u8; 32];
        let public_key = public_key(&secret_key);

        // Public key should be 32 bytes and non-zero
        assert_eq!(public_key.len(), 32);
        assert_ne!(public_key, [0u8; 32]);
    }

    #[test]
    fn test_sign_verify_basic() {
        // Basic sign and verify test
        let secret_key = [1u8; 32];
        let public_key = public_key(&secret_key);
        let message = b"Hello, Bitcoin!";
        let aux_rand = [0u8; 32]; // Deterministic (all zeros)

        let signature = sign(&secret_key, message, &aux_rand);

        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_sign_verify_different_messages() {
        // Signature should fail on different message
        let secret_key = [2u8; 32];
        let public_key = public_key(&secret_key);
        let message1 = b"Message 1";
        let message2 = b"Message 2";
        let aux_rand = [0u8; 32];

        let signature = sign(&secret_key, message1, &aux_rand);

        assert!(verify(&public_key, message1, &signature));
        assert!(!verify(&public_key, message2, &signature));
    }

    #[test]
    fn test_sign_verify_wrong_public_key() {
        // Signature should fail with wrong public key
        let secret_key1 = [3u8; 32];
        let secret_key2 = [4u8; 32];
        let public_key2 = public_key(&secret_key2);
        let message = b"Test message";
        let aux_rand = [0u8; 32];

        let signature = sign(&secret_key1, message, &aux_rand);

        assert!(!verify(&public_key2, message, &signature));
    }

    #[test]
    fn test_deterministic_signatures() {
        // Same inputs should produce same signature
        let secret_key = [5u8; 32];
        let message = b"Deterministic test";
        let aux_rand = [0u8; 32];

        let sig1 = sign(&secret_key, message, &aux_rand);
        let sig2 = sign(&secret_key, message, &aux_rand);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_bip340_vector1() {
        // BIP 340 test vector #0
        // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv

        let secret_key = hex_to_bytes_32("0000000000000000000000000000000000000000000000000000000000000003");
        let public_key_expected = hex_to_bytes_32("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let aux_rand = hex_to_bytes_32("0000000000000000000000000000000000000000000000000000000000000000");
        let message = hex_to_bytes_32("0000000000000000000000000000000000000000000000000000000000000000");
        let signature_expected = hex_to_bytes_64("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");

        // Test public key generation
        let pk = public_key(&secret_key);
        assert_eq!(pk, public_key_expected, "Public key mismatch");

        // Test signature generation
        let sig = sign(&secret_key, &message, &aux_rand);
        assert_eq!(sig, signature_expected, "Signature mismatch");

        // Test verification
        assert!(verify(&pk, &message, &sig), "Verification failed");
    }

    // Helper function to convert hex string to 32-byte array
    fn hex_to_bytes_32(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().expect("Expected 32 bytes")
    }

    // Helper function to convert hex string to 64-byte array
    fn hex_to_bytes_64(hex: &str) -> [u8; 64] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().expect("Expected 64 bytes")
    }
}
