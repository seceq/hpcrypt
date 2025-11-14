//! OPAQUE implementation helpers
//!
//! This module contains the actual implementations of the placeholder functions
//! in the OPAQUE protocol.

use crate::opaque::{Config, HashFunction, KdfFunction, KsfFunction, MacFunction, OpaqueError};
use crate::oprf::{EvaluatedElement, OprfError};

use hpcrypt_curves::ed25519::{base_point, EdwardsPoint, Scalar};
use hpcrypt_hash::{sha512, HmacSha256, HmacSha512};
use hpcrypt_kdf::{HkdfSha256, HkdfSha512};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// ================================
// Random Number Generation
// ================================

/// Generate a random scalar for use in OPRF
pub fn generate_random_scalar() -> Result<Scalar, OpaqueError> {
    let bytes: [u8; 32] = hpcrypt_rng::generate_key().map_err(|_| OpaqueError::InternalError)?;
    Ok(Scalar::from_bytes(bytes))
}

/// Generate random bytes of specified length
pub fn generate_random_bytes_len(len: usize) -> Result<Vec<u8>, OpaqueError> {
    let mut bytes = vec![0u8; len];
    hpcrypt_rng::fill_random(&mut bytes).map_err(|_| OpaqueError::InternalError)?;
    Ok(bytes)
}

// ================================
// OPRF Operations
// ================================

/// Blind a password element (byte slice API)
pub fn oprf_blind(
    password: &[u8],
    blind_bytes: &[u8],
    _config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    if blind_bytes.len() != 32 {
        return Err(OpaqueError::InvalidLength);
    }

    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(blind_bytes);
    let blind = Scalar::from_bytes(blind_arr);

    // Hash password to curve point
    let input_point = hash_to_curve(password).map_err(|_| OpaqueError::OprfError)?;

    // Blind the point
    let blinded_point = input_point.scalar_mul(&blind.to_bytes());

    Ok(blinded_point.encode().to_vec())
}

/// Server evaluates blinded element (byte slice API)
pub fn oprf_evaluate(
    blinded_bytes: &[u8],
    seed: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, OpaqueError> {
    use crate::oprf::{BlindedElement, OprfServer};

    // Deserialize blinded element
    let blinded =
        BlindedElement::from_bytes(blinded_bytes).map_err(|_| OpaqueError::InvalidPoint)?;

    // Derive OPRF key from seed and info
    let key = OprfServer::derive_key(seed, info).map_err(|_| OpaqueError::OprfError)?;

    // Evaluate blinded element with key
    let evaluated = OprfServer::evaluate(&blinded, &key).map_err(|_| OpaqueError::OprfError)?;

    Ok(evaluated.to_bytes().to_vec())
}

/// Finalize OPRF output (byte slice API)
pub fn oprf_finalize(
    password: &[u8],
    blind_bytes: &[u8],
    evaluated_bytes: &[u8],
    _config: &Config,
) -> Result<[u8; 64], OpaqueError> {
    if blind_bytes.len() != 32 {
        return Err(OpaqueError::InvalidLength);
    }

    let mut blind_arr = [0u8; 32];
    blind_arr.copy_from_slice(blind_bytes);
    let blind = Scalar::from_bytes(blind_arr);

    // Deserialize evaluated element
    let evaluated =
        EvaluatedElement::from_bytes(evaluated_bytes).map_err(|_| OpaqueError::InvalidPoint)?;

    // Compute blind inverse
    let blind_inv = scalar_inverse(&blind).map_err(|_| OpaqueError::OprfError)?;

    // Unblind
    let evaluated_point =
        EdwardsPoint::decode(&evaluated.to_bytes()).map_err(|_| OpaqueError::InvalidPoint)?;
    let unblinded_point = evaluated_point.scalar_mul(&blind_inv.to_bytes());

    // Finalize hash
    finalize_hash(password, &unblinded_point).map_err(|_| OpaqueError::OprfError)
}

/// Hash arbitrary input to curve point
fn hash_to_curve(input: &[u8]) -> Result<EdwardsPoint, OprfError> {
    const DST: &[u8] = b"HashToGroup-ristretto255-SHA512";

    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(DST);
    hash_input.extend_from_slice(input);

    let hash_output = sha512(&hash_input);

    // Use first 32 bytes as scalar for hash-to-curve
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash_output[..32]);

    let point = base_point().scalar_mul(&scalar_bytes);
    Ok(point)
}

/// Compute scalar inverse using Fermat's little theorem
fn scalar_inverse(scalar: &Scalar) -> Result<Scalar, OprfError> {
    // L - 2 in little-endian
    let l_minus_2 = [
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    Ok(scalar_pow(scalar, &l_minus_2))
}

/// Scalar exponentiation
fn scalar_pow(scalar: &Scalar, exp: &[u8; 32]) -> Scalar {
    let mut result = Scalar::from_bytes([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    let mut base = *scalar;

    for byte in exp.iter() {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1;
            if bit == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
        }
    }

    result
}

/// Finalize OPRF hash
fn finalize_hash(input: &[u8], unblinded: &EdwardsPoint) -> Result<[u8; 64], OprfError> {
    let point_bytes = unblinded.encode();

    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(b"Finalize");
    hash_input.extend_from_slice(input);
    hash_input.extend_from_slice(&point_bytes);
    hash_input.extend_from_slice(b"ristretto255-SHA512");

    Ok(sha512(&hash_input))
}

// ================================
// Key Derivation (HKDF)
// ================================

/// Extract step of HKDF
#[allow(dead_code)]
pub fn kdf_extract(input: &[u8], info: &[u8], config: &Config) -> Result<Vec<u8>, OpaqueError> {
    match config.kdf {
        KdfFunction::HkdfSha256 => {
            let hkdf = HkdfSha256::new(&[], input);
            let mut output = vec![0u8; 32];
            hkdf.expand(info, &mut output)
                .map_err(|_| OpaqueError::InternalError)?;
            Ok(output)
        }
        KdfFunction::HkdfSha512 => {
            let hkdf = HkdfSha512::new(&[], input);
            let mut output = vec![0u8; 64];
            hkdf.expand(info, &mut output)
                .map_err(|_| OpaqueError::InternalError)?;
            Ok(output)
        }
    }
}

/// Expand step of HKDF
pub fn kdf_expand(
    prk: &[u8],
    info: &[u8],
    output_len: usize,
    config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    match config.kdf {
        KdfFunction::HkdfSha256 => {
            let hkdf = HkdfSha256::new(&[], prk);
            let mut output = vec![0u8; output_len];
            hkdf.expand(info, &mut output)
                .map_err(|_| OpaqueError::InternalError)?;
            Ok(output)
        }
        KdfFunction::HkdfSha512 => {
            let hkdf = HkdfSha512::new(&[], prk);
            let mut output = vec![0u8; output_len];
            hkdf.expand(info, &mut output)
                .map_err(|_| OpaqueError::InternalError)?;
            Ok(output)
        }
    }
}

// ================================
// Key Stretching
// ================================

/// Stretch password using Argon2id or scrypt
pub fn key_stretch(input: &[u8], config: &Config) -> Result<Vec<u8>, OpaqueError> {
    match config.ksf {
        KsfFunction::Argon2id => {
            use hpcrypt_kdf::argon2::{Argon2id, Params};

            // Argon2id parameters as per RFC 9807 recommendation
            let salt = [0u8; 16]; // In real implementation, this should be derived

            let params = Params::new(64, 1 << 21, 1, 4).map_err(|_| OpaqueError::InternalError)?;

            let output =
                Argon2id::hash(input, &salt, &params).map_err(|_| OpaqueError::InternalError)?;

            Ok(output)
        }
        KsfFunction::Scrypt => {
            use hpcrypt_kdf::scrypt::{scrypt, ScryptParams};

            // scrypt parameters as per RFC 9807 recommendation
            let salt = [0u8; 16];

            let params = ScryptParams::new(15, 8, 1).map_err(|_| OpaqueError::InternalError)?;

            let output = scrypt(input, &salt, &params, 64);

            Ok(output)
        }
        KsfFunction::Pbkdf2 => {
            // PBKDF2 is not recommended but supported
            Err(OpaqueError::InvalidConfiguration)
        }
    }
}

// ================================
// MAC Operations
// ================================

/// Compute HMAC
pub fn compute_mac(key: &[u8], message: &[u8], config: &Config) -> Result<Vec<u8>, OpaqueError> {
    match config.mac {
        MacFunction::HmacSha256 => {
            let hmac = HmacSha256::new(key);
            Ok(hmac.compute(message).to_vec())
        }
        MacFunction::HmacSha512 => {
            let hmac = HmacSha512::new(key);
            Ok(hmac.compute(message).to_vec())
        }
    }
}

/// Verify HMAC in constant time
pub fn verify_mac(
    key: &[u8],
    message: &[u8],
    expected_mac: &[u8],
    config: &Config,
) -> Result<(), OpaqueError> {
    let computed = compute_mac(key, message, config)?;

    use subtle::ConstantTimeEq;
    if computed.ct_eq(expected_mac).into() {
        Ok(())
    } else {
        Err(OpaqueError::MacVerificationFailed)
    }
}

// ================================
// Keypair Generation
// ================================

/// Generate a random Ed25519 keypair (for static/long-term keys)
pub fn generate_keypair(config: &Config) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    match config.group {
        crate::opaque::Group::Ristretto255 | crate::opaque::Group::Curve25519 => {
            #[cfg(not(test))]
            {
                // PRODUCTION: Generate cryptographically secure random key
                use hpcrypt_rng::generate_key;
                let private_key: [u8; 32] =
                    generate_key().map_err(|_| OpaqueError::InternalError)?;

                // Derive public key using X25519 (for DH key agreement)
                use hpcrypt_curves::X25519;
                let public_key = X25519::public_key(&private_key);

                Ok((private_key.to_vec(), public_key.to_vec()))
            }

            #[cfg(test)]
            {
                // TESTING ONLY: Use fixed key for deterministic tests
                // WARNING: This is NOT secure for production use!
                let private_key = [99u8; 32]; // Fixed STATIC key for testing

                // Derive public key using X25519 (for DH key agreement)
                use hpcrypt_curves::X25519;
                let public_key = X25519::public_key(&private_key);

                Ok((private_key.to_vec(), public_key.to_vec()))
            }
        }
        crate::opaque::Group::P256 => {
            // P256 keypair generation
            // For now, use placeholder since P256 support is limited
            Err(OpaqueError::InvalidConfiguration)
        }
    }
}

/// Generate an ephemeral keypair (for session-specific keys)
///
/// In production, generates cryptographically secure random keys for each session.
/// In tests, uses deterministic counter-based keys for reproducibility.
pub fn generate_ephemeral_keypair(config: &Config) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    match config.group {
        crate::opaque::Group::Ristretto255 | crate::opaque::Group::Curve25519 => {
            #[cfg(not(test))]
            {
                // PRODUCTION: Generate cryptographically secure random ephemeral key
                // CRITICAL: Each session MUST use a fresh random key for forward secrecy!
                use hpcrypt_rng::generate_key;
                let private_key: [u8; 32] =
                    generate_key().map_err(|_| OpaqueError::InternalError)?;

                // Derive public key using X25519 (for DH key agreement)
                use hpcrypt_curves::X25519;
                let public_key = X25519::public_key(&private_key);

                Ok((private_key.to_vec(), public_key.to_vec()))
            }

            #[cfg(test)]
            {
                // TESTING ONLY: Use counter-based deterministic keys
                // WARNING: This is NOT secure for production use!
                // Client and server get different keys due to counter increment
                use core::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

                // Create a deterministic but unique key using counter
                let mut private_key = [0u8; 32];
                for i in 0..32 {
                    private_key[i] = ((counter.wrapping_mul(i as u64 + 1) >> (i % 8)) & 0xFF) as u8;
                }
                // Ensure it's not all zeros
                private_key[0] |= 1;

                // Derive public key using X25519 (for DH key agreement)
                use hpcrypt_curves::X25519;
                let public_key = X25519::public_key(&private_key);

                Ok((private_key.to_vec(), public_key.to_vec()))
            }
        }
        crate::opaque::Group::P256 => Err(OpaqueError::InvalidConfiguration),
    }
}

/// Derive deterministic keypair from seed
pub fn derive_keypair(seed: &[u8], config: &Config) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    match config.group {
        crate::opaque::Group::Ristretto255 | crate::opaque::Group::Curve25519 => {
            // Derive 32-byte private key from seed using HKDF
            let hkdf = HkdfSha512::new(&[], seed);
            let mut private_key = [0u8; 32];
            hkdf.expand(b"OPAQUE-DeriveKeyPair", &mut private_key)
                .map_err(|_| OpaqueError::InternalError)?;

            // Derive public key using X25519 (for DH key agreement)
            use hpcrypt_curves::X25519;
            let public_key = X25519::public_key(&private_key);

            Ok((private_key.to_vec(), public_key.to_vec()))
        }
        crate::opaque::Group::P256 => Err(OpaqueError::InvalidConfiguration),
    }
}

// ================================
// 3DH Key Agreement
// ================================

/// Perform triple Diffie-Hellman key agreement
pub fn triple_dh(
    ephemeral_private: &[u8],
    static_private: &[u8],
    peer_ephemeral_public: &[u8],
    peer_static_public: &[u8],
    config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    match config.group {
        crate::opaque::Group::Ristretto255 | crate::opaque::Group::Curve25519 => {
            use hpcrypt_curves::X25519;

            // Ensure inputs are 32 bytes
            if ephemeral_private.len() != 32
                || static_private.len() != 32
                || peer_ephemeral_public.len() != 32
                || peer_static_public.len() != 32
            {
                return Err(OpaqueError::InvalidLength);
            }

            let mut eph_priv = [0u8; 32];
            let mut static_priv = [0u8; 32];
            let mut peer_eph_pub = [0u8; 32];
            let mut peer_static_pub = [0u8; 32];

            eph_priv.copy_from_slice(ephemeral_private);
            static_priv.copy_from_slice(static_private);
            peer_eph_pub.copy_from_slice(peer_ephemeral_public);
            peer_static_pub.copy_from_slice(peer_static_public);

            // Compute three DH operations
            let dh1 = X25519::shared_secret(&eph_priv, &peer_eph_pub)
                .map_err(|_| OpaqueError::InternalError)?;
            let dh2 = X25519::shared_secret(&eph_priv, &peer_static_pub)
                .map_err(|_| OpaqueError::InternalError)?;
            let dh3 = X25519::shared_secret(&static_priv, &peer_eph_pub)
                .map_err(|_| OpaqueError::InternalError)?;

            // Concatenate DH outputs in a canonical order
            // IMPORTANT: Both parties must concatenate in the same order!
            // We sort the DH results lexicographically to ensure consistency
            let mut dh_values = [dh1, dh2, dh3];
            dh_values.sort();

            let mut combined = Vec::new();
            combined.extend_from_slice(&dh_values[0]);
            combined.extend_from_slice(&dh_values[1]);
            combined.extend_from_slice(&dh_values[2]);

            // Derive session key using HKDF
            let hkdf = HkdfSha512::new(&[], &combined);
            let mut session_key = vec![0u8; 64];
            hkdf.expand(b"OPAQUE-3DH", &mut session_key)
                .map_err(|_| OpaqueError::InternalError)?;

            Ok(session_key)
        }
        crate::opaque::Group::P256 => Err(OpaqueError::InvalidConfiguration),
    }
}

// ================================
// MAC Key Derivation
// ================================

/// Derive Km2 and Km3 MAC keys from session key
pub fn derive_mac_keys(
    session_key: &[u8],
    config: &Config,
) -> Result<(Vec<u8>, Vec<u8>), OpaqueError> {
    let km2 = kdf_expand(
        session_key,
        b"OPAQUE-ServerMAC",
        hash_output_len(&config.hash),
        config,
    )?;
    let km3 = kdf_expand(
        session_key,
        b"OPAQUE-ClientMAC",
        hash_output_len(&config.hash),
        config,
    )?;
    Ok((km2, km3))
}

// ================================

// Helper function to get hash output length
pub fn hash_output_len(hash: &HashFunction) -> usize {
    match hash {
        HashFunction::Sha256 => 32,
        HashFunction::Sha512 => 64,
    }
}

// ================================
// Envelope Encryption
// ================================

/// Envelope structure for OPAQUE
/// Contains encrypted credentials with authentication
#[derive(Clone)]
#[allow(dead_code)]
pub struct Envelope {
    /// Nonce for encryption
    pub nonce: Vec<u8>,
    /// Encrypted credentials
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub auth_tag: Vec<u8>,
}

/// Create an encrypted envelope
pub fn create_envelope(
    randomized_pwd: &[u8],
    client_private_key: &[u8],
    server_public_key: &[u8],
    server_identity: &[u8],
    client_identity: &[u8],
    config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    // Derive envelope encryption key from randomized password
    let envelope_key = kdf_expand(randomized_pwd, b"OPAQUE-EnvelopeKey", 32, config)?;

    // Serialize cleartext credentials with length prefixes for variable-length fields
    let mut cleartext = Vec::new();
    // Fixed-length: server_public_key (32 bytes for all curves)
    cleartext.extend_from_slice(server_public_key);
    // Variable-length: server_identity
    cleartext.extend_from_slice(&(server_identity.len() as u32).to_be_bytes());
    cleartext.extend_from_slice(server_identity);
    // Variable-length: client_identity
    cleartext.extend_from_slice(&(client_identity.len() as u32).to_be_bytes());
    cleartext.extend_from_slice(client_identity);
    // Fixed-length: client_private_key (32 bytes for all curves)
    cleartext.extend_from_slice(client_private_key);

    // Generate random nonce
    let nonce = generate_random_bytes_len(12)?;

    // Encrypt using HMAC-based authenticated encryption
    let ciphertext = encrypt_then_mac(&envelope_key, &nonce, &cleartext, config)?;

    // Compute authentication tag over envelope
    let auth_tag = compute_mac(&envelope_key, &ciphertext, config)?;

    // Serialize envelope
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    envelope.extend_from_slice(&(auth_tag.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&auth_tag);

    Ok(envelope)
}

/// Result type for envelope recovery
type EnvelopeRecovery = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Recover credentials from encrypted envelope
pub fn recover_envelope(
    randomized_pwd: &[u8],
    envelope_bytes: &[u8],
    config: &Config,
) -> Result<EnvelopeRecovery, OpaqueError> {
    // Derive envelope encryption key
    let envelope_key = kdf_expand(randomized_pwd, b"OPAQUE-EnvelopeKey", 32, config)?;

    // Deserialize envelope
    let (nonce, ciphertext, auth_tag) = deserialize_envelope(envelope_bytes)?;

    // Verify authentication tag
    verify_mac(&envelope_key, &ciphertext, &auth_tag, config)?;

    // Decrypt
    let cleartext = decrypt_and_verify(&envelope_key, &nonce, &ciphertext, config)?;

    // Parse cleartext credentials with length prefixes
    // Minimum: 32 (server_public) + 4 (len) + 0 (identity) + 4 (len) + 0 (identity) + 32 (client_private) = 72 bytes
    if cleartext.len() < 72 {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }

    let mut offset = 0;

    // Fixed-length: server_public_key (32 bytes)
    let server_public_key = cleartext[offset..offset + 32].to_vec();
    offset += 32;

    // Variable-length: server_identity
    if offset + 4 > cleartext.len() {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }
    let server_id_len = u32::from_be_bytes([
        cleartext[offset],
        cleartext[offset + 1],
        cleartext[offset + 2],
        cleartext[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + server_id_len > cleartext.len() {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }
    let server_identity = cleartext[offset..offset + server_id_len].to_vec();
    offset += server_id_len;

    // Variable-length: client_identity
    if offset + 4 > cleartext.len() {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }
    let client_id_len = u32::from_be_bytes([
        cleartext[offset],
        cleartext[offset + 1],
        cleartext[offset + 2],
        cleartext[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + client_id_len > cleartext.len() {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }
    let client_identity = cleartext[offset..offset + client_id_len].to_vec();
    offset += client_id_len;

    // Fixed-length: client_private_key (32 bytes)
    if offset + 32 > cleartext.len() {
        return Err(OpaqueError::EnvelopeDecryptionFailed);
    }
    let client_private_key = cleartext[offset..offset + 32].to_vec();

    Ok((
        client_private_key,
        server_public_key,
        server_identity,
        client_identity,
    ))
}

/// Result type for envelope deserialization
type EnvelopeData = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Deserialize envelope
fn deserialize_envelope(bytes: &[u8]) -> Result<EnvelopeData, OpaqueError> {
    if bytes.len() < 12 {
        return Err(OpaqueError::InvalidLength);
    }

    let mut offset = 0;

    // Read nonce
    let nonce_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    offset += 4;
    if offset + nonce_len > bytes.len() {
        return Err(OpaqueError::InvalidLength);
    }
    let nonce = bytes[offset..offset + nonce_len].to_vec();
    offset += nonce_len;

    // Read ciphertext
    if offset + 4 > bytes.len() {
        return Err(OpaqueError::InvalidLength);
    }
    let ct_len = u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + ct_len > bytes.len() {
        return Err(OpaqueError::InvalidLength);
    }
    let ciphertext = bytes[offset..offset + ct_len].to_vec();
    offset += ct_len;

    // Read auth tag
    if offset + 4 > bytes.len() {
        return Err(OpaqueError::InvalidLength);
    }
    let tag_len = u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) as usize;
    offset += 4;
    if offset + tag_len > bytes.len() {
        return Err(OpaqueError::InvalidLength);
    }
    let auth_tag = bytes[offset..offset + tag_len].to_vec();

    Ok((nonce, ciphertext, auth_tag))
}

/// Simple encrypt-then-MAC authenticated encryption
fn encrypt_then_mac(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    // Derive encryption and MAC keys
    let enc_key = kdf_expand(key, b"Encrypt", 32, config)?;

    // Simple XOR-based encryption (for now - could use AES-CTR in production)
    let mut ciphertext = plaintext.to_vec();
    let keystream = kdf_expand(&enc_key, nonce, ciphertext.len(), config)?;

    for (i, byte) in ciphertext.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }

    Ok(ciphertext)
}

/// Decrypt and verify
fn decrypt_and_verify(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    config: &Config,
) -> Result<Vec<u8>, OpaqueError> {
    // Same as encrypt (XOR is symmetric)
    encrypt_then_mac(key, nonce, ciphertext, config)
}

/// Mask envelope for transmission
pub fn mask_envelope(envelope: &[u8], masking_key: &[u8]) -> Result<Vec<u8>, OpaqueError> {
    let mut masked = envelope.to_vec();

    // XOR with masking key (repeated as needed)
    for (i, byte) in masked.iter_mut().enumerate() {
        *byte ^= masking_key[i % masking_key.len()];
    }

    Ok(masked)
}

/// Unmask envelope
#[allow(dead_code)]
pub fn unmask_envelope(masked: &[u8], masking_key: &[u8]) -> Result<Vec<u8>, OpaqueError> {
    // XOR is symmetric
    mask_envelope(masked, masking_key)
}

// ================================
// Transcript Hashing
// ================================

/// Build MAC input from protocol transcript
pub fn build_mac_input(
    client_nonce: &[u8],
    server_nonce: &[u8],
    client_ephemeral_public: &[u8],
    server_ephemeral_public: &[u8],
    client_identity: &[u8],
    server_identity: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();

    // Concatenate all transcript elements
    input.extend_from_slice(&(client_nonce.len() as u32).to_be_bytes());
    input.extend_from_slice(client_nonce);

    input.extend_from_slice(&(server_nonce.len() as u32).to_be_bytes());
    input.extend_from_slice(server_nonce);

    input.extend_from_slice(&(client_ephemeral_public.len() as u32).to_be_bytes());
    input.extend_from_slice(client_ephemeral_public);

    input.extend_from_slice(&(server_ephemeral_public.len() as u32).to_be_bytes());
    input.extend_from_slice(server_ephemeral_public);

    input.extend_from_slice(&(client_identity.len() as u32).to_be_bytes());
    input.extend_from_slice(client_identity);

    input.extend_from_slice(&(server_identity.len() as u32).to_be_bytes());
    input.extend_from_slice(server_identity);

    input
}
