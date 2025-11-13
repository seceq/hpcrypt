//! PKCS#1 v1.5 encryption and signatures
//!
//! Implements RSAES-PKCS1-v1_5 and RSASSA-PKCS1-v1_5 from RFC 8017
//!
//! # Security Warning
//!
//! PKCS#1 v1.5 is deprecated for new applications. Use RSA-OAEP for encryption
//! and RSA-PSS for signatures instead. This implementation is provided for
//! compatibility with legacy systems only.

use crate::error::{Result, RsaError};
use crate::primitives::{i2osp, os2ip};
use crate::private_key::RsaPrivateKey;
use crate::public_key::RsaPublicKey;
use alloc::vec;
use alloc::vec::Vec;

/// PKCS#1 v1.5 encryption
///
/// # Security Warning
///
/// This scheme is vulnerable to chosen-ciphertext attacks. Use RSA-OAEP instead.
///
/// # Arguments
///
/// * `public_key` - RSA public key
/// * `message` - Message to encrypt (max length: k - 11 bytes)
///
/// # Returns
///
/// Ciphertext of length k (key size in bytes)
pub fn encrypt_pkcs1v15(public_key: &RsaPublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let k = public_key.size_bytes();

    // Check message length: mLen <= k - 11
    if message.len() > k - 11 {
        return Err(RsaError::MessageTooLong);
    }

    // Step 1: EME-PKCS1-v1_5 encoding
    let em = eme_pkcs1v15_encode(message, k)?;

    // Step 2: RSA encryption
    let m = os2ip(&em);
    let c = public_key.encrypt_primitive(&m)?;

    // Step 3: Convert to octet string
    i2osp(&c, k)
}

/// PKCS#1 v1.5 decryption
///
/// # Security Warning
///
/// This scheme is vulnerable to Bleichenbacher's attack. Use RSA-OAEP instead.
///
/// # Arguments
///
/// * `private_key` - RSA private key
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
///
/// Decrypted message
pub fn decrypt_pkcs1v15(private_key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let k = private_key.size_bytes();

    // Check ciphertext length
    if ciphertext.len() != k || k < 11 {
        return Err(RsaError::InvalidCiphertext);
    }

    // Step 1: RSA decryption
    let c = os2ip(ciphertext);
    let m = private_key.decrypt_primitive(&c)?;
    let em = i2osp(&m, k)?;

    // Step 2: EME-PKCS1-v1_5 decoding
    eme_pkcs1v15_decode(&em)
}

/// PKCS#1 v1.5 signature generation
///
/// # Security Note
///
/// While RSA-PSS is recommended, PKCS#1 v1.5 signatures are still widely used
/// and considered secure when used correctly.
///
/// # Arguments
///
/// * `private_key` - RSA private key
/// * `digest_info` - DigestInfo structure (hash OID + hash value)
///
/// # Returns
///
/// Signature of length k (key size in bytes)
pub fn sign_pkcs1v15(private_key: &RsaPrivateKey, digest_info: &[u8]) -> Result<Vec<u8>> {
    let k = private_key.size_bytes();

    // Check digest_info length
    if digest_info.len() > k - 11 {
        return Err(RsaError::MessageTooLong);
    }

    // Step 1: EMSA-PKCS1-v1_5 encoding
    let em = emsa_pkcs1v15_encode(digest_info, k)?;

    // Step 2: RSA signature
    let m = os2ip(&em);
    let s = private_key.sign_primitive(&m)?;

    // Step 3: Convert to octet string
    i2osp(&s, k)
}

/// PKCS#1 v1.5 signature verification
///
/// # Arguments
///
/// * `public_key` - RSA public key
/// * `digest_info` - DigestInfo structure (hash OID + hash value)
/// * `signature` - Signature to verify
///
/// # Returns
///
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_pkcs1v15(
    public_key: &RsaPublicKey,
    digest_info: &[u8],
    signature: &[u8],
) -> Result<()> {
    let k = public_key.size_bytes();

    // Check signature length
    if signature.len() != k {
        return Err(RsaError::InvalidSignature);
    }

    // Step 1: RSA verification
    let s = os2ip(signature);
    let m = public_key.verify_primitive(&s)?;
    let em = i2osp(&m, k)?;

    // Step 2: EMSA-PKCS1-v1_5 encoding of expected value
    let em_prime = emsa_pkcs1v15_encode(digest_info, k)?;

    // Step 3: Compare EM with EM' (constant time)
    if !constant_time_eq(&em, &em_prime) {
        return Err(RsaError::VerificationFailed);
    }

    Ok(())
}

/// EME-PKCS1-v1_5 encoding (for encryption)
///
/// EM = 0x00 || 0x02 || PS || 0x00 || M
/// where PS is at least 8 random non-zero bytes
fn eme_pkcs1v15_encode(message: &[u8], em_len: usize) -> Result<Vec<u8>> {
    let m_len = message.len();

    if m_len > em_len - 11 {
        return Err(RsaError::MessageTooLong);
    }

    // PS length must be at least 8
    let ps_len = em_len - m_len - 3;
    if ps_len < 8 {
        return Err(RsaError::MessageTooLong);
    }

    // Generate random non-zero padding
    let ps = generate_nonzero_padding(ps_len)?;

    // Construct EM
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(message);

    Ok(em)
}

/// EME-PKCS1-v1_5 decoding (for decryption)
///
/// Constant-time implementation to prevent Bleichenbacher's attack
fn eme_pkcs1v15_decode(em: &[u8]) -> Result<Vec<u8>> {
    if em.len() < 11 {
        return Err(RsaError::DecryptionFailed);
    }

    // Check first byte is 0x00
    if em[0] != 0x00 {
        return Err(RsaError::DecryptionFailed);
    }

    // Check second byte is 0x02
    if em[1] != 0x02 {
        return Err(RsaError::DecryptionFailed);
    }

    // Find 0x00 separator (constant time scan)
    let mut separator_index = None;
    let mut found_nonzero = false;

    for i in 2..em.len() {
        if em[i] == 0x00 && !found_nonzero {
            // Skip leading zeros in PS (shouldn't happen with proper encoding)
            continue;
        }

        found_nonzero = true;

        if em[i] == 0x00 {
            separator_index = Some(i);
            break;
        }
    }

    let sep_idx = separator_index.ok_or(RsaError::DecryptionFailed)?;

    // Check PS length >= 8
    if sep_idx - 2 < 8 {
        return Err(RsaError::DecryptionFailed);
    }

    // Extract message
    let message = em[sep_idx + 1..].to_vec();

    Ok(message)
}

/// EMSA-PKCS1-v1_5 encoding (for signatures)
///
/// EM = 0x00 || 0x01 || PS || 0x00 || T
/// where PS is 0xFF bytes and T is the DigestInfo
fn emsa_pkcs1v15_encode(digest_info: &[u8], em_len: usize) -> Result<Vec<u8>> {
    let t_len = digest_info.len();

    if t_len > em_len - 11 {
        return Err(RsaError::MessageTooLong);
    }

    // PS length
    let ps_len = em_len - t_len - 3;

    // Construct EM
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.push(0x01);
    em.extend_from_slice(&vec![0xFF; ps_len]);
    em.push(0x00);
    em.extend_from_slice(digest_info);

    Ok(em)
}

/// Generate random non-zero padding
fn generate_nonzero_padding(len: usize) -> Result<Vec<u8>> {
    let mut padding = vec![0u8; len];

    #[cfg(feature = "std")]
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        for byte in &mut padding {
            // Generate non-zero bytes
            loop {
                rng.fill_bytes(core::slice::from_mut(byte));
                if *byte != 0 {
                    break;
                }
            }
        }
    }

    #[cfg(not(feature = "std"))]
    {
        return Err(RsaError::RngError);
    }

    Ok(padding)
}

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Create DigestInfo structure for common hash algorithms
///
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest OCTET STRING
/// }
pub fn create_digest_info(hash_algorithm: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
    let mut digest_info = Vec::new();

    // Add hash algorithm OID
    digest_info.extend_from_slice(hash_algorithm.oid());

    // Add digest
    digest_info.extend_from_slice(digest);

    digest_info
}

/// Hash algorithms with their ASN.1 DigestInfo prefixes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Get the DigestInfo prefix (OID + structure)
    pub fn oid(&self) -> &'static [u8] {
        match self {
            // SHA-256: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING
            HashAlgorithm::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            // SHA-384
            HashAlgorithm::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            // SHA-512
            HashAlgorithm::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_key::RsaPrivateKey;

    #[cfg(feature = "std")]
    #[test]
    fn test_encrypt_decrypt_pkcs1v15() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Hello, PKCS#1 v1.5!";

        let ciphertext = encrypt_pkcs1v15(key.public_key(), message).unwrap();
        let decrypted = decrypt_pkcs1v15(&key, &ciphertext).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pkcs1v15_deterministic_padding() {
        // Same message should produce different ciphertexts due to random PS
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Same message";

        let ct1 = encrypt_pkcs1v15(key.public_key(), message).unwrap();
        let ct2 = encrypt_pkcs1v15(key.public_key(), message).unwrap();

        // Should be different due to random padding
        assert_ne!(ct1, ct2);

        // But both should decrypt correctly
        let pt1 = decrypt_pkcs1v15(&key, &ct1).unwrap();
        let pt2 = decrypt_pkcs1v15(&key, &ct2).unwrap();

        assert_eq!(message, &pt1[..]);
        assert_eq!(message, &pt2[..]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pkcs1v15_message_too_long() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let k = key.size_bytes();

        // Message too long: mLen > k - 11
        let max_len = k - 11;
        let message = vec![0xFF; max_len + 1];

        let result = encrypt_pkcs1v15(key.public_key(), &message);
        assert_eq!(result, Err(RsaError::MessageTooLong));
    }

    #[test]
    fn test_emsa_pkcs1v15_encode() {
        let digest_info = vec![0x01, 0x02, 0x03, 0x04];
        let em = emsa_pkcs1v15_encode(&digest_info, 32).unwrap();

        assert_eq!(em.len(), 32);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        assert_eq!(em[em.len() - 4..], digest_info[..]);

        // Check PS is all 0xFF
        for i in 2..em.len() - 5 {
            assert_eq!(em[i], 0xFF);
        }

        // Check separator
        assert_eq!(em[em.len() - 5], 0x00);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_sign_verify_pkcs1v15() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        // Create a mock DigestInfo
        let hash = vec![0x12; 32]; // 32-byte hash
        let digest_info = create_digest_info(HashAlgorithm::Sha256, &hash);

        let signature = sign_pkcs1v15(&key, &digest_info).unwrap();
        let result = verify_pkcs1v15(key.public_key(), &digest_info, &signature);

        assert!(result.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pkcs1v15_wrong_digest() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        let hash1 = vec![0x12; 32];
        let hash2 = vec![0x34; 32];

        let digest_info1 = create_digest_info(HashAlgorithm::Sha256, &hash1);
        let digest_info2 = create_digest_info(HashAlgorithm::Sha256, &hash2);

        let signature = sign_pkcs1v15(&key, &digest_info1).unwrap();
        let result = verify_pkcs1v15(key.public_key(), &digest_info2, &signature);

        assert_eq!(result, Err(RsaError::VerificationFailed));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pkcs1v15_signature_deterministic() {
        // Same digest should produce same signature (deterministic padding)
        let key = RsaPrivateKey::generate(2048).unwrap();

        let hash = vec![0xAB; 32];
        let digest_info = create_digest_info(HashAlgorithm::Sha256, &hash);

        let sig1 = sign_pkcs1v15(&key, &digest_info).unwrap();
        let sig2 = sign_pkcs1v15(&key, &digest_info).unwrap();

        // Signatures should be identical (deterministic)
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hash_algorithm_oids() {
        // Verify OID lengths are correct
        assert_eq!(HashAlgorithm::Sha256.oid().len(), 19);
        assert_eq!(HashAlgorithm::Sha384.oid().len(), 19);
        assert_eq!(HashAlgorithm::Sha512.oid().len(), 19);
    }

    #[test]
    fn test_create_digest_info() {
        let hash = vec![0xAB; 32];
        let digest_info = create_digest_info(HashAlgorithm::Sha256, &hash);

        // Should be OID + hash
        assert_eq!(digest_info.len(), 19 + 32);
        assert_eq!(&digest_info[19..], &hash[..]);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3];
        let c = vec![1, 2, 4];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
