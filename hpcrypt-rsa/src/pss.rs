//! RSA-PSS digital signatures
//!
//! Implements RSASSA-PSS from PKCS#1 v2.2 (RFC 8017 Section 8.1)
//!
//! PSS (Probabilistic Signature Scheme) is the recommended signature scheme for new applications.

use crate::error::{Result, RsaError};
use crate::primitives::{i2osp, os2ip};
use crate::private_key::RsaPrivateKey;
use crate::public_key::RsaPublicKey;
use alloc::vec;
use alloc::vec::Vec;

/// RSA-PSS signature generation
///
/// # Arguments
///
/// * `private_key` - RSA private key
/// * `message` - Message to sign
/// * `salt_len` - Salt length in bytes (typically hash length)
/// * `hash_fn` - Hash function (SHA-256, SHA-384, or SHA-512)
///
/// # Security
///
/// - Provably secure in the random oracle model
/// - Randomized: same message produces different signatures
/// - Recommended over PKCS#1 v1.5 for new applications
///
/// # Returns
///
/// Signature of length k (key size in bytes)
pub fn sign_pss<H>(private_key: &RsaPrivateKey, message: &[u8], salt_len: usize) -> Result<Vec<u8>>
where
    H: PssHash,
{
    let k = private_key.size_bytes();
    let h_len = H::output_size();

    // Check salt length
    // RFC 8017: typical salt length is hLen
    if salt_len > k - h_len - 2 {
        return Err(RsaError::InvalidPadding);
    }

    // Step 1: EMSA-PSS encoding
    let em_bits = (k * 8) - 1; // Modulus bit length - 1
    let em = emsa_pss_encode::<H>(message, em_bits, salt_len)?;

    // Step 2: RSA signature
    let m = os2ip(&em);
    let s = private_key.sign_primitive(&m)?;

    // Step 3: Convert to octet string
    i2osp(&s, k)
}

/// RSA-PSS signature verification
///
/// # Arguments
///
/// * `public_key` - RSA public key
/// * `message` - Message that was signed
/// * `signature` - Signature to verify
/// * `salt_len` - Salt length used during signing
/// * `hash_fn` - Hash function (must match signing hash)
///
/// # Returns
///
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_pss<H>(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
    salt_len: usize,
) -> Result<()>
where
    H: PssHash,
{
    let k = public_key.size_bytes();

    // Check signature length
    if signature.len() != k {
        return Err(RsaError::InvalidSignature);
    }

    // Step 1: RSA verification
    let s = os2ip(signature);
    let m = public_key.verify_primitive(&s)?;
    let em = i2osp(&m, k)?;

    // Step 2: EMSA-PSS verification
    let em_bits = (k * 8) - 1;
    emsa_pss_verify::<H>(message, &em, em_bits, salt_len)
}

/// EMSA-PSS encoding operation
///
/// Implements EMSA-PSS-Encode from RFC 8017 Section 9.1.1
fn emsa_pss_encode<H>(message: &[u8], em_bits: usize, s_len: usize) -> Result<Vec<u8>>
where
    H: PssHash,
{
    let h_len = H::output_size();
    let em_len = (em_bits + 7) / 8;

    // Step 1: Check message length (no explicit limit for PSS)

    // Step 2: Hash the message
    let m_hash = H::hash(message);

    // Step 3: Check emLen
    if em_len < h_len + s_len + 2 {
        return Err(RsaError::InvalidPadding);
    }

    // Step 4: Generate salt
    let salt = generate_salt(s_len)?;

    // Step 5: Construct M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::new();
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(&m_hash);
    m_prime.extend_from_slice(&salt);

    // Step 6: H = Hash(M')
    let h = H::hash(&m_prime);

    // Step 7: Generate PS (padding string of zeros)
    let ps_len = em_len - s_len - h_len - 2;
    let ps = vec![0u8; ps_len];

    // Step 8: Construct DB = PS || 0x01 || salt
    let mut db = Vec::new();
    db.extend_from_slice(&ps);
    db.push(0x01);
    db.extend_from_slice(&salt);

    // Step 9: dbMask = MGF(H, emLen - hLen - 1)
    let db_mask = mgf1::<H>(&h, em_len - h_len - 1);

    // Step 10: maskedDB = DB ⊕ dbMask
    let mut masked_db = xor(&db, &db_mask);

    // Step 11: Set leftmost 8emLen - emBits bits to zero
    let bits_to_zero = (8 * em_len - em_bits) as u8;
    if bits_to_zero > 0 {
        let mask = 0xFF >> bits_to_zero;
        masked_db[0] &= mask;
    }

    // Step 12: EM = maskedDB || H || 0xbc
    let mut em = Vec::new();
    em.extend_from_slice(&masked_db);
    em.extend_from_slice(&h);
    em.push(0xbc);

    Ok(em)
}

/// EMSA-PSS verification operation
///
/// Implements EMSA-PSS-Verify from RFC 8017 Section 9.1.2
fn emsa_pss_verify<H>(message: &[u8], em: &[u8], em_bits: usize, s_len: usize) -> Result<()>
where
    H: PssHash,
{
    let h_len = H::output_size();
    let em_len = (em_bits + 7) / 8;

    // Step 1: Hash the message
    let m_hash = H::hash(message);

    // Step 2: Check emLen
    if em_len < h_len + s_len + 2 {
        return Err(RsaError::VerificationFailed);
    }

    // Step 3: Check rightmost octet is 0xbc
    if em[em.len() - 1] != 0xbc {
        return Err(RsaError::VerificationFailed);
    }

    // Step 4: Extract maskedDB and H
    let masked_db = &em[0..em_len - h_len - 1];
    let h = &em[em_len - h_len - 1..em_len - 1];

    // Step 5: Check leftmost bits are zero
    let bits_to_check = (8 * em_len - em_bits) as u8;
    if bits_to_check > 0 {
        let mask = 0xFF << (8 - bits_to_check);
        if (masked_db[0] & mask) != 0 {
            return Err(RsaError::VerificationFailed);
        }
    }

    // Step 6: dbMask = MGF(H, emLen - hLen - 1)
    let db_mask = mgf1::<H>(h, em_len - h_len - 1);

    // Step 7: DB = maskedDB ⊕ dbMask
    let mut db = xor(masked_db, &db_mask);

    // Step 8: Set leftmost bits to zero
    if bits_to_check > 0 {
        let mask = 0xFF >> bits_to_check;
        db[0] &= mask;
    }

    // Step 9: Check DB structure: PS || 0x01 || salt
    let ps_len = em_len - h_len - s_len - 2;

    // Verify PS is all zeros
    for &byte in db.iter().take(ps_len) {
        if byte != 0x00 {
            return Err(RsaError::VerificationFailed);
        }
    }

    // Verify 0x01 separator
    if db[ps_len] != 0x01 {
        return Err(RsaError::VerificationFailed);
    }

    // Step 10: Extract salt
    let salt = &db[ps_len + 1..];

    // Step 11: Construct M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    let mut m_prime = Vec::new();
    m_prime.extend_from_slice(&[0u8; 8]);
    m_prime.extend_from_slice(&m_hash);
    m_prime.extend_from_slice(salt);

    // Step 12: H' = Hash(M')
    let h_prime = H::hash(&m_prime);

    // Step 13: Compare H == H' (constant time)
    if !constant_time_eq(h, &h_prime) {
        return Err(RsaError::VerificationFailed);
    }

    Ok(())
}

/// MGF1 (Mask Generation Function)
fn mgf1<H>(seed: &[u8], mask_len: usize) -> Vec<u8>
where
    H: PssHash,
{
    let h_len = H::output_size();
    let mut t = Vec::new();

    let iterations = (mask_len + h_len - 1) / h_len;

    for counter in 0..iterations {
        let c = (counter as u32).to_be_bytes();

        let mut input = Vec::new();
        input.extend_from_slice(seed);
        input.extend_from_slice(&c);

        let hash = H::hash(&input);
        t.extend_from_slice(&hash);
    }

    t.truncate(mask_len);
    t
}

/// XOR two byte slices
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
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

/// Generate random salt
fn generate_salt(len: usize) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; len];

    #[cfg(feature = "std")]
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
    }

    #[cfg(not(feature = "std"))]
    {
        return Err(RsaError::RngError);
    }

    Ok(salt)
}

/// Trait for hash functions used in PSS
pub trait PssHash {
    /// Output size in bytes
    fn output_size() -> usize;

    /// Hash the input
    fn hash(input: &[u8]) -> Vec<u8>;
}

/// SHA-256 for PSS
#[cfg(feature = "sha2")]
pub struct Sha256;

#[cfg(feature = "sha2")]
impl PssHash for Sha256 {
    fn output_size() -> usize {
        32
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use hpcrypt_hash::{HashFunction, Sha256 as Sha256Hash};
        Sha256Hash::hash(input).to_vec()
    }
}

/// SHA-384 for PSS
#[cfg(feature = "sha2")]
pub struct Sha384;

#[cfg(feature = "sha2")]
impl PssHash for Sha384 {
    fn output_size() -> usize {
        48
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use hpcrypt_hash::{HashFunction, Sha384 as Sha384Hash};
        Sha384Hash::hash(input).to_vec()
    }
}

/// SHA-512 for PSS
#[cfg(feature = "sha2")]
pub struct Sha512;

#[cfg(feature = "sha2")]
impl PssHash for Sha512 {
    fn output_size() -> usize {
        64
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use hpcrypt_hash::{HashFunction, Sha512 as Sha512Hash};
        Sha512Hash::hash(input).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_key::RsaPrivateKey;

    // Mock hash for testing
    struct MockHash;

    impl PssHash for MockHash {
        fn output_size() -> usize {
            32
        }

        fn hash(input: &[u8]) -> Vec<u8> {
            // Better mock hash that's sensitive to input changes
            let mut result = vec![0u8; 32];

            // Include length in hash
            let len_bytes = (input.len() as u32).to_be_bytes();
            for (i, &b) in len_bytes.iter().enumerate() {
                result[i] = b;
            }

            // XOR all input bytes with position-dependent mixing
            for (idx, &byte) in input.iter().enumerate() {
                let pos = (idx % 28) + 4; // Start after length bytes
                result[pos] ^= byte.wrapping_add(idx as u8);
            }

            // Additional mixing to spread changes
            for i in 0..32 {
                result[i] = result[i].wrapping_add(result[(i + 7) % 32]);
            }

            result
        }
    }

    #[test]
    fn test_mgf1() {
        let seed = b"test seed";
        let mask = mgf1::<MockHash>(seed, 64);
        assert_eq!(mask.len(), 64);
    }

    #[test]
    fn test_xor() {
        let a = vec![0xAA, 0xBB];
        let b = vec![0x55, 0x44];
        let result = xor(&a, &b);
        assert_eq!(result, vec![0xFF, 0xFF]);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3];
        let c = vec![1, 2, 4];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_sign_verify_pss() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Test message for PSS";
        let salt_len = MockHash::output_size();

        let signature = sign_pss::<MockHash>(&key, message, salt_len).unwrap();
        let result = verify_pss::<MockHash>(key.public_key(), message, &signature, salt_len);

        assert!(result.is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pss_wrong_message() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message1 = b"Original message";
        let message2 = b"Different message";
        let salt_len = MockHash::output_size();

        let signature = sign_pss::<MockHash>(&key, message1, salt_len).unwrap();
        let result = verify_pss::<MockHash>(key.public_key(), message2, &signature, salt_len);

        assert_eq!(result, Err(RsaError::VerificationFailed));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pss_randomized() {
        // Same message should produce different signatures
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Same message";
        let salt_len = MockHash::output_size();

        let sig1 = sign_pss::<MockHash>(&key, message, salt_len).unwrap();
        let sig2 = sign_pss::<MockHash>(&key, message, salt_len).unwrap();

        // Signatures should be different (randomized)
        assert_ne!(sig1, sig2);

        // But both should verify successfully
        assert!(verify_pss::<MockHash>(key.public_key(), message, &sig1, salt_len).is_ok());
        assert!(verify_pss::<MockHash>(key.public_key(), message, &sig2, salt_len).is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pss_invalid_signature() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Test message";
        let salt_len = MockHash::output_size();

        let mut signature = sign_pss::<MockHash>(&key, message, salt_len).unwrap();

        // Corrupt the signature
        signature[0] ^= 0x01;

        let result = verify_pss::<MockHash>(key.public_key(), message, &signature, salt_len);
        assert_eq!(result, Err(RsaError::VerificationFailed));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pss_signature_length() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Test";
        let salt_len = MockHash::output_size();

        let signature = sign_pss::<MockHash>(&key, message, salt_len).unwrap();

        // Signature should be same length as key
        assert_eq!(signature.len(), 256); // 2048 bits = 256 bytes
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_pss_different_salt_lengths() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Test message";

        // Test with different salt lengths
        for salt_len in [0, 16, 32, 48, 64] {
            let signature = sign_pss::<MockHash>(&key, message, salt_len).unwrap();
            let result = verify_pss::<MockHash>(key.public_key(), message, &signature, salt_len);
            assert!(result.is_ok(), "Failed with salt_len = {}", salt_len);
        }
    }
}
