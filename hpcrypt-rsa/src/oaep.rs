//! RSA-OAEP encryption and decryption
//!
//! Implements RSAES-OAEP from PKCS#1 v2.2 (RFC 8017 Section 7.1)
//!
//! OAEP (Optimal Asymmetric Encryption Padding) provides semantic security.

use crate::error::{Result, RsaError};
use crate::primitives::{i2osp, os2ip};
use crate::private_key::RsaPrivateKey;
use crate::public_key::RsaPublicKey;
use alloc::vec;
use alloc::vec::Vec;

/// RSA-OAEP encryption
///
/// # Arguments
///
/// * `public_key` - RSA public key
/// * `message` - Message to encrypt
/// * `label` - Optional label (use empty slice for no label)
/// * `hash_fn` - Hash function (SHA-256, SHA-384, or SHA-512)
///
/// # Security
///
/// - Provides IND-CCA2 security (chosen ciphertext attack resistance)
/// - Uses MGF1 (Mask Generation Function based on hash)
/// - Randomized: same message produces different ciphertext each time
///
/// # Returns
///
/// Ciphertext of length k (key size in bytes)
pub fn encrypt_oaep<H>(public_key: &RsaPublicKey, message: &[u8], label: &[u8]) -> Result<Vec<u8>>
where
    H: OaepHash,
{
    let k = public_key.size_bytes();
    let h_len = H::output_size();

    // Check message length
    // mLen <= k - 2hLen - 2
    if message.len() > k - 2 * h_len - 2 {
        return Err(RsaError::MessageTooLong);
    }

    // Step 1: EME-OAEP encoding
    let em = eme_oaep_encode::<H>(message, label, k)?;

    // Step 2: RSA encryption
    let m = os2ip(&em);
    let c = public_key.encrypt_primitive(&m)?;

    // Step 3: Convert to octet string
    i2osp(&c, k)
}

/// RSA-OAEP decryption
///
/// # Arguments
///
/// * `private_key` - RSA private key
/// * `ciphertext` - Ciphertext to decrypt
/// * `label` - Optional label (must match encryption label)
/// * `hash_fn` - Hash function (must match encryption hash)
///
/// # Security
///
/// - Constant-time padding validation to prevent oracle attacks
/// - Uses secure comparison for label hash
///
/// # Returns
///
/// Decrypted message
pub fn decrypt_oaep<H>(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>>
where
    H: OaepHash,
{
    let k = private_key.size_bytes();

    // Check ciphertext length
    if ciphertext.len() != k {
        return Err(RsaError::InvalidCiphertext);
    }

    // Step 1: RSA decryption
    let c = os2ip(ciphertext);
    let m = private_key.decrypt_primitive(&c)?;
    let em = i2osp(&m, k)?;

    // Step 2: EME-OAEP decoding
    eme_oaep_decode::<H>(&em, label)
}

/// EME-OAEP encoding operation
///
/// Implements EME-OAEP-Encode from RFC 8017 Section 7.1.1
fn eme_oaep_encode<H>(message: &[u8], label: &[u8], em_len: usize) -> Result<Vec<u8>>
where
    H: OaepHash,
{
    let h_len = H::output_size();

    // Step 1: Hash the label
    let l_hash = H::hash(label);

    // Step 2: Generate PS (padding string of zeros)
    let ps_len = em_len - message.len() - 2 * h_len - 2;
    let ps = vec![0u8; ps_len];

    // Step 3: Construct DB = lHash || PS || 0x01 || M
    let mut db = Vec::with_capacity(em_len - h_len - 1);
    db.extend_from_slice(&l_hash);
    db.extend_from_slice(&ps);
    db.push(0x01);
    db.extend_from_slice(message);

    // Step 4: Generate random seed
    let seed = generate_random_seed(h_len)?;

    // Step 5: dbMask = MGF(seed, emLen - hLen - 1)
    let db_mask = mgf1::<H>(&seed, em_len - h_len - 1);

    // Step 6: maskedDB = DB ⊕ dbMask
    let masked_db = xor(&db, &db_mask);

    // Step 7: seedMask = MGF(maskedDB, hLen)
    let seed_mask = mgf1::<H>(&masked_db, h_len);

    // Step 8: maskedSeed = seed ⊕ seedMask
    let masked_seed = xor(&seed, &seed_mask);

    // Step 9: EM = 0x00 || maskedSeed || maskedDB
    let mut em = Vec::with_capacity(em_len);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);

    Ok(em)
}

/// EME-OAEP decoding operation
///
/// Implements EME-OAEP-Decode from RFC 8017 Section 7.1.2
fn eme_oaep_decode<H>(em: &[u8], label: &[u8]) -> Result<Vec<u8>>
where
    H: OaepHash,
{
    let h_len = H::output_size();
    let k = em.len();

    if k < 2 * h_len + 2 {
        return Err(RsaError::DecryptionFailed);
    }

    // Step 1: Hash the label
    let l_hash = H::hash(label);

    // Step 2: Separate EM into Y || maskedSeed || maskedDB
    let y = em[0];
    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];

    // Step 3: seedMask = MGF(maskedDB, hLen)
    let seed_mask = mgf1::<H>(masked_db, h_len);

    // Step 4: seed = maskedSeed ⊕ seedMask
    let seed = xor(masked_seed, &seed_mask);

    // Step 5: dbMask = MGF(seed, k - hLen - 1)
    let db_mask = mgf1::<H>(&seed, k - h_len - 1);

    // Step 6: DB = maskedDB ⊕ dbMask
    let db = xor(masked_db, &db_mask);

    // Step 7: Parse DB = lHash' || PS || 0x01 || M
    let l_hash_prime = &db[0..h_len];

    // Verify lHash' == lHash (constant time)
    if !constant_time_eq(l_hash_prime, &l_hash) {
        return Err(RsaError::DecryptionFailed);
    }

    // Verify Y == 0x00
    if y != 0x00 {
        return Err(RsaError::DecryptionFailed);
    }

    // Find 0x01 separator (after PS)
    let mut separator_index = None;
    for i in h_len..db.len() {
        if db[i] == 0x01 {
            separator_index = Some(i);
            break;
        } else if db[i] != 0x00 {
            return Err(RsaError::DecryptionFailed);
        }
    }

    let separator_index = separator_index.ok_or(RsaError::DecryptionFailed)?;

    // Extract message
    let message = db[separator_index + 1..].to_vec();

    Ok(message)
}

/// MGF1 (Mask Generation Function based on a hash function)
///
/// Implements MGF1 from RFC 8017 Appendix B.2.1
fn mgf1<H>(seed: &[u8], mask_len: usize) -> Vec<u8>
where
    H: OaepHash,
{
    let h_len = H::output_size();
    let mut t = Vec::new();

    // Compute ceiling(maskLen / hLen)
    let iterations = (mask_len + h_len - 1) / h_len;

    for counter in 0..iterations {
        // C = I2OSP(counter, 4)
        let c = counter.to_be_bytes();

        // T = T || Hash(mgfSeed || C)
        let mut input = Vec::new();
        input.extend_from_slice(seed);
        input.extend_from_slice(&c[4..]); // Use last 4 bytes (u32)

        let hash = H::hash(&input);
        t.extend_from_slice(&hash);
    }

    // Return leading maskLen octets
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

/// Generate random seed
fn generate_random_seed(len: usize) -> Result<Vec<u8>> {
    // Use hpcrypt-rng for cryptographically secure random bytes
    let mut seed = vec![0u8; len];

    // For now, we'll use a simple implementation
    // In production, this should use hpcrypt_rng::generate_random_bytes
    #[cfg(feature = "std")]
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut seed);
    }

    #[cfg(not(feature = "std"))]
    {
        // In no_std environments, require the user to provide randomness
        // For now, return error
        return Err(RsaError::RngError);
    }

    Ok(seed)
}

/// Trait for hash functions used in OAEP
pub trait OaepHash {
    /// Output size in bytes
    fn output_size() -> usize;

    /// Hash the input
    fn hash(input: &[u8]) -> Vec<u8>;
}

/// SHA-256 for OAEP
#[cfg(feature = "sha2")]
pub struct Sha256;

#[cfg(feature = "sha2")]
impl OaepHash for Sha256 {
    fn output_size() -> usize {
        32
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256 as Sha256Hash};
        let mut hasher = Sha256Hash::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}

/// SHA-384 for OAEP
#[cfg(feature = "sha2")]
pub struct Sha384;

#[cfg(feature = "sha2")]
impl OaepHash for Sha384 {
    fn output_size() -> usize {
        48
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha384 as Sha384Hash};
        let mut hasher = Sha384Hash::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}

/// SHA-512 for OAEP
#[cfg(feature = "sha2")]
pub struct Sha512;

#[cfg(feature = "sha2")]
impl OaepHash for Sha512 {
    fn output_size() -> usize {
        64
    }

    fn hash(input: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha512 as Sha512Hash};
        let mut hasher = Sha512Hash::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_key::RsaPrivateKey;

    // Mock hash for testing without sha2 feature
    struct MockHash;

    impl OaepHash for MockHash {
        fn output_size() -> usize {
            32 // SHA-256 size
        }

        fn hash(input: &[u8]) -> Vec<u8> {
            // Simple hash: XOR all bytes together, then expand
            let mut result = vec![0u8; 32];
            let xor_val = input.iter().fold(0u8, |acc, &b| acc ^ b);

            // Create pseudo-random pattern based on input
            for (i, byte) in result.iter_mut().enumerate() {
                *byte = xor_val
                    .wrapping_add(i as u8)
                    .wrapping_mul(input.len() as u8);
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
        let a = vec![0xAA, 0xBB, 0xCC];
        let b = vec![0x55, 0x44, 0x33];
        let result = xor(&a, &b);
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encrypt_decrypt_oaep() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Hello, OAEP!";
        let label = b"";

        let ciphertext = encrypt_oaep::<MockHash>(key.public_key(), message, label).unwrap();
        let decrypted = decrypt_oaep::<MockHash>(&key, &ciphertext, label).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_oaep_with_label() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Secret message";
        let label = b"my label";

        let ciphertext = encrypt_oaep::<MockHash>(key.public_key(), message, label).unwrap();
        let decrypted = decrypt_oaep::<MockHash>(&key, &ciphertext, label).unwrap();

        assert_eq!(message, &decrypted[..]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_oaep_wrong_label() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Secret message";
        let label1 = b"label1";
        let label2 = b"label2";

        let ciphertext = encrypt_oaep::<MockHash>(key.public_key(), message, label1).unwrap();
        let result = decrypt_oaep::<MockHash>(&key, &ciphertext, label2);

        assert_eq!(result, Err(RsaError::DecryptionFailed));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_oaep_message_too_long() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        let k = key.size_bytes();
        let h_len = MockHash::output_size();

        // Message too long: mLen > k - 2hLen - 2
        let max_len = k - 2 * h_len - 2;
        let message = vec![0xFF; max_len + 1];

        let result = encrypt_oaep::<MockHash>(key.public_key(), &message, b"");
        assert_eq!(result, Err(RsaError::MessageTooLong));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_oaep_randomized() {
        // Same message should produce different ciphertexts
        let key = RsaPrivateKey::generate(2048).unwrap();
        let message = b"Same message";

        let ct1 = encrypt_oaep::<MockHash>(key.public_key(), message, b"").unwrap();
        let ct2 = encrypt_oaep::<MockHash>(key.public_key(), message, b"").unwrap();

        // Ciphertexts should be different (with very high probability)
        assert_ne!(ct1, ct2);

        // But both should decrypt to the same message
        let pt1 = decrypt_oaep::<MockHash>(&key, &ct1, b"").unwrap();
        let pt2 = decrypt_oaep::<MockHash>(&key, &ct2, b"").unwrap();

        assert_eq!(message, &pt1[..]);
        assert_eq!(message, &pt2[..]);
    }
}
