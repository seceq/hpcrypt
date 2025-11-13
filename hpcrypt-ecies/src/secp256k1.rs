//! ECIES implementation for secp256k1 curve

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{EciesError, Result};
use hpcrypt_aead::aes_gcm::{Aes128Gcm, NONCE_SIZE, TAG_SIZE};
use hpcrypt_curves::secp256k1::{AffinePoint, FieldElement, Point, Scalar};
use hpcrypt_kdf::x963_kdf_sha256;

/// ECIES implementation for secp256k1 curve
///
/// Uses:
/// - **KDF**: ANSI X9.63 with SHA-256
/// - **AEAD**: AES-128-GCM
/// - **Curve**: secp256k1 (Bitcoin/Ethereum)
///
/// # Security
///
/// - IND-CCA2 secure (indistinguishable under adaptive chosen-ciphertext attack)
/// - Forward secrecy through ephemeral keys
/// - Authenticated encryption via AES-GCM
///
/// # Example
///
/// ```rust,ignore
/// use hpcrypt_ecies::EciesSecp256k1;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
///
/// // Generate recipient keypair
/// let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng)?;
///
/// // Encrypt message
/// let message = b"Hello, Bitcoin!";
/// let ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng)?;
///
/// // Decrypt message
/// let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[])?;
/// assert_eq!(plaintext, message);
/// ```
pub struct EciesSecp256k1;

impl EciesSecp256k1 {
    /// Size of AES-128 key in bytes
    const AES_KEY_SIZE: usize = 16;

    /// Size of secp256k1 public key (uncompressed): 1 byte prefix + 32 bytes x + 32 bytes y
    const PUBLIC_KEY_SIZE: usize = 65;

    /// Size of secp256k1 public key (compressed): 1 byte prefix + 32 bytes x
    const PUBLIC_KEY_SIZE_COMPRESSED: usize = 33;

    /// Size of secp256k1 scalar (private key)
    const SCALAR_SIZE: usize = 32;

    /// Generate a keypair for ECIES
    ///
    /// Returns `(secret_key, public_key)` where:
    /// - `secret_key`: 32-byte scalar
    /// - `public_key`: 65-byte uncompressed point (0x04 || x || y)
    pub fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate random scalar (32 bytes)
        let mut secret_bytes = [0u8; Self::SCALAR_SIZE];
        rng.fill(&mut secret_bytes[..]);

        // Create scalar from bytes
        let secret = Scalar::from_bytes(&secret_bytes);

        // Compute public key: Q = secret * G
        let secret_bytes_array: [u8; 32] = secret.to_bytes();
        let public_point = Point::generator().scalar_mul(&secret_bytes_array);

        // Encode public key (uncompressed format)
        let public_bytes = Self::encode_public_key(&public_point)?;

        Ok((secret_bytes.to_vec(), public_bytes))
    }

    /// Encrypt a message using ECIES
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - Recipient's public key (65 bytes, uncompressed)
    /// * `message` - Message to encrypt
    /// * `shared_info` - Optional shared information for KDF
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// Ciphertext format: `ephemeral_public_key || nonce || encrypted_data || tag`
    /// - ephemeral_public_key: 65 bytes
    /// - nonce: 12 bytes
    /// - encrypted_data: same length as message
    /// - tag: 16 bytes
    ///
    /// Total overhead: 65 + 12 + 16 = 93 bytes
    pub fn encrypt<R: rand::Rng>(
        recipient_public_key: &[u8],
        message: &[u8],
        shared_info: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        // 1. Parse recipient public key
        let recipient_point = Self::decode_public_key(recipient_public_key)?;

        // 2. Generate ephemeral keypair
        let (ephemeral_secret_bytes, ephemeral_public_bytes) = Self::generate_keypair(rng)?;
        let ephemeral_secret = Scalar::from_bytes(&ephemeral_secret_bytes.try_into().unwrap());

        // 3. Compute shared secret: S = ephemeral_secret * recipient_public_key
        let ephemeral_secret_bytes: [u8; 32] = ephemeral_secret.to_bytes();
        let shared_point = recipient_point.scalar_mul(&ephemeral_secret_bytes);

        // Check for point at infinity (should never happen with valid keys)
        if bool::from(shared_point.is_infinity()) {
            return Err(EciesError::SharedSecretFailed);
        }

        // Extract x-coordinate as shared secret
        let shared_secret = Self::extract_x_coordinate(&shared_point)?;

        // 4. Derive encryption key using X9.63 KDF
        let key_material = x963_kdf_sha256(&shared_secret, shared_info, Self::AES_KEY_SIZE);
        let aes_key: [u8; 16] = key_material
            .try_into()
            .map_err(|_| EciesError::KeyDerivationFailed)?;

        // 5. Generate random nonce for AES-GCM
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce[..]);

        // 6. Encrypt message with AES-128-GCM (no additional authenticated data)
        let ciphertext_with_tag = Aes128Gcm::encrypt(&aes_key, &nonce, message, &[]);

        // 7. Construct output: ephemeral_public_key || nonce || ciphertext || tag
        let mut output =
            Vec::with_capacity(Self::PUBLIC_KEY_SIZE + NONCE_SIZE + ciphertext_with_tag.len());
        output.extend_from_slice(&ephemeral_public_bytes);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext_with_tag);

        Ok(output)
    }

    /// Encrypt a message using ECIES with compressed ephemeral public key
    ///
    /// This variant uses compressed ephemeral keys (33 bytes) instead of uncompressed (65 bytes),
    /// reducing overhead from 93 to 61 bytes (35% reduction).
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - Recipient's public key (65 bytes uncompressed or 33 bytes compressed)
    /// * `message` - Message to encrypt
    /// * `shared_info` - Optional shared information for KDF
    /// * `rng` - Random number generator
    ///
    /// # Returns
    ///
    /// Ciphertext format: `ephemeral_public_key_compressed || nonce || encrypted_data || tag`
    /// - ephemeral_public_key_compressed: 33 bytes
    /// - nonce: 12 bytes
    /// - encrypted_data: same length as message
    /// - tag: 16 bytes
    ///
    /// Total overhead: 33 + 12 + 16 = 61 bytes (vs 93 bytes for uncompressed)
    pub fn encrypt_compressed<R: rand::Rng>(
        recipient_public_key: &[u8],
        message: &[u8],
        shared_info: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        // 1. Parse recipient public key (accept both compressed and uncompressed)
        let recipient_point = Self::decode_public_key_flexible(recipient_public_key)?;

        // 2. Generate ephemeral keypair
        let (ephemeral_secret_bytes, _) = Self::generate_keypair(rng)?;
        let ephemeral_secret = Scalar::from_bytes(&ephemeral_secret_bytes.try_into().unwrap());

        // Compute ephemeral public key
        let ephemeral_secret_array: [u8; 32] = ephemeral_secret.to_bytes();
        let ephemeral_public_point = Point::generator().scalar_mul(&ephemeral_secret_array);

        // Encode as compressed
        let ephemeral_public_bytes = Self::encode_public_key_compressed(&ephemeral_public_point)?;

        // 3. Compute shared secret: S = ephemeral_secret * recipient_public_key
        let shared_point = recipient_point.scalar_mul(&ephemeral_secret_array);

        // Check for point at infinity (should never happen with valid keys)
        if bool::from(shared_point.is_infinity()) {
            return Err(EciesError::SharedSecretFailed);
        }

        // Extract x-coordinate as shared secret
        let shared_secret = Self::extract_x_coordinate(&shared_point)?;

        // 4. Derive encryption key using X9.63 KDF
        let key_material = x963_kdf_sha256(&shared_secret, shared_info, Self::AES_KEY_SIZE);
        let aes_key: [u8; 16] = key_material
            .try_into()
            .map_err(|_| EciesError::KeyDerivationFailed)?;

        // 5. Generate random nonce for AES-GCM
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce[..]);

        // 6. Encrypt message with AES-128-GCM (no additional authenticated data)
        let ciphertext_with_tag = Aes128Gcm::encrypt(&aes_key, &nonce, message, &[]);

        // 7. Construct output: ephemeral_public_key_compressed || nonce || ciphertext || tag
        let mut output = Vec::with_capacity(
            Self::PUBLIC_KEY_SIZE_COMPRESSED + NONCE_SIZE + ciphertext_with_tag.len(),
        );
        output.extend_from_slice(&ephemeral_public_bytes);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext_with_tag);

        Ok(output)
    }

    /// Decrypt a message using ECIES
    ///
    /// Automatically detects compressed (33 bytes) or uncompressed (65 bytes) ephemeral keys.
    ///
    /// # Arguments
    ///
    /// * `recipient_secret_key` - Recipient's secret key (32 bytes)
    /// * `ciphertext` - Ciphertext produced by `encrypt` or `encrypt_compressed`
    /// * `shared_info` - Optional shared information for KDF (must match encryption)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext message
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Ciphertext is too short or malformed
    /// - Authentication tag verification fails
    /// - Key derivation fails
    pub fn decrypt(
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
        shared_info: &[u8],
    ) -> Result<Vec<u8>> {
        // Check minimum ciphertext size (compressed is smaller)
        let min_size_compressed = Self::PUBLIC_KEY_SIZE_COMPRESSED + NONCE_SIZE + TAG_SIZE;
        if ciphertext.len() < min_size_compressed {
            return Err(EciesError::InvalidCiphertext);
        }

        // Auto-detect compressed vs uncompressed format by checking first byte
        let (ephemeral_public_bytes, nonce_start) = match ciphertext[0] {
            0x02 | 0x03 => {
                // Compressed format (33 bytes)
                (
                    &ciphertext[..Self::PUBLIC_KEY_SIZE_COMPRESSED],
                    Self::PUBLIC_KEY_SIZE_COMPRESSED,
                )
            }
            0x04 => {
                // Uncompressed format (65 bytes)
                let min_size_uncompressed = Self::PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE;
                if ciphertext.len() < min_size_uncompressed {
                    return Err(EciesError::InvalidCiphertext);
                }
                (&ciphertext[..Self::PUBLIC_KEY_SIZE], Self::PUBLIC_KEY_SIZE)
            }
            _ => return Err(EciesError::InvalidPublicKey),
        };

        // 1. Parse ciphertext components
        let nonce = &ciphertext[nonce_start..nonce_start + NONCE_SIZE];
        let encrypted_data_and_tag = &ciphertext[nonce_start + NONCE_SIZE..];

        // 2. Parse ephemeral public key (flexible: compressed or uncompressed)
        let ephemeral_public_point = Self::decode_public_key_flexible(ephemeral_public_bytes)?;

        // 3. Parse recipient secret key
        if recipient_secret_key.len() != Self::SCALAR_SIZE {
            return Err(EciesError::InvalidCiphertext);
        }
        let secret_bytes: [u8; 32] = recipient_secret_key.try_into().unwrap();
        let secret = Scalar::from_bytes(&secret_bytes);

        // 4. Compute shared secret: S = recipient_secret * ephemeral_public_key
        let secret_bytes_array: [u8; 32] = secret.to_bytes();
        let shared_point = ephemeral_public_point.scalar_mul(&secret_bytes_array);

        // Check for point at infinity (should never happen with valid keys)
        if bool::from(shared_point.is_infinity()) {
            return Err(EciesError::SharedSecretFailed);
        }

        // Extract x-coordinate as shared secret
        let shared_secret = Self::extract_x_coordinate(&shared_point)?;

        // 5. Derive encryption key using X9.63 KDF
        let key_material = x963_kdf_sha256(&shared_secret, shared_info, Self::AES_KEY_SIZE);
        let aes_key: [u8; 16] = key_material
            .try_into()
            .map_err(|_| EciesError::KeyDerivationFailed)?;

        // 6. Decrypt and verify with AES-128-GCM
        let nonce_array: [u8; NONCE_SIZE] = nonce.try_into().unwrap();
        let plaintext = Aes128Gcm::decrypt(&aes_key, &nonce_array, encrypted_data_and_tag, &[])
            .map_err(|_| EciesError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Encode a point as uncompressed public key (0x04 || x || y)
    fn encode_public_key(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine().ok_or(EciesError::InvalidPublicKey)?;

        let x_bytes = affine.x.to_bytes();
        let y_bytes = affine.y.to_bytes();

        let mut output = Vec::with_capacity(Self::PUBLIC_KEY_SIZE);
        output.push(0x04); // Uncompressed point prefix
        output.extend_from_slice(&x_bytes);
        output.extend_from_slice(&y_bytes);

        Ok(output)
    }

    /// Decode uncompressed public key to point
    fn decode_public_key(bytes: &[u8]) -> Result<Point> {
        if bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(EciesError::InvalidPublicKey);
        }

        if bytes[0] != 0x04 {
            return Err(EciesError::InvalidPublicKey);
        }

        let x_bytes: [u8; 32] = bytes[1..33].try_into().unwrap();
        let y_bytes: [u8; 32] = bytes[33..65].try_into().unwrap();

        let x = FieldElement::from_bytes(&x_bytes);
        let y = FieldElement::from_bytes(&y_bytes);

        let point = Point::from_affine(&AffinePoint { x, y });

        // Verify point is on curve
        if !bool::from(point.is_on_curve()) {
            return Err(EciesError::InvalidPublicKey);
        }

        Ok(point)
    }

    /// Extract X-coordinate from shared secret point
    fn extract_x_coordinate(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine().ok_or(EciesError::SharedSecretFailed)?;

        Ok(affine.x.to_bytes().to_vec())
    }

    /// Encode a point as compressed public key (0x02/0x03 || x)
    fn encode_public_key_compressed(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine().ok_or(EciesError::InvalidPublicKey)?;

        let compressed = affine.to_compressed_bytes();
        Ok(compressed.to_vec())
    }

    /// Decode compressed public key to point
    fn decode_public_key_compressed(bytes: &[u8]) -> Result<Point> {
        if bytes.len() != Self::PUBLIC_KEY_SIZE_COMPRESSED {
            return Err(EciesError::InvalidPublicKey);
        }

        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(EciesError::InvalidPublicKey);
        }

        let compressed_array: [u8; 33] = bytes.try_into().unwrap();
        let affine = AffinePoint::from_compressed_bytes(&compressed_array)
            .ok_or(EciesError::InvalidPublicKey)?;

        let point = Point::from_affine(&affine);

        // Verify point is on curve (should already be verified, but double-check)
        if !bool::from(point.is_on_curve()) {
            return Err(EciesError::InvalidPublicKey);
        }

        Ok(point)
    }

    /// Decode public key (flexible: compressed or uncompressed)
    fn decode_public_key_flexible(bytes: &[u8]) -> Result<Point> {
        match bytes.len() {
            33 => Self::decode_public_key_compressed(bytes),
            65 => Self::decode_public_key(bytes),
            _ => Err(EciesError::InvalidPublicKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::thread_rng;

    #[test]
    fn test_generate_keypair() {
        let mut rng = thread_rng();
        let result = EciesSecp256k1::generate_keypair(&mut rng);
        assert!(result.is_ok());

        let (secret, public) = result.unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04); // Uncompressed prefix
    }

    #[test]
    fn test_encrypt_decrypt_basic() {
        let mut rng = thread_rng();

        // Generate recipient keypair
        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        // Encrypt message
        let message = b"Hello, Bitcoin!";
        let ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();

        // Verify ciphertext has correct overhead
        assert_eq!(ciphertext.len(), message.len() + 93); // 65 + 12 + 16

        // Decrypt message
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_encrypt_decrypt_with_shared_info() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";
        let shared_info = b"context-123";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, shared_info).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_shared_info() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, b"info1", &mut rng).unwrap();
        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, b"info2");

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_modified_ciphertext() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let mut ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();

        // Modify last byte (part of tag)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fails_with_short_ciphertext() {
        let (secret, _) = EciesSecp256k1::generate_keypair(&mut thread_rng()).unwrap();

        let short_ciphertext = vec![0u8; 50]; // Too short
        let result = EciesSecp256k1::decrypt(&secret, &short_ciphertext, &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_message() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        assert_eq!(ciphertext.len(), 93); // Just overhead, no data
    }

    #[test]
    fn test_encrypt_large_message() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 10000]; // 10 KB

        let ciphertext = EciesSecp256k1::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
    }

    // ========== Compressed Key Tests ==========

    #[test]
    fn test_encrypt_compressed_basic() {
        let mut rng = thread_rng();

        // Generate recipient keypair
        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        // Encrypt with compressed ephemeral key
        let message = b"Hello, Bitcoin with compression!";
        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Verify ciphertext has reduced overhead (61 bytes instead of 93)
        assert_eq!(ciphertext.len(), message.len() + 61); // 33 + 12 + 16

        // Verify first byte indicates compressed format
        assert!(ciphertext[0] == 0x02 || ciphertext[0] == 0x03);

        // Decrypt should work automatically
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_encrypt_compressed_with_shared_info() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Message with context";
        let shared_info = b"bitcoin-context-v1";

        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, shared_info).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_decrypt_auto_detects_compressed() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Test message";

        // Encrypt with compressed key
        let ct_compressed =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Encrypt with uncompressed key
        let ct_uncompressed = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();

        // Decrypt should handle both formats
        let pt_compressed = EciesSecp256k1::decrypt(&secret, &ct_compressed, &[]).unwrap();
        let pt_uncompressed = EciesSecp256k1::decrypt(&secret, &ct_uncompressed, &[]).unwrap();

        assert_eq!(pt_compressed, message);
        assert_eq!(pt_uncompressed, message);

        // Verify size difference
        assert_eq!(ct_compressed.len(), message.len() + 61);
        assert_eq!(ct_uncompressed.len(), message.len() + 93);
        assert_eq!(ct_uncompressed.len() - ct_compressed.len(), 32); // 32-byte Y coordinate saved
    }

    #[test]
    fn test_compress_reduces_overhead() {
        let mut rng = thread_rng();

        let (_, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Same message for both";

        let ct_compressed =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();
        let ct_uncompressed = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();

        // Compressed saves 32 bytes (entire Y coordinate)
        assert_eq!(ct_uncompressed.len() - ct_compressed.len(), 32);

        // Overhead reduction: 93 -> 61 = 35% reduction
        let overhead_uncompressed = 93;
        let overhead_compressed = 61;
        let reduction_pct =
            (overhead_uncompressed - overhead_compressed) * 100 / overhead_uncompressed;
        assert_eq!(reduction_pct, 34); // ~35% reduction
    }

    #[test]
    fn test_encrypted_compressed_empty_message() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        assert_eq!(ciphertext.len(), 61); // Just overhead, no data
    }

    #[test]
    fn test_encrypted_compressed_large_message() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 10000]; // 10 KB

        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        assert_eq!(ciphertext.len(), message.len() + 61);
    }

    #[test]
    fn test_decrypt_compressed_fails_with_wrong_shared_info() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, b"info1", &mut rng).unwrap();
        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, b"info2");

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_compressed_fails_with_tampered_ciphertext() {
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let mut ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Modify last byte (part of tag)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;

        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_compressed_with_compressed_recipient_key() {
        let mut rng = thread_rng();

        // Generate keypair and get compressed public key
        let (secret, public_uncompressed) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        // Extract compressed public key
        let x_bytes: [u8; 32] = public_uncompressed[1..33].try_into().unwrap();
        let y_bytes: [u8; 32] = public_uncompressed[33..65].try_into().unwrap();
        let x = FieldElement::from_bytes(&x_bytes);
        let y = FieldElement::from_bytes(&y_bytes);
        let affine = AffinePoint { x, y };
        let public_compressed = affine.to_compressed_bytes();

        // Encrypt using compressed recipient key
        let message = b"Test with compressed recipient key";
        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public_compressed, message, &[], &mut rng).unwrap();

        // Decrypt should work
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_decrypt_rejects_invalid_compressed_prefix() {
        let (secret, _) = EciesSecp256k1::generate_keypair(&mut thread_rng()).unwrap();

        // Create malformed ciphertext with invalid prefix
        let mut malformed = vec![0u8; 61];
        malformed[0] = 0x05; // Invalid prefix (not 0x02, 0x03, or 0x04)

        let result = EciesSecp256k1::decrypt(&secret, &malformed, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_compressed_ciphertext_format() {
        let mut rng = thread_rng();

        let (_, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Format test";

        let ciphertext =
            EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Verify format: compressed_key (33) || nonce (12) || encrypted (11) || tag (16)
        assert_eq!(ciphertext.len(), 33 + 12 + message.len() + 16);

        // Check compressed key prefix
        assert!(ciphertext[0] == 0x02 || ciphertext[0] == 0x03);

        // Ciphertext should be 32 bytes smaller than uncompressed
        let ct_uncompressed = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        assert_eq!(ct_uncompressed.len() - ciphertext.len(), 32);
    }
}
