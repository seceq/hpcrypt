//! ECIES implementation for NIST P-256 curve

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{EciesError, Result};
use hpcrypt_aead::aes_gcm::{Aes128Gcm, NONCE_SIZE, TAG_SIZE};
use hpcrypt_curves::p256::{AffinePoint, FieldElement, Point, Scalar};
use hpcrypt_kdf::x963_kdf_sha256;

/// ECIES implementation for P-256 curve
///
/// Uses:
/// - **KDF**: ANSI X9.63 with SHA-256
/// - **AEAD**: AES-128-GCM
/// - **Curve**: NIST P-256 (secp256r1)
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
/// use hpcrypt_ecies::EciesP256;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
///
/// // Generate recipient keypair
/// let (secret, public) = EciesP256::generate_keypair(&mut rng)?;
///
/// // Encrypt message
/// let message = b"Hello, ECIES!";
/// let ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng)?;
///
/// // Decrypt message
/// let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[])?;
/// assert_eq!(plaintext, message);
/// ```
pub struct EciesP256;

impl EciesP256 {
    /// Size of AES-128 key in bytes
    const AES_KEY_SIZE: usize = 16;

    /// Size of P-256 public key (uncompressed): 1 byte prefix + 32 bytes x + 32 bytes y
    const PUBLIC_KEY_SIZE: usize = 65;

    /// Size of P-256 scalar (private key)
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

    /// Decrypt a message using ECIES
    ///
    /// # Arguments
    ///
    /// * `recipient_secret_key` - Recipient's secret key (32 bytes)
    /// * `ciphertext` - Ciphertext produced by `encrypt`
    /// * `shared_info` - Optional shared information for KDF (must match encryption)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext or error if authentication fails
    pub fn decrypt(
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
        shared_info: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Parse ciphertext components
        if ciphertext.len() < Self::PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(EciesError::CiphertextTooShort);
        }

        let ephemeral_public_bytes = &ciphertext[..Self::PUBLIC_KEY_SIZE];
        let nonce_start = Self::PUBLIC_KEY_SIZE;
        let nonce_end = nonce_start + NONCE_SIZE;
        let nonce: [u8; NONCE_SIZE] = ciphertext[nonce_start..nonce_end]
            .try_into()
            .map_err(|_| EciesError::InvalidCiphertext)?;
        let encrypted_data_with_tag = &ciphertext[nonce_end..];

        // 2. Parse ephemeral public key
        let ephemeral_point = Self::decode_public_key(ephemeral_public_bytes)?;

        // 3. Parse recipient secret key
        if recipient_secret_key.len() != Self::SCALAR_SIZE {
            return Err(EciesError::InvalidPublicKey);
        }
        let secret_array: [u8; 32] = recipient_secret_key
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;
        let secret = Scalar::from_bytes(&secret_array);

        // 4. Compute shared secret: S = recipient_secret * ephemeral_public_key
        let secret_bytes: [u8; 32] = secret.to_bytes();
        let shared_point = ephemeral_point.scalar_mul(&secret_bytes);

        // Check for point at infinity
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

        // 6. Decrypt message with AES-128-GCM
        let plaintext = Aes128Gcm::decrypt(&aes_key, &nonce, encrypted_data_with_tag, &[])
            .map_err(|_| EciesError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Encode public key in uncompressed format: 0x04 || x || y
    fn encode_public_key(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine().ok_or(EciesError::InternalError)?;

        let mut encoded = Vec::with_capacity(Self::PUBLIC_KEY_SIZE);
        encoded.push(0x04); // Uncompressed point prefix
        encoded.extend_from_slice(&affine.x.to_bytes());
        encoded.extend_from_slice(&affine.y.to_bytes());

        Ok(encoded)
    }

    /// Decode public key from uncompressed format
    fn decode_public_key(bytes: &[u8]) -> Result<Point> {
        if bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(EciesError::InvalidPublicKey);
        }

        if bytes[0] != 0x04 {
            return Err(EciesError::InvalidPublicKey);
        }

        let x_bytes: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;
        let y_bytes: [u8; 32] = bytes[33..65]
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;

        let x = FieldElement::from_bytes(&x_bytes).ok_or(EciesError::InvalidPublicKey)?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(EciesError::InvalidPublicKey)?;

        let affine = AffinePoint { x, y };
        Ok(Point::from_affine(&affine))
    }

    /// Extract x-coordinate from point as bytes
    fn extract_x_coordinate(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine().ok_or(EciesError::InternalError)?;
        Ok(affine.x.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_ecies_p256_encrypt_decrypt() {
        use rand::thread_rng;
        let mut rng = thread_rng();

        // Generate recipient keypair
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        // Encrypt message
        let message = b"Hello, ECIES!";
        let shared_info = b"test";
        let ciphertext = EciesP256::encrypt(&public, message, shared_info, &mut rng).unwrap();

        // Decrypt message
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, shared_info).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_ecies_p256_empty_message() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        let message = b"";
        let ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_ecies_p256_long_message() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        let message = vec![0x42u8; 1024];
        let ciphertext = EciesP256::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_ecies_p256_wrong_shared_info() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        let message = b"Test message";
        let ciphertext = EciesP256::encrypt(&public, message, b"info1", &mut rng).unwrap();

        // Decryption with wrong shared_info should fail
        let result = EciesP256::decrypt(&secret, &ciphertext, b"info2");
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_p256_corrupted_ciphertext() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        let message = b"Test message";
        let mut ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();

        // Corrupt the ciphertext
        let idx = ciphertext.len() / 2;
        ciphertext[idx] ^= 0xFF;

        // Decryption should fail
        let result = EciesP256::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_p256_ciphertext_too_short() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, _) = EciesP256::generate_keypair(&mut rng).unwrap();

        let short_ciphertext = vec![0u8; 50]; // Too short
        let result = EciesP256::decrypt(&secret, &short_ciphertext, &[]);

        assert_eq!(result, Err(EciesError::CiphertextTooShort));
    }

    #[test]
    fn test_ecies_p256_randomization() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        let message = b"Same message";

        // Encrypt same message twice
        let ct1 = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();
        let ct2 = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();

        // Ciphertexts should be different (randomized)
        assert_ne!(ct1, ct2);

        // But both decrypt to same plaintext
        let pt1 = EciesP256::decrypt(&secret, &ct1, &[]).unwrap();
        let pt2 = EciesP256::decrypt(&secret, &ct2, &[]).unwrap();
        assert_eq!(pt1, message);
        assert_eq!(pt2, message);
    }
}
