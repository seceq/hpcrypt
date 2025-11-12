//! ECIES implementation for NIST P-521 curve

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{EciesError, Result};
use hpcrypt_curves::p521::{Point, Scalar, FieldElement};
use hpcrypt_kdf::x963_kdf_sha512;
use hpcrypt_aead::aes_gcm::{Aes256Gcm, NONCE_SIZE, TAG_SIZE};

/// ECIES implementation for P-521 curve
///
/// Uses:
/// - **KDF**: ANSI X9.63 with SHA-512
/// - **AEAD**: AES-256-GCM
/// - **Curve**: NIST P-521 (secp521r1)
///
/// # Security
///
/// - IND-CCA2 secure
/// - 256-bit security level
/// - Forward secrecy through ephemeral keys
pub struct EciesP521;

impl EciesP521 {
    /// Size of AES-256 key in bytes
    const AES_KEY_SIZE: usize = 32;
    
    /// Size of P-521 public key (uncompressed): 1 byte prefix + 66 bytes x + 66 bytes y
    const PUBLIC_KEY_SIZE: usize = 133;
    
    /// Size of P-521 scalar (private key)
    const SCALAR_SIZE: usize = 66;
    
    /// Generate a keypair for ECIES
    pub fn generate_keypair<R: rand::Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut secret_bytes = [0u8; Self::SCALAR_SIZE];
        rng.fill(&mut secret_bytes[..]);

        let secret = Scalar::from_bytes(&secret_bytes);
        let public_point = Point::generator().scalar_mul(&secret);

        let public_bytes = Self::encode_public_key(&public_point)?;

        Ok((secret_bytes.to_vec(), public_bytes))
    }
    
    /// Encrypt a message using ECIES
    pub fn encrypt<R: rand::Rng>(
        recipient_public_key: &[u8],
        message: &[u8],
        shared_info: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let recipient_point = Self::decode_public_key(recipient_public_key)?;
        let (ephemeral_secret_bytes, ephemeral_public_bytes) = Self::generate_keypair(rng)?;
        let ephemeral_secret = Scalar::from_bytes(
            &ephemeral_secret_bytes.as_slice().try_into()
                .map_err(|_| EciesError::InternalError)?
        );

        let shared_point = recipient_point.scalar_mul(&ephemeral_secret);
        
        if bool::from(shared_point.is_infinity()) {
            return Err(EciesError::SharedSecretFailed);
        }
        
        let shared_secret = Self::extract_x_coordinate(&shared_point)?;
        let key_material = x963_kdf_sha512(&shared_secret, shared_info, Self::AES_KEY_SIZE);
        let aes_key: [u8; 32] = key_material.try_into()
            .map_err(|_| EciesError::KeyDerivationFailed)?;
        
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill(&mut nonce[..]);
        
        let ciphertext_with_tag = Aes256Gcm::encrypt(&aes_key, &nonce, message, &[]);
        
        let mut output = Vec::with_capacity(
            Self::PUBLIC_KEY_SIZE + NONCE_SIZE + ciphertext_with_tag.len()
        );
        output.extend_from_slice(&ephemeral_public_bytes);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext_with_tag);
        
        Ok(output)
    }
    
    /// Decrypt a message using ECIES
    pub fn decrypt(
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
        shared_info: &[u8],
    ) -> Result<Vec<u8>> {
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
        
        let ephemeral_point = Self::decode_public_key(ephemeral_public_bytes)?;
        
        if recipient_secret_key.len() != Self::SCALAR_SIZE {
            return Err(EciesError::InvalidPublicKey);
        }
        let secret_array: [u8; 66] = recipient_secret_key
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;
        let secret = Scalar::from_bytes(&secret_array);

        let shared_point = ephemeral_point.scalar_mul(&secret);
        
        if bool::from(shared_point.is_infinity()) {
            return Err(EciesError::SharedSecretFailed);
        }
        
        let shared_secret = Self::extract_x_coordinate(&shared_point)?;
        let key_material = x963_kdf_sha512(&shared_secret, shared_info, Self::AES_KEY_SIZE);
        let aes_key: [u8; 32] = key_material.try_into()
            .map_err(|_| EciesError::KeyDerivationFailed)?;
        
        let plaintext = Aes256Gcm::decrypt(&aes_key, &nonce, encrypted_data_with_tag, &[])
            .map_err(|_| EciesError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
    
    fn encode_public_key(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine()
            .ok_or(EciesError::InternalError)?;

        let mut encoded = Vec::with_capacity(Self::PUBLIC_KEY_SIZE);
        encoded.push(0x04);
        encoded.extend_from_slice(&affine.x.to_bytes());
        encoded.extend_from_slice(&affine.y.to_bytes());

        Ok(encoded)
    }
    
    fn decode_public_key(bytes: &[u8]) -> Result<Point> {
        if bytes.len() != Self::PUBLIC_KEY_SIZE || bytes[0] != 0x04 {
            return Err(EciesError::InvalidPublicKey);
        }

        let x_bytes: [u8; 66] = bytes[1..67]
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;
        let y_bytes: [u8; 66] = bytes[67..133]
            .try_into()
            .map_err(|_| EciesError::InvalidPublicKey)?;

        let x = FieldElement::from_bytes(&x_bytes)
            .ok_or(EciesError::InvalidPublicKey)?;
        let y = FieldElement::from_bytes(&y_bytes)
            .ok_or(EciesError::InvalidPublicKey)?;

        Point::from_affine(&x, &y)
            .ok_or(EciesError::InvalidPublicKey)
    }
    
    fn extract_x_coordinate(point: &Point) -> Result<Vec<u8>> {
        let affine = point.to_affine()
            .ok_or(EciesError::InternalError)?;
        Ok(affine.x.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    
    #[test]
    fn test_ecies_p521_encrypt_decrypt() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"Hello, ECIES P-521!";
        let ciphertext = EciesP521::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, &[]).unwrap();
        
        assert_eq!(plaintext, message);
    }
    
    #[test]
    fn test_ecies_p521_large_message() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        
        let message = vec![0xAAu8; 4096];
        let ciphertext = EciesP521::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, &[]).unwrap();
        
        assert_eq!(plaintext, message);
    }
    
    #[test]
    fn test_ecies_p521_with_shared_info() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        
        let message = b"Secure message";
        let shared_info = b"context-data";
        let ciphertext = EciesP521::encrypt(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, shared_info).unwrap();
        
        assert_eq!(plaintext, message);
    }
    
    #[test]
    fn test_ecies_p521_authentication_failure() {
        use rand::thread_rng;
        let mut rng = thread_rng();
        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        
        let message = b"Test";
        let mut ciphertext = EciesP521::encrypt(&public, message, &[], &mut rng).unwrap();
        
        let idx = ciphertext.len() - 5;
        ciphertext[idx] ^= 0x01;
        
        let result = EciesP521::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
    }
}
