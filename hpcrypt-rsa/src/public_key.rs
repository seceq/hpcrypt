//! RSA public key operations

use crate::error::{Result, RsaError};
use crate::primitives::{i2osp, os2ip, rsaep, rsavp1};
use alloc::vec::Vec;
use num_bigint::BigUint;

/// RSA public key
///
/// Contains the public modulus `n` and public exponent `e`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Modulus n = p * q
    pub(crate) n: BigUint,
    /// Public exponent e (typically 65537)
    pub(crate) e: BigUint,
}

impl RsaPublicKey {
    /// Create a new RSA public key
    ///
    /// # Arguments
    ///
    /// * `n` - Modulus (product of two primes)
    /// * `e` - Public exponent (must be odd and > 2)
    ///
    /// # Security
    ///
    /// This constructor does NOT validate that n is a product of primes.
    /// Use `RsaPrivateKey::generate()` for secure key generation.
    pub fn new(n: BigUint, e: BigUint) -> Result<Self> {
        // Basic validation
        if e < BigUint::from(3u32) {
            return Err(RsaError::InvalidPublicExponent);
        }

        if !e.bit(0) {
            // e must be odd
            return Err(RsaError::InvalidPublicExponent);
        }

        if n.bits() < 2048 {
            return Err(RsaError::InvalidKeySize);
        }

        Ok(Self { n, e })
    }

    /// Get the modulus
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Get the public exponent
    pub fn e(&self) -> &BigUint {
        &self.e
    }

    /// Get the key size in bits
    pub fn size(&self) -> usize {
        self.n.bits() as usize
    }

    /// Get the key size in bytes
    pub fn size_bytes(&self) -> usize {
        (self.size() + 7) / 8
    }

    /// Encrypt a message using RSAEP primitive
    ///
    /// This is a low-level operation. For actual encryption, use RSA-OAEP.
    ///
    /// # Arguments
    ///
    /// * `m` - Message representative (must be < n)
    ///
    /// # Returns
    ///
    /// Ciphertext c = m^e mod n
    pub(crate) fn encrypt_primitive(&self, m: &BigUint) -> Result<BigUint> {
        rsaep(&self.n, &self.e, m)
    }

    /// Verify a signature using RSAVP1 primitive
    ///
    /// This is a low-level operation. For actual verification, use RSA-PSS or PKCS#1 v1.5.
    ///
    /// # Arguments
    ///
    /// * `s` - Signature (must be < n)
    ///
    /// # Returns
    ///
    /// Message representative m = s^e mod n
    pub(crate) fn verify_primitive(&self, s: &BigUint) -> Result<BigUint> {
        rsavp1(&self.n, &self.e, s)
    }

    /// Encrypt raw bytes using RSAEP
    ///
    /// # Warning
    ///
    /// This performs textbook RSA encryption, which is NOT semantically secure.
    /// Use RSA-OAEP for actual encryption.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to encrypt (length must be < key size in bytes)
    #[allow(dead_code)]
    pub(crate) fn encrypt_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        let k = self.size_bytes();

        if data.len() >= k {
            return Err(RsaError::MessageTooLong);
        }

        let m = os2ip(data);
        let c = self.encrypt_primitive(&m)?;
        i2osp(&c, k)
    }

    /// Verify a signature and return the message representative
    ///
    /// # Warning
    ///
    /// This is a low-level operation. Use the signature scheme wrappers instead.
    #[allow(dead_code)]
    pub(crate) fn verify_raw(&self, signature: &[u8]) -> Result<Vec<u8>> {
        let k = self.size_bytes();

        if signature.len() != k {
            return Err(RsaError::InvalidSignature);
        }

        let s = os2ip(signature);
        let m = self.verify_primitive(&s)?;
        i2osp(&m, k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_keypair_default;
    use alloc::vec;

    #[test]
    fn test_public_key_creation() {
        let (n, e, _d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();
        let public_key = RsaPublicKey::new(n.clone(), e.clone()).unwrap();

        assert_eq!(public_key.n(), &n);
        assert_eq!(public_key.e(), &e);
        assert_eq!(public_key.size(), 2048);
        assert_eq!(public_key.size_bytes(), 256);
    }

    #[test]
    fn test_invalid_exponent() {
        let (n, _e, _d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();

        // Even exponent
        assert_eq!(
            RsaPublicKey::new(n.clone(), BigUint::from(4u32)),
            Err(RsaError::InvalidPublicExponent)
        );

        // Too small exponent
        assert_eq!(
            RsaPublicKey::new(n, BigUint::from(2u32)),
            Err(RsaError::InvalidPublicExponent)
        );
    }

    #[test]
    fn test_encrypt_decrypt_primitive() {
        let (n, e, d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();
        let public_key = RsaPublicKey::new(n.clone(), e).unwrap();

        // Encrypt with public key
        let msg = BigUint::from(42u32);
        let ciphertext = public_key.encrypt_primitive(&msg).unwrap();

        // Decrypt with private exponent
        let decrypted = ciphertext.modpow(&d, &n);

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_encrypt_raw() {
        let (n, e, d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();
        let public_key = RsaPublicKey::new(n.clone(), e).unwrap();

        // Test data
        let data = b"Hello, RSA!";

        // Encrypt
        let ciphertext = public_key.encrypt_raw(data).unwrap();
        assert_eq!(ciphertext.len(), 256); // 2048 bits = 256 bytes

        // Decrypt using private exponent
        let c = os2ip(&ciphertext);
        let m = c.modpow(&d, &n);
        let decrypted = i2osp(&m, 256).unwrap();

        // Remove leading zeros and compare
        let mut start = 0;
        while start < decrypted.len() && decrypted[start] == 0 {
            start += 1;
        }

        assert_eq!(&decrypted[start..start + data.len()], data);
    }

    #[test]
    fn test_message_too_long() {
        let (n, e, _d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();
        let public_key = RsaPublicKey::new(n, e).unwrap();

        // Create data larger than key size
        let data = vec![0xFF; 257]; // 2048 bits = 256 bytes, so 257 is too long

        assert_eq!(public_key.encrypt_raw(&data), Err(RsaError::MessageTooLong));
    }
}
