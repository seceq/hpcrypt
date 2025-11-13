//! RSA private key operations

use crate::error::{Result, RsaError};
use crate::keygen::{generate_keypair, generate_keypair_default};
use crate::primitives::{i2osp, os2ip};
use crate::public_key::RsaPublicKey;
use alloc::vec::Vec;
use num_bigint::BigUint;

/// RSA private key
///
/// Contains both the public components (n, e) and private components (d, p, q, etc.).
/// Uses Chinese Remainder Theorem (CRT) for efficient private key operations.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    /// Public key components
    pub(crate) public_key: RsaPublicKey,

    /// Private exponent d
    pub(crate) d: BigUint,

    /// First prime factor p
    pub(crate) p: BigUint,

    /// Second prime factor q
    pub(crate) q: BigUint,

    /// CRT exponent: dp = d mod (p-1)
    pub(crate) dp: BigUint,

    /// CRT exponent: dq = d mod (q-1)
    pub(crate) dq: BigUint,

    /// CRT coefficient: qinv = q^-1 mod p
    pub(crate) qinv: BigUint,
}

impl RsaPrivateKey {
    /// Generate a new RSA private key
    ///
    /// # Arguments
    ///
    /// * `bits` - Key size in bits (must be >= 2048)
    ///
    /// # Security
    ///
    /// - Uses cryptographically secure random number generation
    /// - Validates all key components
    /// - Tests the key pair before returning
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_rsa::RsaPrivateKey;
    ///
    /// let private_key = RsaPrivateKey::generate(2048).unwrap();
    /// ```
    pub fn generate(bits: usize) -> Result<Self> {
        let (n, e, d, p, q, dp, dq, qinv) = generate_keypair_default(bits)?;

        let public_key = RsaPublicKey::new(n, e)?;

        Ok(Self {
            public_key,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }

    /// Generate a new RSA private key with a custom public exponent
    ///
    /// # Arguments
    ///
    /// * `bits` - Key size in bits (must be >= 2048)
    /// * `e` - Public exponent (must be odd and > 2)
    pub fn generate_with_exponent(bits: usize, e: u64) -> Result<Self> {
        let (n, e_big, d, p, q, dp, dq, qinv) = generate_keypair(bits, Some(e))?;

        let public_key = RsaPublicKey::new(n, e_big)?;

        Ok(Self {
            public_key,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Get the modulus
    pub fn n(&self) -> &BigUint {
        &self.public_key.n
    }

    /// Get the public exponent
    pub fn e(&self) -> &BigUint {
        &self.public_key.e
    }

    /// Get the private exponent (use with caution!)
    pub fn d(&self) -> &BigUint {
        &self.d
    }

    /// Get the key size in bits
    pub fn size(&self) -> usize {
        self.public_key.size()
    }

    /// Get the key size in bytes
    pub fn size_bytes(&self) -> usize {
        self.public_key.size_bytes()
    }

    /// Decrypt a ciphertext using RSADP primitive
    ///
    /// This is a low-level operation. For actual decryption, use RSA-OAEP.
    ///
    /// # Arguments
    ///
    /// * `c` - Ciphertext (must be < n)
    ///
    /// # Returns
    ///
    /// Message representative m = c^d mod n
    ///
    /// # Performance
    ///
    /// Uses Chinese Remainder Theorem for ~4x speedup over naive exponentiation.
    pub(crate) fn decrypt_primitive(&self, c: &BigUint) -> Result<BigUint> {
        self.decrypt_crt(c)
    }

    /// Sign a message using RSASP1 primitive
    ///
    /// This is a low-level operation. For actual signing, use RSA-PSS or PKCS#1 v1.5.
    ///
    /// # Arguments
    ///
    /// * `m` - Message representative (must be < n)
    ///
    /// # Returns
    ///
    /// Signature s = m^d mod n
    pub(crate) fn sign_primitive(&self, m: &BigUint) -> Result<BigUint> {
        self.sign_crt(m)
    }

    /// Decrypt using Chinese Remainder Theorem
    ///
    /// This is approximately 4x faster than c^d mod n.
    ///
    /// Algorithm:
    /// 1. m1 = c^dp mod p
    /// 2. m2 = c^dq mod q
    /// 3. h = qinv * (m1 - m2) mod p
    /// 4. m = m2 + h * q
    fn decrypt_crt(&self, c: &BigUint) -> Result<BigUint> {
        if c >= self.n() {
            return Err(RsaError::InvalidCiphertext);
        }

        // m1 = c^dp mod p
        let c_mod_p = c % &self.p;
        let m1 = c_mod_p.modpow(&self.dp, &self.p);

        // m2 = c^dq mod q
        let c_mod_q = c % &self.q;
        let m2 = c_mod_q.modpow(&self.dq, &self.q);

        // h = qinv * (m1 - m2) mod p
        let h = if m1 >= m2 {
            (&self.qinv * (m1 - &m2)) % &self.p
        } else {
            // Handle m1 < m2: add p before subtracting
            let diff = &self.p + &m1 - &m2;
            (&self.qinv * diff) % &self.p
        };

        // m = m2 + h * q
        let m = m2 + (h * &self.q);

        Ok(m)
    }

    /// Sign using Chinese Remainder Theorem
    ///
    /// Same algorithm as decrypt_crt, but used for signing.
    fn sign_crt(&self, m: &BigUint) -> Result<BigUint> {
        if m >= self.n() {
            return Err(RsaError::MessageTooLong);
        }

        // Same as decrypt_crt
        let m_mod_p = m % &self.p;
        let s1 = m_mod_p.modpow(&self.dp, &self.p);

        let m_mod_q = m % &self.q;
        let s2 = m_mod_q.modpow(&self.dq, &self.q);

        let h = if s1 >= s2 {
            (&self.qinv * (s1 - &s2)) % &self.p
        } else {
            let diff = &self.p + &s1 - &s2;
            (&self.qinv * diff) % &self.p
        };

        let s = s2 + (h * &self.q);

        Ok(s)
    }

    /// Decrypt raw bytes using RSADP
    ///
    /// # Warning
    ///
    /// This performs textbook RSA decryption, which is vulnerable to attacks.
    /// Use RSA-OAEP for actual decryption.
    #[allow(dead_code)]
    pub(crate) fn decrypt_raw(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let k = self.size_bytes();

        if ciphertext.len() != k {
            return Err(RsaError::InvalidCiphertext);
        }

        let c = os2ip(ciphertext);
        let m = self.decrypt_primitive(&c)?;
        i2osp(&m, k)
    }

    /// Sign raw bytes using RSASP1
    ///
    /// # Warning
    ///
    /// This is a low-level operation. Use RSA-PSS or PKCS#1 v1.5 wrappers instead.
    #[allow(dead_code)]
    pub(crate) fn sign_raw(&self, message_repr: &[u8]) -> Result<Vec<u8>> {
        let k = self.size_bytes();

        if message_repr.len() > k {
            return Err(RsaError::MessageTooLong);
        }

        let m = os2ip(message_repr);
        let s = self.sign_primitive(&m)?;
        i2osp(&s, k)
    }
}

// Implement PartialEq manually to avoid comparing sensitive data in tests
impl PartialEq for RsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.d == other.d
    }
}

impl Eq for RsaPrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn test_generate_2048() {
        let key = RsaPrivateKey::generate(2048).unwrap();
        assert_eq!(key.size(), 2048);
        assert_eq!(key.size_bytes(), 256);
    }

    #[test]
    fn test_generate_3072() {
        let key = RsaPrivateKey::generate(3072).unwrap();
        assert_eq!(key.size(), 3072);
    }

    #[test]
    fn test_generate_4096() {
        let key = RsaPrivateKey::generate(4096).unwrap();
        assert_eq!(key.size(), 4096);
    }

    #[test]
    fn test_generate_with_custom_exponent() {
        let key = RsaPrivateKey::generate_with_exponent(2048, 3).unwrap();
        assert_eq!(key.e(), &BigUint::from(3u32));
    }

    #[test]
    fn test_encrypt_decrypt_primitive() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        let msg = BigUint::from(42u32);
        let ciphertext = key.public_key().encrypt_primitive(&msg).unwrap();
        let decrypted = key.decrypt_primitive(&ciphertext).unwrap();

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_sign_verify_primitive() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        let msg = BigUint::from(1337u32);
        let signature = key.sign_primitive(&msg).unwrap();
        let verified = key.public_key().verify_primitive(&signature).unwrap();

        assert_eq!(msg, verified);
    }

    #[test]
    fn test_encrypt_decrypt_raw() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        let data = b"Hello, RSA!";
        let ciphertext = key.public_key().encrypt_raw(data).unwrap();
        let decrypted = key.decrypt_raw(&ciphertext).unwrap();

        // Find the start of the actual data (skip leading zeros)
        let mut start = 0;
        while start < decrypted.len() && decrypted[start] == 0 {
            start += 1;
        }

        assert_eq!(&decrypted[start..start + data.len()], data);
    }

    #[test]
    fn test_crt_correctness() {
        // Verify CRT gives same result as direct exponentiation
        let key = RsaPrivateKey::generate(2048).unwrap();

        let msg = BigUint::from(12345u32);
        let ciphertext = key.public_key().encrypt_primitive(&msg).unwrap();

        // Decrypt with CRT
        let decrypted_crt = key.decrypt_crt(&ciphertext).unwrap();

        // Decrypt without CRT (direct exponentiation)
        let decrypted_direct = ciphertext.modpow(key.d(), key.n());

        assert_eq!(decrypted_crt, decrypted_direct);
        assert_eq!(decrypted_crt, msg);
    }

    #[test]
    fn test_sign_crt_correctness() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        let msg = BigUint::from(9999u32);

        // Sign with CRT
        let sig_crt = key.sign_crt(&msg).unwrap();

        // Sign without CRT
        let sig_direct = msg.modpow(key.d(), key.n());

        assert_eq!(sig_crt, sig_direct);
    }

    #[test]
    fn test_multiple_encrypt_decrypt() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        // Test with multiple messages
        for i in 1u32..100 {
            let msg = BigUint::from(i);
            let ct = key.public_key().encrypt_primitive(&msg).unwrap();
            let pt = key.decrypt_primitive(&ct).unwrap();
            assert_eq!(msg, pt);
        }
    }

    #[test]
    fn test_key_components() {
        let key = RsaPrivateKey::generate(2048).unwrap();

        // Verify n = p * q
        assert_eq!(key.n(), &(&key.p * &key.q));

        // Verify dp = d mod (p-1)
        assert_eq!(key.dp, &key.d % (&key.p - BigUint::one()));

        // Verify dq = d mod (q-1)
        assert_eq!(key.dq, &key.d % (&key.q - BigUint::one()));

        // Verify qinv * q ≡ 1 (mod p)
        assert_eq!((&key.qinv * &key.q) % &key.p, BigUint::one());
    }
}
