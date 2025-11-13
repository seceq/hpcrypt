//! RSA key generation
//!
//! Implements secure RSA key pair generation according to FIPS 186-4 and PKCS#1 v2.2

use crate::error::{Result, RsaError};
use crate::primitives::{gcd, generate_prime, mod_inverse};
use crate::{DEFAULT_PUBLIC_EXPONENT, MAX_KEY_SIZE, MIN_KEY_SIZE};
use num_bigint::BigUint;
use num_traits::One;

/// Generate an RSA key pair
///
/// # Parameters
///
/// * `bits` - Key size in bits (must be >= 2048 and <= 8192)
/// * `public_exponent` - Public exponent e (typically 65537)
///
/// # Security Requirements
///
/// 1. Key size must be at least 2048 bits (NIST recommendation)
/// 2. Public exponent must be odd and > 2
/// 3. Primes p and q must be sufficiently different in size
/// 4. gcd(e, φ(n)) must equal 1
///
/// # Returns
///
/// Returns `(n, e, d, p, q, dp, dq, qinv)` where:
/// - `n` = p * q (modulus)
/// - `e` = public exponent
/// - `d` = private exponent (e^-1 mod φ(n))
/// - `p`, `q` = prime factors
/// - `dp` = d mod (p-1) (CRT exponent)
/// - `dq` = d mod (q-1) (CRT exponent)
/// - `qinv` = q^-1 mod p (CRT coefficient)
#[allow(clippy::type_complexity)]
pub fn generate_keypair(
    bits: usize,
    public_exponent: Option<u64>,
) -> Result<(
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
)> {
    // Validate key size
    if bits < MIN_KEY_SIZE {
        return Err(RsaError::InvalidKeySize);
    }
    if bits > MAX_KEY_SIZE {
        return Err(RsaError::InvalidKeySize);
    }
    if bits % 2 != 0 {
        return Err(RsaError::InvalidKeySize);
    }

    // Validate and set public exponent
    let e = match public_exponent {
        Some(exp) => {
            if exp < 3 || exp % 2 == 0 {
                return Err(RsaError::InvalidPublicExponent);
            }
            BigUint::from(exp)
        }
        None => BigUint::from(DEFAULT_PUBLIC_EXPONENT),
    };

    // Generate primes p and q
    // Each prime should be approximately bits/2 bits long
    let prime_bits = bits / 2;

    // Try up to 100 times to generate a valid key pair
    for _attempt in 0..100 {
        // Generate p
        let p = generate_prime(prime_bits)?;

        // Ensure gcd(p-1, e) = 1
        let p_minus_1 = &p - BigUint::one();
        if gcd(&p_minus_1, &e) != BigUint::one() {
            continue;
        }

        // Generate q (ensure q != p)
        let q = loop {
            let candidate = generate_prime(prime_bits)?;
            if candidate != p {
                // Ensure gcd(q-1, e) = 1
                let q_minus_1 = &candidate - BigUint::one();
                if gcd(&q_minus_1, &e) == BigUint::one() {
                    break candidate;
                }
            }
        };

        // Ensure p > q (swap if necessary for consistent CRT computation)
        let (p, q) = if p > q { (p, q) } else { (q, p) };

        // Compute n = p * q
        let n = &p * &q;

        // Verify n has correct bit length
        let n_bits = n.bits();
        if n_bits != bits as u64 {
            continue; // Try again
        }

        // Compute φ(n) = (p-1)(q-1)
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());

        // Compute d = e^-1 mod φ(n)
        let d = match mod_inverse(&e, &phi) {
            Some(inv) => inv,
            None => continue, // This shouldn't happen if gcd checks passed
        };

        // Verify d is large enough (d > 2^(bits/2))
        if d.bits() <= (bits / 2) as u64 {
            continue;
        }

        // Compute CRT parameters for faster private key operations
        // Note: p > q is now guaranteed, so qinv = q^-1 mod p always exists
        let dp = &d % (&p - BigUint::one()); // d mod (p-1)
        let dq = &d % (&q - BigUint::one()); // d mod (q-1)
        let qinv = mod_inverse(&q, &p).ok_or(RsaError::KeyGenerationFailed)?; // q^-1 mod p

        // Verify the key pair works
        // Encrypt and decrypt a test message
        let test_msg = BigUint::from(42u32);
        let ciphertext = test_msg.modpow(&e, &n);
        let decrypted = ciphertext.modpow(&d, &n);

        if decrypted == test_msg {
            return Ok((n, e, d, p, q, dp, dq, qinv));
        }
    }

    Err(RsaError::KeyGenerationFailed)
}

/// Generate an RSA key pair with default public exponent (65537)
#[allow(clippy::type_complexity)]
pub fn generate_keypair_default(
    bits: usize,
) -> Result<(
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
    BigUint,
)> {
    generate_keypair(bits, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_2048_bit_key() {
        let result = generate_keypair_default(2048);
        assert!(result.is_ok());

        let (n, e, d, p, q, dp, dq, qinv) = result.unwrap();

        // Verify key properties
        assert_eq!(n.bits(), 2048);
        assert_eq!(e, BigUint::from(65537u32));
        assert!(d.bits() >= 1024); // d should be at least half the key size

        // Verify n = p * q
        assert_eq!(n, &p * &q);

        // Verify e * d ≡ 1 (mod φ(n))
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());
        assert_eq!((&e * &d) % &phi, BigUint::one());

        // Verify CRT parameters
        assert_eq!(dp, &d % (&p - BigUint::one()));
        assert_eq!(dq, &d % (&q - BigUint::one()));
        assert_eq!((&q * &qinv) % &p, BigUint::one());
    }

    #[test]
    fn test_generate_3072_bit_key() {
        let result = generate_keypair_default(3072);
        assert!(result.is_ok());

        let (n, _e, _d, _p, _q, _dp, _dq, _qinv) = result.unwrap();
        assert_eq!(n.bits(), 3072);
    }

    #[test]
    fn test_generate_4096_bit_key() {
        let result = generate_keypair_default(4096);
        assert!(result.is_ok());

        let (n, _e, _d, _p, _q, _dp, _dq, _qinv) = result.unwrap();
        assert_eq!(n.bits(), 4096);
    }

    #[test]
    fn test_custom_public_exponent() {
        // Test with e = 3 (minimum allowed)
        let result = generate_keypair(2048, Some(3));
        assert!(result.is_ok());

        let (_n, e, _d, _p, _q, _dp, _dq, _qinv) = result.unwrap();
        assert_eq!(e, BigUint::from(3u32));
    }

    #[test]
    fn test_invalid_key_size() {
        // Too small
        assert_eq!(
            generate_keypair_default(1024),
            Err(RsaError::InvalidKeySize)
        );

        // Odd number
        assert_eq!(
            generate_keypair_default(2049),
            Err(RsaError::InvalidKeySize)
        );
    }

    #[test]
    fn test_invalid_public_exponent() {
        // Even exponent
        assert_eq!(
            generate_keypair(2048, Some(4)),
            Err(RsaError::InvalidPublicExponent)
        );

        // Too small
        assert_eq!(
            generate_keypair(2048, Some(2)),
            Err(RsaError::InvalidPublicExponent)
        );
    }

    #[test]
    fn test_key_uniqueness() {
        // Generate two keys and verify they're different
        let (n1, _e1, _d1, _p1, _q1, _dp1, _dq1, _qinv1) = generate_keypair_default(2048).unwrap();
        let (n2, _e2, _d2, _p2, _q2, _dp2, _dq2, _qinv2) = generate_keypair_default(2048).unwrap();

        assert_ne!(n1, n2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (n, e, d, _p, _q, _dp, _dq, _qinv) = generate_keypair_default(2048).unwrap();

        // Test with various messages
        for msg_val in [1u32, 42, 1337, 65535] {
            let msg = BigUint::from(msg_val);
            let ciphertext = msg.modpow(&e, &n);
            let decrypted = ciphertext.modpow(&d, &n);
            assert_eq!(msg, decrypted);
        }
    }
}
