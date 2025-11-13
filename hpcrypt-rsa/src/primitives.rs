//! RSA mathematical primitives
//!
//! Low-level operations for RSA: modular exponentiation, conversions, etc.

use crate::error::{Result, RsaError};
use crate::montgomery::MontgomeryContext;
use alloc::vec;
use alloc::vec::Vec;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// RSA encryption primitive (RSAEP)
///
/// Computes c = m^e mod n
/// where m is the message, e is the public exponent, and n is the modulus
///
/// Note: Uses standard modpow since public exponent e is typically small (65537)
pub fn rsaep(n: &BigUint, e: &BigUint, m: &BigUint) -> Result<BigUint> {
    if m >= n {
        return Err(RsaError::MessageTooLong);
    }

    // Public exponent is small, standard modpow is fine
    Ok(m.modpow(e, n))
}

/// RSA decryption primitive (RSADP)
///
/// Computes m = c^d mod n
/// where c is the ciphertext, d is the private exponent, and n is the modulus
///
/// Uses Montgomery multiplication for 30-50% speedup (private exponent d is large)
#[allow(dead_code)] // Public API primitive, used by external callers
pub fn rsadp(n: &BigUint, d: &BigUint, c: &BigUint) -> Result<BigUint> {
    if c >= n {
        return Err(RsaError::InvalidCiphertext);
    }

    // Use Montgomery multiplication for private key operations (large exponent)
    let ctx = MontgomeryContext::new(n);
    Ok(ctx.modpow(c, d, n))
}

/// RSA signature primitive (RSASP1)
///
/// Computes s = m^d mod n
/// where m is the message representative, d is the private exponent, and n is the modulus
///
/// Uses Montgomery multiplication for 30-50% speedup (private exponent d is large)
#[allow(dead_code)] // Public API primitive, used by external callers
pub fn rsasp1(n: &BigUint, d: &BigUint, m: &BigUint) -> Result<BigUint> {
    if m >= n {
        return Err(RsaError::MessageTooLong);
    }

    // Use Montgomery multiplication for private key operations (large exponent)
    let ctx = MontgomeryContext::new(n);
    Ok(ctx.modpow(m, d, n))
}

/// RSA verification primitive (RSAVP1)
///
/// Computes m = s^e mod n
/// where s is the signature, e is the public exponent, and n is the modulus
pub fn rsavp1(n: &BigUint, e: &BigUint, s: &BigUint) -> Result<BigUint> {
    if s >= n {
        return Err(RsaError::InvalidSignature);
    }

    Ok(s.modpow(e, n))
}

/// Convert a byte array to a BigUint (OS2IP - Octet String to Integer Primitive)
///
/// Interprets bytes as a big-endian unsigned integer
pub fn os2ip(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Convert a BigUint to a byte array of specified length (I2OSP - Integer to Octet String Primitive)
///
/// Returns error if the integer is too large for the specified length
pub fn i2osp(x: &BigUint, x_len: usize) -> Result<Vec<u8>> {
    let bytes = x.to_bytes_be();

    if bytes.len() > x_len {
        return Err(RsaError::MessageTooLong);
    }

    // Pad with leading zeros if necessary
    let mut result = vec![0u8; x_len - bytes.len()];
    result.extend_from_slice(&bytes);

    Ok(result)
}

/// Generate a random prime number of specified bit length
///
/// Uses Miller-Rabin primality testing with sufficient rounds for cryptographic security
pub fn generate_prime(bits: usize) -> Result<BigUint> {
    use num_bigint::RandBigInt;
    use rand::SeedableRng;

    let mut rng = match hpcrypt_rng::generate_key::<32>() {
        Ok(seed) => {
            // Create a PRNG from the seed
            rand::rngs::StdRng::from_seed(seed)
        }
        Err(_) => return Err(RsaError::RngError),
    };

    // Generate random odd numbers and test for primality
    // We use a simple probabilistic primality test
    loop {
        // Generate a random number of the specified bit length
        let mut candidate = rng.gen_biguint(bits as u64);

        // Ensure the top bit is set (correct bit length)
        candidate |= BigUint::one() << (bits - 1);

        // Ensure it's odd
        candidate |= BigUint::one();

        // Test for primality using Miller-Rabin
        if is_probably_prime(&candidate, &mut rng, 50) {
            return Ok(candidate);
        }
    }
}

/// Miller-Rabin primality test
///
/// Returns true if n is probably prime, false if definitely composite.
/// Uses k rounds of testing for accuracy.
fn is_probably_prime<R: rand::Rng>(n: &BigUint, rng: &mut R, k: usize) -> bool {
    use num_bigint::RandBigInt;

    // Handle small cases
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if !n.bit(0) {
        // Even number
        return false;
    }

    // Write n-1 as 2^r * d
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u64;

    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }

    // Witness loop
    'witness: for _ in 0..k {
        // Pick random a in [2, n-2]
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &n_minus_1);

        // Compute x = a^d mod n
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..(r - 1) {
            x = x.modpow(&BigUint::from(2u32), n);

            if x == n_minus_1 {
                continue 'witness;
            }
        }

        // Definitely composite
        return false;
    }

    // Probably prime
    true
}

/// Compute the modular multiplicative inverse
///
/// Computes x such that (a * x) mod m = 1
/// Returns None if the inverse doesn't exist (i.e., gcd(a, m) != 1)
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_integer::Integer;

    // Convert to BigInt for extended_gcd
    let a_int = num_bigint::BigInt::from(a.clone());
    let m_int = num_bigint::BigInt::from(m.clone());

    // Extended Euclidean algorithm
    let ext_gcd = a_int.extended_gcd(&m_int);

    if ext_gcd.gcd != num_bigint::BigInt::one() {
        return None;
    }

    // Ensure positive result
    let result = if ext_gcd.x < num_bigint::BigInt::zero() {
        (ext_gcd.x + &m_int).to_biguint().unwrap()
    } else {
        ext_gcd.x.to_biguint().unwrap()
    };

    Some(result)
}

/// Compute GCD (Greatest Common Divisor)
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    use num_integer::Integer;
    a.gcd(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os2ip_i2osp_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let num = os2ip(&bytes);
        let result = i2osp(&num, 4).unwrap();
        assert_eq!(bytes, result);
    }

    #[test]
    fn test_i2osp_padding() {
        let num = BigUint::from(0x1234u32);
        let result = i2osp(&num, 4).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = mod_inverse(&a, &m).unwrap();

        // 3 * 4 mod 11 = 12 mod 11 = 1
        assert_eq!(inv, BigUint::from(4u32));

        // Verify
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }

    #[test]
    fn test_gcd() {
        assert_eq!(
            gcd(&BigUint::from(12u32), &BigUint::from(18u32)),
            BigUint::from(6u32)
        );
        assert_eq!(
            gcd(&BigUint::from(17u32), &BigUint::from(19u32)),
            BigUint::one()
        );
    }

    #[test]
    fn test_rsaep_rsadp() {
        // Simple RSA example with small numbers
        let p = BigUint::from(61u32);
        let q = BigUint::from(53u32);
        let n = &p * &q; // 3233
        let e = BigUint::from(17u32);

        // Compute d (private exponent)
        let phi = (p - 1u32) * (q - 1u32); // 3120
        let d = mod_inverse(&e, &phi).unwrap();

        // Encrypt/Decrypt
        let m = BigUint::from(123u32);
        let c = rsaep(&n, &e, &m).unwrap();
        let m2 = rsadp(&n, &d, &c).unwrap();

        assert_eq!(m, m2);
    }
}
