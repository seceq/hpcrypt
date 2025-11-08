//! Ed448 Digital Signature Algorithm (EdDSA)
//!
//! This module implements the Ed448 signature scheme as specified in RFC 8032.
//! Ed448 provides approximately 224 bits of security.
//!
//! # Key Generation
//!
//! 1. Hash the private key (57 bytes) with SHAKE256 to produce 114 bytes
//! 2. Use first 57 bytes for secret scalar (with clamping)
//! 3. Use last 57 bytes as prefix for nonce generation
//! 4. Compute public key A = [s]B where s is the secret scalar
//!
//! # Signing
//!
//! 1. Compute nonce r = SHAKE256(prefix || message)
//! 2. Compute R = [r]B
//! 3. Compute challenge k = SHAKE256(R || A || message)
//! 4. Compute s = (r + k·secret) mod L
//! 5. Signature = (R, s) (114 bytes total)
//!
//! # Verification
//!
//! 1. Parse R and s from signature
//! 2. Check that s < L (reject if not)
//! 3. Compute k = SHAKE256(R || A || message)
//! 4. Verify [s]B = R + [k]A using double scalar multiplication

use super::constants::ED448_L;
use super::point::Point;
use super::scalar::Scalar;

/// Ed448 public key (57 bytes)
pub type PublicKey = [u8; 57];

/// Ed448 signature (114 bytes: 57 for R, 57 for s)
pub type Signature = [u8; 114];

/// Generate Ed448 public key from private key
///
/// # Arguments
///
/// * `private_key` - 57-byte private key (should be cryptographically random)
///
/// # Returns
///
/// 57-byte public key
///
/// # Example
///
/// ```ignore
/// use hpcrypt_curves::ed448;
///
/// let private_key = [0u8; 57]; // Use secure random in production!
/// let public_key = ed448::public_key(&private_key);
/// ```
pub fn public_key(private_key: &[u8; 57]) -> PublicKey {
    // Hash the private key with SHAKE256
    let mut hash = [0u8; 114];
    shake256_114(private_key, &mut hash);

    // Extract secret scalar from first 57 bytes
    let secret_scalar = hash_to_scalar(&hash[..57]);

    // Compute public key A = [secret]B
    let public_point = Point::generator().scalar_mul(&secret_scalar);

    // Encode public key
    public_point.to_bytes()
}

/// Sign a message with Ed448
///
/// # Arguments
///
/// * `private_key` - 57-byte private key
/// * `message` - Message to sign (arbitrary length)
///
/// # Returns
///
/// 114-byte signature (R || s)
///
/// # Example
///
/// ```ignore
/// use hpcrypt_curves::ed448;
///
/// let private_key = [0u8; 57];
/// let message = b"Hello, Ed448!";
/// let signature = ed448::sign(&private_key, message);
/// ```
pub fn sign(private_key: &[u8; 57], message: &[u8]) -> Signature {
    // Hash the private key with SHAKE256
    let mut hash = [0u8; 114];
    shake256_114(private_key, &mut hash);

    // Extract secret scalar and prefix
    let secret_scalar = hash_to_scalar(&hash[..57]);
    let prefix = &hash[57..114];

    // Compute public key A = [secret]B
    let public_point = Point::generator().scalar_mul(&secret_scalar);
    let public_key_bytes = public_point.to_bytes();

    // Compute nonce r = SHAKE256(prefix || message)
    let nonce_scalar = {
        let mut nonce_hash = [0u8; 114];
        shake256_with_prefix(prefix, message, &mut nonce_hash);
        hash_to_scalar(&nonce_hash[..57])
    };

    // Compute R = [r]B
    let r_point = Point::generator().scalar_mul(&nonce_scalar);
    let r_bytes = r_point.to_bytes();

    // Compute challenge k = SHAKE256(R || A || message)
    let challenge = {
        let mut challenge_hash = [0u8; 114];
        shake256_dom4(&r_bytes, &public_key_bytes, message, &mut challenge_hash);
        hash_to_scalar(&challenge_hash[..57])
    };

    // Compute s = (r + k·secret) mod L
    let s_scalar = nonce_scalar + (challenge * secret_scalar);

    // Encode signature as R || s
    let mut signature = [0u8; 114];
    signature[..57].copy_from_slice(&r_bytes);
    signature[57..114].copy_from_slice(&s_scalar.to_bytes());

    signature
}

/// Verify an Ed448 signature
///
/// # Arguments
///
/// * `public_key` - 57-byte public key
/// * `message` - Message that was signed
/// * `signature` - 114-byte signature to verify
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise
///
/// # Example
///
/// ```ignore
/// use hpcrypt_curves::ed448;
///
/// let private_key = [0u8; 57];
/// let public_key = ed448::public_key(&private_key);
/// let message = b"Hello, Ed448!";
/// let signature = ed448::sign(&private_key, message);
///
/// assert!(ed448::verify(&public_key, message, &signature));
/// ```
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    // Parse R and s from signature
    let mut r_bytes = [0u8; 57];
    let mut s_bytes = [0u8; 57];
    r_bytes.copy_from_slice(&signature[..57]);
    s_bytes.copy_from_slice(&signature[57..114]);

    // Decode R point
    let r_point = match Point::from_bytes(&r_bytes) {
        Some(p) => p,
        None => return false, // Invalid R encoding
    };

    // Decode s scalar
    let s_scalar = Scalar::from_bytes(&s_bytes);

    // Check that s < L (reject if s >= L)
    if !is_scalar_valid(&s_scalar) {
        return false;
    }

    // Decode public key A
    let a_point = match Point::from_bytes(public_key) {
        Some(p) => p,
        None => return false, // Invalid public key encoding
    };

    // Compute challenge k = SHAKE256(R || A || message)
    let challenge = {
        let mut challenge_hash = [0u8; 114];
        shake256_dom4(&r_bytes, public_key, message, &mut challenge_hash);
        hash_to_scalar(&challenge_hash[..57])
    };

    // Verify [s]B = R + [k]A using double scalar multiplication
    // Equivalently: [s]B - [k]A - R = O (point at infinity)
    let lhs = Point::generator().scalar_mul(&s_scalar);
    let rhs = Point::double_scalar_mul(&challenge, &a_point, &Scalar::one(), &r_point);

    lhs == rhs
}

//
// Helper functions
//

/// Convert hash bytes to scalar (with clamping for private key)
///
/// RFC 8032 Section 5.2.5: The private key is clamped:
/// - Clear the two least significant bits
/// - Clear the most significant bit
/// - Set the second most significant bit
fn hash_to_scalar(hash: &[u8]) -> Scalar {
    let mut bytes = [0u8; 57];
    bytes.copy_from_slice(&hash[..57]);

    // Clamp the scalar (RFC 8032 Section 5.2.5)
    bytes[0] &= 0xFC; // Clear bottom 2 bits
    bytes[56] = 0; // Clear top byte
    bytes[55] |= 0x80; // Set second-highest bit

    Scalar::from_bytes(&bytes)
}

/// Check if scalar is valid (s < L)
fn is_scalar_valid(s: &Scalar) -> bool {
    // Check if s < L by comparing limbs from highest to lowest
    let s_limbs = &s.limbs;

    for i in (0..8).rev() {
        if s_limbs[i] < ED448_L[i] {
            return true;
        } else if s_limbs[i] > ED448_L[i] {
            return false;
        }
        // If equal, continue to next limb
    }

    // If all limbs are equal, s == L, which is invalid
    false
}

/// SHAKE256 hash producing 114 bytes
///
/// This is a wrapper around the hpcrypt-hash SHAKE256 implementation.
fn shake256_114(input: &[u8], output: &mut [u8; 114]) {
    // We'll use the SHAKE256 from hpcrypt-hash
    // For now, use a placeholder - will integrate with hpcrypt-hash
    use hpcrypt_hash::Shake256;

    let mut shake = Shake256::new();
    shake.update(input);
    shake.finalize(output);
}

/// SHAKE256 with prefix || message
fn shake256_with_prefix(prefix: &[u8], message: &[u8], output: &mut [u8; 114]) {
    use hpcrypt_hash::Shake256;

    let mut shake = Shake256::new();
    shake.update(prefix);
    shake.update(message);
    shake.finalize(output);
}

/// SHAKE256 with dom4 prefix for Ed448
///
/// RFC 8032 Section 5.2.6: The hash function for Ed448 is SHAKE256(dom4(F, C) || x)
/// where dom4(x, y) = "SigEd448" || octet(x) || octet(y)
///
/// For Ed448 (not Ed448ph), F = 0 and C = empty string.
fn shake256_dom4(r: &[u8], a: &[u8], message: &[u8], output: &mut [u8; 114]) {
    use hpcrypt_hash::Shake256;

    let mut shake = Shake256::new();

    // dom4(F, C) where F = 0 (no prehash), C = empty (no context)
    shake.update(b"SigEd448");
    shake.update(&[0x00]); // F = 0 (phflag)
    shake.update(&[0x00]); // len(C) = 0 (context length)

    // R || A || message
    shake.update(r);
    shake.update(a);
    shake.update(message);

    shake.finalize(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        // Test that public key generation is deterministic
        let private_key = [42u8; 57];
        let public_key1 = public_key(&private_key);
        let public_key2 = public_key(&private_key);

        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_sign_verify_basic() {
        // Basic sign/verify test
        let private_key = [1u8; 57];
        let public_key = public_key(&private_key);
        let message = b"Hello, Ed448!";

        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_sign_verify_empty_message() {
        // Test with empty message
        let private_key = [2u8; 57];
        let public_key = public_key(&private_key);
        let message = b"";

        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        // Signature should fail on wrong message
        let private_key = [3u8; 57];
        let public_key = public_key(&private_key);
        let message1 = b"Original message";
        let message2 = b"Different message";

        let signature = sign(&private_key, message1);
        assert!(!verify(&public_key, message2, &signature));
    }

    #[test]
    fn test_verify_wrong_public_key() {
        // Signature should fail with wrong public key
        let private_key1 = [4u8; 57];
        let private_key2 = [5u8; 57];
        let public_key2 = public_key(&private_key2);
        let message = b"Test message";

        let signature = sign(&private_key1, message);
        assert!(!verify(&public_key2, message, &signature));
    }

    #[test]
    fn test_signature_deterministic() {
        // Ed448 signatures should be deterministic
        let private_key = [6u8; 57];
        let message = b"Deterministic test";

        let sig1 = sign(&private_key, message);
        let sig2 = sign(&private_key, message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_is_scalar_valid() {
        // Test scalar validation
        let zero = Scalar::zero();
        assert!(is_scalar_valid(&zero));

        let one = Scalar::one();
        assert!(is_scalar_valid(&one));

        // L - 1 should be valid
        let l_minus_1 = Scalar::from_bytes(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff,
        ])
        .reduce();
        assert!(is_scalar_valid(&l_minus_1));
    }
}
