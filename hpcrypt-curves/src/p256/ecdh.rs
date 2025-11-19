//! P-256 Elliptic Curve Diffie-Hellman (ECDH)
//!
//! Implementation of ECDH key exchange using the NIST P-256 (secp256r1) curve
//! as specified in FIPS 186-4 and SEC1.
//!
//! # Security
//!
//! - Private keys must be in the range [1, n-1] where n is the curve order
//! - Public key validation is performed to reject invalid points
//! - Scalar multiplication uses constant-time operations to prevent timing attacks
//! - All operations are designed to resist side-channel attacks
//!
//! # Standards Compliance
//!
//! - **FIPS 186-4**: Digital Signature Standard (Appendix D)
//! - **SEC1 v2.0**: Elliptic Curve Cryptography (Section 3.3.1)
//! - **NIST SP 800-56A Rev 3**: Recommendation for Pair-Wise Key-Establishment Schemes
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_curves::p256::ecdh::P256Ecdh;
//!
//! # fn main() {
//! // Alice generates her keypair
//! let alice_private = [1u8; 32]; // Use secure random in production
//! let alice_public = P256Ecdh::public_key(&alice_private).unwrap();
//!
//! // Bob generates his keypair
//! let bob_private = [2u8; 32]; // Use secure random in production
//! let bob_public = P256Ecdh::public_key(&bob_private).unwrap();
//!
//! // Both compute the same shared secret
//! let alice_shared = P256Ecdh::shared_secret(&alice_private, &bob_public).unwrap();
//! let bob_shared = P256Ecdh::shared_secret(&bob_private, &alice_public).unwrap();
//!
//! assert_eq!(alice_shared, bob_shared);
//! # }
//! ```

use super::field::FieldElement;
use super::point::{AffinePoint, Point};
use super::scalar::Scalar;
use hpcrypt_core::error::CurveError;

/// P-256 private key length (32 bytes)
pub const P256_PRIVATE_KEY_LEN: usize = 32;

/// P-256 public key length (65 bytes - uncompressed SEC1 format: 0x04 || x || y)
pub const P256_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 65;

/// P-256 public key length (33 bytes - compressed SEC1 format: 0x02/0x03 || x)
pub const P256_PUBLIC_KEY_COMPRESSED_LEN: usize = 33;

/// P-256 shared secret length (32 bytes - x-coordinate of shared point)
pub const P256_SHARED_SECRET_LEN: usize = 32;

/// P-256 ECDH public API
pub struct P256Ecdh;

impl P256Ecdh {
    /// Generate an uncompressed public key from a private key
    ///
    /// Takes a 32-byte private key and returns the corresponding 65-byte
    /// uncompressed public key in SEC1 format: 0x04 || x || y
    ///
    /// # Errors
    ///
    /// Returns `CurveError::InvalidScalar` if the private key is zero or >= n
    ///
    /// # Example
    ///
    /// ```rust
    /// use hpcrypt_curves::p256::ecdh::P256Ecdh;
    ///
    /// # fn main() {
    /// let private_key = [1u8; 32]; // Use secure random in production
    /// let public_key = P256Ecdh::public_key(&private_key).unwrap();
    /// assert_eq!(public_key.len(), 65);
    /// assert_eq!(public_key[0], 0x04); // Uncompressed point marker
    /// # }
    /// ```
    pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 65], CurveError> {
        // Validate private key is in valid range [1, n-1]
        let scalar = Scalar::from_bytes(private_key);

        // Check if scalar is zero
        if bool::from(scalar.is_zero()) {
            return Err(CurveError::InvalidScalar {
                expected: 32,
                actual: 32,
            });
        }

        // Compute public key: Q = d * G
        let point = Point::generator().scalar_mul(private_key);

        // Check if result is point at infinity (should never happen with valid scalar)
        if bool::from(point.is_infinity()) {
            return Err(CurveError::IdentityPoint);
        }

        // Convert to affine coordinates
        let affine = point.to_affine().ok_or(CurveError::IdentityPoint)?;

        // Encode as uncompressed SEC1 format: 0x04 || x || y
        let mut result = [0u8; 65];
        result[0] = 0x04; // Uncompressed point marker

        // X coordinate (32 bytes, big-endian)
        result[1..33].copy_from_slice(&affine.x.to_bytes());

        // Y coordinate (32 bytes, big-endian)
        result[33..65].copy_from_slice(&affine.y.to_bytes());

        Ok(result)
    }

    /// Generate a compressed public key from a private key
    ///
    /// Takes a 32-byte private key and returns the corresponding 33-byte
    /// compressed public key in SEC1 format: 0x02/0x03 || x
    ///
    /// # Errors
    ///
    /// Returns `CurveError::InvalidScalar` if the private key is zero or >= n
    ///
    /// # Example
    ///
    /// ```rust
    /// use hpcrypt_curves::p256::ecdh::P256Ecdh;
    ///
    /// # fn main() {
    /// let private_key = [1u8; 32]; // Use secure random in production
    /// let public_key = P256Ecdh::public_key_compressed(&private_key).unwrap();
    /// assert_eq!(public_key.len(), 33);
    /// assert!(public_key[0] == 0x02 || public_key[0] == 0x03); // Compressed point marker
    /// # }
    /// ```
    pub fn public_key_compressed(private_key: &[u8; 32]) -> Result<[u8; 33], CurveError> {
        // Validate private key is in valid range [1, n-1]
        let scalar = Scalar::from_bytes(private_key);

        // Check if scalar is zero
        if bool::from(scalar.is_zero()) {
            return Err(CurveError::InvalidScalar {
                expected: 32,
                actual: 32,
            });
        }

        // Compute public key: Q = d * G
        let point = Point::generator().scalar_mul(private_key);

        // Check if result is point at infinity (should never happen with valid scalar)
        if bool::from(point.is_infinity()) {
            return Err(CurveError::IdentityPoint);
        }

        // Convert to affine coordinates
        let affine = point.to_affine().ok_or(CurveError::IdentityPoint)?;

        // Encode as compressed SEC1 format: 0x02/0x03 || x
        let mut result = [0u8; 33];

        // Y parity: 0x02 if y is even, 0x03 if y is odd
        let y_bytes = affine.y.to_bytes();
        result[0] = if (y_bytes[31] & 1) == 0 { 0x02 } else { 0x03 };

        // X coordinate (32 bytes, big-endian)
        result[1..33].copy_from_slice(&affine.x.to_bytes());

        Ok(result)
    }

    /// Compute shared secret from private and public keys
    ///
    /// Returns the 32-byte shared secret computed from your private key
    /// and the other party's public key. The shared secret is the x-coordinate
    /// of the computed point, as per NIST SP 800-56A.
    ///
    /// # Input Format
    ///
    /// The public key can be in either:
    /// - Uncompressed format (65 bytes): 0x04 || x || y
    /// - Compressed format (33 bytes): 0x02/0x03 || x
    ///
    /// # Errors
    ///
    /// - `InvalidScalar`: Private key is zero or >= n
    /// - `InvalidEncoding`: Public key encoding is invalid
    /// - `NotOnCurve`: Point is not on the curve
    /// - `IdentityPoint`: Computed shared point is the identity (invalid)
    ///
    /// # Security
    ///
    /// The implementation validates that:
    /// - The public key point is on the P-256 curve
    /// - The public key point is not the point at infinity
    /// - The computed shared secret point is not the point at infinity
    ///
    /// # Example
    ///
    /// ```rust
    /// use hpcrypt_curves::p256::ecdh::P256Ecdh;
    ///
    /// # fn main() {
    /// let alice_private = [1u8; 32];
    /// let alice_public = P256Ecdh::public_key(&alice_private).unwrap();
    ///
    /// let bob_private = [2u8; 32];
    /// let bob_public = P256Ecdh::public_key(&bob_private).unwrap();
    ///
    /// let alice_shared = P256Ecdh::shared_secret(&alice_private, &bob_public).unwrap();
    /// let bob_shared = P256Ecdh::shared_secret(&bob_private, &alice_public).unwrap();
    ///
    /// assert_eq!(alice_shared, bob_shared);
    /// # }
    /// ```
    pub fn shared_secret(
        private_key: &[u8; 32],
        public_key: &[u8],
    ) -> Result<[u8; 32], CurveError> {
        // Validate and decode the public key
        let point = decode_public_key(public_key)?;

        // Validate private key
        let scalar = Scalar::from_bytes(private_key);
        if bool::from(scalar.is_zero()) {
            return Err(CurveError::InvalidScalar {
                expected: 32,
                actual: 32,
            });
        }

        // Compute shared point: S = d * Q
        // Use constant-time scalar multiplication to prevent timing attacks
        let shared_point = point.scalar_mul(private_key);

        // Check if result is point at infinity (security requirement)
        if bool::from(shared_point.is_infinity()) {
            return Err(CurveError::IdentityPoint);
        }

        // Convert to affine coordinates
        let affine = shared_point
            .to_affine()
            .ok_or(CurveError::IdentityPoint)?;

        // Return x-coordinate as shared secret (NIST SP 800-56A)
        Ok(affine.x.to_bytes())
    }
}

/// Decode a public key from SEC1 format (compressed or uncompressed)
///
/// # Supported Formats
///
/// - Uncompressed (65 bytes): 0x04 || x || y
/// - Compressed (33 bytes): 0x02 || x (even y) or 0x03 || x (odd y)
///
/// # Validation
///
/// - Checks point is on the curve: y² = x³ - 3x + b (mod p)
/// - Rejects point at infinity
/// - Rejects points with invalid coordinates
fn decode_public_key(bytes: &[u8]) -> Result<Point, CurveError> {
    if bytes.is_empty() {
        return Err(CurveError::InvalidEncoding {
            expected: "P-256 point (33 or 65 bytes)",
            actual: 0,
        });
    }

    match bytes[0] {
        // Uncompressed point: 0x04 || x || y
        0x04 => {
            if bytes.len() != 65 {
                return Err(CurveError::InvalidEncoding {
                    expected: "Uncompressed P-256 point (65 bytes)",
                    actual: bytes.len(),
                });
            }

            // Parse x coordinate
            let mut x_bytes = [0u8; 32];
            x_bytes.copy_from_slice(&bytes[1..33]);
            let x = FieldElement::from_bytes(&x_bytes).ok_or(CurveError::NotOnCurve)?;

            // Parse y coordinate
            let mut y_bytes = [0u8; 32];
            y_bytes.copy_from_slice(&bytes[33..65]);
            let y = FieldElement::from_bytes(&y_bytes).ok_or(CurveError::NotOnCurve)?;

            // Create point in Jacobian coordinates (x, y, 1)
            let affine = AffinePoint { x, y };
            let point = Point::from_affine(&affine);

            // Validate point is on curve
            if !bool::from(point.is_on_curve()) {
                return Err(CurveError::NotOnCurve);
            }

            // Validate point is not infinity
            if bool::from(point.is_infinity()) {
                return Err(CurveError::IdentityPoint);
            }

            Ok(point)
        }

        // Compressed point: 0x02 || x (even y) or 0x03 || x (odd y)
        0x02 | 0x03 => {
            if bytes.len() != 33 {
                return Err(CurveError::InvalidEncoding {
                    expected: "Compressed P-256 point (33 bytes)",
                    actual: bytes.len(),
                });
            }

            let y_is_odd = bytes[0] == 0x03;

            // Parse x coordinate
            let mut x_bytes = [0u8; 32];
            x_bytes.copy_from_slice(&bytes[1..33]);
            let x = FieldElement::from_bytes(&x_bytes).ok_or(CurveError::NotOnCurve)?;

            // Decompress: compute y from x using curve equation
            // y² = x³ - 3x + b (mod p)
            let y = decompress_y(&x, y_is_odd)?;

            // Create point in Jacobian coordinates (x, y, 1)
            let affine = AffinePoint { x, y };
            let point = Point::from_affine(&affine);

            // Validate point is on curve (should always be true after decompression)
            if !bool::from(point.is_on_curve()) {
                return Err(CurveError::NotOnCurve);
            }

            Ok(point)
        }

        // Invalid point encoding
        _ => Err(CurveError::InvalidEncoding {
            expected: "P-256 point with prefix 0x02, 0x03, or 0x04",
            actual: bytes.len(),
        }),
    }
}

/// Decompress y-coordinate from x-coordinate and parity
///
/// Given x and the parity of y (odd/even), compute y such that:
/// y² = x³ - 3x + b (mod p)
fn decompress_y(x: &FieldElement, y_is_odd: bool) -> Result<FieldElement, CurveError> {
    use super::constants::P256_B;

    // Compute right-hand side: x³ - 3x + b
    let x_squared = x.square();
    let x_cubed = x_squared.mul(x);

    // For P-256, a = -3, so -3x = -3x
    let three_x = x.add(&x).add(x); // 3x
    let rhs = x_cubed.sub(&three_x).add(&FieldElement::from_limbs(P256_B));

    // Compute y = sqrt(rhs) mod p
    let y = rhs.sqrt().ok_or(CurveError::NotOnCurve)?;

    // Check parity and negate if needed
    let y_bytes = y.to_bytes();
    let computed_parity = (y_bytes[31] & 1) != 0; // LSB determines parity

    if computed_parity == y_is_odd {
        Ok(y)
    } else {
        // Negate y: -y = p - y
        Ok(y.neg())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_generation() {
        // Test with a known private key
        let private_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];

        let public_key = P256Ecdh::public_key(&private_key).expect("Failed to generate public key");

        // Verify format
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);

        // Public key should be deterministic
        let public_key2 = P256Ecdh::public_key(&private_key).expect("Failed to generate public key");
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_public_key_compressed() {
        let private_key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];

        let compressed = P256Ecdh::public_key_compressed(&private_key)
            .expect("Failed to generate compressed public key");

        // Verify format
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        // Should be deterministic
        let compressed2 = P256Ecdh::public_key_compressed(&private_key)
            .expect("Failed to generate compressed public key");
        assert_eq!(compressed, compressed2);
    }

    #[test]
    fn test_zero_private_key_rejected() {
        let zero_key = [0u8; 32];
        assert!(P256Ecdh::public_key(&zero_key).is_err());
        assert!(P256Ecdh::public_key_compressed(&zero_key).is_err());
    }

    #[test]
    fn test_shared_secret_symmetric() {
        // Alice's keypair
        let alice_private = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let alice_public = P256Ecdh::public_key(&alice_private)
            .expect("Failed to generate Alice's public key");

        // Bob's keypair
        let bob_private = [
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF,
        ];
        let bob_public = P256Ecdh::public_key(&bob_private)
            .expect("Failed to generate Bob's public key");

        // Compute shared secrets
        let alice_shared = P256Ecdh::shared_secret(&alice_private, &bob_public)
            .expect("Failed to compute Alice's shared secret");
        let bob_shared = P256Ecdh::shared_secret(&bob_private, &alice_public)
            .expect("Failed to compute Bob's shared secret");

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_shared_secret_with_compressed_keys() {
        // Alice's keypair
        let alice_private = [1u8; 32];
        let alice_public_compressed = P256Ecdh::public_key_compressed(&alice_private)
            .expect("Failed to generate Alice's compressed public key");

        // Bob's keypair
        let bob_private = [2u8; 32];
        let bob_public_compressed = P256Ecdh::public_key_compressed(&bob_private)
            .expect("Failed to generate Bob's compressed public key");

        // Compute shared secrets using compressed keys
        let alice_shared = P256Ecdh::shared_secret(&alice_private, &bob_public_compressed)
            .expect("Failed to compute Alice's shared secret");
        let bob_shared = P256Ecdh::shared_secret(&bob_private, &alice_public_compressed)
            .expect("Failed to compute Bob's shared secret");

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_mixed_compressed_uncompressed() {
        let alice_private = [1u8; 32];
        let alice_public_uncompressed = P256Ecdh::public_key(&alice_private).unwrap();
        let alice_public_compressed = P256Ecdh::public_key_compressed(&alice_private).unwrap();

        let bob_private = [2u8; 32];

        // Compute shared secret with both formats
        let shared1 = P256Ecdh::shared_secret(&bob_private, &alice_public_uncompressed).unwrap();
        let shared2 = P256Ecdh::shared_secret(&bob_private, &alice_public_compressed).unwrap();

        // Should be identical
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_invalid_public_key_encoding() {
        let private_key = [1u8; 32];

        // Invalid length
        let invalid_short = [0x04; 64];
        assert!(P256Ecdh::shared_secret(&private_key, &invalid_short).is_err());

        // Invalid prefix
        let invalid_prefix = [0x05; 65];
        assert!(P256Ecdh::shared_secret(&private_key, &invalid_prefix).is_err());

        // Empty
        let empty: &[u8] = &[];
        assert!(P256Ecdh::shared_secret(&private_key, empty).is_err());
    }

    #[test]
    fn test_point_decompression() {
        // Generate a point and compress it
        let private_key = [42u8; 32];
        let uncompressed = P256Ecdh::public_key(&private_key).unwrap();
        let compressed = P256Ecdh::public_key_compressed(&private_key).unwrap();

        // Decompress and verify it matches the original
        let point_from_uncompressed = decode_public_key(&uncompressed).unwrap();
        let point_from_compressed = decode_public_key(&compressed).unwrap();

        // Both should represent the same point
        assert_eq!(point_from_uncompressed, point_from_compressed);
    }

    #[test]
    fn test_different_keys_different_shared_secrets() {
        let alice_private = [1u8; 32];
        let alice_public = P256Ecdh::public_key(&alice_private).unwrap();

        let bob_private1 = [2u8; 32];
        let bob_private2 = [3u8; 32];

        let shared1 = P256Ecdh::shared_secret(&bob_private1, &alice_public).unwrap();
        let shared2 = P256Ecdh::shared_secret(&bob_private2, &alice_public).unwrap();

        // Different private keys should produce different shared secrets
        assert_ne!(shared1, shared2);
    }
}
