//! ECDSA-P521 (Elliptic Curve Digital Signature Algorithm) implementation
//!
//! Implements ECDSA signing and verification for P-521 (secp521r1) curve
//! according to FIPS 186-4 and RFC 6979 (deterministic signatures).
//!
//! # Security
//!
//! - Uses RFC 6979 deterministic k-generation to avoid nonce reuse attacks
//! - Constant-time scalar multiplication for signing
//! - Variable-time operations for verification (public inputs)
//! - Provides approximately 260 bits of security
//!
//! # Example
//!
//! ```ignore
//! use hpcrypt_signatures::ecdsa_p521::{SigningKey, VerifyingKey, Signature};
//!
//! // Generate key pair
//! let signing_key = SigningKey::generate();
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign message
//! let message = b"Hello, world!";
//! let signature = signing_key.sign(message);
//!
//! // Verify signature
//! assert!(verifying_key.verify(message, &signature));
//! ```

use hpcrypt_core::error::CurveError;
use hpcrypt_curves::p521::{Point, Scalar};
// Note: generator_mul disabled due to potential precomputed table bug (similar to P-384 issue)
use hpcrypt_curves::ct_utils::ConstantTimeEq;
use hpcrypt_hash::hmac::HmacSha512;
use hpcrypt_hash::sha512::Sha512;

/// ECDSA-P521 signature (r, s) components
///
/// Both r and s are 66-byte values representing field elements (521 bits).
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// The r component of the signature
    pub r: [u8; 66],
    /// The s component of the signature
    pub s: [u8; 66],
}

impl Signature {
    /// Create a new signature from r and s components
    pub const fn new(r: [u8; 66], s: [u8; 66]) -> Self {
        Self { r, s }
    }

    /// Convert signature to DER encoding (ASN.1)
    ///
    /// Returns a variable-length byte array in DER format.
    /// Maximum size is 141 bytes for P-521 (66-byte integers).
    ///
    /// Format: 0x30 \[total-len\] 0x02 \[r-len\] \[r\] 0x02 \[s-len\] \[s\]
    pub fn to_der(&self) -> ([u8; 141], usize) {
        let mut der = [0u8; 141];
        let mut pos = 0;

        // Helper to encode an integer in DER format
        let encode_integer = |buf: &mut [u8], pos: &mut usize, value: &[u8; 66]| {
            // Skip leading zeros, but keep at least one byte
            let mut start = 0;
            while start < 65 && value[start] == 0 {
                start += 1;
            }

            // If high bit is set, we need to add a 0x00 padding byte
            let needs_padding = (value[start] & 0x80) != 0;
            let len = 66 - start + if needs_padding { 1 } else { 0 };

            buf[*pos] = 0x02; // INTEGER tag
            *pos += 1;
            buf[*pos] = len as u8;
            *pos += 1;

            if needs_padding {
                buf[*pos] = 0x00;
                *pos += 1;
            }

            buf[*pos..*pos + (66 - start)].copy_from_slice(&value[start..]);
            *pos += 66 - start;
        };

        // SEQUENCE tag
        der[pos] = 0x30;
        pos += 1;

        // Length placeholder (we'll fill this in later)
        let len_pos = pos;
        pos += 1;

        // Encode r
        encode_integer(&mut der, &mut pos, &self.r);

        // Encode s
        encode_integer(&mut der, &mut pos, &self.s);

        // Fill in total length
        let total_len = pos - len_pos - 1;
        der[len_pos] = total_len as u8;

        (der, pos)
    }

    /// Parse signature from DER encoding
    ///
    /// Returns None if the DER encoding is invalid or the integers
    /// are out of range for P-521 (> 66 bytes each).
    pub fn from_der(der: &[u8]) -> Option<Self> {
        if der.len() < 8 {
            return None;
        }

        let mut pos = 0;

        // Check SEQUENCE tag
        if der[pos] != 0x30 {
            return None;
        }
        pos += 1;

        // Read total length
        let total_len = der[pos] as usize;
        pos += 1;

        if der.len() < pos + total_len {
            return None;
        }

        // Helper to decode an integer
        let decode_integer = |buf: &[u8], pos: &mut usize| -> Option<[u8; 66]> {
            if *pos + 2 > buf.len() {
                return None;
            }

            // Check INTEGER tag
            if buf[*pos] != 0x02 {
                return None;
            }
            *pos += 1;

            // Read length
            let len = buf[*pos] as usize;
            *pos += 1;

            if len == 0 || len > 67 || *pos + len > buf.len() {
                return None;
            }

            // Read integer bytes
            let mut value = [0u8; 66];
            let mut src_start = 0;

            // Skip padding 0x00 byte if present
            if len > 66 && buf[*pos] == 0x00 {
                src_start = 1;
            }

            let actual_len = len - src_start;
            if actual_len > 66 {
                return None;
            }

            let dst_start = 66 - actual_len;
            value[dst_start..].copy_from_slice(&buf[*pos + src_start..*pos + len]);
            *pos += len;

            Some(value)
        };

        // Decode r
        let r = decode_integer(der, &mut pos)?;

        // Decode s
        let s = decode_integer(der, &mut pos)?;

        Some(Signature { r, s })
    }

    /// Convert signature to bytes (r || s concatenation)
    pub fn to_bytes(&self) -> [u8; 132] {
        let mut bytes = [0u8; 132];
        bytes[0..66].copy_from_slice(&self.r);
        bytes[66..132].copy_from_slice(&self.s);
        bytes
    }

    /// Parse signature from bytes (r || s concatenation)
    pub fn from_bytes(bytes: &[u8; 132]) -> Self {
        let mut r = [0u8; 66];
        let mut s = [0u8; 66];
        r.copy_from_slice(&bytes[0..66]);
        s.copy_from_slice(&bytes[66..132]);
        Self { r, s }
    }
}

/// ECDSA-P521 signing key (private key)
///
/// Contains a secret scalar value used for signing messages.
/// Must be kept confidential.
#[derive(Clone)]
pub struct SigningKey {
    secret: Scalar,
}

impl SigningKey {
    /// Generate a new random signing key
    ///
    /// Uses the system's cryptographically secure random number generator.
    pub fn generate() -> Self {
        use hpcrypt_rng::generate_random_bytes;

        // Try up to 100 times to generate a valid key
        for _ in 0..100 {
            let mut bytes = [0u8; 66];
            generate_random_bytes(&mut bytes).expect("RNG failure");

            // Convert to scalar (automatically reduces mod n)
            let secret = Scalar::from_bytes(&bytes);

            // Ensure the value is not zero
            if !bool::from(secret.is_zero()) {
                return Self { secret };
            }
        }

        // If we reach here (extremely unlikely), panic
        panic!("Failed to generate valid signing key after 100 attempts");
    }

    /// Create a signing key from a byte array
    ///
    /// Returns None if the bytes don't represent a valid scalar in [1, n-1].
    pub fn from_bytes(bytes: &[u8; 66]) -> Option<Self> {
        let secret = Scalar::from_bytes(bytes);
        if bool::from(secret.is_zero()) {
            return None;
        }
        Some(Self { secret })
    }

    /// Convert signing key to bytes (secret scalar)
    ///
    /// WARNING: This exposes the private key. Handle with care.
    pub fn to_bytes(&self) -> [u8; 66] {
        self.secret.to_bytes()
    }

    /// Get the corresponding verifying key (public key)
    pub fn verifying_key(&self) -> VerifyingKey {
        let point = Point::generator().scalar_mul(&self.secret);
        VerifyingKey { point }
    }

    /// Sign a message using ECDSA with RFC 6979 deterministic nonce
    ///
    /// The message is hashed with SHA-512 before signing.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Hash the message
        let mut hasher = Sha512::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // Use RFC 6979 to generate deterministic k
        let k = self.generate_k_rfc6979(&hash);

        // Compute signature
        self.sign_prehashed(&hash, &k)
    }

    /// Sign a pre-hashed message with a given nonce
    ///
    /// This is a low-level function. For normal use, prefer `sign()`.
    ///
    /// # Security
    ///
    /// The nonce k must be:
    /// - Uniformly random or deterministic (RFC 6979)
    /// - In range [1, n-1]
    /// - Never reused for different messages with the same key
    ///
    /// Nonce reuse leads to private key recovery!
    fn sign_prehashed(&self, hash: &[u8; 64], k: &Scalar) -> Signature {
        // Convert hash to scalar (will automatically reduce mod n)
        let mut hash_bytes = [0u8; 66];
        hash_bytes[0..64].copy_from_slice(hash);
        // No masking needed - Scalar::from_bytes handles reduction

        let z = Scalar::from_bytes(&hash_bytes);

        // Compute R = k*G
        let r_point = Point::generator().scalar_mul(k);

        // Get x-coordinate of R (convert to affine)
        let affine_r = r_point
            .to_affine()
            .expect("k*G should not be infinity for valid k");

        // Convert r_x to scalar (x-coordinate mod n)
        let r_x_bytes = affine_r.x.to_bytes();
        let r = Scalar::from_bytes(&r_x_bytes);

        // If r = 0, we need a different k (extremely unlikely with RFC 6979)
        if bool::from(r.is_zero()) {
            // In practice, this should never happen with RFC 6979
            panic!("Generated r = 0, which should be impossible with RFC 6979");
        }

        // Compute s = k^(-1) * (z + r*d) mod n
        let k_inv = k.invert().expect("k should be invertible");
        let r_d = r.mul(&self.secret);
        let z_plus_rd = z.add(&r_d);
        let s = k_inv.mul(&z_plus_rd);

        // If s = 0, we need a different k (extremely unlikely)
        if bool::from(s.is_zero()) {
            panic!("Generated s = 0, which should be impossible with RFC 6979");
        }

        Signature {
            r: r.to_bytes(),
            s: s.to_bytes(),
        }
    }

    /// Generate deterministic nonce k using RFC 6979
    ///
    /// This ensures that the same message always produces the same signature
    /// with a given key, while maintaining security.
    fn generate_k_rfc6979(&self, hash: &[u8; 64]) -> Scalar {
        // RFC 6979 with HMAC-SHA-512
        // V = 0x01 0x01 ... 0x01 (64 bytes)
        let mut v = [0x01u8; 64];
        // K = 0x00 0x00 ... 0x00 (64 bytes)
        let mut k = [0x00u8; 64];

        let secret_bytes = self.secret.to_bytes();

        // Prepare hash for RFC 6979 (scalar reduction handled automatically)
        let mut hash_truncated = [0u8; 66];
        hash_truncated[0..64].copy_from_slice(hash);

        // K = HMAC_K(V || 0x00 || secret || hash)
        let mut data = [0u8; 64 + 1 + 66 + 66]; // V + 0x00 + secret + hash
        data[0..64].copy_from_slice(&v);
        data[64] = 0x00;
        data[65..131].copy_from_slice(&secret_bytes);
        data[131..197].copy_from_slice(&hash_truncated);
        let hmac = HmacSha512::new(&k);
        k = hmac.compute(&data[..197]);

        // V = HMAC_K(V)
        let hmac = HmacSha512::new(&k);
        v = hmac.compute(&v);

        // K = HMAC_K(V || 0x01 || secret || hash)
        data[0..64].copy_from_slice(&v);
        data[64] = 0x01;
        data[65..131].copy_from_slice(&secret_bytes);
        data[131..197].copy_from_slice(&hash_truncated);
        let hmac = HmacSha512::new(&k);
        k = hmac.compute(&data[..197]);

        // V = HMAC_K(V)
        let hmac = HmacSha512::new(&k);
        v = hmac.compute(&v);

        // Generate nonce candidates
        loop {
            // V = HMAC_K(V)
            let hmac = HmacSha512::new(&k);
            v = hmac.compute(&v);

            // Try to convert V to a valid scalar (reduction handled automatically)
            let mut candidate = [0u8; 66];
            candidate[0..64].copy_from_slice(&v);

            let nonce = Scalar::from_bytes(&candidate);
            if !bool::from(nonce.is_zero()) {
                return nonce;
            }

            // If not valid, update K and V
            let mut data2 = [0u8; 65]; // V + 0x00
            data2[0..64].copy_from_slice(&v);
            data2[64] = 0x00;
            let hmac = HmacSha512::new(&k);
            k = hmac.compute(&data2);

            let hmac = HmacSha512::new(&k);
            v = hmac.compute(&v);
        }
    }
}

/// ECDSA-P521 verifying key (public key)
///
/// Contains a point on the P-521 curve used for verifying signatures.
/// Can be safely shared.
#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey {
    point: Point,
}

impl VerifyingKey {
    /// Create a verifying key from a point
    ///
    /// Returns None if the point is the point at infinity or not on the curve.
    pub fn from_point(point: Point) -> Option<Self> {
        if bool::from(point.is_infinity()) {
            return None;
        }
        if !bool::from(point.is_on_curve()) {
            return None;
        }
        Some(Self { point })
    }

    /// Create a verifying key from uncompressed SEC1 encoding
    ///
    /// Format: 0x04 || x (66 bytes) || y (66 bytes)
    /// Total: 133 bytes
    pub fn from_sec1_uncompressed(bytes: &[u8; 133]) -> Result<Self, CurveError> {
        if bytes[0] != 0x04 {
            return Err(CurveError::InvalidEncoding {
                expected: "Uncompressed SEC1 encoding (0x04 prefix)",
                actual: 133,
            });
        }

        use hpcrypt_curves::p521::FieldElement;

        let mut x_bytes = [0u8; 66];
        let mut y_bytes = [0u8; 66];
        x_bytes.copy_from_slice(&bytes[1..67]);
        y_bytes.copy_from_slice(&bytes[67..133]);

        let x = FieldElement::from_bytes(&x_bytes).ok_or(CurveError::InvalidEncoding {
            expected: "Valid field element for P-521",
            actual: 66,
        })?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(CurveError::InvalidEncoding {
            expected: "Valid field element for P-521",
            actual: 66,
        })?;

        let point = Point::from_affine(&x, &y).ok_or(CurveError::NotOnCurve)?;

        Ok(Self { point })
    }

    /// Convert verifying key to uncompressed SEC1 encoding
    ///
    /// Format: 0x04 || x (66 bytes) || y (66 bytes)
    pub fn to_sec1_uncompressed(&self) -> [u8; 133] {
        let mut bytes = [0u8; 133];
        bytes[0] = 0x04;

        let affine = self
            .point
            .to_affine()
            .expect("Public key should not be infinity");

        bytes[1..67].copy_from_slice(&affine.x.to_bytes());
        bytes[67..133].copy_from_slice(&affine.y.to_bytes());

        bytes
    }

    /// Verify a signature on a message
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        // Hash the message
        let mut hasher = Sha512::new();
        hasher.update(message);
        let hash = hasher.finalize();

        self.verify_prehashed(&hash, signature)
    }

    /// Verify a signature on a pre-hashed message
    ///
    /// This is a low-level function. For normal use, prefer `verify()`.
    fn verify_prehashed(&self, hash: &[u8; 64], signature: &Signature) -> bool {
        // Parse r and s from signature
        let r = Scalar::from_bytes(&signature.r);
        if bool::from(r.is_zero()) {
            return false;
        }

        let s = Scalar::from_bytes(&signature.s);
        if bool::from(s.is_zero()) {
            return false;
        }

        // Convert hash to scalar (reduction handled automatically)
        let mut hash_bytes = [0u8; 66];
        hash_bytes[0..64].copy_from_slice(hash);

        let z = Scalar::from_bytes(&hash_bytes);

        // Compute w = s^(-1) mod n
        let w = match s.invert() {
            Some(w) => w,
            None => return false,
        };

        // Compute u1 = z*w mod n
        let u1 = z.mul(&w);

        // Compute u2 = r*w mod n
        let u2 = r.mul(&w);

        // Compute point R = u1*G + u2*Q
        // TEMPORARY FIX: Precomputed table has potential bug (similar to P-384), use regular scalar multiplication
        // TODO: Debug and fix the precomputed table implementation
        let g = Point::generator();
        let u1_g = g.scalar_mul(&u1);
        let u2_q = self.point.scalar_mul(&u2);
        let r_point = u1_g.add(&u2_q);

        // Check if R is infinity (invalid signature)
        if bool::from(r_point.is_infinity()) {
            return false;
        }

        // Get x-coordinate of R
        let affine_r = match r_point.to_affine() {
            Some(coords) => coords,
            None => return false,
        };

        // Convert r_x to scalar
        let r_x_bytes = affine_r.x.to_bytes();
        let r_x_scalar = Scalar::from_bytes(&r_x_bytes);

        // Check if r_x mod n == r
        bool::from(r_x_scalar.ct_eq(&r))
    }

    /// Get the underlying point
    pub fn as_point(&self) -> &Point {
        &self.point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_roundtrip_bytes() {
        let r = [0x42u8; 66];
        let s = [0x84u8; 66];
        let sig = Signature::new(r, s);

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes);

        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    #[test]
    fn test_signature_der_encoding() {
        let r = [0x42u8; 66];
        let s = [0x84u8; 66];
        let sig = Signature::new(r, s);

        let (der, len) = sig.to_der();
        let sig2 = Signature::from_der(&der[..len]).expect("DER parsing failed");

        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    #[test]
    fn test_key_generation() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        // Public key should be on curve
        assert!(!bool::from(vk.point.is_infinity()));
        assert!(bool::from(vk.point.is_on_curve()));
    }

    #[test]
    fn test_signing_and_verification() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        let message = b"Hello, ECDSA-P521!";
        let signature = sk.sign(message);

        // Signature should verify
        assert!(vk.verify(message, &signature));

        // Modified message should not verify
        let bad_message = b"Goodbye, ECDSA-P521!";
        assert!(!vk.verify(bad_message, &signature));
    }

    #[test]
    fn test_deterministic_signing() {
        let sk = SigningKey::generate();
        let message = b"Test message";

        // Sign the same message twice
        let sig1 = sk.sign(message);
        let sig2 = sk.sign(message);

        // Signatures should be identical (RFC 6979 is deterministic)
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
    }

    #[test]
    fn test_verifying_key_sec1_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        let sec1 = vk.to_sec1_uncompressed();
        let vk2 = VerifyingKey::from_sec1_uncompressed(&sec1).expect("SEC1 parsing failed");

        // Should produce the same public key
        let message = b"Test";
        let sig = sk.sign(message);

        assert!(vk.verify(message, &sig));
        assert!(vk2.verify(message, &sig));
    }

    #[test]
    fn test_invalid_signature_detection() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();

        let message = b"Original message";
        let mut signature = sk.sign(message);

        // Corrupt the signature
        signature.r[0] ^= 0x01;

        // Should not verify
        assert!(!vk.verify(message, &signature));
    }

    #[test]
    fn test_zero_scalar_rejection() {
        let zero_bytes = [0u8; 66];
        assert!(SigningKey::from_bytes(&zero_bytes).is_none());
    }

    #[test]
    fn test_simple_sign_verify() {
        use hpcrypt_curves::p521::Scalar;
        use hpcrypt_hash::sha512::Sha512;

        // Use a simple known private key: d = 2
        let two = Scalar::from_u64(2);
        let sk_bytes = two.to_bytes();
        let sk = SigningKey::from_bytes(&sk_bytes).expect("d=2 should be valid");

        // Hash a simple message
        let message = b"test";
        let mut hasher = Sha512::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // Use a simple fixed nonce: k = 3
        let three = Scalar::from_u64(3);
        let k_bytes = three.to_bytes();
        let k = Scalar::from_bytes(&k_bytes);

        // Sign using the fixed nonce
        let sig = sk.sign_prehashed(&hash, &k);

        // Verify should work
        let vk = sk.verifying_key();
        let valid = vk.verify(message, &sig);

        assert!(valid, "Signature verification failed with fixed nonce");
    }

    #[test]
    fn test_sec1_with_known_key() {
        use hpcrypt_curves::p521::{FieldElement, Scalar};

        // Use d = 2 for simplicity
        let two = Scalar::from_u64(2);
        let sk_bytes = two.to_bytes();
        let sk = SigningKey::from_bytes(&sk_bytes).expect("d=2 should be valid");

        // Get verifying key (Q = 2*G)
        let vk = sk.verifying_key();

        // Check that vk.point is on curve
        assert!(
            bool::from(vk.point.is_on_curve()),
            "Public key not on curve!"
        );

        // Get affine coordinates
        let affine_orig = vk.point.to_affine().expect("Should not be infinity");

        // Encode to SEC1
        let sec1 = vk.to_sec1_uncompressed();
        assert_eq!(sec1[0], 0x04, "SEC1 should start with 0x04");

        // Extract x and y from SEC1
        let mut x_bytes = [0u8; 66];
        let mut y_bytes = [0u8; 66];
        x_bytes.copy_from_slice(&sec1[1..67]);
        y_bytes.copy_from_slice(&sec1[67..133]);

        // Parse x and y
        let x_decoded = FieldElement::from_bytes(&x_bytes).expect("X should be valid");
        let y_decoded = FieldElement::from_bytes(&y_bytes).expect("Y should be valid");

        // Check if they match original
        assert_eq!(affine_orig.x, x_decoded, "X coordinates don't match!");
        assert_eq!(affine_orig.y, y_decoded, "Y coordinates don't match!");

        // Try to create point from these coordinates
        let point_reconstructed = Point::from_affine(&x_decoded, &y_decoded);
        assert!(
            point_reconstructed.is_some(),
            "from_affine should succeed with valid coordinates"
        );

        let point = point_reconstructed.unwrap();
        assert!(
            bool::from(point.is_on_curve()),
            "Reconstructed point should be on curve"
        );
    }

    #[test]
    fn test_ecdsa_step_by_step() {
        use hpcrypt_curves::p521::{Point, Scalar};
        use hpcrypt_hash::sha512::Sha512;

        // Use d = 2, k = 3 for easy verification
        let d = Scalar::from_u64(2);
        let k = Scalar::from_u64(3);

        // Compute public key Q = d*G = 2*G
        let g = Point::generator();
        let q = g.scalar_mul(&d);

        assert!(bool::from(q.is_on_curve()), "Q should be on curve");

        // Verify Q == 2*G by checking against double()
        let g_doubled = g.double();
        let affine_q = q.to_affine().unwrap();
        let affine_g2 = g_doubled.to_affine().unwrap();
        assert_eq!(
            affine_q.x.to_bytes(),
            affine_g2.x.to_bytes(),
            "Q should equal 2*G (X coord)"
        );
        assert_eq!(
            affine_q.y.to_bytes(),
            affine_g2.y.to_bytes(),
            "Q should equal 2*G (Y coord)"
        );

        // Hash message
        let message = b"test";
        let mut hasher = Sha512::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // Convert hash to scalar z
        let mut hash_bytes = [0u8; 66];
        hash_bytes[0..64].copy_from_slice(&hash);
        let z = Scalar::from_bytes(&hash_bytes);
        assert!(!bool::from(z.is_zero()), "z should not be zero");

        // Sign: R = k*G
        let r_point = g.scalar_mul(&k);
        assert!(bool::from(r_point.is_on_curve()), "R should be on curve");

        let affine_r = r_point.to_affine().expect("R should not be infinity");
        let r_x_bytes = affine_r.x.to_bytes();
        let r = Scalar::from_bytes(&r_x_bytes);
        assert!(!bool::from(r.is_zero()), "r should not be zero");

        // s = k^(-1) * (z + r*d)
        let k_inv = k.invert().expect("k should be invertible");
        let r_d = r.mul(&d);
        let z_plus_rd = z.add(&r_d);
        let s = k_inv.mul(&z_plus_rd);
        assert!(!bool::from(s.is_zero()), "s should not be zero");

        // Verify: w = s^(-1)
        let w = s.invert().expect("s should be invertible");

        // u1 = z*w, u2 = r*w
        let u1 = z.mul(&w);
        let u2 = r.mul(&w);
        assert!(!bool::from(u1.is_zero()), "u1 should not be zero");
        assert!(!bool::from(u2.is_zero()), "u2 should not be zero");

        // R' = u1*G + u2*Q
        let u1_g = g.scalar_mul(&u1);
        let u2_q = q.scalar_mul(&u2);
        assert!(bool::from(u1_g.is_on_curve()), "u1*G should be on curve");
        assert!(bool::from(u2_q.is_on_curve()), "u2*Q should be on curve");

        let r_prime = u1_g.add(&u2_q);
        assert!(bool::from(r_prime.is_on_curve()), "R' should be on curve");
        assert!(
            !bool::from(r_prime.is_infinity()),
            "R' should not be infinity"
        );

        let affine_rprime = r_prime.to_affine().expect("R' should not be infinity");
        let r_prime_x_bytes = affine_rprime.x.to_bytes();
        let v = Scalar::from_bytes(&r_prime_x_bytes);

        assert!(!bool::from(v.is_zero()), "v should not be zero");

        // Mathematical check: For d=2, k=3:
        // u1*G + u2*Q = u1*G + 2*u2*G = (u1 + 2*u2)*G
        // Should equal 3*G (since k=3)
        // So: u1 + 2*u2 should equal 3 (mod n)

        let two = Scalar::from_u64(2);
        let three = Scalar::from_u64(3);
        let two_u2 = two.mul(&u2);
        let u1_plus_2u2 = u1.add(&two_u2);

        // Check if u1 + 2*u2 == 3
        let u1_plus_2u2_bytes = u1_plus_2u2.to_bytes();
        let three_bytes = three.to_bytes();

        // Also manually compute (u1 + 2*u2)*G to see what we get
        let manual_r_prime = g.scalar_mul(&u1_plus_2u2);
        let affine_manual = manual_r_prime.to_affine().unwrap();

        // And compute k*G directly
        let expected_r = g.scalar_mul(&k);
        let affine_expected = expected_r.to_affine().unwrap();

        // Check if manual_r_prime == expected_r (both should be 3*G)
        if affine_manual.x.to_bytes() != affine_expected.x.to_bytes() {
            panic!("(u1+2*u2)*G != 3*G - scalar arithmetic is broken!");
        }

        if u1_plus_2u2_bytes != three_bytes {
            // The math doesn't check out - there's a bug in our scalar arithmetic or ECDSA logic
            panic!("Math error: u1 + 2*u2 should equal 3, but it doesn't!");
        }

        // Now check if R' actually equals R (which it should if math is correct)
        let affine_orig_r = r_point.to_affine().unwrap();
        let affine_rprime_check = r_prime.to_affine().unwrap();

        // Compare the actual points
        assert_eq!(
            affine_orig_r.x.to_bytes(),
            affine_rprime_check.x.to_bytes(),
            "R and R' X coordinates should match"
        );
        assert_eq!(
            affine_orig_r.y.to_bytes(),
            affine_rprime_check.y.to_bytes(),
            "R and R' Y coordinates should match"
        );

        // If we get here, R == R', so the field element encoding must be the issue
        // Compare r and v by encoding to bytes
        let r_bytes = r.to_bytes();
        let v_bytes = v.to_bytes();

        assert_eq!(
            r_bytes, v_bytes,
            "Verification should succeed: v should equal r"
        );
    }
}
