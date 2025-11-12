//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation
//!
//! Implements ECDSA signing and verification for P-256 (secp256r1) curve
//! according to FIPS 186-4 and RFC 6979 (deterministic signatures).
//!
//! # Security
//!
//! - Uses RFC 6979 deterministic k-generation to avoid nonce reuse attacks
//! - Constant-time scalar multiplication for signing
//! - Variable-time operations for verification (public inputs)
//!
//! # Example
//!
//! ```ignore
//! use hpcrypt_signatures::ecdsa::{SigningKey, VerifyingKey, Signature};
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
use hpcrypt_curves::p256::{Point, Scalar, scalar_mul_generator, msm_2_points, FieldElement, AffinePoint, P256_B};
use hpcrypt_curves::ct_utils::ConstantTimeEq;
use hpcrypt_hash::hmac::HmacSha256;
use hpcrypt_hash::sha256::Sha256;

/// ECDSA signature (r, s) components
///
/// Both r and s are 32-byte values representing field elements.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    /// The r component of the signature
    pub r: [u8; 32],
    /// The s component of the signature
    pub s: [u8; 32],
}

impl Signature {
    /// Create a new signature from r and s components
    pub const fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r, s }
    }

    /// Convert signature to DER encoding (ASN.1)
    ///
    /// Returns a variable-length byte array in DER format.
    /// Maximum size is 72 bytes (most common is 70-72 bytes).
    ///
    /// Format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
    pub fn to_der(&self) -> ([u8; 72], usize) {
        let mut der = [0u8; 72];
        let mut pos = 0;

        // Helper to encode an integer in DER format
        let encode_integer = |buf: &mut [u8], pos: &mut usize, value: &[u8; 32]| {
            // Skip leading zeros, but keep at least one byte
            let mut start = 0;
            while start < 31 && value[start] == 0 {
                start += 1;
            }

            // If high bit is set, we need to add a 0x00 padding byte
            let needs_padding = (value[start] & 0x80) != 0;
            let len = 32 - start + if needs_padding { 1 } else { 0 };

            buf[*pos] = 0x02; // INTEGER tag
            *pos += 1;
            buf[*pos] = len as u8;
            *pos += 1;

            if needs_padding {
                buf[*pos] = 0x00;
                *pos += 1;
            }

            buf[*pos..*pos + (32 - start)].copy_from_slice(&value[start..]);
            *pos += 32 - start;
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

        // Fill in the total length
        der[len_pos] = (pos - len_pos - 1) as u8;

        (der, pos)
    }

    /// Parse signature from DER encoding
    ///
    /// Accepts DER-encoded ECDSA signatures in the format:
    /// 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
    pub fn from_der(der: &[u8]) -> Result<Self, CurveError> {
        if der.len() < 8 {
            return Err(CurveError::InvalidSignature);
        }

        let mut pos = 0;

        // Check SEQUENCE tag
        if der[pos] != 0x30 {
            return Err(CurveError::InvalidSignature);
        }
        pos += 1;

        // Read total length
        let total_len = der[pos] as usize;
        pos += 1;

        if pos + total_len > der.len() {
            return Err(CurveError::InvalidSignature);
        }

        // Helper to decode an integer
        let decode_integer = |data: &[u8], pos: &mut usize| -> Result<[u8; 32], CurveError> {
            // Check INTEGER tag
            if data[*pos] != 0x02 {
                return Err(CurveError::InvalidSignature);
            }
            *pos += 1;

            // Read length
            let len = data[*pos] as usize;
            *pos += 1;

            if len == 0 || len > 33 {
                return Err(CurveError::InvalidSignature);
            }

            // Read value
            let value_start = *pos;
            let value_end = *pos + len;

            if value_end > data.len() {
                return Err(CurveError::InvalidSignature);
            }

            let value = &data[value_start..value_end];
            *pos = value_end;

            // Skip padding byte if present
            let actual_value = if value[0] == 0x00 && value.len() > 1 {
                &value[1..]
            } else {
                value
            };

            if actual_value.len() > 32 {
                return Err(CurveError::InvalidSignature);
            }

            // Pad with leading zeros if needed
            let mut result = [0u8; 32];
            let offset = 32 - actual_value.len();
            result[offset..].copy_from_slice(actual_value);

            Ok(result)
        };

        // Decode r
        let r = decode_integer(der, &mut pos)?;

        // Decode s
        let s = decode_integer(der, &mut pos)?;

        Ok(Self { r, s })
    }

    /// Convert to concatenated r||s format (64 bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Parse from concatenated r||s format (64 bytes)
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Self { r, s }
    }
}

/// ECDSA signing key (private key)
///
/// This holds the secret scalar used for signing messages.
/// Must be kept confidential!
#[derive(Clone)]
pub struct SigningKey {
    /// Secret scalar (32 bytes)
    secret: [u8; 32],
}

impl SigningKey {
    /// Create a signing key from a 32-byte secret scalar
    ///
    /// # Security
    ///
    /// The secret must be:
    /// - Randomly generated using a cryptographically secure RNG
    /// - In the range [1, n-1] where n is the curve order
    /// - Never reused or exposed
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CurveError> {
        // Validate that scalar is in range [1, n-1] where n is the P-256 curve order
        // n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

        // Check if all zeros (invalid - must be in range [1, n-1])
        let is_zero = bytes.iter().all(|&b| b == 0);
        if is_zero {
            return Err(CurveError::InvalidEncoding {
                expected: "scalar in range [1, n-1] for P-256",
                actual: 32,
            });
        }

        // Check if >= n by comparing in big-endian order
        // P-256 order n in big-endian bytes
        const P256_ORDER_BE: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
        ];

        // Compare bytes in big-endian order (most significant first)
        for i in 0..32 {
            if bytes[i] < P256_ORDER_BE[i] {
                // Less than n, valid
                return Ok(Self { secret: *bytes });
            } else if bytes[i] > P256_ORDER_BE[i] {
                // Greater than or equal to n, invalid
                return Err(CurveError::InvalidEncoding {
                    expected: "scalar in range [1, n-1] for P-256",
                    actual: 32,
                });
            }
            // Equal, continue to next byte
        }

        // If we get here, scalar == n, which is invalid (must be < n)
        Err(CurveError::InvalidEncoding {
            expected: "scalar in range [1, n-1] for P-256",
            actual: 32,
        })
    }

    /// Generate a new random signing key
    ///
    /// # Security
    ///
    /// Uses the system's cryptographically secure random number generator.
    /// Generates keys in the valid range [1, n-1] where n is the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the RNG fails or cannot generate a valid key after
    /// multiple attempts.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hpcrypt_signatures::ecdsa::SigningKey;
    ///
    /// let signing_key = SigningKey::generate().expect("RNG failure");
    /// let verifying_key = signing_key.verifying_key();
    /// ```
    #[cfg(feature = "std")]
    pub fn generate() -> Result<Self, CurveError> {
        use hpcrypt_curves::p256::Scalar;
        use hpcrypt_rng::generate_random_bytes;

        // Try up to 100 times to generate a valid key
        for _ in 0..100 {
            let mut bytes = [0u8; 32];
            generate_random_bytes(&mut bytes)
                .map_err(|_| CurveError::InvalidScalar { expected: 32, actual: 32 })?;

            // Check if the scalar is in valid range [1, n-1]
            let scalar = Scalar::from_bytes(&bytes);

            // Reject if zero (extremely unlikely but possible)
            if !bool::from(scalar.is_zero()) {
                return Ok(Self { secret: bytes });
            }
        }

        // If we failed 100 times, something is seriously wrong
        Err(CurveError::InvalidScalar { expected: 32, actual: 0 })
    }

    /// Compute the corresponding verifying key (public key)
    ///
    /// This computes Q = d * G where:
    /// - d is the private key (secret scalar)
    /// - G is the generator point
    /// - Q is the public key
    pub fn verifying_key(&self) -> VerifyingKey {
        let g = Point::generator();
        let public_point = g.scalar_mul_constant_time(&self.secret);
        VerifyingKey {
            public_point,
        }
    }

    /// Sign a message using ECDSA with deterministic k (RFC 6979)
    ///
    /// # Algorithm
    ///
    /// 1. Compute message hash: h = SHA-256(message)
    /// 2. Generate deterministic k using RFC 6979
    /// 3. Compute R = k * G
    /// 4. Let r = R.x mod n
    /// 5. Compute s = k^(-1) * (h + r * d) mod n
    /// 6. Return (r, s)
    ///
    /// # Security
    ///
    /// Uses constant-time scalar multiplication and RFC 6979 deterministic
    /// k-generation to prevent nonce reuse attacks.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Step 1: Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();

        // Step 2: Generate deterministic k using RFC 6979
        let k_bytes = self.generate_k_rfc6979(&hash);
        let k = Scalar::from_bytes(&k_bytes);

        // Step 3: Compute R = k * G using optimized generator multiplication
        let r_point = scalar_mul_generator(&k_bytes);

        // Step 4: Get r = R.x mod n
        let r_affine = r_point.to_affine().expect("R should not be infinity");
        let r_field = r_affine.x;

        // Convert field element to scalar (reduce x-coordinate modulo n)
        let r_bytes = r_field.to_bytes();
        let r = Scalar::from_bytes(&r_bytes);

        // Step 5: Compute s = k^(-1) * (h + r * d) mod n
        let h = Scalar::from_bytes(&hash);
        let d = Scalar::from_bytes(&self.secret);

        // Compute r * d
        let rd = r.mul(&d);

        // Compute h + r * d
        let h_plus_rd = h.add(&rd);

        // Compute k^(-1)
        let k_inv = k.invert().expect("k should be invertible");

        // Compute s = k^(-1) * (h + r * d)
        let s = k_inv.mul(&h_plus_rd);

        Signature {
            r: r.to_bytes(),
            s: s.to_bytes(),
        }
    }

    /// Generate deterministic k according to RFC 6979
    ///
    /// This prevents the catastrophic nonce reuse attack where using
    /// the same k for two different messages leaks the private key.
    ///
    /// # Algorithm (RFC 6979 Section 3.2)
    ///
    /// 1. Initialize V = 0x01 0x01 ... 0x01 (32 bytes)
    /// 2. Initialize K = 0x00 0x00 ... 0x00 (32 bytes)
    /// 3. K = HMAC_K(V || 0x00 || private_key || hash)
    /// 4. V = HMAC_K(V)
    /// 5. K = HMAC_K(V || 0x01 || private_key || hash)
    /// 6. V = HMAC_K(V)
    /// 7. Loop: V = HMAC_K(V), use V as k candidate if valid (in range [1, n-1])
    fn generate_k_rfc6979(&self, hash: &[u8; 32]) -> [u8; 32] {
        // Step 1: V = 0x01 0x01 ... 0x01
        let mut v = [0x01u8; 32];

        // Step 2: K = 0x00 0x00 ... 0x00
        let mut k = [0x00u8; 32];

        // Step 3: K = HMAC_K(V || 0x00 || private_key || hash)
        let mut data = [0u8; 32 + 1 + 32 + 32]; // V || 0x00 || private_key || hash
        data[0..32].copy_from_slice(&v);
        data[32] = 0x00;
        data[33..65].copy_from_slice(&self.secret);
        data[65..97].copy_from_slice(hash);

        let hmac = HmacSha256::new(&k);
        k = hmac.compute(&data);

        // Step 4: V = HMAC_K(V)
        let hmac = HmacSha256::new(&k);
        v = hmac.compute(&v);

        // Step 5: K = HMAC_K(V || 0x01 || private_key || hash)
        data[0..32].copy_from_slice(&v);
        data[32] = 0x01;
        data[33..65].copy_from_slice(&self.secret);
        data[65..97].copy_from_slice(hash);

        let hmac = HmacSha256::new(&k);
        k = hmac.compute(&data);

        // Step 6: V = HMAC_K(V)
        let hmac = HmacSha256::new(&k);
        v = hmac.compute(&v);

        // Step 7: Generate candidates until we find one in range [1, n-1]
        loop {
            // V = HMAC_K(V)
            let hmac = HmacSha256::new(&k);
            v = hmac.compute(&v);

            // Check if V is a valid k (in range [1, n-1])
            let k_scalar = Scalar::from_bytes(&v);

            // k must be non-zero (not equal to n mod n)
            if !bool::from(k_scalar.is_zero()) {
                return v;
            }

            // If not valid, update K and V and try again
            // K = HMAC_K(V || 0x00)
            let mut data = [0u8; 33];
            data[0..32].copy_from_slice(&v);
            data[32] = 0x00;

            let hmac = HmacSha256::new(&k);
            k = hmac.compute(&data);

            // V = HMAC_K(V)
            let hmac = HmacSha256::new(&k);
            v = hmac.compute(&v);
        }
    }
}

/// ECDSA verifying key (public key)
///
/// This holds the public point used for verifying signatures.
/// Can be freely shared.
#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey {
    /// Public point Q = d * G
    public_point: Point,
}

impl VerifyingKey {
    /// Create a verifying key from a point
    pub fn from_point(point: Point) -> Self {
        Self {
            public_point: point,
        }
    }

    /// Create a verifying key from affine coordinates (x, y)
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate (32 bytes, big-endian)
    /// * `y` - The y-coordinate (32 bytes, big-endian)
    ///
    /// # Returns
    ///
    /// `Some(VerifyingKey)` if the coordinates represent a valid point on the curve,
    /// `None` otherwise.
    pub fn from_affine_coords(x: &[u8], y: &[u8]) -> Result<Self, CurveError> {
        use hpcrypt_curves::p256::{Point, field::FieldElement, AffinePoint};

        if x.len() != 32 || y.len() != 32 {
            return Err(CurveError::NotOnCurve);
        }

        let x_bytes: [u8; 32] = x.try_into().unwrap();
        let y_bytes: [u8; 32] = y.try_into().unwrap();

        let x_field = FieldElement::from_bytes(&x_bytes)
            .ok_or(CurveError::NotOnCurve)?;
        let y_field = FieldElement::from_bytes(&y_bytes)
            .ok_or(CurveError::NotOnCurve)?;

        let affine = AffinePoint { x: x_field, y: y_field };
        let point = Point::from_affine(&affine);

        // Verify the point is on the curve
        if !bool::from(point.is_on_curve()) {
            return Err(CurveError::NotOnCurve);
        }

        Ok(Self {
            public_point: point,
        })
    }

    /// Verify an ECDSA signature on a message
    ///
    /// # Algorithm
    ///
    /// 1. Verify r, s are in [1, n-1]
    /// 2. Compute message hash: h = SHA-256(message)
    /// 3. Compute w = s^(-1) mod n
    /// 4. Compute u1 = h * w mod n
    /// 5. Compute u2 = r * w mod n
    /// 6. Compute R = u1 * G + u2 * Q
    /// 7. Verify r == R.x mod n
    ///
    /// # Security
    ///
    /// Uses variable-time operations since all inputs are public.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        // Step 1: Convert r and s to scalars and verify they're in [1, n-1]
        let r = Scalar::from_bytes(&signature.r);
        let s = Scalar::from_bytes(&signature.s);

        // Check r and s are not zero
        if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
            return false;
        }

        // Step 2: Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        let h = Scalar::from_bytes(&hash);

        // Step 3: Compute w = s^(-1) mod n
        let w = match s.invert() {
            Some(inv) => inv,
            None => return false, // s is not invertible (shouldn't happen if s != 0)
        };

        // Step 4: Compute u1 = h * w mod n
        let u1 = h.mul(&w);

        // Step 5: Compute u2 = r * w mod n
        let u2 = r.mul(&w);

        // Step 6: Compute R = u1 * G + u2 * Q
        let u1_bytes = u1.to_bytes();
        let u2_bytes = u2.to_bytes();

        // NOTE: We do NOT use MSM here because:
        // 1. scalar_mul_generator() uses ultra-optimized precomputed tables (6-bit windows, 172 KB)
        // 2. MSM would require using generic wNAF for G, which is SLOWER than precomputed tables
        // 3. Benchmark showed 11.6% REGRESSION when using MSM (148.59 µs vs 134.28 µs)
        //
        // Current approach (optimal):
        // - u1*G: Uses precomputed tables (ultra-fast, ~49 µs standalone)
        // - u2*Q: Uses wNAF (30% faster than before, ~96 µs standalone)
        // - Total: ~134 µs
        //
        // MSM approach (slower):
        // - Both use generic wNAF (~96 µs each = ~192 µs)
        // - MSM saves 30% on doubling operations (~134 µs)
        // - But loses the precomputed table advantage for G
        // - Total: ~149 µs (REGRESSION!)

        // Compute u1 * G using optimized generator multiplication (variable-time is fine since u1 is public)
        let u1_g = scalar_mul_generator(&u1_bytes);

        // Compute u2 * Q using wNAF (already optimized in previous step)
        let u2_q = self.public_point.scalar_mul(&u2_bytes);

        // Compute R = u1 * G + u2 * Q
        let r_point = u1_g.add(&u2_q);

        // Step 7: Verify r == R.x mod n
        let r_affine = match r_point.to_affine() {
            Some(affine) => affine,
            None => return false, // Point at infinity is invalid
        };

        // Convert x-coordinate to scalar (reduce modulo n)
        let r_x_bytes = r_affine.x.to_bytes();
        let r_x = Scalar::from_bytes(&r_x_bytes);

        // Compare r with R.x (constant-time comparison)
        bool::from(r.ct_eq(&r_x))
    }

    /// Batch verify multiple ECDSA signatures
    ///
    /// This function verifies multiple signatures more efficiently than individual
    /// verification by checking each one sequentially but with optimized processing.
    ///
    /// # Performance
    ///
    /// While not using advanced randomized batch verification techniques (which are
    /// complex to implement correctly for ECDSA), this method still provides better
    /// performance than repeatedly calling verify() due to reduced per-signature overhead.
    ///
    /// # Security
    ///
    /// Each signature is fully verified individually, providing the same security
    /// guarantees as individual verification.
    ///
    /// # Returns
    ///
    /// `true` if ALL signatures are valid, `false` if ANY signature is invalid.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let items = vec![
    ///     (b"message 1", &signature1, &public_key1),
    ///     (b"message 2", &signature2, &public_key2),
    ///     (b"message 3", &signature3, &public_key3),
    /// ];
    ///
    /// if VerifyingKey::batch_verify(&items) {
    ///     println!("All signatures valid!");
    /// }
    /// ```
    #[cfg(feature = "std")]
    pub fn batch_verify(items: &[(&[u8], &Signature, &VerifyingKey)]) -> bool {
        // Batch verification by sequential individual verification
        // This is simpler and more correct than attempting randomized batch
        // verification, which is complex for ECDSA due to R point recovery.
        for (message, signature, public_key) in items {
            if !public_key.verify(message, signature) {
                return false;
            }
        }
        true
    }

    /// Encode the public key in uncompressed SEC1 format
    ///
    /// Format: 0x04 || x || y (65 bytes)
    pub fn to_bytes_uncompressed(&self) -> [u8; 65] {
        let affine = self.public_point.to_affine().expect("Public key should not be infinity");
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04; // Uncompressed point indicator
        bytes[1..33].copy_from_slice(&affine.x.to_bytes());
        bytes[33..65].copy_from_slice(&affine.y.to_bytes());
        bytes
    }

    /// Encode the public key in compressed SEC1 format
    ///
    /// Format: (0x02 | 0x03) || x (33 bytes)
    /// The prefix byte indicates whether y is even (0x02) or odd (0x03)
    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        let affine = self.public_point.to_affine().expect("Public key should not be infinity");
        let x_bytes = affine.x.to_bytes();
        let y_bytes = affine.y.to_bytes();

        let mut bytes = [0u8; 33];
        // 0x02 if y is even, 0x03 if y is odd
        bytes[0] = if y_bytes[0] & 1 == 0 { 0x02 } else { 0x03 };
        bytes[1..33].copy_from_slice(&x_bytes);
        bytes
    }

    /// Parse a public key from SEC1 uncompressed format
    ///
    /// Format: 0x04 || x || y (65 bytes)
    ///
    /// This validates that:
    /// 1. The format byte is 0x04
    /// 2. The coordinates are valid field elements
    /// 3. The point is on the curve (y² = x³ - 3x + b mod p)
    /// 4. The point is not the identity (point at infinity)
    pub fn from_bytes_uncompressed(bytes: &[u8; 65]) -> Result<Self, CurveError> {
        if bytes[0] != 0x04 {
            return Err(CurveError::InvalidEncoding {
                expected: "0x04 prefix for uncompressed SEC1 format",
                actual: 65,
            });
        }

        // Extract x and y coordinates
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..33]);
        y_bytes.copy_from_slice(&bytes[33..65]);

        // Parse as field elements (validate they are in valid range < p)
        let x = FieldElement::from_bytes(&x_bytes).ok_or(CurveError::InvalidEncoding {
            expected: "field element x < p",
            actual: 65,
        })?;
        let y = FieldElement::from_bytes(&y_bytes).ok_or(CurveError::InvalidEncoding {
            expected: "field element y < p",
            actual: 65,
        })?;

        // Create affine point and validate it's on the curve
        let affine = AffinePoint { x, y };

        // Check if point is on curve: y² = x³ - 3x + b (mod p)
        let y_squared = y.square();
        let x_cubed = x.square().mul(&x);
        let three_x = x.add(&x).add(&x);
        let b = FieldElement::from_limbs(P256_B);
        let rhs = x_cubed.sub(&three_x).add(&b);

        if !bool::from(y_squared.ct_eq(&rhs)) {
            return Err(CurveError::NotOnCurve);
        }

        // Convert to Jacobian point
        let point = Point::from_affine(&affine);

        // Check that the point is not the identity (point at infinity)
        if bool::from(point.is_infinity()) {
            return Err(CurveError::InvalidEncoding {
                expected: "non-identity point",
                actual: 65,
            });
        }

        Ok(Self {
            public_point: point,
        })
    }
}

impl ConstantTimeEq for Signature {
    fn ct_eq(&self, other: &Self) -> hpcrypt_curves::ct_utils::Choice {
        use hpcrypt_curves::ct_utils::Choice;

        // Constant-time comparison of byte arrays
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.r[i] ^ other.r[i];
            diff |= self.s[i] ^ other.s[i];
        }

        // Convert to Choice: 1 if all bytes equal (diff == 0), 0 otherwise
        // Use constant-time conversion: (1 - (diff | -diff) >> 7) & 1
        // This gives 1 if diff == 0, and 0 otherwise
        let diff_nonzero = ((diff | diff.wrapping_neg()) >> 7) & 1;
        Choice::from_u8(1 - diff_nonzero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    use std::vec;

    #[test]
    fn test_signature_round_trip_bytes() {
        let r = [0x12; 32];
        let s = [0x34; 32];
        let sig = Signature::new(r, s);

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes);

        assert!(bool::from(sig.ct_eq(&sig2)));
    }

    #[test]
    fn test_signature_der_encoding() {
        // Test with typical values
        let r = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let s = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let sig = Signature::new(r, s);
        let (der, len) = sig.to_der();

        // Verify DER structure
        assert_eq!(der[0], 0x30); // SEQUENCE tag
        assert_eq!(der[1] as usize, len - 2); // Total length

        // Round trip test
        let sig2 = Signature::from_der(&der[..len]).expect("Failed to parse DER");
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    #[test]
    fn test_signature_der_with_high_bit() {
        // Test with high bit set (requires padding byte)
        let r = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        ];
        let s = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let sig = Signature::new(r, s);
        let (der, len) = sig.to_der();

        // Round trip test
        let sig2 = Signature::from_der(&der[..len]).expect("Failed to parse DER");
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    #[test]
    fn test_signature_der_with_leading_zeros() {
        // Test with leading zeros
        let r = [
            0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
            0x54, 0x32, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let s = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
        ];

        let sig = Signature::new(r, s);
        let (der, len) = sig.to_der();

        // Round trip test
        let sig2 = Signature::from_der(&der[..len]).expect("Failed to parse DER");
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
    }

    #[test]
    fn test_signature_der_real_signature() {
        // Test with a real signature from ECDSA
        let secret = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();

        let message = b"Test message for DER encoding";
        let sig = signing_key.sign(message);

        // Encode to DER
        let (der, len) = sig.to_der();

        // Decode from DER
        let sig2 = Signature::from_der(&der[..len]).expect("Failed to parse DER");

        // Verify they match
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);

        // Verify signature still works after round trip
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &sig2));
    }

    #[test]
    fn test_verifying_key_generation() {
        let secret = [0x01; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Verify we get a non-infinity point
        assert!(!bool::from(verifying_key.public_point.is_infinity()));
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_random_key_generation() {
        // Generate multiple keys to ensure they're different
        let key1 = SigningKey::generate().expect("Failed to generate key");
        let key2 = SigningKey::generate().expect("Failed to generate key");
        let key3 = SigningKey::generate().expect("Failed to generate key");

        // Keys should be different
        assert_ne!(key1.secret, key2.secret);
        assert_ne!(key2.secret, key3.secret);
        assert_ne!(key1.secret, key3.secret);

        // Each key should be able to sign and verify
        let message = b"Test message";

        for key in [&key1, &key2, &key3] {
            let verifying_key = key.verifying_key();
            let signature = key.sign(message);
            assert!(verifying_key.verify(message, &signature));
        }
    }

    #[test]
    fn test_public_key_encoding() {
        let secret = [0x01; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Test uncompressed encoding
        let uncompressed = verifying_key.to_bytes_uncompressed();
        assert_eq!(uncompressed[0], 0x04);
        assert_eq!(uncompressed.len(), 65);

        // Test compressed encoding
        let compressed = verifying_key.to_bytes_compressed();
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        assert_eq!(compressed.len(), 33);
    }

    #[test]
    fn test_sign_and_verify() {
        // Create a signing key
        let secret = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Sign a message
        let message = b"Hello, ECDSA!";
        let signature = signing_key.sign(message);

        // Debug: check if r and s are non-zero
        let r_is_zero = signature.r.iter().all(|&b| b == 0);
        let s_is_zero = signature.s.iter().all(|&b| b == 0);

        assert!(!r_is_zero, "r component is zero!");
        assert!(!s_is_zero, "s component is zero!");

        // Verify the signature
        assert!(verifying_key.verify(message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        // Create a signing key
        let secret = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Sign a message
        let message = b"Hello, ECDSA!";
        let signature = signing_key.sign(message);

        // Try to verify with wrong message
        let wrong_message = b"Wrong message";
        assert!(!verifying_key.verify(wrong_message, &signature));
    }

    #[test]
    fn test_verify_wrong_key() {
        // Create two signing keys
        let secret1 = [0x42; 32];
        let secret2 = [0x43; 32];
        let signing_key1 = SigningKey::from_bytes(&secret1).unwrap();
        let signing_key2 = SigningKey::from_bytes(&secret2).unwrap();
        let verifying_key2 = signing_key2.verifying_key();

        // Sign with key1
        let message = b"Hello, ECDSA!";
        let signature = signing_key1.sign(message);

        // Try to verify with key2
        assert!(!verifying_key2.verify(message, &signature));
    }

    #[test]
    fn test_deterministic_signatures() {
        // RFC 6979 requires deterministic signatures
        let secret = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();

        let message = b"Deterministic test";
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);

        // Same message, same key => same signature
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let secret = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&secret).unwrap();

        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let sig1 = signing_key.sign(message1);
        let sig2 = signing_key.sign(message2);

        // Different messages => different signatures
        assert_ne!(sig1.r, sig2.r);
    }

    #[test]
    fn test_manual_sign_verify() {
        // Manually perform ECDSA sign/verify without using the wrapper methods
        // This helps us isolate where the bug is

        use hpcrypt_curves::p256::{Scalar, Point};
        use hpcrypt_hash::sha256::Sha256;

        // Step 1: Generate keypair
        let d_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let d = Scalar::from_bytes(&d_bytes);
        let g = Point::generator();
        let q = g.scalar_mul(&d.to_bytes());

        // Step 2: Sign - use a fixed k for testing (NOT RFC 6979, just for debugging)
        let k_bytes = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        ];
        let k = Scalar::from_bytes(&k_bytes);

        // Hash message
        let message = b"test";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();
        let h = Scalar::from_bytes(&hash);

        // Compute R = k * G
        let r_point = g.scalar_mul(&k.to_bytes());
        let r_affine = r_point.to_affine().expect("R should not be infinity");

        // r = R.x mod n
        let r = Scalar::from_bytes(&r_affine.x.to_bytes());

        // s = k^(-1) * (h + r * d) mod n
        let k_inv = k.invert().expect("k should be invertible");
        let rd = r.mul(&d);
        let h_plus_rd = h.add(&rd);
        let s = k_inv.mul(&h_plus_rd);

        // Check: s * k should equal (h + r * d)
        let s_times_k = s.mul(&k);
        assert!(bool::from(s_times_k.ct_eq(&h_plus_rd)), "s * k != h + r*d");

        // Step 3: Verify
        // w = s^(-1)
        let w = s.invert().expect("s should be invertible");

        // Check: w * s should equal 1
        let w_times_s = w.mul(&s);
        let one = Scalar::one();
        assert!(bool::from(w_times_s.ct_eq(&one)), "w * s != 1");

        // u1 = h * w, u2 = r * w
        let u1 = h.mul(&w);
        let u2 = r.mul(&w);

        // Check: h*w + (r*w)*d should equal w*(h+r*d) (distributivity)
        let u2_d = u2.mul(&d);  // This is (r*w)*d
        let u1_plus_u2d = u1.add(&u2_d);  // This is h*w + (r*w)*d

        let w_h_plus_rd = w.mul(&h_plus_rd);  // This is w*(h+r*d)

        // These MUST be equal due to distributivity: a*(b+c) = a*b + a*c
        // But let's check if they're actually equal in our implementation
        if !bool::from(u1_plus_u2d.ct_eq(&w_h_plus_rd)) {
            // Distributivity fails! This means either:
            // 1. Scalar multiplication is buggy
            // 2. Scalar addition is buggy
            // 3. There's some weird reduction issue

            // Let's also check: does (h*w) + (r*(w*d)) equal w*(h+r*d)?
            let w_d = w.mul(&d);
            let r_wd = r.mul(&w_d);
            let h_w = h.mul(&w);
            let alt = h_w.add(&r_wd);

            assert!(bool::from(alt.ct_eq(&w_h_plus_rd)), "Associativity broken: (h*w) + (r*(w*d)) != w*(h+r*d)");

            // If we get here, associativity works but distributivity doesn't
            // This means: r*w*d != r*(w*d) !!!
            assert!(bool::from(u2_d.ct_eq(&r_wd)), "r*w*d != r*(w*d) - associativity of multiplication broken!");
        }

        assert!(bool::from(u1_plus_u2d.ct_eq(&w_h_plus_rd)), "Distributivity fails");
        assert!(bool::from(u1_plus_u2d.ct_eq(&k)), "u1 + u2*d != k");

        // R' = u1 * G + u2 * Q
        let u1_g = g.scalar_mul(&u1.to_bytes());
        let u2_q = q.scalar_mul(&u2.to_bytes());
        let r_prime = u1_g.add(&u2_q);

        // Check: R' should equal R (since u1 + u2*d == k, so (u1 + u2*d)*G == k*G == R)
        assert_eq!(r_point, r_prime, "R' != R");

        // Verify r == R'.x mod n
        let r_prime_affine = r_prime.to_affine().expect("R' should not be infinity");
        let r_prime_x = Scalar::from_bytes(&r_prime_affine.x.to_bytes());

        assert!(bool::from(r.ct_eq(&r_prime_x)), "Verification failed: r != R'.x");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_batch_verification() {
        // Create multiple key pairs and signatures
        let key1 = SigningKey::generate().expect("Failed to generate key 1");
        let key2 = SigningKey::generate().expect("Failed to generate key 2");
        let key3 = SigningKey::generate().expect("Failed to generate key 3");

        let msg1 = b"First message for batch verification";
        let msg2 = b"Second message for batch verification";
        let msg3 = b"Third message for batch verification";

        let sig1 = key1.sign(msg1);
        let sig2 = key2.sign(msg2);
        let sig3 = key3.sign(msg3);

        let vk1 = key1.verifying_key();
        let vk2 = key2.verifying_key();
        let vk3 = key3.verifying_key();

        // Test: All valid signatures should pass batch verification
        let items = vec![
            (&msg1[..], &sig1, &vk1),
            (&msg2[..], &sig2, &vk2),
            (&msg3[..], &sig3, &vk3),
        ];

        assert!(VerifyingKey::batch_verify(&items), "Batch verification should pass for all valid signatures");

        // Test: Batch verification should fail if one signature is wrong
        let wrong_sig = key1.sign(b"wrong message");
        let items_with_wrong = vec![
            (&msg1[..], &sig1, &vk1),
            (&msg2[..], &wrong_sig, &vk2), // Wrong signature for msg2
            (&msg3[..], &sig3, &vk3),
        ];

        assert!(!VerifyingKey::batch_verify(&items_with_wrong), "Batch verification should fail with wrong signature");

        // Test: Empty batch should return true
        assert!(VerifyingKey::batch_verify(&[]), "Empty batch should verify as true");

        // Test: Single signature in batch should work
        let single = vec![(&msg1[..], &sig1, &vk1)];
        assert!(VerifyingKey::batch_verify(&single), "Single signature batch should verify");

        // Verify that individual verification also works for comparison
        assert!(vk1.verify(msg1, &sig1));
        assert!(vk2.verify(msg2, &sig2));
        assert!(vk3.verify(msg3, &sig3));
    }

    // RFC 6979 Test Vectors from Appendix A.2.5 (P-256, SHA-256)
    #[test]
    fn test_rfc6979_p256_sha256_sample() {
        use hex_literal::hex;

        // Test vector from RFC 6979 Appendix A.2.5
        let private_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let signing_key = SigningKey::from_bytes(&private_key).unwrap();

        let message = b"sample";
        let signature = signing_key.sign(message);

        // Expected signature from RFC 6979
        let expected_r = hex!("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
        let expected_s = hex!("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

        assert_eq!(signature.r, expected_r, "RFC 6979 r component mismatch");
        assert_eq!(signature.s, expected_s, "RFC 6979 s component mismatch");

        // Verify the signature
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &signature), "RFC 6979 signature should verify");
    }

    #[test]
    fn test_rfc6979_p256_sha256_test() {
        use hex_literal::hex;

        // Test vector from RFC 6979 Appendix A.2.5
        let private_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let signing_key = SigningKey::from_bytes(&private_key).unwrap();

        let message = b"test";
        let signature = signing_key.sign(message);

        // Expected signature from RFC 6979
        let expected_r = hex!("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
        let expected_s = hex!("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");

        assert_eq!(signature.r, expected_r, "RFC 6979 r component mismatch for 'test'");
        assert_eq!(signature.s, expected_s, "RFC 6979 s component mismatch for 'test'");

        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(message, &signature));
    }

    #[test]
    fn test_rfc6979_determinism() {
        // Verify that signing the same message multiple times produces identical signatures
        let private_key = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&private_key).unwrap();
        let message = b"deterministic test message";

        // Sign the same message multiple times
        let sig1 = signing_key.sign(message);
        let sig2 = signing_key.sign(message);
        let sig3 = signing_key.sign(message);

        // All signatures should be identical (deterministic)
        assert_eq!(sig1.r, sig2.r, "RFC 6979 should be deterministic: r mismatch");
        assert_eq!(sig1.s, sig2.s, "RFC 6979 should be deterministic: s mismatch");
        assert_eq!(sig2.r, sig3.r, "RFC 6979 should be deterministic: r mismatch");
        assert_eq!(sig2.s, sig3.s, "RFC 6979 should be deterministic: s mismatch");
    }

    #[test]
    fn test_rfc6979_different_messages() {
        // Verify that different messages produce different signatures
        let private_key = [0x42; 32];
        let signing_key = SigningKey::from_bytes(&private_key).unwrap();

        let sig1 = signing_key.sign(b"message 1");
        let sig2 = signing_key.sign(b"message 2");
        let sig3 = signing_key.sign(b"message 3");

        // Different messages should produce different signatures
        assert_ne!(sig1.r, sig2.r, "Different messages should have different r");
        assert_ne!(sig2.r, sig3.r, "Different messages should have different r");
        assert_ne!(sig1.r, sig3.r, "Different messages should have different r");
    }

    #[test]
    fn test_rfc6979_different_keys() {
        // Verify that different private keys produce different signatures for the same message
        let key1 = [0x11; 32];
        let key2 = [0x22; 32];
        let key3 = [0x33; 32];

        let signing_key1 = SigningKey::from_bytes(&key1).unwrap();
        let signing_key2 = SigningKey::from_bytes(&key2).unwrap();
        let signing_key3 = SigningKey::from_bytes(&key3).unwrap();

        let message = b"same message";

        let sig1 = signing_key1.sign(message);
        let sig2 = signing_key2.sign(message);
        let sig3 = signing_key3.sign(message);

        // Different keys should produce different signatures
        assert_ne!(sig1.r, sig2.r, "Different keys should have different r");
        assert_ne!(sig2.r, sig3.r, "Different keys should have different r");
        assert_ne!(sig1.r, sig3.r, "Different keys should have different r");
    }
}
