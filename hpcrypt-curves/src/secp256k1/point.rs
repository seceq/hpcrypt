//! secp256k1 Point Arithmetic
//!
//! This module implements elliptic curve point operations for secp256k1
//! using Jacobian coordinates for efficient computation.
//!
//! # Curve Equation
//!
//! y² = x³ + 7 (mod p)
//!
//! Note: secp256k1 has a = 0 and b = 7, which simplifies some formulas
//! compared to P-256 which has a = -3.

use super::constants::{SECP256K1_B, SECP256K1_GX, SECP256K1_GY};
use super::field_ops::FieldElement;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A point on the secp256k1 elliptic curve in Jacobian coordinates
///
/// Jacobian coordinates (X, Y, Z) represent the affine point (X/Z², Y/Z³).
/// The point at infinity is represented as (1, 1, 0).
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl Point {
    /// The point at infinity (identity element)
    #[inline]
    pub const fn infinity() -> Self {
        Point {
            x: FieldElement::ONE,
            y: FieldElement::ONE,
            z: FieldElement::ZERO,
        }
    }

    /// The generator point G
    #[inline]
    pub const fn generator() -> Self {
        Point {
            x: FieldElement::from_limbs(SECP256K1_GX),
            y: FieldElement::from_limbs(SECP256K1_GY),
            z: FieldElement::ONE,
        }
    }

    /// Check if this point is the point at infinity
    #[inline]
    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Check if this point is on the curve (in Jacobian coordinates)
    ///
    /// For secp256k1: y² = x³ + 7 (mod p)
    /// In Jacobian coordinates: Y² = X³ + 7·Z⁶
    pub fn is_on_curve(&self) -> Choice {
        // Infinity is considered on curve
        if bool::from(self.is_infinity()) {
            return Choice::from(1);
        }

        // Compute Y²
        let y_squared = self.y.square();

        // Compute X³
        let x_squared = self.x.square();
        let x_cubed = x_squared.mul(&self.x);

        // Compute 7·Z⁶
        let z_squared = self.z.square(); // Z²
        let z_fourth = z_squared.square(); // Z⁴
        let z_sixth = z_fourth.mul(&z_squared); // Z⁶
        let seven = FieldElement::from_limbs([7, 0, 0, 0]);
        let b_z6 = seven.mul(&z_sixth);

        // Check Y² = X³ + 7·Z⁶
        let rhs = x_cubed.add(&b_z6);
        y_squared.ct_eq(&rhs)
    }

    /// Add two points
    ///
    /// Uses the complete addition formula that works for all cases
    /// including point doubling and adding a point to itself.
    pub fn add(&self, other: &Point) -> Point {
        // Handle special case: P is infinity
        let p_inf = self.is_infinity();

        // Handle special case: Q is infinity
        let q_inf = other.is_infinity();

        // Compute addition formula (always, for constant-time)

        // U₁ = X₁·Z₂²
        let z2_squared = other.z.square();
        let u1 = self.x.mul(&z2_squared);

        // U₂ = X₂·Z₁²
        let z1_squared = self.z.square();
        let u2 = other.x.mul(&z1_squared);

        // S₁ = Y₁·Z₂³
        let z2_cubed = z2_squared.mul(&other.z);
        let s1 = self.y.mul(&z2_cubed);

        // S₂ = Y₂·Z₁³
        let z1_cubed = z1_squared.mul(&self.z);
        let s2 = other.y.mul(&z1_cubed);

        // H = U₂ - U₁
        let h = u2.sub(&u1);

        // R = S₂ - S₁
        let r = s2.sub(&s1);

        // Check for special cases
        let h_zero = h.is_zero();
        let r_zero = r.is_zero();

        // If H = 0 and R = 0: points are equal, use doubling
        let points_equal = h_zero & r_zero;

        // If H = 0 and R ≠ 0: points are inverses, return infinity
        let points_inverse = h_zero & (!r_zero);

        // Compute general addition (even if we might not use it)
        let h_squared = h.square(); // H²
        let h_cubed = h_squared.mul(&h); // H³

        let u1_h2 = u1.mul(&h_squared); // U₁·H²
        let two = FieldElement::from_limbs([2, 0, 0, 0]);
        let two_u1_h2 = u1_h2.mul(&two); // 2·U₁·H²

        // X₃ = R² - H³ - 2·U₁·H²
        let r_squared = r.square();
        let x3 = r_squared.sub(&h_cubed).sub(&two_u1_h2);

        // Y₃ = R·(U₁·H² - X₃) - S₁·H³
        let s1_h3 = s1.mul(&h_cubed);
        let u1_h2_minus_x3 = u1_h2.sub(&x3);
        let y3 = r.mul(&u1_h2_minus_x3).sub(&s1_h3);

        // Z₃ = H·Z₁·Z₂
        let z3 = h.mul(&self.z).mul(&other.z);

        let add_result = Point {
            x: x3,
            y: y3,
            z: z3,
        };

        // Select the appropriate result based on special cases
        let doubled = self.double();
        let infinity = Point::infinity();

        // Start with the general addition result
        let mut result = add_result;

        // If points are inverses, use infinity
        result = Point::conditional_select(&result, &infinity, points_inverse);

        // If points are equal, use doubling
        result = Point::conditional_select(&result, &doubled, points_equal);

        // If P is infinity, use Q
        result = Point::conditional_select(&result, other, p_inf);

        // If Q is infinity, use P
        result = Point::conditional_select(&result, self, q_inf);

        result
    }

    /// Mixed Jacobian-affine point addition
    ///
    /// Adds an affine point to a Jacobian point more efficiently than general addition.
    /// This is useful for algorithms like wNAF that use precomputed affine points.
    ///
    /// Cost: ~8M + 3S (vs ~12M + 4S for Jacobian-Jacobian addition)
    ///
    /// # Arguments
    ///
    /// * `other` - An affine point (Z = 1) to add to `self`
    ///
    /// # Returns
    ///
    /// A Jacobian point representing `self + other`
    pub fn add_affine(&self, other: &AffinePoint) -> Self {
        // Handle special case: P is infinity (return Q in Jacobian)
        let p_inf = self.is_infinity();

        // Compute mixed addition (always, for constant-time)

        // U₁ = X₁ (simplified because Z₂ = 1)
        let u1 = self.x;

        // U₂ = x₂·Z₁²
        let z1_squared = self.z.square();
        let u2 = other.x.mul(&z1_squared);

        // S₁ = Y₁ (simplified because Z₂ = 1)
        let s1 = self.y;

        // S₂ = y₂·Z₁³
        let z1_cubed = z1_squared.mul(&self.z);
        let s2 = other.y.mul(&z1_cubed);

        // H = U₂ - U₁
        let h = u2.sub(&u1);

        // R = S₂ - S₁
        let r = s2.sub(&s1);

        // Check for special cases
        let h_zero = h.is_zero();
        let r_zero = r.is_zero();

        // If H = 0 and R = 0: points are equal, use doubling
        let points_equal = h_zero & r_zero;

        // If H = 0 and R ≠ 0: points are inverses, return infinity
        let points_inverse = h_zero & (!r_zero);

        // Compute mixed addition
        let h_squared = h.square();
        let h_cubed = h_squared.mul(&h);

        let u1_h2 = u1.mul(&h_squared);
        let two = FieldElement::from_limbs([2, 0, 0, 0]);
        let two_u1_h2 = u1_h2.mul(&two);

        // X₃ = R² - H³ - 2·U₁·H²
        let r_squared = r.square();
        let x3 = r_squared.sub(&h_cubed).sub(&two_u1_h2);

        // Y₃ = R·(U₁·H² - X₃) - S₁·H³
        let s1_h3 = s1.mul(&h_cubed);
        let u1_h2_minus_x3 = u1_h2.sub(&x3);
        let y3 = r.mul(&u1_h2_minus_x3).sub(&s1_h3);

        // Z₃ = H·Z₁ (simplified because Z₂ = 1)
        let z3 = h.mul(&self.z);

        let add_result = Point {
            x: x3,
            y: y3,
            z: z3,
        };

        // Select the appropriate result based on special cases

        // If P is infinity, return Q (convert to Jacobian)
        let q_jacobian = Point::from_affine(other);
        let mut result = Point::conditional_select(&add_result, &q_jacobian, p_inf);

        // If points are equal, return double(P)
        let doubled = self.double();
        result = Point::conditional_select(&result, &doubled, points_equal);

        // If points are inverses, return infinity
        result = Point::conditional_select(&result, &Point::infinity(), points_inverse);

        result
    }

    /// Double a point
    ///
    /// This is more efficient than general addition when doubling.
    pub fn double(&self) -> Point {
        // If point is infinity, return infinity
        let is_inf = self.is_infinity();

        // If Y = 0, doubling gives infinity (tangent is vertical)
        let y_zero = self.y.is_zero();

        // Should return infinity if either condition is true
        let ret_inf = is_inf | y_zero;

        // Compute doubling formula (same structure as P-256, adapted for a=0)
        let y_squared = self.y.square(); // Y²
        let y_fourth = y_squared.square(); // Y⁴

        // S = 4·X·Y²
        let two = FieldElement::from_limbs([2, 0, 0, 0]);
        let four = FieldElement::from_limbs([4, 0, 0, 0]);
        let s = self.x.mul(&y_squared).mul(&four);

        // M = 3·X²  (for secp256k1 where a=0)
        // (P-256 uses M = 3·(X + Z²)·(X - Z²) for a=-3)
        let three = FieldElement::from_limbs([3, 0, 0, 0]);
        let x_squared = self.x.square();
        let m = x_squared.mul(&three);

        // X₃ = M² - 2·S
        let m_squared = m.square();
        let two_s = s.mul(&two);
        let x3 = m_squared.sub(&two_s);

        // Y₃ = M·(S - X₃) - 8·Y⁴
        let eight = FieldElement::from_limbs([8, 0, 0, 0]);
        let eight_y4 = y_fourth.mul(&eight);
        let s_minus_x3 = s.sub(&x3);
        let y3 = m.mul(&s_minus_x3).sub(&eight_y4);

        // Z₃ = 2·Y·Z
        let z3 = self.y.mul(&self.z).mul(&two);

        let result = Point {
            x: x3,
            y: y3,
            z: z3,
        };

        // Constant-time select: return infinity if ret_inf is true, else result
        Point::conditional_select(&result, &Point::infinity(), ret_inf)
    }

    // NOTE: secp256k1 does NOT implement double_incomplete() (lazy reduction)
    //
    // Unlike P-256/P-384/P-521, lazy reduction provides NO benefit for secp256k1
    // and actually HURTS performance (292% slowdown measured in testing).
    //
    // Reasons:
    // 1. secp256k1 has a=0, so the doubling formula M = 3·X² cannot use the
    //    (X+Z²)(X-Z²) optimization that P-256 (a=-3) benefits from
    // 2. Fewer intermediate additions means fewer opportunities for lazy reduction
    // 3. The overhead of incomplete reduction checks exceeds any potential savings
    //
    // Tested and rejected during Phase 8 optimization (0.13s → 0.51s regression).

    /// Negate a point (flip Y coordinate)
    pub fn neg(&self) -> Point {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Negate a point (alias for neg, used by BIP 340 Schnorr)
    pub fn negate(&self) -> Point {
        self.neg()
    }

    /// Check if this point is the identity element (alias for is_infinity)
    ///
    /// Used by BIP 340 Schnorr signature verification
    pub fn is_identity(&self) -> bool {
        bool::from(self.is_infinity())
    }

    /// Scalar multiplication using GLV endomorphism (variable-time, ~2x faster)
    ///
    /// Uses the GLV (Gallant-Lambert-Vanstone) endomorphism to achieve approximately
    /// 2x speedup over naive double-and-add by decomposing a 256-bit scalar into
    /// two 128-bit scalars.
    ///
    /// WARNING: This is NOT constant-time and should only be used
    /// when the scalar is public (e.g., during signature verification).
    ///
    /// # Performance
    ///
    /// - Old (double-and-add): ~750 µs
    /// - New (GLV): ~400 µs
    /// - Speedup: ~2x
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Point {
        use super::glv::scalar_mul_glv;
        scalar_mul_glv(self, scalar)
    }

    /// Scalar multiplication using Montgomery ladder (constant-time)
    ///
    /// This should be used when the scalar is secret (e.g., private keys).
    pub fn scalar_mul_constant_time(&self, scalar: &[u8; 32]) -> Point {
        let mut r0 = Point::infinity();
        let mut r1 = *self;

        // Montgomery ladder for constant-time execution
        for byte in scalar.iter() {
            for bit in (0..8).rev() {
                let bit_set = Choice::from(((byte >> bit) & 1) as u8);

                // Conditionally swap r0 and r1 based on bit
                let r0_copy = r0;
                let r1_copy = r1;
                r0 = Point::conditional_select(&r0_copy, &r1_copy, bit_set);
                r1 = Point::conditional_select(&r1_copy, &r0_copy, bit_set);

                // Always do the same operations
                let sum = r0.add(&r1);
                r0 = r0.double();
                r1 = sum;

                // Conditionally swap back
                let r0_copy = r0;
                let r1_copy = r1;
                r0 = Point::conditional_select(&r0_copy, &r1_copy, bit_set);
                r1 = Point::conditional_select(&r1_copy, &r0_copy, bit_set);
            }
        }

        r0
    }

    /// Fast scalar multiplication of the generator point using precomputed tables
    ///
    /// This is ~3-4x faster than generic scalar multiplication for the generator point.
    /// Should be used for key generation and signing operations.
    ///
    /// # Performance
    ///
    /// - Without precomputed tables: ~760 µs
    /// - With precomputed tables: ~200-250 µs
    ///
    /// # Security
    ///
    /// This function is NOT constant-time. It should only be used when:
    /// - The scalar is public, OR
    /// - The scalar is from RFC 6979 (deterministic ECDSA), OR
    /// - You're generating a public key (scalar is private but operation timing doesn't matter)
    ///
    /// For signing with secret scalars in non-deterministic ECDSA, use
    /// `scalar_mul_constant_time` instead.
    pub fn scalar_mul_generator(scalar: &[u8; 32]) -> Point {
        use super::precomputed::PRECOMPUTED_TABLE;
        PRECOMPUTED_TABLE.scalar_mul_generator(scalar)
    }

    /// Multi-scalar multiplication: compute a*G + Σ(b_i * P_i)
    ///
    /// This is more efficient than computing scalar multiplications separately
    /// because it uses Strauss's algorithm (also known as Shamir's trick) to
    /// process all scalars simultaneously.
    ///
    /// # Arguments
    ///
    /// * `generator_scalar` - Scalar for the generator point G
    /// * `scalars` - Scalars for arbitrary points
    /// * `points` - Arbitrary points
    ///
    /// # Performance
    ///
    /// For N points, this is approximately 1.3-1.5x faster than N separate
    /// scalar multiplications.
    ///
    /// # Security
    ///
    /// This function uses variable-time operations and should only be used
    /// with public scalars (e.g., in signature verification).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Compute u1*G + u2*Q (ECDSA verification)
    /// let result = Point::multi_scalar_mul_mixed(&u1, &[u2], &[Q]);
    /// ```
    pub fn multi_scalar_mul_mixed(
        generator_scalar: &[u8; 32],
        scalars: &[[u8; 32]],
        points: &[Point],
    ) -> Point {
        assert_eq!(
            scalars.len(),
            points.len(),
            "Scalars and points must have same length"
        );

        if scalars.is_empty() {
            // Just generator multiplication (use precomputed tables)
            return Point::scalar_mul_generator(generator_scalar);
        }

        // Compute generator part separately using precomputed tables for speed
        let generator_part = Point::scalar_mul_generator(generator_scalar);

        // If only one other point, just compute and add
        if scalars.len() == 1 {
            let other_part = points[0].scalar_mul(&scalars[0]);
            return generator_part.add(&other_part);
        }

        // For multiple points, use Strauss's algorithm for the arbitrary points
        let mut arbitrary_result = Point::infinity();

        // Process from MSB to LSB
        for byte_idx in 0..32 {
            for bit_idx in (0..8).rev() {
                // Double the accumulator
                arbitrary_result = arbitrary_result.double();

                // Add each point if its corresponding scalar bit is set
                for i in 0..scalars.len() {
                    if (scalars[i][byte_idx] >> bit_idx) & 1 == 1 {
                        arbitrary_result = arbitrary_result.add(&points[i]);
                    }
                }
            }
        }

        // Combine generator part + arbitrary points part
        generator_part.add(&arbitrary_result)
    }

    /// Compute u1*G + u2*P using Shamir's trick (optimized for ECDSA verification)
    ///
    /// This is specifically optimized for the two-scalar case and provides
    /// approximately 40% speedup over computing the two scalar multiplications
    /// separately.
    ///
    /// # Algorithm
    ///
    /// 1. Precompute table: [O, G, P, G+P] where O = point at infinity
    /// 2. Process both scalars bit-by-bit simultaneously
    /// 3. For each bit pair (b1, b2), select from table:
    ///    - (0,0) → O (identity, no change)
    ///    - (0,1) → P
    ///    - (1,0) → G
    ///    - (1,1) → G+P
    /// 4. Use double-and-add with table lookup
    ///
    /// # Performance
    ///
    /// - ~40% faster than separate multiplications for ECDSA verification
    /// - Requires only 2 points of precomputation (G+P)
    /// - Uses variable-time operations (safe for public inputs)
    ///
    /// # Security
    ///
    /// This function uses variable-time operations and should only be used
    /// with public scalars (e.g., in ECDSA/Schnorr signature verification).
    ///
    /// # Arguments
    ///
    /// * `scalar_g` - Scalar for the generator point G (u1 in ECDSA)
    /// * `scalar_p` - Scalar for arbitrary point P (u2 in ECDSA)
    /// * `point_p` - Arbitrary point P (public key in ECDSA)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // ECDSA verification: R = u1*G + u2*Q
    /// let r_point = Point::scalar_mul_shamir(&u1_bytes, &u2_bytes, &public_key);
    /// ```
    pub fn scalar_mul_shamir(scalar_g: &[u8; 32], scalar_p: &[u8; 32], point_p: &Point) -> Point {
        // Step 1: Precompute table [O, G, P, G+P]
        // We use lazy computation since O and G are trivial
        let g = Point::generator();
        let g_plus_p = g.add(point_p); // This is the only expensive precomputation

        // Table indices:
        // 0b00 = 0 → O (point at infinity)
        // 0b01 = 1 → P
        // 0b10 = 2 → G
        // 0b11 = 3 → G+P
        let table = [
            Point::infinity(), // 0b00
            *point_p,          // 0b01
            g,                 // 0b10
            g_plus_p,          // 0b11
        ];

        // Step 2: Process bits from MSB to LSB
        let mut result = Point::infinity();

        // Process each byte from most significant to least significant
        for byte_idx in 0..32 {
            // Process each bit from MSB to LSB within the byte
            for bit_idx in (0..8).rev() {
                // Double the accumulator
                result = result.double();

                // Extract bit from scalar_g and scalar_p
                let bit_g = (scalar_g[byte_idx] >> bit_idx) & 1;
                let bit_p = (scalar_p[byte_idx] >> bit_idx) & 1;

                // Form table index: bit_g is high bit, bit_p is low bit
                let table_idx = ((bit_g << 1) | bit_p) as usize;

                // Add the corresponding table entry
                // Note: adding infinity (table[0]) is a no-op, which is handled by add()
                if table_idx != 0 {
                    result = result.add(&table[table_idx]);
                }
            }
        }

        result
    }

    /// Convert from Jacobian to affine coordinates
    ///
    /// Returns None if the point is at infinity.
    pub fn to_affine(&self) -> Option<AffinePoint> {
        if bool::from(self.is_infinity()) {
            return None;
        }

        // Compute z_inv = 1/Z
        let z_inv = self.z.invert().ok()?;

        // Compute z_inv² and z_inv³
        let z_inv_squared = z_inv.square();
        let z_inv_cubed = z_inv.mul(&z_inv_squared);

        // x = X / Z²
        let x = self.x.mul(&z_inv_squared);

        // y = Y / Z³
        let y = self.y.mul(&z_inv_cubed);

        Some(AffinePoint { x, y })
    }

    /// Create a point from affine coordinates
    pub fn from_affine(affine: &AffinePoint) -> Point {
        Point {
            x: affine.x,
            y: affine.y,
            z: FieldElement::ONE,
        }
    }

    /// Lift an X-coordinate to a point (BIP 340)
    ///
    /// Given an X-coordinate, compute the corresponding Y-coordinate
    /// and return a point with even Y (as required by BIP 340).
    ///
    /// Returns None if x is not a valid X-coordinate on the curve.
    pub fn lift_x(x_bytes: &[u8]) -> Option<Point> {
        // Parse X coordinate
        let x = FieldElement::from_bytes(&<[u8; 32]>::try_from(x_bytes).ok()?);

        // Compute y² = x³ + 7
        let x_squared = x.square();
        let x_cubed = x_squared.mul(&x);
        let b = FieldElement::from_limbs(SECP256K1_B);
        let y_squared = x_cubed.add(&b);

        // Compute y = sqrt(y²)
        let y = y_squared.sqrt()?;

        // If y is odd, negate it to get even y (BIP 340 convention)
        // Note: to_bytes() returns big-endian, so LSB is at the end
        let y_bytes = y.to_bytes();
        let y_final = if y_bytes[31] & 1 == 1 { y.neg() } else { y };

        Some(Point {
            x,
            y: y_final,
            z: FieldElement::ONE,
        })
    }
}

/// A point in affine coordinates (x, y)
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// The x-coordinate
    pub x: FieldElement,
    /// The y-coordinate
    pub y: FieldElement,
}

impl AffinePoint {
    /// Check if this point is on the curve: y² = x³ + 7
    pub fn is_on_curve(&self) -> bool {
        // Compute y²
        let y_squared = self.y.square();

        // Compute x³ + 7
        let x_cubed = self.x.square().mul(&self.x);
        let b = FieldElement::from_limbs(SECP256K1_B);
        let rhs = x_cubed.add(&b);

        bool::from(y_squared.ct_eq(&rhs))
    }

    /// Encode as uncompressed public key (65 bytes: 0x04 || X || Y)
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04; // Uncompressed prefix
        bytes[1..33].copy_from_slice(&self.x.to_bytes());
        bytes[33..65].copy_from_slice(&self.y.to_bytes());
        bytes
    }

    /// Encode as compressed public key (33 bytes: 0x02/0x03 || X)
    ///
    /// Format: 0x02 if Y is even, 0x03 if Y is odd
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        let y_bytes = self.y.to_bytes();

        // Check if Y is even or odd (LSB of big-endian representation)
        let y_is_odd = y_bytes[31] & 1 == 1;
        bytes[0] = if y_is_odd { 0x03 } else { 0x02 };

        bytes[1..33].copy_from_slice(&self.x.to_bytes());
        bytes
    }

    /// Decode from uncompressed public key (65 bytes: 0x04 || X || Y)
    pub fn from_uncompressed_bytes(bytes: &[u8; 65]) -> Option<Self> {
        if bytes[0] != 0x04 {
            return None;
        }

        let x_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
        let y_bytes: [u8; 32] = bytes[33..65].try_into().ok()?;

        let x = FieldElement::from_bytes(&x_bytes);
        let y = FieldElement::from_bytes(&y_bytes);

        let point = AffinePoint { x, y };

        // Verify point is on curve
        if !point.is_on_curve() {
            return None;
        }

        Some(point)
    }

    /// Decode from compressed public key (33 bytes: 0x02/0x03 || X)
    ///
    /// Recovers Y coordinate from X using the curve equation y² = x³ + 7
    pub fn from_compressed_bytes(bytes: &[u8; 33]) -> Option<Self> {
        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return None;
        }

        let x_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
        let x = FieldElement::from_bytes(&x_bytes);

        // Compute y² = x³ + 7
        let x_squared = x.square();
        let x_cubed = x_squared.mul(&x);
        let b = FieldElement::from_limbs(SECP256K1_B);
        let y_squared = x_cubed.add(&b);

        // Compute y = sqrt(y²)
        let y = y_squared.sqrt()?;

        // Check if y matches the parity indicated by the prefix
        let y_bytes = y.to_bytes();
        let y_is_odd = y_bytes[31] & 1 == 1;
        let expected_odd = prefix == 0x03;

        // If parity doesn't match, negate y
        let y_final = if y_is_odd == expected_odd { y } else { y.neg() };

        let point = AffinePoint { x, y: y_final };

        // Verify point is on curve (should always be true if sqrt succeeded)
        if !point.is_on_curve() {
            return None;
        }

        Some(point)
    }
}

impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Point) -> Choice {
        // Two points are equal if they represent the same affine point
        // In Jacobian coordinates: (X1, Y1, Z1) == (X2, Y2, Z2)
        // if X1*Z2² == X2*Z1² and Y1*Z2³ == Y2*Z1³

        let z1_squared = self.z.square();
        let z2_squared = other.z.square();

        let x1z2sq = self.x.mul(&z2_squared);
        let x2z1sq = other.x.mul(&z1_squared);

        let z1_cubed = self.z.mul(&z1_squared);
        let z2_cubed = other.z.mul(&z2_squared);

        let y1z2cu = self.y.mul(&z2_cubed);
        let y2z1cu = other.y.mul(&z1_cubed);

        x1z2sq.ct_eq(&x2z1sq) & y1z2cu.ct_eq(&y2z1cu)
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Point {}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Point, b: &Point, choice: Choice) -> Point {
        Point {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infinity() {
        let inf = Point::infinity();
        assert!(bool::from(inf.is_infinity()));
    }

    #[test]
    fn test_generator() {
        let g = Point::generator();
        assert!(!bool::from(g.is_infinity()));

        // Check generator is on curve (Jacobian)
        assert!(bool::from(g.is_on_curve()));

        // Check generator is on curve (affine)
        let g_affine = g.to_affine().unwrap();
        assert!(g_affine.is_on_curve());
    }

    #[test]
    fn test_double_generator() {
        let g = Point::generator();
        let g2 = g.double();

        assert!(!bool::from(g2.is_infinity()));

        // Expected 2G coordinates (from Python calculation)
        let expected_x = FieldElement::from_limbs([
            0xABAC09B95C709EE5,
            0x5C778E4B8CEF3CA7,
            0x3045406E95C07CD8,
            0xC6047F9441ED7D6D,
        ]);
        let expected_y = FieldElement::from_limbs([
            0x236431A950CFE52A,
            0xF7F632653266D0E1,
            0xA3C58419466CEAEE,
            0x1AE168FEA63DC339,
        ]);

        // First convert to affine and check coordinates match expected
        let g2_affine = g2.to_affine().expect("2G should not be infinity");

        if !bool::from(g2_affine.x.ct_eq(&expected_x)) {
            // Coordinates don't match - there's a bug in doubling formula
            panic!("2G x coordinate mismatch");
        }

        if !bool::from(g2_affine.y.ct_eq(&expected_y)) {
            // Coordinates don't match - there's a bug in doubling formula
            panic!("2G y coordinate mismatch");
        }

        // Now check if it's on curve
        assert!(
            g2_affine.is_on_curve(),
            "2G not on curve (but coordinates match expected)"
        );
    }

    #[test]
    fn test_add_generator() {
        let g = Point::generator();
        let g2 = g.double();
        let g3 = g.add(&g2);

        assert!(!bool::from(g3.is_infinity()));

        // 3G should be on curve
        let g3_affine = g3.to_affine().unwrap();
        assert!(g3_affine.is_on_curve());
    }

    #[test]
    fn test_add_inverse() {
        let g = Point::generator();
        let neg_g = g.neg();
        let result = g.add(&neg_g);

        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_double_equals_add() {
        let g = Point::generator();
        let g_double = g.double();
        let g_add = g.add(&g);

        assert_eq!(g_double, g_add);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = Point::generator();
        let zero_scalar = [0u8; 32];
        let result = g.scalar_mul(&zero_scalar);

        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = Point::generator();
        let mut one_scalar = [0u8; 32];
        one_scalar[31] = 1;
        let result = g.scalar_mul(&one_scalar);

        assert_eq!(result, g);
    }

    #[test]
    fn test_scalar_mul_two() {
        let g = Point::generator();
        let mut two_scalar = [0u8; 32];
        two_scalar[31] = 2;
        let result = g.scalar_mul(&two_scalar);

        let expected = g.double();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scalar_mul_three() {
        let g = Point::generator();
        let mut three_scalar = [0u8; 32];
        three_scalar[31] = 3;
        let result = g.scalar_mul(&three_scalar);

        let expected = g.double().add(&g);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_negation() {
        let g = Point::generator();
        let neg_g = g.neg();
        let neg_neg_g = neg_g.neg();

        assert_eq!(g, neg_neg_g);
    }

    #[test]
    fn test_associativity() {
        let g = Point::generator();
        let g2 = g.double();
        let g3 = g2.add(&g);

        // (G + G) + G should equal G + (G + G)
        let left = g.add(&g).add(&g);
        let right = g.add(&g.add(&g));

        assert_eq!(left, right);
        assert_eq!(left, g3);
    }

    #[test]
    fn test_to_affine_roundtrip() {
        let g = Point::generator();
        let affine = g.to_affine().unwrap();
        let back = Point::from_affine(&affine);

        assert_eq!(g, back);
    }

    #[test]
    fn test_scalar_mul_constant_time_equivalence() {
        let g = Point::generator();
        let mut scalar = [0u8; 32];
        scalar[31] = 42;

        let result1 = g.scalar_mul(&scalar);
        let result2 = g.scalar_mul_constant_time(&scalar);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_distributivity() {
        let g = Point::generator();

        // Test: (a + b) * G == a * G + b * G
        let mut a_scalar = [0u8; 32];
        a_scalar[31] = 5;
        let mut b_scalar = [0u8; 32];
        b_scalar[31] = 3;

        let a_g = g.scalar_mul(&a_scalar);
        let b_g = g.scalar_mul(&b_scalar);
        let left = a_g.add(&b_g);

        let mut ab_scalar = [0u8; 32];
        ab_scalar[31] = 8;
        let right = g.scalar_mul(&ab_scalar);

        assert_eq!(left, right);
    }

    #[test]
    fn test_pubkey_against_reference() {
        // Test against known-good value from Python reference implementation
        // d = 0x42424242...
        let d_bytes = [0x42u8; 32];

        // Expected Q = d*G from Python (using standard secp256k1 implementation)
        let expected_qx = [
            0x24, 0x65, 0x3e, 0xac, 0x43, 0x44, 0x88, 0x00, 0x2c, 0xc0, 0x6b, 0xbf, 0xb7, 0xf1,
            0x0f, 0xe1, 0x89, 0x91, 0xe3, 0x5f, 0x9f, 0xe4, 0x30, 0x2d, 0xbe, 0xa6, 0xd2, 0x35,
            0x3d, 0xc0, 0xab, 0x1c,
        ];
        let expected_qy = [
            0x11, 0x9f, 0xc5, 0x00, 0x9a, 0x03, 0x2a, 0xa9, 0xfe, 0x47, 0xf5, 0xe1, 0x49, 0xbb,
            0x84, 0x42, 0xf7, 0x1f, 0x88, 0x4c, 0xcb, 0x51, 0x65, 0x90, 0x68, 0x6d, 0x8f, 0xf6,
            0xab, 0x91, 0xc6, 0x13,
        ];

        let g = Point::generator();
        let q = g.scalar_mul_constant_time(&d_bytes);

        let q_affine = q.to_affine().expect("Q should not be infinity");
        let qx_bytes = q_affine.x.to_bytes();
        let qy_bytes = q_affine.y.to_bytes();

        assert_eq!(
            qx_bytes, expected_qx,
            "Public key X coordinate doesn't match reference"
        );
        assert_eq!(
            qy_bytes, expected_qy,
            "Public key Y coordinate doesn't match reference"
        );
    }

    #[test]
    fn test_verification_computation() {
        // Test the exact computation that happens in ECDSA verification: R' = u1*G + u2*Q
        // Using values from Python reference where verification succeeds

        // Public key Q (from d*G where d = 0x42...)
        let qx_bytes = [
            0x24, 0x65, 0x3e, 0xac, 0x43, 0x44, 0x88, 0x00, 0x2c, 0xc0, 0x6b, 0xbf, 0xb7, 0xf1,
            0x0f, 0xe1, 0x89, 0x91, 0xe3, 0x5f, 0x9f, 0xe4, 0x30, 0x2d, 0xbe, 0xa6, 0xd2, 0x35,
            0x3d, 0xc0, 0xab, 0x1c,
        ];
        let qy_bytes = [
            0x11, 0x9f, 0xc5, 0x00, 0x9a, 0x03, 0x2a, 0xa9, 0xfe, 0x47, 0xf5, 0xe1, 0x49, 0xbb,
            0x84, 0x42, 0xf7, 0x1f, 0x88, 0x4c, 0xcb, 0x51, 0x65, 0x90, 0x68, 0x6d, 0x8f, 0xf6,
            0xab, 0x91, 0xc6, 0x13,
        ];
        let qx = FieldElement::from_bytes(&qx_bytes);
        let qy = FieldElement::from_bytes(&qy_bytes);
        let q_affine = AffinePoint { x: qx, y: qy };
        let q = Point::from_affine(&q_affine);

        // Verification scalars u1 and u2
        let u1_bytes = [
            0x68, 0xec, 0x7d, 0x60, 0x7e, 0x60, 0x51, 0x85, 0x3a, 0xd7, 0x03, 0xf6, 0x4d, 0x7f,
            0x95, 0x8e, 0x3c, 0x39, 0xb3, 0xc6, 0xac, 0x7a, 0xac, 0xac, 0x81, 0x8e, 0x6d, 0x48,
            0xf3, 0xfd, 0xdc, 0x76,
        ];
        let u2_bytes = [
            0x79, 0x21, 0x69, 0x4a, 0x98, 0x78, 0x37, 0x75, 0x93, 0x87, 0x40, 0x9d, 0x5d, 0xa8,
            0xc4, 0xb9, 0x6a, 0x0b, 0x5f, 0x1b, 0x53, 0x2f, 0x04, 0xf9, 0x97, 0xd8, 0x30, 0x0e,
            0x2f, 0x91, 0x71, 0xfa,
        ];

        // Expected result R' from Python
        let expected_rx = [
            0xc1, 0xef, 0x64, 0x65, 0x11, 0xeb, 0x63, 0x98, 0xd9, 0x3f, 0x6c, 0x98, 0x06, 0x85,
            0xdf, 0x74, 0xdb, 0xed, 0x28, 0x15, 0x55, 0x9c, 0x76, 0x92, 0x1a, 0x3e, 0x14, 0x34,
            0x88, 0xd7, 0xe1, 0xae,
        ];

        // Compute R' = u1*G + u2*Q
        let g = Point::generator();
        let u1_g = g.scalar_mul(&u1_bytes);
        let u2_q = q.scalar_mul(&u2_bytes);
        let r_prime = u1_g.add(&u2_q);

        let r_prime_affine = r_prime.to_affine().expect("R' should not be infinity");
        let rx_bytes = r_prime_affine.x.to_bytes();

        assert_eq!(
            rx_bytes, expected_rx,
            "Verification point R'.x doesn't match Python reference"
        );
    }

    #[test]
    fn test_signature_generation() {
        // Test signature generation with fixed k value
        // This matches the Python test case

        let k_bytes = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x19, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d,
        ];

        // Compute R = k*G
        let g = Point::generator();
        let r_point = g.scalar_mul_constant_time(&k_bytes);
        let r_affine = r_point.to_affine().expect("R should not be infinity");

        // Expected from Python
        let expected_rx = [
            0xc1, 0xef, 0x64, 0x65, 0x11, 0xeb, 0x63, 0x98, 0xd9, 0x3f, 0x6c, 0x98, 0x06, 0x85,
            0xdf, 0x74, 0xdb, 0xed, 0x28, 0x15, 0x55, 0x9c, 0x76, 0x92, 0x1a, 0x3e, 0x14, 0x34,
            0x88, 0xd7, 0xe1, 0xae,
        ];

        let rx_bytes = r_affine.x.to_bytes();
        assert_eq!(rx_bytes, expected_rx, "k*G doesn't match Python reference");
    }

    #[test]
    fn test_uncompressed_encoding_decoding() {
        // Test uncompressed point encoding/decoding (65 bytes: 0x04 || X || Y)
        let g = Point::generator();
        let point = g.to_affine().expect("Generator should not be infinity");

        // Encode as uncompressed
        let uncompressed = point.to_uncompressed_bytes();

        // Check format
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed prefix

        // Decode back
        let decoded = AffinePoint::from_uncompressed_bytes(&uncompressed)
            .expect("Should decode valid uncompressed point");

        // Check roundtrip
        assert_eq!(decoded.x.to_bytes(), point.x.to_bytes());
        assert_eq!(decoded.y.to_bytes(), point.y.to_bytes());
    }

    #[test]
    fn test_compressed_encoding_decoding() {
        // Test compressed point encoding/decoding (33 bytes: 0x02/0x03 || X)
        let g = Point::generator();
        let point = g.to_affine().expect("Generator should not be infinity");

        // Encode as compressed
        let compressed = point.to_compressed_bytes();

        // Check format
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        // Decode back
        let decoded = AffinePoint::from_compressed_bytes(&compressed)
            .expect("Should decode valid compressed point");

        // Check roundtrip (X must match, Y must match)
        assert_eq!(decoded.x.to_bytes(), point.x.to_bytes());
        assert_eq!(decoded.y.to_bytes(), point.y.to_bytes());
    }

    #[test]
    fn test_compressed_parity_even() {
        // Test compression of a point with even Y coordinate
        // Using a known point with even Y
        let private_key = [0x01u8; 32];
        let g = Point::generator();
        let point = g.scalar_mul(&private_key);
        let affine = point.to_affine().expect("Should not be infinity");

        let compressed = affine.to_compressed_bytes();
        let y_bytes = affine.y.to_bytes();
        let y_is_odd = y_bytes[31] & 1 == 1;

        // Check prefix matches Y parity
        if y_is_odd {
            assert_eq!(compressed[0], 0x03);
        } else {
            assert_eq!(compressed[0], 0x02);
        }

        // Verify X coordinate is preserved
        assert_eq!(&compressed[1..33], &affine.x.to_bytes()[..]);
    }

    #[test]
    fn test_compressed_decompression_recovers_correct_y() {
        // Test that decompression recovers the correct Y coordinate
        let private_key = [0x42u8; 32];
        let g = Point::generator();
        let point = g.scalar_mul(&private_key);
        let original = point.to_affine().expect("Should not be infinity");

        // Compress then decompress
        let compressed = original.to_compressed_bytes();
        let recovered = AffinePoint::from_compressed_bytes(&compressed)
            .expect("Should decompress successfully");

        // Y coordinates must match exactly
        assert_eq!(
            recovered.y.to_bytes(),
            original.y.to_bytes(),
            "Recovered Y coordinate must match original"
        );

        // Verify point is on curve
        assert!(recovered.is_on_curve());
    }

    #[test]
    fn test_invalid_compressed_prefix() {
        // Test that invalid prefixes are rejected
        let mut invalid = [0u8; 33];
        invalid[0] = 0x04; // Invalid for compressed format
        invalid[1..].copy_from_slice(&[0x01; 32]);

        assert!(
            AffinePoint::from_compressed_bytes(&invalid).is_none(),
            "Should reject compressed point with 0x04 prefix"
        );

        invalid[0] = 0x01; // Also invalid
        assert!(
            AffinePoint::from_compressed_bytes(&invalid).is_none(),
            "Should reject compressed point with 0x01 prefix"
        );
    }

    #[test]
    fn test_invalid_uncompressed_prefix() {
        // Test that invalid prefixes are rejected
        let mut invalid = [0u8; 65];
        invalid[0] = 0x02; // Invalid for uncompressed format

        assert!(
            AffinePoint::from_uncompressed_bytes(&invalid).is_none(),
            "Should reject uncompressed point with 0x02 prefix"
        );

        invalid[0] = 0x03;
        assert!(
            AffinePoint::from_uncompressed_bytes(&invalid).is_none(),
            "Should reject uncompressed point with 0x03 prefix"
        );
    }

    #[test]
    fn test_compression_reduces_size() {
        // Verify compressed format is smaller
        let g = Point::generator();
        let point = g.to_affine().expect("Should not be infinity");

        let uncompressed = point.to_uncompressed_bytes();
        let compressed = point.to_compressed_bytes();

        assert_eq!(uncompressed.len(), 65);
        assert_eq!(compressed.len(), 33);
        assert_eq!(65 - 33, 32); // Saves 32 bytes (entire Y coordinate)
    }

    #[test]
    fn test_known_compressed_point() {
        // Test with Bitcoin generator point (known compressed format)
        // secp256k1 generator G has known coordinates
        let g = Point::generator();
        let g_affine = g.to_affine().expect("Generator should not be infinity");

        // Known compressed generator (from Bitcoin/secp256k1)
        let expected_compressed = [
            0x02, // Prefix (G has even Y)
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];

        let compressed = g_affine.to_compressed_bytes();
        assert_eq!(
            compressed, expected_compressed,
            "Generator compression should match known value"
        );

        // Verify decompression works
        let decoded = AffinePoint::from_compressed_bytes(&expected_compressed)
            .expect("Should decode known compressed generator");

        assert_eq!(decoded.x.to_bytes(), g_affine.x.to_bytes());
        assert_eq!(decoded.y.to_bytes(), g_affine.y.to_bytes());
    }

    #[test]
    fn test_scalar_mul_shamir() {
        use crate::secp256k1::scalar::Scalar;

        // Test: u1*G + u2*P should give same result whether computed separately or with Shamir's trick

        // Choose test scalars
        let u1_scalar = Scalar::from_u64(12345);
        let u2_scalar = Scalar::from_u64(67890);
        let u1_bytes = u1_scalar.to_bytes();
        let u2_bytes = u2_scalar.to_bytes();

        // Choose test point P = 3*G
        let p = Point::generator().double().add(&Point::generator());

        // Method 1: Separate scalar multiplications (original method)
        let u1_g = Point::scalar_mul_generator(&u1_bytes);
        let u2_p = p.scalar_mul(&u2_bytes);
        let result_separate = u1_g.add(&u2_p);

        // Method 2: Shamir's trick (optimized method)
        let result_shamir = Point::scalar_mul_shamir(&u1_bytes, &u2_bytes, &p);

        // Convert both to affine and compare
        let affine_separate = result_separate
            .to_affine()
            .expect("Result should not be infinity");
        let affine_shamir = result_shamir
            .to_affine()
            .expect("Result should not be infinity");

        // Check that both methods produce the same result
        assert!(
            bool::from(affine_separate.x.ct_eq(&affine_shamir.x)),
            "X coordinates should match"
        );
        assert!(
            bool::from(affine_separate.y.ct_eq(&affine_shamir.y)),
            "Y coordinates should match"
        );
    }

    #[test]
    fn test_scalar_mul_shamir_edge_cases() {
        use crate::secp256k1::scalar::Scalar;

        let g = Point::generator();

        // Test 1: u1=0, u2=1 → should give P
        let u1_zero = Scalar::zero().to_bytes();
        let u2_one = Scalar::one().to_bytes();
        let p = g.double();

        let result = Point::scalar_mul_shamir(&u1_zero, &u2_one, &p);
        let expected = p;

        let result_affine = result.to_affine().unwrap();
        let expected_affine = expected.to_affine().unwrap();
        assert!(bool::from(result_affine.x.ct_eq(&expected_affine.x)));
        assert!(bool::from(result_affine.y.ct_eq(&expected_affine.y)));

        // Test 2: u1=1, u2=0 → should give G
        let u1_one = Scalar::one().to_bytes();
        let u2_zero = Scalar::zero().to_bytes();

        let result = Point::scalar_mul_shamir(&u1_one, &u2_zero, &p);
        let expected = g;

        let result_affine = result.to_affine().unwrap();
        let expected_affine = expected.to_affine().unwrap();
        assert!(bool::from(result_affine.x.ct_eq(&expected_affine.x)));
        assert!(bool::from(result_affine.y.ct_eq(&expected_affine.y)));

        // Test 3: u1=1, u2=1 → should give G+P
        let result = Point::scalar_mul_shamir(&u1_one, &u2_one, &p);
        let expected = g.add(&p);

        let result_affine = result.to_affine().unwrap();
        let expected_affine = expected.to_affine().unwrap();
        assert!(bool::from(result_affine.x.ct_eq(&expected_affine.x)));
        assert!(bool::from(result_affine.y.ct_eq(&expected_affine.y)));
    }

    #[test]
    fn test_scalar_mul_shamir_vs_multi_scalar_mul() {
        use crate::secp256k1::scalar::Scalar;

        // Test that scalar_mul_shamir produces same result as multi_scalar_mul_mixed
        let u1_scalar = Scalar::from_u64(9876);
        let u2_scalar = Scalar::from_u64(54321);
        let u1_bytes = u1_scalar.to_bytes();
        let u2_bytes = u2_scalar.to_bytes();

        let p = Point::generator().double().double(); // P = 4*G

        // Method 1: Shamir's trick (new optimized function)
        let result_shamir = Point::scalar_mul_shamir(&u1_bytes, &u2_bytes, &p);

        // Method 2: multi_scalar_mul_mixed (existing function)
        let result_multi = Point::multi_scalar_mul_mixed(&u1_bytes, &[u2_bytes], &[p]);

        // Compare results
        let affine_shamir = result_shamir.to_affine().unwrap();
        let affine_multi = result_multi.to_affine().unwrap();

        assert!(bool::from(affine_shamir.x.ct_eq(&affine_multi.x)));
        assert!(bool::from(affine_shamir.y.ct_eq(&affine_multi.y)));
    }
}
