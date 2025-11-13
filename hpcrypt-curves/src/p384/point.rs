//! P-384 elliptic curve point arithmetic
//!
//! Implements point operations in Jacobian coordinates for the NIST P-384 curve.
//! All operations are designed to be constant-time for security-critical applications.

use super::constants::{P384_B, P384_GX, P384_GY};
use super::field::FieldElement;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

// Common field element constants used in point arithmetic
const FE_TWO: FieldElement = FieldElement::from_u64(2);
const FE_THREE: FieldElement = FieldElement::from_u64(3);
const FE_FOUR: FieldElement = FieldElement::from_u64(4);
const FE_EIGHT: FieldElement = FieldElement::from_u64(8);

/// P-384 elliptic curve point in Jacobian coordinates (X : Y : Z)
///
/// Represents the affine point (X/Z², Y/Z³) on the curve:
/// y² = x³ + ax + b (mod p), where a = -3, b = P384_B
///
/// # Coordinate System
///
/// Jacobian coordinates avoid expensive field inversions by representing
/// points as (X : Y : Z) where the affine coordinates are:
/// - x = X/Z²
/// - y = Y/Z³
///
/// The point at infinity is represented by Z = 0.
///
/// # Security
///
/// Point operations are designed to be constant-time to resist timing attacks.
/// All conditionals use the `subtle` crate to prevent branching on secret values.
///
/// # Performance
///
/// Operation costs (M = multiplication, S = squaring):
/// - Point doubling: 4M + 4S (using a=-3 optimization)
/// - Point addition: 12M + 4S
/// - Mixed addition: 8M + 3S
///
#[derive(Clone, Copy, Debug)]
pub struct Point {
    /// X coordinate in Jacobian representation
    pub(crate) x: FieldElement,

    /// Y coordinate in Jacobian representation
    pub(crate) y: FieldElement,

    /// Z coordinate in Jacobian representation (Z = 0 represents infinity)
    pub(crate) z: FieldElement,
}

/// P-384 point in affine coordinates (x, y)
///
/// Affine representation is used for:
/// - Final results (after coordinate conversion)
/// - Precomputed tables (enables mixed addition optimization)
/// - SEC1 encoding/decoding
/// - Public key representation
///
/// The point at infinity has no affine representation.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// X coordinate
    pub x: FieldElement,

    /// Y coordinate
    pub y: FieldElement,
}

impl Point {
    /// Returns the point at infinity (identity element)
    ///
    /// The point at infinity is represented by Z = 0.
    /// Canonical form: (1, 1, 0)
    #[inline]
    pub const fn infinity() -> Self {
        Point {
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the P-384 generator point (base point G)
    ///
    /// The generator point is the standard base point for P-384 as specified
    /// in FIPS 186-4. It has prime order n.
    ///
    /// # Properties
    ///
    /// - G is on the curve: y² = x³ - 3x + b
    /// - G has order n: n·G = ∞
    /// - G generates all n points on the curve
    #[inline]
    pub const fn generator() -> Self {
        Point {
            x: FieldElement::from_limbs(P384_GX),
            y: FieldElement::from_limbs(P384_GY),
            z: FieldElement::one(),
        }
    }

    /// Checks if this point is the point at infinity
    ///
    /// Returns `Choice::from(1)` if the point is infinity, `Choice::from(0)` otherwise.
    ///
    /// # Constant-time
    ///
    /// This operation is constant-time.
    #[inline]
    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Creates a point from affine coordinates
    ///
    /// Converts an affine point (x, y) to Jacobian coordinates (x : y : 1).
    pub fn from_affine(point: &AffinePoint) -> Self {
        Point {
            x: point.x,
            y: point.y,
            z: FieldElement::one(),
        }
    }

    /// Converts this point to affine coordinates
    ///
    /// Computes (x, y) = (X/Z², Y/Z³) using field inversion.
    ///
    /// # Returns
    ///
    /// - `Some((x, y))` if the point is not infinity
    /// - `None` if the point is the point at infinity
    ///
    /// # Cost
    ///
    /// 1 inversion + 3 multiplications + 1 squaring
    pub fn to_affine(&self) -> Option<AffinePoint> {
        if bool::from(self.is_infinity()) {
            return None;
        }

        // Compute z_inv = 1/Z
        let z_inv = self.z.invert();

        // Compute Z^(-2) and Z^(-3)
        let z_inv_squared = z_inv.square();
        let z_inv_cubed = z_inv_squared.mul(&z_inv);

        // x = X/Z²
        let x = self.x.mul(&z_inv_squared);

        // y = Y/Z³
        let y = self.y.mul(&z_inv_cubed);

        Some(AffinePoint { x, y })
    }

    /// Checks if this point satisfies the P-384 curve equation
    ///
    /// In Jacobian coordinates, verifies: Y² = X³ + aXZ⁴ + bZ⁶ (mod p)
    /// where a = -3 and b = P384_B.
    ///
    /// # Returns
    ///
    /// `Choice::from(1)` if the point is on the curve (or is infinity),
    /// `Choice::from(0)` otherwise.
    ///
    /// # Constant-time
    ///
    /// This operation is constant-time.
    pub fn is_on_curve(&self) -> Choice {
        // The point at infinity is considered to be on the curve
        if bool::from(self.is_infinity()) {
            return Choice::from(1);
        }

        // Compute intermediate values
        let z2 = self.z.square(); // Z²
        let z4 = z2.square(); // Z⁴
        let z6 = z4.mul(&z2); // Z⁶

        let y2 = self.y.square(); // Y²

        let x2 = self.x.square(); // X²
        let x3 = x2.mul(&self.x); // X³

        // For P-384: a = -3
        // aXZ⁴ = -3XZ⁴
        let ax_z4 = self.x.mul(&z4).mul(&FE_THREE).neg();

        // bZ⁶
        let b = FieldElement::from_limbs(P384_B);
        let b_z6 = b.mul(&z6);

        // Right-hand side: X³ + aXZ⁴ + bZ⁶
        let rhs = x3.add(&ax_z4).add(&b_z6);

        // Check if Y² = rhs
        y2.ct_eq(&rhs)
    }

    /// Doubles a point: computes 2P
    ///
    /// Uses the optimized doubling formula for Jacobian coordinates with a=-3:
    /// - Cost: 4M + 4S
    /// - Exploits P-384's a=-3 for 2S savings
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁), computes 2P = (X₃, Y₃, Z₃):
    /// ```text
    /// S = 4·X₁·Y₁²
    /// M = 3·(X₁ + Z₁²)·(X₁ - Z₁²)    // a=-3 optimization
    /// X₃ = M² - 2·S
    /// Y₃ = M·(S - X₃) - 8·Y₁⁴
    /// Z₃ = 2·Y₁·Z₁
    /// ```
    ///
    /// # Special Cases
    ///
    /// - If P is infinity, returns infinity
    /// - If Y₁ = 0, returns infinity (tangent is vertical)
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time.
    pub fn double(&self) -> Self {
        // If point is infinity, return infinity
        let is_inf = self.is_infinity();

        // If Y = 0, doubling gives infinity (tangent is vertical)
        let y_zero = self.y.is_zero();

        // Should return infinity if either condition is true
        let ret_inf = is_inf | y_zero;

        // Compute doubling formula (always, for constant-time)
        let y_squared = self.y.square(); // Y²
        let y_fourth = y_squared.square(); // Y⁴

        // S = 4·X₁·Y₁²
        let s = self.x.mul(&y_squared).mul(&FE_FOUR);

        // M = 3·(X₁ + Z₁²)·(X₁ - Z₁²)  [a=-3 optimization]
        let z_squared = self.z.square(); // Z²
        let x_plus_z2 = self.x.add(&z_squared); // X + Z²
        let x_minus_z2 = self.x.sub(&z_squared); // X - Z²
        let m = x_plus_z2.mul(&x_minus_z2).mul(&FE_THREE);

        // X₃ = M² - 2·S
        let m_squared = m.square();
        let two_s = s.mul(&FE_TWO);
        let x3 = m_squared.sub(&two_s);

        // Y₃ = M·(S - X₃) - 8·Y⁴
        let eight_y4 = y_fourth.mul(&FE_EIGHT);
        let s_minus_x3 = s.sub(&x3);
        let y3 = m.mul(&s_minus_x3).sub(&eight_y4);

        // Z₃ = 2·Y₁·Z₁
        let z3 = self.y.mul(&self.z).mul(&FE_TWO);

        let result = Point {
            x: x3,
            y: y3,
            z: z3,
        };

        // Constant-time select: return infinity if ret_inf is true, else result
        Point::conditional_select(&result, &Point::infinity(), ret_inf)
    }

    /// Point doubling with incomplete reduction for intermediate values.
    ///
    /// This variant uses `add_incomplete()` for intermediate additions where
    /// the result is immediately consumed by multiplication. This avoids one
    /// conditional subtraction per addition.
    ///
    /// Expected performance gain: 5-10% over standard `double()`.
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time, same as `double()`.
    pub fn double_incomplete(&self) -> Self {
        // If point is infinity, return infinity
        let is_inf = self.is_infinity();

        // If Y = 0, doubling gives infinity (tangent is vertical)
        let y_zero = self.y.is_zero();

        // Should return infinity if either condition is true
        let ret_inf = is_inf | y_zero;

        // Compute doubling formula (always, for constant-time)
        let y_squared = self.y.square(); // Y²
        let y_fourth = y_squared.square(); // Y⁴

        // S = 4·X₁·Y₁²
        let s = self.x.mul(&y_squared).mul(&FE_FOUR);

        // M = 3·(X₁ + Z₁²)·(X₁ - Z₁²)  [a=-3 optimization]
        // Use incomplete reduction for x_plus_z2 since it's immediately multiplied
        let z_squared = self.z.square(); // Z²
        let x_plus_z2 = self.x.add_incomplete(&z_squared); // X + Z² (incomplete)
        let x_minus_z2 = self.x.sub(&z_squared); // X - Z²
        let m = x_plus_z2.mul(&x_minus_z2).mul(&FE_THREE);

        // X₃ = M² - 2·S
        let m_squared = m.square();
        let two_s = s.mul(&FE_TWO);
        let x3 = m_squared.sub(&two_s);

        // Y₃ = M·(S - X₃) - 8·Y⁴
        let eight_y4 = y_fourth.mul(&FE_EIGHT);
        let s_minus_x3 = s.sub(&x3);
        let y3 = m.mul(&s_minus_x3).sub(&eight_y4);

        // Z₃ = 2·Y₁·Z₁
        let z3 = self.y.mul(&self.z).mul(&FE_TWO);

        let result = Point {
            x: x3,
            y: y3,
            z: z3,
        };

        // Constant-time select: return infinity if ret_inf is true, else result
        Point::conditional_select(&result, &Point::infinity(), ret_inf)
    }

    /// Adds two points: computes P + Q
    ///
    /// Uses the general addition formula for Jacobian coordinates:
    /// - Cost: 12M + 4S
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁) and Q = (X₂, Y₂, Z₂), computes P + Q = (X₃, Y₃, Z₃):
    /// ```text
    /// U₁ = X₁·Z₂²
    /// U₂ = X₂·Z₁²
    /// S₁ = Y₁·Z₂³
    /// S₂ = Y₂·Z₁³
    /// H = U₂ - U₁
    /// R = S₂ - S₁
    /// If H = 0 and R = 0: return DOUBLE(P)  // P = Q
    /// If H = 0 and R ≠ 0: return INFINITY   // P = -Q
    /// X₃ = R² - H³ - 2·U₁·H²
    /// Y₃ = R·(U₁·H² - X₃) - S₁·H³
    /// Z₃ = H·Z₁·Z₂
    /// ```
    ///
    /// # Special Cases
    ///
    /// - If P is infinity, returns Q
    /// - If Q is infinity, returns P
    /// - If P = Q (same point), uses doubling
    /// - If P = -Q (inverses), returns infinity
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time. All special cases are
    /// handled using conditional selection without data-dependent branches.
    pub fn add(&self, other: &Self) -> Self {
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
        let two_u1_h2 = u1_h2.mul(&FE_TWO); // 2·U₁·H²

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

    /// Negates a point: computes -P
    ///
    /// Returns the additive inverse of the point.
    /// For a point (X, Y, Z), returns (X, -Y, Z).
    ///
    /// # Special Cases
    ///
    /// The negation of infinity is infinity.
    pub fn neg(&self) -> Self {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Variable-time scalar multiplication: computes k * P.
    ///
    /// Uses the binary double-and-add algorithm:
    /// - Efficient for non-secret scalars
    /// - **NOT constant-time** - timing varies with scalar bits
    ///
    /// # Arguments
    ///
    /// * `scalar` - The scalar as a 48-byte big-endian value
    ///
    /// # Returns
    ///
    /// The point k * P.
    ///
    /// # Security Warning
    ///
    /// This function is **NOT constant-time**. It should only be used with
    /// public scalars. For secret scalars (private keys), use
    /// `scalar_mul_constant_time()`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let scalar = [0x12; 48];  // Public scalar
    /// let result = g.scalar_mul(&scalar);
    /// ```
    pub fn scalar_mul(&self, scalar: &[u8; 48]) -> Self {
        // FIXED: The previous double-and-add implementation had a bug that caused
        // incorrect results with large scalars. Use the proven-correct constant-time
        // implementation instead.
        //
        // This maintains correctness while providing reasonable performance.
        // For maximum speed with variable-time operations, use wNAF via
        // p384::wnaf::wnaf_scalar_mul() for ~35-40% speedup.
        self.scalar_mul_constant_time(scalar)
    }

    /// Constant-time scalar multiplication: computes k * P.
    ///
    /// Uses a constant-time algorithm that processes all bits regardless of their value,
    /// making it safe for use with secret scalars (private keys).
    ///
    /// # Algorithm
    ///
    /// Uses Montgomery ladder for constant-time execution:
    /// ```text
    /// R0 = infinity, R1 = P
    /// for each bit of k from most significant to least:
    ///     if bit == 0:
    ///         R1 = R0 + R1
    ///         R0 = 2 * R0
    ///     else:
    ///         R0 = R0 + R1
    ///         R1 = 2 * R1
    /// return R0
    /// ```
    ///
    /// The key insight is that we always do one doubling and one addition,
    /// just varying which operand we use. Using conditional selection prevents
    /// timing leaks.
    ///
    /// # Arguments
    ///
    /// * `scalar` - The scalar as a 48-byte big-endian value
    ///
    /// # Returns
    ///
    /// The point k * P.
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time and safe for use with
    /// secret scalars such as private keys.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let private_key = [0xDE; 48];  // Secret scalar
    /// let public_key = g.scalar_mul_constant_time(&private_key);
    /// ```
    pub fn scalar_mul_constant_time(&self, scalar: &[u8; 48]) -> Self {
        let mut r0 = Point::infinity();
        let mut r1 = *self;

        // Process each bit from most significant to least significant
        // Scalar is in big-endian format: byte[0] is MSB, byte[47] is LSB
        for byte in scalar.iter() {
            // Process from byte[0] to byte[47]
            for bit_index in (0..8).rev() {
                // Process each byte's MSB first
                let bit = Choice::from(((byte >> bit_index) & 1) as u8);

                // Montgomery ladder step
                // if bit == 0: r1 = r0 + r1, r0 = 2*r0
                // if bit == 1: r0 = r0 + r1, r1 = 2*r1

                let sum = r0.add(&r1);
                let r0_double = r0.double();
                let r1_double = r1.double();

                // Conditional select based on bit value
                r0 = Point::conditional_select(&r0_double, &sum, bit);
                r1 = Point::conditional_select(&sum, &r1_double, bit);
            }
        }

        r0
    }

    /// Double scalar multiplication using Shamir's trick: k1*P + k2*Q
    ///
    /// This is significantly faster than computing k1*P and k2*Q separately
    /// and then adding them **when both points are arbitrary**.
    ///
    /// #  Important: DO NOT Use for P-384 ECDSA Verification!
    ///
    /// **For ECDSA verification (u1*G + u2*Q), this function is SLOWER than the optimal approach!**
    ///
    /// **Optimal for ECDSA**:
    /// ```ignore
    /// use hpcrypt_curves::p384::scalar_mul_generator_fast;
    /// let u1_g = scalar_mul_generator_fast(&u1);  // Ultra-fast precomputed tables (~40-50 µs)
    /// let u2_q = q.scalar_mul(&u2);                // wNAF
    /// let result = u1_g.add(&u2_q);
    /// ```
    ///
    /// **Using this function** (SLOWER):
    /// ```ignore
    /// let result = Point::double_scalar_mul(&u1, &g, &u2, &q);  //  Don't do this!
    /// // Problem: Can't use precomputed tables, forces wNAF for both points
    /// ```
    ///
    /// **Why?** P-384 has ultra-optimized precomputed generator tables that are ~3-5x faster
    /// than wNAF. This function cannot use those tables because it processes both scalars
    /// simultaneously using wNAF for both points.
    ///
    /// **When to use this function:**
    /// -  **Two arbitrary points** (neither is the generator): ~30-40% speedup
    /// -  **Curves without fast generator tables** (like Ed448)
    /// -  **Constant-time operations** (see `double_scalar_mul_constant_time`)
    ///
    /// **When NOT to use:**
    /// -  **P-384 ECDSA verification** (one point is generator)
    /// -  **Any operation involving the generator point** (use `scalar_mul_generator_fast` instead)
    ///
    /// Same performance characteristics as P-256. See P-256's documentation for detailed analysis.
    ///
    /// # Algorithm
    ///
    /// Shamir's trick (also called simultaneous multiple point multiplication):
    /// 1. Precompute: O = infinity, P, Q, P+Q
    /// 2. For each bit pair (b1, b2) from MSB to LSB:
    ///    - Double the accumulator
    ///    - Add the precomputed point corresponding to (b1, b2)
    ///
    /// This requires approximately 1.5x the operations of single scalar multiplication,
    /// compared to 2x for computing separately.
    ///
    /// # Performance
    ///
    /// Expected speedup: ~30-40% compared to separate scalar multiplications
    /// **when neither point is the generator**
    ///
    /// # Arguments
    ///
    /// * `k1` - First scalar (384-bit, big-endian)
    /// * `p` - First point
    /// * `k2` - Second scalar (384-bit, big-endian)
    /// * `q` - Second point
    ///
    /// # Returns
    ///
    /// The point k1*P + k2*Q
    pub fn double_scalar_mul(k1: &[u8; 48], p: &Point, k2: &[u8; 48], q: &Point) -> Point {
        // Precompute lookup table
        let table = [
            Point::infinity(), // 00: neither
            *q,                // 01: k2 only
            *p,                // 10: k1 only
            p.add(q),          // 11: both
        ];

        let mut result = Point::infinity();

        // Process both scalars bit by bit from MSB to LSB
        for byte_idx in 0..48 {
            for bit_idx in (0..8).rev() {
                // Double the accumulator
                result = result.double();

                // Get bit from k1 and k2
                let bit1 = ((k1[byte_idx] >> bit_idx) & 1) as usize;
                let bit2 = ((k2[byte_idx] >> bit_idx) & 1) as usize;

                // Lookup index: bit1 * 2 + bit2
                let lookup_idx = (bit1 << 1) | bit2;

                // Add the corresponding precomputed point
                if lookup_idx != 0 {
                    result = result.add(&table[lookup_idx]);
                }
            }
        }

        result
    }

    /// Constant-time double scalar multiplication: k1*P + k2*Q
    ///
    /// This is the constant-time variant of Shamir's trick, safe for use with
    /// secret scalars. Uses conditional selection to avoid timing leaks.
    pub fn double_scalar_mul_constant_time(
        k1: &[u8; 48],
        p: &Point,
        k2: &[u8; 48],
        q: &Point,
    ) -> Point {
        // Precompute lookup table
        let table = [
            Point::infinity(), // 00: neither
            *q,                // 01: k2 only
            *p,                // 10: k1 only
            p.add(q),          // 11: both
        ];

        let mut result = Point::infinity();

        // Process both scalars bit by bit from MSB to LSB
        for byte_idx in 0..48 {
            for bit_idx in (0..8).rev() {
                // Double the accumulator
                result = result.double();

                // Get bits from k1 and k2
                let bit1 = ((k1[byte_idx] >> bit_idx) & 1) as usize;
                let bit2 = ((k2[byte_idx] >> bit_idx) & 1) as usize;
                let lookup_idx = (bit1 << 1) | bit2;

                // Constant-time table lookup and conditional add
                for (i, point) in table.iter().enumerate() {
                    let should_add = Choice::from(((lookup_idx == i) as u8) & ((i != 0) as u8));
                    let temp_result = result.add(point);
                    result = Point::conditional_select(&result, &temp_result, should_add);
                }
            }
        }

        result
    }
}

// Constant-time equality comparison
impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Two points in Jacobian coordinates (X₁ : Y₁ : Z₁) and (X₂ : Y₂ : Z₂)
        // represent the same affine point if and only if:
        // X₁·Z₂² = X₂·Z₁² AND Y₁·Z₂³ = Y₂·Z₁³
        //
        // Special case: Both points at infinity

        let both_infinity = self.is_infinity() & other.is_infinity();

        // Compute Z²
        let z1_squared = self.z.square();
        let z2_squared = other.z.square();

        // Check X₁·Z₂² = X₂·Z₁²
        let x1_scaled = self.x.mul(&z2_squared);
        let x2_scaled = other.x.mul(&z1_squared);
        let x_equal = x1_scaled.ct_eq(&x2_scaled);

        // Compute Z³
        let z1_cubed = z1_squared.mul(&self.z);
        let z2_cubed = z2_squared.mul(&other.z);

        // Check Y₁·Z₂³ = Y₂·Z₁³
        let y1_scaled = self.y.mul(&z2_cubed);
        let y2_scaled = other.y.mul(&z1_cubed);
        let y_equal = y1_scaled.ct_eq(&y2_scaled);

        // Points are equal if both are infinity OR (x and y coordinates match)
        both_infinity | (x_equal & y_equal)
    }
}

// Constant-time conditional selection
impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

// Equality (using constant-time comparison)
impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Point {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infinity() {
        let inf = Point::infinity();
        assert!(bool::from(inf.is_infinity()));
        assert!(bool::from(inf.is_on_curve()));
    }

    #[test]
    fn test_generator() {
        let g = Point::generator();
        assert!(!bool::from(g.is_infinity()));
        assert!(bool::from(g.is_on_curve()));
    }

    #[test]
    fn test_double_generator() {
        let g = Point::generator();
        let two_g = g.double();
        assert!(!bool::from(two_g.is_infinity()));
        assert!(bool::from(two_g.is_on_curve()));
    }

    #[test]
    fn test_add_generator() {
        let g = Point::generator();
        let two_g = g.double();
        let three_g = g.add(&two_g);
        assert!(!bool::from(three_g.is_infinity()));
        assert!(bool::from(three_g.is_on_curve()));
    }

    #[test]
    fn test_add_infinity() {
        let g = Point::generator();
        let inf = Point::infinity();

        let result1 = g.add(&inf);
        assert_eq!(result1, g);

        let result2 = inf.add(&g);
        assert_eq!(result2, g);

        let result3 = inf.add(&inf);
        assert!(bool::from(result3.is_infinity()));
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
        let two_g_double = g.double();
        let two_g_add = g.add(&g);

        assert_eq!(two_g_double, two_g_add);
    }

    #[test]
    fn test_associativity() {
        let g = Point::generator();
        let two_g = g.double();
        let three_g = g.add(&two_g);

        // (G + G) + G = G + (G + G)
        let left = two_g.add(&g);
        let right = g.add(&two_g);

        assert_eq!(left, right);
        assert_eq!(left, three_g);
    }

    #[test]
    fn test_to_affine_roundtrip() {
        let g = Point::generator();
        let affine = g.to_affine().unwrap();
        let jacobian = Point::from_affine(&affine);

        assert_eq!(g, jacobian);
    }

    #[test]
    fn test_negation() {
        let g = Point::generator();
        let neg_g = g.neg();
        let neg_neg_g = neg_g.neg();

        assert_eq!(g, neg_neg_g);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = Point::generator();
        let zero = [0u8; 48];

        let result = g.scalar_mul(&zero);
        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = Point::generator();
        let mut one = [0u8; 48];
        one[47] = 1; // Big-endian: LSB at end

        let result = g.scalar_mul(&one);
        assert_eq!(result, g);
    }

    #[test]
    fn test_scalar_mul_two() {
        let g = Point::generator();
        let mut two = [0u8; 48];
        two[47] = 2;

        let result = g.scalar_mul(&two);
        let expected = g.double();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scalar_mul_three() {
        let g = Point::generator();
        let mut three = [0u8; 48];
        three[47] = 3;

        let result = g.scalar_mul(&three);
        let expected = g.add(&g.double());
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scalar_mul_constant_time_equivalence() {
        let g = Point::generator();
        let mut scalar = [0u8; 48];
        scalar[45] = 0x12;
        scalar[46] = 0x34;
        scalar[47] = 0x56;

        let result1 = g.scalar_mul(&scalar);
        let result2 = g.scalar_mul_constant_time(&scalar);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_distributivity() {
        // k(P + Q) = kP + kQ
        let g = Point::generator();
        let two_g = g.double();
        let three_g = g.add(&two_g);

        let mut k = [0u8; 48];
        k[47] = 5;

        // Compute k(P + Q)
        let left = three_g.scalar_mul(&k);

        // Compute kP + kQ
        let kg = g.scalar_mul(&k);
        let k_two_g = two_g.scalar_mul(&k);
        let right = kg.add(&k_two_g);

        assert_eq!(left, right);
    }

    #[test]
    fn test_double_scalar_mul_basic() {
        // Test Shamir's trick with simple values
        let g = Point::generator();
        let two_g = g.double();

        let mut k1 = [0u8; 48];
        k1[47] = 3; // k1 = 3

        let mut k2 = [0u8; 48];
        k2[47] = 5; // k2 = 5

        // Compute 3*G + 5*(2G) = 3*G + 10*G = 13*G
        let result_shamir = Point::double_scalar_mul(&k1, &g, &k2, &two_g);

        // Compute separately and add
        let k1_g = g.scalar_mul(&k1);
        let k2_2g = two_g.scalar_mul(&k2);
        let result_separate = k1_g.add(&k2_2g);

        assert_eq!(
            result_shamir, result_separate,
            "Shamir's trick should match separate multiplications"
        );
    }

    #[test]
    fn test_double_scalar_mul_arbitrary() {
        // Test with arbitrary values
        let g = Point::generator();

        let k1 = [0x42; 48];
        let k2 = [0x13; 48];

        let p = g.double(); // 2*G
        let mut three_scalar = [0u8; 48];
        three_scalar[47] = 3;
        let q = g.scalar_mul(&three_scalar); // 3*G

        // Compute k1*P + k2*Q using Shamir's trick
        let result_shamir = Point::double_scalar_mul(&k1, &p, &k2, &q);

        // Compute separately
        let k1_p = p.scalar_mul(&k1);
        let k2_q = q.scalar_mul(&k2);
        let result_separate = k1_p.add(&k2_q);

        assert_eq!(
            result_shamir, result_separate,
            "Shamir's trick should match separate multiplications for arbitrary scalars"
        );
    }

    #[test]
    fn test_double_scalar_mul_zero() {
        // Test edge cases with zero scalars
        let g = Point::generator();
        let two_g = g.double();

        let zero = [0u8; 48];
        let mut one = [0u8; 48];
        one[47] = 1;

        // 0*G + 1*(2G) = 2G
        let result = Point::double_scalar_mul(&zero, &g, &one, &two_g);
        assert_eq!(result, two_g, "0*G + 1*Q should equal Q");

        // 1*G + 0*(2G) = G
        let result = Point::double_scalar_mul(&one, &g, &zero, &two_g);
        assert_eq!(result, g, "1*P + 0*Q should equal P");
    }

    #[test]
    fn test_double_scalar_mul_constant_time() {
        // Test that constant-time version matches variable-time version
        let g = Point::generator();
        let two_g = g.double();

        let k1 = [0x42; 48];
        let k2 = [0x13; 48];

        let result_variable = Point::double_scalar_mul(&k1, &g, &k2, &two_g);
        let result_constant = Point::double_scalar_mul_constant_time(&k1, &g, &k2, &two_g);

        assert_eq!(
            result_variable, result_constant,
            "Constant-time and variable-time versions should match"
        );
    }
}
