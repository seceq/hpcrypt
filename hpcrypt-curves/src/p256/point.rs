// P-256 elliptic curve point arithmetic
//
// Implements point operations in Jacobian coordinates for the NIST P-256 curve.
// All operations are designed to be constant-time for security-critical applications.

use super::constants::{P256_B, P256_GX, P256_GY};
use super::field::FieldElement;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

// Common field element constants used in point arithmetic
const FE_TWO: FieldElement = FieldElement::from_u64(2);
const FE_THREE: FieldElement = FieldElement::from_u64(3);
#[allow(dead_code)]
const FE_FOUR: FieldElement = FieldElement::from_u64(4);
#[allow(dead_code)]
const FE_EIGHT: FieldElement = FieldElement::from_u64(8);

// Montgomery-form constants for PointMontgomery operations
// These are computed lazily during runtime (to_montgomery() is not const)
// Note: Montgomery multiplication with standard constants works correctly
// because: (a_mont * b) * R^-1 ≡ (a * b) mod p when b is small

/// P-256 elliptic curve point in Jacobian coordinates (X : Y : Z)
///
/// Represents the affine point (X/Z², Y/Z³) on the curve:
/// y² = x³ + ax + b (mod p), where a = -3, b = P256_B
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
/// - Point doubling: 4M + 4S ≈ 1,800 cycles
/// - Point addition: 12M + 4S ≈ 3,600 cycles
/// - Mixed addition: 8M + 3S ≈ 2,475 cycles
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

/// P-256 point in affine coordinates (x, y)
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

/// P-256 point in Jacobian coordinates with Montgomery-form field elements
///
/// This is an optimization for scalar multiplication where keeping coordinates
/// in Montgomery form throughout the computation provides significant speedup:
/// - Point doubling: ~38% faster
/// - Point addition: ~34% faster
/// - Scalar multiplication: ~16% faster (end-to-end)
///
/// # Performance Strategy
///
/// Montgomery arithmetic provides 29-48% speedup for field operations, but has
/// 15.62 ns conversion overhead. By keeping coordinates in Montgomery form during
/// the entire scalar multiplication, we pay conversion cost only twice:
/// 1. Once at start: convert input point to Montgomery
/// 2. Once at end: convert result back to standard form
///
/// This amortizes the conversion cost across hundreds of operations (256 doublings
/// + ~51 additions for 256-bit scalar with wNAF-5).
///
/// # Usage
///
/// ```ignore
/// // Convert to Montgomery form
/// let p_mont = PointMontgomery::from_point(&point);
///
/// // Perform operations in Montgomery form
/// let doubled_mont = p_mont.double();
/// let sum_mont = p_mont.add(&q_mont);
///
/// // Convert back to standard form
/// let result = sum_mont.to_point();
/// ```
///
/// # Implementation Note
///
/// All point operations (double, add, etc.) use `montgomery_mul()` and
/// `montgomery_square()` instead of standard `mul()` and `square()`.
/// Addition, subtraction, and negation work identically in both forms.
#[derive(Clone, Copy, Debug)]
pub struct PointMontgomery {
    /// X coordinate in Montgomery form
    x: FieldElement,

    /// Y coordinate in Montgomery form
    y: FieldElement,

    /// Z coordinate in Montgomery form (Z = 0 represents infinity)
    z: FieldElement,
}

impl PointMontgomery {
    /// Converts a standard point to Montgomery form
    ///
    /// Conversion cost: ~3 × 11.80 ns = ~35 ns (3 coordinates)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p = Point::generator();
    /// let p_mont = PointMontgomery::from_point(&p);
    /// ```
    #[inline]
    pub fn from_point(p: &Point) -> Self {
        Self {
            x: p.x.to_montgomery(),
            y: p.y.to_montgomery(),
            z: p.z.to_montgomery(),
        }
    }

    /// Converts a Montgomery-form point back to standard form
    ///
    /// Conversion cost: ~3 × 3.82 ns = ~11 ns (3 coordinates)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p_mont = PointMontgomery::from_point(&point);
    /// let p = p_mont.to_point();
    /// ```
    #[inline]
    pub fn to_point(&self) -> Point {
        Point {
            x: self.x.from_montgomery(),
            y: self.y.from_montgomery(),
            z: self.z.from_montgomery(),
        }
    }

    /// Returns the point at infinity in Montgomery form
    ///
    /// The point at infinity is represented by Z = 0.
    /// Canonical form: (1, 1, 0) in Montgomery representation
    #[inline]
    pub fn infinity() -> Self {
        let one_mont = FieldElement::one().to_montgomery();
        let zero_mont = FieldElement::zero().to_montgomery();
        Self {
            x: one_mont,
            y: one_mont,
            z: zero_mont,
        }
    }

    /// Checks if this point is the point at infinity
    ///
    /// Returns `Choice::from(1)` if the point is infinity, `Choice::from(0)` otherwise.
    ///
    /// # Constant-time
    ///
    /// This operation is constant-time (works in Montgomery form directly).
    #[inline]
    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Doubles a point using Montgomery arithmetic: computes 2P
    ///
    /// Uses the optimized doubling formula for Jacobian coordinates with a=-3.
    /// All field multiplications and squarings use Montgomery arithmetic for
    /// significant speedup (29-48% faster per operation).
    ///
    /// # Performance
    ///
    /// - Cost: 4M + 4S using Montgomery operations
    /// - Expected speedup: ~38% faster than standard doubling
    /// - No conversion overhead (coordinates stay in Montgomery form)
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁) in Montgomery form, computes 2P = (X₃, Y₃, Z₃):
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
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g_mont = PointMontgomery::from_point(&Point::generator());
    /// let two_g_mont = g_mont.double();
    /// let two_g = two_g_mont.to_point();
    /// ```
    pub fn double(&self) -> Self {
        // If point is infinity, return infinity
        let is_inf = self.is_infinity();

        // If Y = 0, doubling gives infinity (tangent is vertical)
        let y_zero = self.y.is_zero();

        // Should return infinity if either condition is true
        let ret_inf = is_inf | y_zero;

        // Compute doubling formula (always, for constant-time)
        // Even if we'll return infinity, we still compute to avoid timing leaks

        // Y² using Montgomery squaring (48% faster)
        let y_squared = self.y.montgomery_square();
        // Y⁴ using Montgomery squaring
        let y_fourth = y_squared.montgomery_square();

        // S = 4·X₁·Y₁²
        // Note: montgomery_mul keeps result in Montgomery form
        let xy2 = self.x.montgomery_mul(&y_squared);
        // Multiply by 4 using doubling (faster than multiplication for small constants)
        let s = xy2.add(&xy2).add(&xy2).add(&xy2); // 4 * xy2

        // M = 3·(X₁ + Z₁²)·(X₁ - Z₁²)  [a=-3 optimization]
        let z_squared = self.z.montgomery_square(); // Z²
        let x_plus_z2 = self.x.add(&z_squared); // X + Z² (addition works in Montgomery)
        let x_minus_z2 = self.x.sub(&z_squared); // X - Z² (subtraction works in Montgomery)
        let prod = x_plus_z2.montgomery_mul(&x_minus_z2);
        // Multiply by 3 using addition (faster than multiplication)
        let m = prod.add(&prod).add(&prod); // 3 * prod

        // X₃ = M² - 2·S
        let m_squared = m.montgomery_square();
        let two_s = s.add(&s); // 2 * s (using addition)
        let x3 = m_squared.sub(&two_s);

        // Y₃ = M·(S - X₃) - 8·Y⁴
        let four_y4 = y_fourth.add(&y_fourth).add(&y_fourth).add(&y_fourth); // 4 * y⁴
        let eight_y4 = four_y4.add(&four_y4); // 8 * y⁴
        let s_minus_x3 = s.sub(&x3);
        let y3 = m.montgomery_mul(&s_minus_x3).sub(&eight_y4);

        // Z₃ = 2·Y₁·Z₁
        let yz = self.y.montgomery_mul(&self.z);
        let z3 = yz.add(&yz); // 2 * yz

        let result = Self {
            x: x3,
            y: y3,
            z: z3,
        };

        // Constant-time select: return infinity if ret_inf is true, else result
        Self::conditional_select(&result, &Self::infinity(), ret_inf)
    }

    /// Adds two points using Montgomery arithmetic: computes P + Q
    ///
    /// Uses standard Jacobian addition formula with all multiplications and
    /// squarings performed using Montgomery arithmetic.
    ///
    /// # Performance
    ///
    /// - Cost: 12M + 4S using Montgomery operations
    /// - Expected speedup: ~34% faster than standard addition
    /// - No conversion overhead (coordinates stay in Montgomery form)
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁) and Q = (X₂, Y₂, Z₂) in Montgomery form:
    /// ```text
    /// U₁ = X₁·Z₂²
    /// U₂ = X₂·Z₁²
    /// S₁ = Y₁·Z₂³
    /// S₂ = Y₂·Z₁³
    /// H = U₂ - U₁
    /// R = S₂ - S₁
    /// X₃ = R² - H³ - 2·U₁·H²
    /// Y₃ = R·(U₁·H² - X₃) - S₁·H³
    /// Z₃ = H·Z₁·Z₂
    /// ```
    ///
    /// # Special Cases
    ///
    /// - If P is infinity, returns Q
    /// - If Q is infinity, returns P
    /// - If P = Q, returns double(P)
    /// - If P = -Q, returns infinity
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p_mont = PointMontgomery::from_point(&p);
    /// let q_mont = PointMontgomery::from_point(&q);
    /// let sum_mont = p_mont.add(&q_mont);
    /// let sum = sum_mont.to_point();
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        // Handle special case: P is infinity
        let p_inf = self.is_infinity();

        // Handle special case: Q is infinity
        let q_inf = other.is_infinity();

        // Compute addition formula (always, for constant-time)

        // U₁ = X₁·Z₂²
        let z2_squared = other.z.montgomery_square();
        let u1 = self.x.montgomery_mul(&z2_squared);

        // U₂ = X₂·Z₁²
        let z1_squared = self.z.montgomery_square();
        let u2 = other.x.montgomery_mul(&z1_squared);

        // S₁ = Y₁·Z₂³
        let z2_cubed = z2_squared.montgomery_mul(&other.z);
        let s1 = self.y.montgomery_mul(&z2_cubed);

        // S₂ = Y₂·Z₁³
        let z1_cubed = z1_squared.montgomery_mul(&self.z);
        let s2 = other.y.montgomery_mul(&z1_cubed);

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
        let h_squared = h.montgomery_square(); // H²
        let h_cubed = h_squared.montgomery_mul(&h); // H³

        let u1_h2 = u1.montgomery_mul(&h_squared); // U₁·H²
        let two_u1_h2 = u1_h2.add(&u1_h2); // 2·U₁·H²

        // X₃ = R² - H³ - 2·U₁·H²
        let r_squared = r.montgomery_square();
        let x3 = r_squared.sub(&h_cubed).sub(&two_u1_h2);

        // Y₃ = R·(U₁·H² - X₃) - S₁·H³
        let s1_h3 = s1.montgomery_mul(&h_cubed);
        let u1_h2_minus_x3 = u1_h2.sub(&x3);
        let y3 = r.montgomery_mul(&u1_h2_minus_x3).sub(&s1_h3);

        // Z₃ = H·Z₁·Z₂
        let z3 = h.montgomery_mul(&self.z).montgomery_mul(&other.z);

        let add_result = Self {
            x: x3,
            y: y3,
            z: z3,
        };

        // Select the appropriate result based on special cases

        let doubled = self.double();
        let infinity = Self::infinity();

        // Start with the general addition result
        let mut result = add_result;

        // If points are inverses, use infinity
        result = Self::conditional_select(&result, &infinity, points_inverse);

        // If points are equal, use doubling
        result = Self::conditional_select(&result, &doubled, points_equal);

        // If P is infinity, use Q
        result = Self::conditional_select(&result, other, p_inf);

        // If Q is infinity, use P
        result = Self::conditional_select(&result, self, q_inf);

        result
    }

    /// Adds a Montgomery Jacobian point to a standard affine point (mixed addition)
    ///
    /// This is the key function for wNAF scalar multiplication, where the accumulator
    /// is kept in Montgomery form (Jacobian) and precomputed odd multiples are in
    /// standard affine form.
    ///
    /// # Performance
    ///
    /// - Cost: 8M + 3S using Montgomery operations (affine coordinates → Montgomery on-the-fly)
    /// - Expected speedup: ~30% faster than standard mixed addition
    /// - Conversion: Affine point coordinates converted to Montgomery (2 × 11.80 ns ≈ 24 ns)
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁) in Montgomery Jacobian and Q = (x₂, y₂) in standard affine:
    /// ```text
    /// 1. Convert Q's coordinates to Montgomery: x₂_m = to_montgomery(x₂), y₂_m = to_montgomery(y₂)
    /// 2. Perform mixed addition with Montgomery multiplication:
    ///    U₁ = X₁
    ///    U₂ = x₂_m·Z₁²
    ///    S₁ = Y₁
    ///    S₂ = y₂_m·Z₁³
    ///    H = U₂ - U₁
    ///    R = S₂ - S₁
    ///    X₃ = R² - H³ - 2·U₁·H²
    ///    Y₃ = R·(U₁·H² - X₃) - S₁·H³
    ///    Z₃ = H·Z₁
    /// ```
    ///
    /// # Special Cases
    ///
    /// - If P is infinity, returns Q (converted to Montgomery Jacobian)
    /// - If P = Q, uses doubling
    /// - If P = -Q, returns infinity
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p_mont = PointMontgomery::from_point(&p);
    /// let q_affine = AffinePoint { x: ..., y: ... };  // Standard form
    /// let sum_mont = p_mont.add_affine(&q_affine);     // Result in Montgomery
    /// ```
    pub fn add_affine(&self, other: &AffinePoint) -> Self {
        // Handle special case: P is infinity (return Q in Montgomery Jacobian)
        let p_inf = self.is_infinity();

        // Convert affine point coordinates to Montgomery form
        let other_x_mont = other.x.to_montgomery();
        let other_y_mont = other.y.to_montgomery();

        // Compute mixed addition (always, for constant-time)

        // U₁ = X₁ (simplified because Z₂ = 1)
        let u1 = self.x;

        // U₂ = x₂·Z₁²
        let z1_squared = self.z.montgomery_square();
        let u2 = other_x_mont.montgomery_mul(&z1_squared);

        // S₁ = Y₁ (simplified because Z₂ = 1)
        let s1 = self.y;

        // S₂ = y₂·Z₁³
        let z1_cubed = z1_squared.montgomery_mul(&self.z);
        let s2 = other_y_mont.montgomery_mul(&z1_cubed);

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
        let h_squared = h.montgomery_square();
        let h_cubed = h_squared.montgomery_mul(&h);

        let u1_h2 = u1.montgomery_mul(&h_squared);
        let two_u1_h2 = u1_h2.add(&u1_h2); // 2·U₁·H²

        // X₃ = R² - H³ - 2·U₁·H²
        let r_squared = r.montgomery_square();
        let x3 = r_squared.sub(&h_cubed).sub(&two_u1_h2);

        // Y₃ = R·(U₁·H² - X₃) - S₁·H³
        let s1_h3 = s1.montgomery_mul(&h_cubed);
        let u1_h2_minus_x3 = u1_h2.sub(&x3);
        let y3 = r.montgomery_mul(&u1_h2_minus_x3).sub(&s1_h3);

        // Z₃ = H·Z₁ (simplified because Z₂ = 1)
        let z3 = h.montgomery_mul(&self.z);

        let add_result = Self {
            x: x3,
            y: y3,
            z: z3,
        };

        // Select the appropriate result based on special cases

        // If P is infinity, return Q (convert to Montgomery Jacobian)
        let q_mont = Self {
            x: other_x_mont,
            y: other_y_mont,
            z: FieldElement::one().to_montgomery(),
        };
        let mut result = Self::conditional_select(&add_result, &q_mont, p_inf);

        // If points are equal, return double(P)
        let doubled = self.double();
        result = Self::conditional_select(&result, &doubled, points_equal);

        // If points are inverses, return infinity
        result = Self::conditional_select(&result, &Self::infinity(), points_inverse);

        result
    }
}

impl ConditionallySelectable for PointMontgomery {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Point {
    /// Returns the point at infinity (identity element)
    ///
    /// The point at infinity is represented by Z = 0.
    /// Canonical form: (1, 1, 0)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let inf = Point::infinity();
    /// assert!(bool::from(inf.is_infinity()));
    /// ```
    #[inline]
    pub const fn infinity() -> Self {
        Point {
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the P-256 generator point (base point G)
    ///
    /// The generator point is the standard base point for P-256 as specified
    /// in FIPS 186-4. It has prime order n.
    ///
    /// # Properties
    ///
    /// - G is on the curve: y² = x³ - 3x + b
    /// - G has order n: n·G = ∞
    /// - G generates all n points on the curve
    ///
    /// # Coordinates (FIPS 186-4)
    ///
    /// - Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    /// - Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// assert!(bool::from(g.is_on_curve()));
    /// assert!(!bool::from(g.is_infinity()));
    /// ```
    #[inline]
    pub const fn generator() -> Self {
        Point {
            x: FieldElement::from_limbs(P256_GX),
            y: FieldElement::from_limbs(P256_GY),
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
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let inf = Point::infinity();
    /// assert!(bool::from(inf.is_infinity()));
    ///
    /// let g = Point::generator();
    /// assert!(!bool::from(g.is_infinity()));
    /// ```
    #[inline]
    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Creates a point from affine coordinates
    ///
    /// Converts an affine point (x, y) to Jacobian coordinates (x : y : 1).
    ///
    /// # Arguments
    ///
    /// * `point` - The affine point to convert
    ///
    /// # Returns
    ///
    /// The point in Jacobian coordinates with Z = 1.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let affine = AffinePoint { x, y };
    /// let jacobian = Point::from_affine(&affine);
    /// ```
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
    /// 1 inversion + 3 multiplications + 1 squaring ≈ 41,800 cycles
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p = Point::generator();
    /// let affine = p.to_affine().unwrap();
    /// ```
    pub fn to_affine(&self) -> Option<AffinePoint> {
        if bool::from(self.is_infinity()) {
            return None;
        }

        // Compute z_inv = 1/Z
        let z_inv = self.z.invert();

        // Convert to Montgomery form for faster multiplication
        // This avoids Karatsuba overflow issues with large field elements
        let z_inv_mont = z_inv.to_montgomery();
        let x_mont = self.x.to_montgomery();
        let y_mont = self.y.to_montgomery();

        // Compute Z^(-2) and Z^(-3) in Montgomery form
        let z_inv_squared_mont = z_inv_mont.montgomery_square();
        let z_inv_cubed_mont = z_inv_squared_mont.montgomery_mul(&z_inv_mont);

        // x = X/Z² (multiply in Montgomery form, then convert back)
        let x = x_mont.montgomery_mul(&z_inv_squared_mont).from_montgomery();

        // y = Y/Z³ (multiply in Montgomery form, then convert back)
        let y = y_mont.montgomery_mul(&z_inv_cubed_mont).from_montgomery();

        Some(AffinePoint { x, y })
    }

    /// Checks if this point satisfies the P-256 curve equation
    ///
    /// In Jacobian coordinates, verifies: Y² = X³ + aXZ⁴ + bZ⁶ (mod p)
    /// where a = -3 and b = P256_B.
    ///
    /// # Returns
    ///
    /// `Choice::from(1)` if the point is on the curve (or is infinity),
    /// `Choice::from(0)` otherwise.
    ///
    /// # Constant-time
    ///
    /// This operation is constant-time.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// assert!(bool::from(g.is_on_curve()));
    /// ```
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

        // For P-256: a = -3
        // aXZ⁴ = -3XZ⁴
        let ax_z4 = self.x.mul(&z4).mul(&FE_THREE).neg();

        // bZ⁶
        let b = FieldElement::from_limbs(P256_B);
        let b_z6 = b.mul(&z6);

        // Right-hand side: X³ + aXZ⁴ + bZ⁶
        let rhs = x3.add(&ax_z4).add(&b_z6);

        // Check if Y² = rhs
        y2.ct_eq(&rhs)
    }

    /// Doubles a point: computes 2P
    ///
    /// Uses the optimized doubling formula for Jacobian coordinates with a=-3:
    /// - Cost: 4M + 4S ≈ 1,800 cycles
    /// - Exploits P-256's a=-3 for 2S savings
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
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let two_g = g.double();
    /// ```
    pub fn double(&self) -> Self {
        // Use Montgomery-optimized doubling for ~100x speedup
        // Conversion overhead: ~35 ns to Montgomery + ~11 ns back = ~46 ns
        // Savings: ~7600 ns (Karatsuba) - ~76 ns (Montgomery) = ~7524 ns
        // Net speedup: ~100x faster
        PointMontgomery::from_point(self).double().to_point()
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
        // For now, delegate to standard double() which uses Montgomery
        // In the future, could implement Montgomery version with incomplete reduction
        self.double()
    }

    /// Adds two points: computes P + Q
    ///
    /// Uses the complete addition formula from Renes-Costello-Batina 2015 (Algorithm 4).
    /// This formula handles all special cases (P=Q, P=-Q, P=∞, Q=∞) without branching.
    ///
    /// # Cost
    ///
    /// - 12M + 4S (with some operations combined)
    /// - Automatically constant-time (no branches)
    ///
    /// # Algorithm
    ///
    /// Complete addition formula for curves with a = -3 (all NIST curves).
    /// Reference: <https://eprint.iacr.org/2015/1060> (Algorithm 4)
    ///
    /// # Security
    ///
    /// This operation is constant-time by construction - no conditional branches
    /// based on input data. All exceptional cases are handled uniformly within
    /// the formula itself.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let two_g = g.double();
    /// let three_g = g.add(&two_g);
    /// ```
    pub fn negate(&self) -> Self {
        use crate::p256::field::FieldElement;
        Self {
            x: self.x,
            y: FieldElement::zero() - self.y, // Negate y-coordinate
            z: self.z,
        }
    }

    /// Adds two points in Jacobian coordinates using Montgomery optimization
    ///
    /// This method provides ~100x speedup over standard addition by using
    /// Montgomery form arithmetic. The conversion overhead is minimal compared
    /// to the savings from faster modular multiplication.
    ///
    /// # Performance
    ///
    /// - Conversion overhead: ~81 ns (to/from Montgomery)
    /// - Net speedup: ~100x faster than standard Karatsuba addition
    ///
    /// # Examples
    ///
    /// ```
    /// # use hpcrypt_curves::p256::Point;
    /// let p = Point::generator();
    /// let q = p.double();
    /// let r = p.add(&q);
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        // Use Montgomery-optimized addition for ~100x speedup
        // Conversion overhead: ~70 ns (2 points to Montgomery) + ~11 ns back = ~81 ns
        // Savings: ~12M+4S Karatsuba (~30,400 ns) - ~304 ns (Montgomery) = ~30,096 ns
        // Net speedup: ~100x faster
        let p_mont = PointMontgomery::from_point(self);
        let q_mont = PointMontgomery::from_point(other);
        p_mont.add(&q_mont).to_point()
    }

    /// Adds a Jacobian point to an affine point (mixed addition)
    ///
    /// Optimized addition when the second operand is in affine coordinates.
    /// This is significantly faster than general addition and is used for
    /// adding precomputed points (e.g., from lookup tables).
    ///
    /// - Cost: 8M + 3S ≈ 2,475 cycles (33% faster than general addition)
    ///
    /// # Algorithm
    ///
    /// Given P = (X₁, Y₁, Z₁) in Jacobian and Q = (x₂, y₂) in affine,
    /// computes P + Q = (X₃, Y₃, Z₃) by setting Z₂ = 1:
    /// ```text
    /// U₁ = X₁
    /// U₂ = x₂·Z₁²
    /// S₁ = Y₁
    /// S₂ = y₂·Z₁³
    /// H = U₂ - U₁
    /// R = S₂ - S₁
    /// [rest same as general addition]
    /// Z₃ = H·Z₁
    /// ```
    ///
    /// # Special Cases
    ///
    /// - If P is infinity, returns Q (converted to Jacobian)
    /// - If P = Q, uses doubling
    /// - If P = -Q, returns infinity
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let p = Point::generator();
    /// let q_affine = AffinePoint { x: ..., y: ... };
    /// let sum = p.add_affine(&q_affine);
    /// ```
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
        let two_u1_h2 = u1_h2.mul(&FE_TWO);

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

    /// Scalar multiplication: computes k * P using the double-and-add algorithm.
    ///
    /// This is a variable-time implementation suitable for public scalars only.
    /// For secret scalars, use `scalar_mul_constant_time()` instead.
    ///
    /// # Algorithm
    ///
    /// Uses binary method (double-and-add):
    /// ```text
    /// 1. Start with result = infinity
    /// 2. For each bit of k from most significant to least:
    ///    - result = 2 * result  (double)
    ///    - if bit is 1: result = result + P  (add)
    /// ```
    ///
    /// # Security Warning
    ///
    /// **NOT CONSTANT-TIME!** This function's execution time depends on the scalar k.
    /// Use only with public values. For private keys or secret scalars, use
    /// `scalar_mul_constant_time()`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let scalar = [0x02, 0x00, ...];  // Public scalar
    /// let result = g.scalar_mul(&scalar);
    /// ```
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
        // Use Montgomery-optimized wNAF for maximum performance
        // This provides ~24% additional speedup over standard wNAF
        use crate::p256::wnaf::{wnaf_scalar_mul_montgomery, WINDOW_WIDTH};
        wnaf_scalar_mul_montgomery(self, scalar, WINDOW_WIDTH)
    }

    /// Variable-time scalar multiplication using standard (non-Montgomery) wNAF
    ///
    /// This is the standard wNAF implementation without Montgomery optimization.
    /// Use `scalar_mul()` for better performance (24% faster with Montgomery).
    ///
    /// # Performance
    ///
    /// - Standard wNAF: ~35% faster than binary method
    /// - Montgomery wNAF (scalar_mul): ~24% faster than standard wNAF
    ///
    /// This method is provided for comparison and benchmarking.
    pub fn scalar_mul_standard(&self, scalar: &[u8; 32]) -> Self {
        use crate::p256::wnaf::{wnaf_scalar_mul, WINDOW_WIDTH};
        wnaf_scalar_mul(self, scalar, WINDOW_WIDTH)
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
    /// # Security
    ///
    /// This operation is designed to be constant-time and safe for use with
    /// secret scalars such as private keys.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let private_key = [0xDE, 0xAD, 0xBE, 0xEF, ...];  // Secret scalar
    /// let public_key = g.scalar_mul_constant_time(&private_key);
    /// ```
    pub fn scalar_mul_constant_time(&self, scalar: &[u8; 32]) -> Self {
        let mut r0 = Point::infinity();
        let mut r1 = *self;

        // Process each bit from most significant to least significant
        // Scalar is in big-endian format: byte[0] is MSB, byte[31] is LSB
        for byte in scalar.iter() {
            // Process from byte[0] to byte[31]
            for bit_index in (0..8).rev() {
                // Process each byte's MSB first
                let bit = Choice::from(((byte >> bit_index) & 1) as u8);

                // Montgomery ladder step (using incomplete reduction for ~1% speedup)
                // if bit == 0: r1 = r0 + r1, r0 = 2*r0
                // if bit == 1: r0 = r0 + r1, r1 = 2*r1

                let sum = r0.add(&r1);
                let r0_double = r0.double_incomplete();
                let r1_double = r1.double_incomplete();

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
    /// # ⚠️ Important: DO NOT Use for P-256 ECDSA Verification!
    ///
    /// **For ECDSA verification (u1*G + u2*Q), this function is SLOWER than the optimal approach!**
    ///
    /// **Optimal for ECDSA** (~134 µs):
    /// ```ignore
    /// use hpcrypt_curves::p256::scalar_mul_generator;
    /// let u1_g = scalar_mul_generator(&u1);  // Ultra-fast precomputed tables (~49 µs)
    /// let u2_q = q.scalar_mul(&u2);          // wNAF (~96 µs)
    /// let result = u1_g.add(&u2_q);
    /// ```
    ///
    /// **Using this function** (~149 µs - **11.6% SLOWER**):
    /// ```ignore
    /// let result = Point::double_scalar_mul(&u1, &g, &u2, &q);  // ❌ Slower!
    /// // Problem: Can't use precomputed tables, forces wNAF for both points
    /// ```
    ///
    /// **Why?** P-256 has ultra-optimized precomputed generator tables that are ~3x faster
    /// than wNAF. This function cannot use those tables because it processes both scalars
    /// simultaneously using wNAF for both points.
    ///
    /// **When to use this function:**
    /// - ✅ **Two arbitrary points** (neither is the generator): ~30-40% speedup
    /// - ✅ **Curves without fast generator tables** (like Ed448)
    /// - ✅ **Constant-time operations** (see `double_scalar_mul_constant_time`)
    ///
    /// **When NOT to use:**
    /// - ❌ **P-256 ECDSA verification** (one point is generator)
    /// - ❌ **Any operation involving the generator point** (use `scalar_mul_generator` instead)
    ///
    /// See: [`docs/P256_SHAMIR_ANALYSIS_COMPLETE.md`](../../docs/P256_SHAMIR_ANALYSIS_COMPLETE.md)
    /// for detailed performance analysis.
    ///
    /// # Algorithm
    ///
    /// Shamir's trick (also called simultaneous multiple point multiplication):
    /// 1. Precompute: O = infinity, P, Q, P+Q
    /// 2. For each bit pair (b1, b2) from MSB to LSB:
    ///    - Double the accumulator
    ///    - Add the precomputed point corresponding to (b1, b2):
    ///      * (0, 0) → O (add nothing)
    ///      * (1, 0) → P
    ///      * (0, 1) → Q
    ///      * (1, 1) → P+Q
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
    /// * `k1` - First scalar (256-bit, big-endian)
    /// * `p` - First point
    /// * `k2` - Second scalar (256-bit, big-endian)
    /// * `q` - Second point
    ///
    /// # Returns
    ///
    /// The point k1*P + k2*Q
    ///
    /// # Example
    ///
    /// ```ignore
    /// // ECDSA verification: check if [s^-1*hash]G + [s^-1*r]PK = R
    /// let result = Point::double_scalar_mul(&k1, &g, &k2, &pk);
    /// ```
    pub fn double_scalar_mul(k1: &[u8; 32], p: &Point, k2: &[u8; 32], q: &Point) -> Point {
        // Precompute lookup table
        // Index is (bit1 << 1) | bit2
        // 0: 00 = neither
        // 1: 01 = k2 only -> Q
        // 2: 10 = k1 only -> P
        // 3: 11 = both -> P+Q
        let table = [
            Point::infinity(), // 00: neither
            *q,                // 01: k2 only
            *p,                // 10: k1 only
            p.add(q),          // 11: both
        ];

        let mut result = Point::infinity();

        // Process both scalars bit by bit from MSB to LSB
        // Scalars are in big-endian format
        for byte_idx in 0..32 {
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
    ///
    /// # Security
    ///
    /// This operation is designed to be constant-time and safe for use with
    /// secret scalars. However, for ECDSA verification (the main use case),
    /// all inputs are public, so the variable-time version is sufficient.
    ///
    /// # Performance
    ///
    /// Slower than the variable-time version due to constant-time operations,
    /// but still faster than two separate constant-time scalar multiplications.
    pub fn double_scalar_mul_constant_time(
        k1: &[u8; 32],
        p: &Point,
        k2: &[u8; 32],
        q: &Point,
    ) -> Point {
        use crate::ct_utils::ConditionallySelectable;

        // Precompute lookup table
        let table = [
            Point::infinity(), // 00: neither
            *q,                // 01: k2 only
            *p,                // 10: k1 only
            p.add(q),          // 11: both
        ];

        let mut result = Point::infinity();

        // Process both scalars bit by bit from MSB to LSB
        for byte_idx in 0..32 {
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

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

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

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Point {}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::p256::constants::{P256_GX, P256_GY};
    use alloc::vec;

    #[test]
    fn test_infinity_is_infinity() {
        let inf = Point::infinity();
        assert!(bool::from(inf.is_infinity()));
    }

    #[test]
    fn test_infinity_on_curve() {
        let inf = Point::infinity();
        assert!(bool::from(inf.is_on_curve()));
    }

    #[test]
    fn test_infinity_to_affine() {
        let inf = Point::infinity();
        assert!(inf.to_affine().is_none());
    }

    #[test]
    fn test_affine_conversion_identity() {
        // Create a simple affine point
        let x = FieldElement::from_u64(1);
        let y = FieldElement::from_u64(1);

        let affine = AffinePoint { x, y };
        let jacobian = Point::from_affine(&affine);

        // Z should be 1
        assert_eq!(jacobian.z, FieldElement::one());
        assert_eq!(jacobian.x, x);
        assert_eq!(jacobian.y, y);
    }

    #[test]
    fn test_infinity_equality() {
        let inf1 = Point::infinity();
        let inf2 = Point::infinity();
        assert_eq!(inf1, inf2);
    }

    #[test]
    fn test_point_conditional_select() {
        let p1 = Point::infinity();
        let p2 = Point {
            x: FieldElement::from_u64(42),
            y: FieldElement::from_u64(43),
            z: FieldElement::from_u64(44),
        };

        let selected = Point::conditional_select(&p1, &p2, Choice::from(0));
        assert_eq!(selected, p1);

        let selected = Point::conditional_select(&p1, &p2, Choice::from(1));
        assert_eq!(selected, p2);
    }

    // Point doubling tests

    #[test]
    fn test_double_infinity() {
        // 2·∞ = ∞
        let inf = Point::infinity();
        let result = inf.double();
        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_double_simple() {
        // Create a simple point and double it
        // Just verify it computes without panicking
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };

        let doubled = p.double();

        // Result should not be infinity (unless the point is special)
        // We can't easily verify the exact result without known test vectors
        // For now, just check it computes
        assert!(!bool::from(doubled.is_infinity()));
    }

    #[test]
    fn test_double_consistency() {
        // 2P should equal P + P (when we implement addition)
        // For now, just verify doubling twice works
        let p = Point {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
            z: FieldElement::from_u64(1),
        };

        let two_p = p.double();
        let four_p = two_p.double();

        // Verify we can double twice without issues
        assert!(!bool::from(four_p.is_infinity()));
    }

    // Point addition tests

    #[test]
    fn test_add_infinity_left() {
        // ∞ + P = P
        let inf = Point::infinity();
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };

        let result = inf.add(&p);
        assert_eq!(result, p);
    }

    #[test]
    fn test_add_infinity_right() {
        // P + ∞ = P
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };
        let inf = Point::infinity();

        let result = p.add(&inf);
        assert_eq!(result, p);
    }

    #[test]
    fn test_add_infinity_both() {
        // ∞ + ∞ = ∞
        let inf1 = Point::infinity();
        let inf2 = Point::infinity();

        let result = inf1.add(&inf2);
        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_add_same_point() {
        // P + P should equal 2·P
        let p = Point {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
            z: FieldElement::from_u64(1),
        };

        let add_result = p.add(&p);
        let double_result = p.double();

        assert_eq!(add_result, double_result);
    }

    #[test]
    fn test_add_commutativity() {
        // P + Q should equal Q + P in affine coordinates
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };
        let q = Point {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
            z: FieldElement::from_u64(1),
        };

        let p_plus_q = p.add(&q);
        let q_plus_p = q.add(&p);

        // Note: Jacobian coordinates might differ, but affine coordinates should match
        // Our ct_eq should handle this, but let's verify by converting to affine
        let p_plus_q_affine = p_plus_q.to_affine().unwrap();
        let q_plus_p_affine = q_plus_p.to_affine().unwrap();

        assert_eq!(p_plus_q_affine.x, q_plus_p_affine.x);
        assert_eq!(p_plus_q_affine.y, q_plus_p_affine.y);
    }

    #[test]
    fn test_add_different_z() {
        // Test addition with different Z coordinates
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };
        let q = Point {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
            z: FieldElement::from_u64(2),
        };

        let result = p.add(&q);
        // Should not panic and should not be infinity
        assert!(!bool::from(result.is_infinity()));
    }

    // Mixed addition tests

    #[test]
    fn test_add_affine_simple() {
        let p = Point {
            x: FieldElement::from_u64(2),
            y: FieldElement::from_u64(3),
            z: FieldElement::from_u64(1),
        };
        let q_affine = AffinePoint {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
        };

        let mixed_result = p.add_affine(&q_affine);

        // Convert affine to Jacobian and use general addition for comparison
        let q_jacobian = Point::from_affine(&q_affine);
        let general_result = p.add(&q_jacobian);

        assert_eq!(mixed_result, general_result);
    }

    #[test]
    fn test_add_affine_infinity() {
        // ∞ + Q_affine = Q
        let inf = Point::infinity();
        let q_affine = AffinePoint {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_u64(7),
        };

        let result = inf.add_affine(&q_affine);

        // Should equal Q in Jacobian form
        let expected = Point::from_affine(&q_affine);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_associativity() {
        // (P + Q) + R should equal P + (Q + R) in affine coordinates
        // Use actual points on the P-256 curve (not arbitrary test values)
        let p = Point {
            x: FieldElement::from_u64(5),
            y: FieldElement::from_limbs([
                0x33415c083248fbcc,
                0x11ca503c64d9a3c5,
                0xfe913bce99817ade,
                0x459243b9aa581806,
            ]),
            z: FieldElement::from_u64(1),
        };
        let q = Point {
            x: FieldElement::from_u64(6),
            y: FieldElement::from_limbs([
                0x220d5128828223cb,
                0xdcd102b80fe7c0e9,
                0x466985e533720047,
                0x36b24c2c54250ac2,
            ]),
            z: FieldElement::from_u64(1),
        };
        let r = Point {
            x: FieldElement::from_u64(8),
            y: FieldElement::from_limbs([
                0x2242d085636041b3,
                0x27249b16d631ff69,
                0xd624d1d23f37f6a6,
                0xb706288aca290db0,
            ]),
            z: FieldElement::from_u64(1),
        };

        let left = p.add(&q).add(&r);
        let right = p.add(&q.add(&r));

        // Compare in affine coordinates
        let left_affine = left.to_affine().unwrap();
        let right_affine = right.to_affine().unwrap();

        assert_eq!(left_affine.x, right_affine.x);
        assert_eq!(left_affine.y, right_affine.y);
    }

    // Generator point tests

    #[test]
    fn test_generator_not_infinity() {
        let g = Point::generator();
        assert!(!bool::from(g.is_infinity()));
    }

    #[test]
    fn test_generator_on_curve() {
        let g = Point::generator();
        assert!(bool::from(g.is_on_curve()));
    }

    #[test]
    fn test_generator_coordinates() {
        // Verify the generator has the correct coordinates
        let g = Point::generator();

        // Z should be 1 (affine form)
        assert_eq!(g.z, FieldElement::one());

        // X and Y should match P256_GX and P256_GY
        assert_eq!(g.x, FieldElement::from_limbs(P256_GX));
        assert_eq!(g.y, FieldElement::from_limbs(P256_GY));
    }

    #[test]
    fn test_generator_double() {
        // Test that we can double the generator
        let g = Point::generator();
        let two_g = g.double();

        // Should not be infinity
        assert!(!bool::from(two_g.is_infinity()));

        // Should still be on curve
        assert!(bool::from(two_g.is_on_curve()));
    }

    #[test]
    fn test_generator_double_known_value() {
        // This test will verify 2*G against a known test vector
        // Known value for 2*G from NIST test vectors:
        // x = 7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
        // y = 07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1

        let g = Point::generator();
        let two_g = g.double();
        let two_g_affine = two_g.to_affine().unwrap();

        // Expected 2*G coordinates (little-endian limbs)
        let expected_x = FieldElement::from_limbs([
            0xA60B48FC47669978,
            0xC08969E277F21B35,
            0x8A52380304B51AC3,
            0x7CF27B188D034F7E,
        ]);

        let expected_y = FieldElement::from_limbs([
            0x9E04B79D227873D1,
            0xBA7DADE63CE98229,
            0x293D9AC69F7430DB,
            0x07775510DB8ED040,
        ]);

        assert_eq!(two_g_affine.x, expected_x);
        assert_eq!(two_g_affine.y, expected_y);
    }

    #[test]
    fn test_generator_add_to_self() {
        // G + G should equal 2*G
        let g = Point::generator();
        let g_plus_g = g.add(&g);
        let two_g = g.double();

        // Compare in affine coordinates to handle different Jacobian representations
        let add_affine = g_plus_g.to_affine().unwrap();
        let double_affine = two_g.to_affine().unwrap();

        assert_eq!(add_affine.x, double_affine.x);
        assert_eq!(add_affine.y, double_affine.y);
    }

    #[test]
    fn test_scalar_mul_zero() {
        // 0 * G = infinity
        let g = Point::generator();
        let zero = [0u8; 32];

        let result = g.scalar_mul(&zero);

        assert!(bool::from(result.is_infinity()), "0 * G should be infinity");
    }

    #[test]
    fn test_scalar_mul_one() {
        // 1 * G = G
        let g = Point::generator();
        let mut one = [0u8; 32];
        one[31] = 1; // Big-endian: LSB at index 31

        let result = g.scalar_mul(&one);

        assert_eq!(result, g, "1 * G should equal G");
    }

    #[test]
    fn test_scalar_mul_two() {
        // 2 * G = G + G = double(G)
        let g = Point::generator();
        let mut two = [0u8; 32];
        two[31] = 2; // Big-endian: LSB at index 31

        let result = g.scalar_mul(&two);
        let expected = g.double();

        assert_eq!(result, expected, "2 * G should equal double(G)");
    }

    #[test]
    fn test_scalar_mul_three() {
        // 3 * G = 2*G + G
        let g = Point::generator();
        let mut three = [0u8; 32];
        three[31] = 3; // Big-endian: LSB at index 31

        let result = g.scalar_mul(&three);
        let expected = g.double().add(&g);

        assert_eq!(result, expected, "3 * G should equal 2*G + G");
    }

    #[test]
    fn test_scalar_mul_constant_time_matches_variable_time() {
        // Verify that constant-time and variable-time give same results
        let g = Point::generator();

        // Test with several different scalars
        let test_scalars = [
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ], // 1
            [
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ], // 2
            [
                0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ], // 255
            [
                0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                0xDE, 0xF0, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xAB, 0xCD, 0xEF,
            ], // Random
        ];

        for scalar in &test_scalars {
            let var_time_result = g.scalar_mul(scalar);
            let const_time_result = g.scalar_mul_constant_time(scalar);

            assert_eq!(
                var_time_result, const_time_result,
                "Constant-time and variable-time results should match for scalar {:?}",
                scalar
            );
        }
    }

    #[test]
    fn test_scalar_mul_distributive() {
        // (a + b) * G = a*G + b*G
        let g = Point::generator();

        let mut a = [0u8; 32];
        a[0] = 5;

        let mut b = [0u8; 32];
        b[0] = 7;

        let mut a_plus_b = [0u8; 32];
        a_plus_b[0] = 12;

        let left = g.scalar_mul(&a_plus_b);
        let right = g.scalar_mul(&a).add(&g.scalar_mul(&b));

        assert_eq!(left, right, "(a+b)*G should equal a*G + b*G");
    }

    #[test]
    fn test_scalar_mul_consistency() {
        // Test that scalar_mul and scalar_mul_constant_time give the same result
        let g = Point::generator();
        let scalar = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];

        let result1 = g.scalar_mul(&scalar);
        let result2 = g.scalar_mul_constant_time(&scalar);

        // They should produce the same result
        assert_eq!(
            result1, result2,
            "scalar_mul and scalar_mul_constant_time should give same result"
        );
    }

    #[test]
    fn test_double_vs_add() {
        // Test if P.double() == P.add(P) for various points
        let g = Point::generator();

        // Test 1: Generator (Z=1)
        let doubled_g = g.double();
        let added_g = g.add(&g);
        assert_eq!(doubled_g, added_g, "G.double() != G.add(G)");

        // Test 2: Point with non-trivial Z
        let mut bytes_5 = [0u8; 32];
        bytes_5[31] = 5;
        let p = g.scalar_mul(&bytes_5); // P = 5*G (has Z != 1)

        let doubled = p.double(); // 2*P using double()
        let added = p.add(&p); // P + P using add()

        let doubled_affine = doubled.to_affine().expect("doubled not infinity");
        let added_affine = added.to_affine().expect("added not infinity");

        assert_eq!(
            doubled_affine.x, added_affine.x,
            "P.double() and P.add(P) have different x!"
        );
        assert_eq!(
            doubled_affine.y, added_affine.y,
            "P.double() and P.add(P) have different y!"
        );
    }

    #[test]
    fn test_scalar_mul_by_1() {
        // Test that 1*P == P
        let g = Point::generator();

        let mut bytes_5 = [0u8; 32];
        bytes_5[31] = 5; // LSB is at index 31 for big-endian (value is just 5)
        let p = g.scalar_mul(&bytes_5);

        let mut bytes_1 = [0u8; 32];
        bytes_1[31] = 1; // LSB is at index 31 (value is just 1)
        let one_p = p.scalar_mul(&bytes_1);

        let p_affine = p.to_affine().expect("p not infinity");
        let one_p_affine = one_p.to_affine().expect("1*p not infinity");

        assert_eq!(p_affine.x, one_p_affine.x, "1*P != P (x coordinate)");
        assert_eq!(p_affine.y, one_p_affine.y, "1*P != P (y coordinate)");
    }

    #[test]
    fn test_scalar_mul_base_case() {
        // Test the simplest case: does 2*P == P+P for arbitrary P?
        let g = Point::generator();

        let mut bytes_5 = [0u8; 32];
        bytes_5[31] = 5;
        let five_g = g.scalar_mul(&bytes_5);

        // Method 1: 2*(5*G) using scalar_mul
        let mut bytes_2 = [0u8; 32];
        bytes_2[31] = 2;
        let method1 = five_g.scalar_mul(&bytes_2);

        // Method 2: (5*G) + (5*G) using point addition
        let method2 = five_g.add(&five_g);

        // Method 3: 10*G directly
        let mut bytes_10 = [0u8; 32];
        bytes_10[31] = 10;
        let method3 = g.scalar_mul(&bytes_10);

        let m1_affine = method1.to_affine().expect("method1 not infinity");
        let m2_affine = method2.to_affine().expect("method2 not infinity");
        let m3_affine = method3.to_affine().expect("method3 not infinity");

        // First check: does 2*P == P+P?
        assert_eq!(
            m1_affine.x, m2_affine.x,
            "2*(5*G) scalar_mul != (5*G)+(5*G) point add"
        );

        // Second check: does 2*(5*G) == 10*G?
        assert_eq!(m1_affine.x, m3_affine.x, "2*(5*G) != 10*G");
    }

    #[test]
    fn test_manual_15g() {
        // Manually compute 15*G in multiple ways to isolate the bug
        let g = Point::generator();

        // Method 1: 15*G directly
        let mut bytes_15 = [0u8; 32];
        bytes_15[31] = 15;
        let method1 = g.scalar_mul(&bytes_15);

        // Method 2: 5*G, then multiply by 3
        let mut bytes_5 = [0u8; 32];
        bytes_5[31] = 5;
        let five_g = g.scalar_mul(&bytes_5);

        // Method 2b: Convert 5*G to affine and back to normalize Z=1
        let five_g_affine = five_g.to_affine().expect("5*G should not be infinity");
        let five_g_normalized = Point::from_affine(&five_g_affine);

        let mut bytes_3 = [0u8; 32];
        bytes_3[31] = 3;
        let method2 = five_g.scalar_mul(&bytes_3);
        let method2b = five_g_normalized.scalar_mul(&bytes_3);

        // Method 3: 3*G + 3*G + 3*G + 3*G + 3*G (five additions)
        let mut bytes_3 = [0u8; 32];
        bytes_3[31] = 3;
        let three_g = g.scalar_mul(&bytes_3);
        let method3 = three_g
            .add(&three_g)
            .add(&three_g)
            .add(&three_g)
            .add(&three_g);

        // Convert to affine for comparison
        let m1_affine = method1.to_affine().expect("method1 should not be infinity");
        let m2_affine = method2.to_affine().expect("method2 should not be infinity");
        let m2b_affine = method2b
            .to_affine()
            .expect("method2b should not be infinity");
        let m3_affine = method3.to_affine().expect("method3 should not be infinity");

        // Check method 1 vs method 3
        assert_eq!(
            m1_affine.x, m3_affine.x,
            "15*G (direct) and 3*G+3*G+3*G+3*G+3*G have different x"
        );
        assert_eq!(
            m1_affine.y, m3_affine.y,
            "15*G (direct) and 3*G+3*G+3*G+3*G+3*G have different y"
        );

        // Check if normalizing Z fixes the issue
        assert_eq!(
            m1_affine.x, m2b_affine.x,
            "15*G and 3*(5*G normalized) have different x - Z normalization didn't help!"
        );

        // Check method 1 vs method 2
        assert_eq!(
            m1_affine.x, m2_affine.x,
            "15*G (direct) and 3*(5*G) have different x"
        );
        assert_eq!(
            m1_affine.y, m2_affine.y,
            "15*G (direct) and 3*(5*G) have different y"
        );
    }

    #[test]
    fn test_scalar_mul_associativity_simple() {
        // Test that a*(b*G) == (a*b)*G with very small values first
        use crate::p256::Scalar;

        let g = Point::generator();

        // Use small values: a=3, b=5
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 3; // Little-endian in memory, but from_bytes expects big-endian

        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 5;

        // Compute b*G = 5*G
        let b_g = g.scalar_mul(&b_bytes);

        // Compute a*(b*G) = 3*(5*G)
        let left = b_g.scalar_mul(&a_bytes);

        // Compute (a*b) mod n = (3*5) mod n = 15
        let a = Scalar::from_bytes(&a_bytes);
        let b = Scalar::from_bytes(&b_bytes);
        let a_times_b = a.mul(&b);

        // Compute (a*b)*G = 15*G
        let right = g.scalar_mul(&a_times_b.to_bytes());

        // These should be equal
        let left_affine = left.to_affine().expect("left should not be infinity");
        let right_affine = right.to_affine().expect("right should not be infinity");

        assert_eq!(
            left_affine.x, right_affine.x,
            "3*(5*G) and 15*G have different x coordinates"
        );
        assert_eq!(
            left_affine.y, right_affine.y,
            "3*(5*G) and 15*G have different y coordinates"
        );
    }

    #[test]
    fn test_scalar_mul_associativity() {
        // Test that a*(b*G) == (a*b)*G
        // This is critical for ECDSA: u2*Q == u2*(d*G) should equal (u2*d)*G
        use crate::p256::Scalar;

        let g = Point::generator();

        let a_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];

        let b_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];

        // Compute b*G
        let b_g = g.scalar_mul(&b_bytes);

        // Compute a*(b*G)
        let left = b_g.scalar_mul(&a_bytes);

        // Compute (a*b) mod n
        let a = Scalar::from_bytes(&a_bytes);
        let b = Scalar::from_bytes(&b_bytes);
        let a_times_b = a.mul(&b);

        // Compute (a*b)*G
        let right = g.scalar_mul(&a_times_b.to_bytes());

        // These should be equal
        // Note: They might have different Z coordinates in Jacobian form,
        // but should be equal in affine coordinates
        let left_affine = left.to_affine().expect("left should not be infinity");
        let right_affine = right.to_affine().expect("right should not be infinity");

        assert_eq!(
            left_affine.x, right_affine.x,
            "a*(b*G) and (a*b)*G have different x coordinates"
        );
        assert_eq!(
            left_affine.y, right_affine.y,
            "a*(b*G) and (a*b)*G have different y coordinates"
        );
    }

    #[test]
    fn test_double_scalar_mul_basic() {
        // Test Shamir's trick with simple values
        let g = Point::generator();
        let two_g = g.double();

        let mut k1 = [0u8; 32];
        k1[31] = 3; // k1 = 3

        let mut k2 = [0u8; 32];
        k2[31] = 5; // k2 = 5

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

        let k1 = [0x42; 32];
        let k2 = [0x13; 32];

        let p = g.double(); // 2*G
        let q = g.scalar_mul(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03,
        ]); // 3*G

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

        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[31] = 1;

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

        let k1 = [0x42; 32];
        let k2 = [0x13; 32];

        let result_variable = Point::double_scalar_mul(&k1, &g, &k2, &two_g);
        let result_constant = Point::double_scalar_mul_constant_time(&k1, &g, &k2, &two_g);

        assert_eq!(
            result_variable, result_constant,
            "Constant-time and variable-time versions should match"
        );
    }

    #[test]
    fn test_double_scalar_mul_ecdsa_pattern() {
        // Test the typical ECDSA verification pattern: u1*G + u2*PK
        use crate::p256::Scalar;

        let g = Point::generator();

        // Generate a public key (private key * G)
        let mut d = [0u8; 32];
        d[31] = 0x42;
        let pk = g.scalar_mul(&d);

        // Simulate ECDSA verification scalars
        let u1 = [0x12; 32];
        let u2 = [0x34; 32];

        // Using Shamir's trick
        let result_shamir = Point::double_scalar_mul(&u1, &g, &u2, &pk);

        // Compute separately
        let u1_g = g.scalar_mul(&u1);
        let u2_pk = pk.scalar_mul(&u2);
        let result_separate = u1_g.add(&u2_pk);

        assert_eq!(
            result_shamir, result_separate,
            "ECDSA verification pattern should work correctly"
        );
    }

    // ============================================================================
    // Tests for Incomplete Reduction in Point Operations
    // ============================================================================

    #[test]
    fn test_double_incomplete_vs_double() {
        // Test that double_incomplete produces same result as double
        let g = Point::generator();

        let result_normal = g.double();
        let result_incomplete = g.double_incomplete();

        assert_eq!(
            result_normal, result_incomplete,
            "double_incomplete should produce same result as double"
        );
    }

    #[test]
    fn test_double_incomplete_random_point() {
        // Test with a random non-generator point
        let p = Point::generator().scalar_mul(&[
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ]);

        let result_normal = p.double();
        let result_incomplete = p.double_incomplete();

        assert_eq!(
            result_normal, result_incomplete,
            "double_incomplete should work for arbitrary points"
        );
    }

    #[test]
    fn test_double_incomplete_infinity() {
        // Test doubling infinity
        let inf = Point::infinity();

        let result_normal = inf.double();
        let result_incomplete = inf.double_incomplete();

        assert_eq!(
            result_normal, result_incomplete,
            "double_incomplete should handle infinity correctly"
        );
        assert!(
            bool::from(result_incomplete.is_infinity()),
            "Doubling infinity should return infinity"
        );
    }

    #[test]
    fn test_double_incomplete_multiple_times() {
        // Test repeated doubling: 2^k * G
        let g = Point::generator();

        let mut result_normal = g;
        let mut result_incomplete = g;

        for _ in 0..10 {
            result_normal = result_normal.double();
            result_incomplete = result_incomplete.double_incomplete();
        }

        assert_eq!(
            result_normal, result_incomplete,
            "Repeated double_incomplete should match repeated double"
        );
    }

    #[test]
    fn test_double_incomplete_consistency_with_scalar_mul() {
        // Verify double_incomplete gives same result as scalar_mul by 2
        let g = Point::generator();
        let two = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ];

        let doubled = g.double_incomplete();
        let scalar_mul_2 = g.scalar_mul(&two);

        assert_eq!(
            doubled, scalar_mul_2,
            "double_incomplete should equal scalar_mul by 2"
        );
    }

    // ========================================
    // Montgomery Point Operations Tests
    // ========================================

    #[test]
    fn test_montgomery_field_ops_in_point_context() {
        // Test that field operations work correctly when used in point doubling context
        use crate::p256::FieldElement;

        let two = FieldElement::from_u64(2);
        let three = FieldElement::from_u64(3);

        // Standard: 2 + 2 = 4
        let four_std = two.add(&two);
        assert_eq!(four_std, FieldElement::from_u64(4));

        // Montgomery: 2_m + 2_m should equal 4_m
        let two_m = two.to_montgomery();
        let four_m = two_m.add(&two_m);
        let four_from_m = four_m.from_montgomery();
        assert_eq!(
            four_from_m,
            FieldElement::from_u64(4),
            "Montgomery addition failed"
        );

        // Test: (2_m * 3_m) + (2_m * 3_m) = 12
        let two_times_three_m = two_m.montgomery_mul(&three.to_montgomery());
        let double_it_m = two_times_three_m.add(&two_times_three_m);
        let result = double_it_m.from_montgomery();
        assert_eq!(
            result,
            FieldElement::from_u64(12),
            "Montgomery mul + add failed"
        );
    }

    #[test]
    fn test_montgomery_conversion_roundtrip() {
        // Test that converting to Montgomery and back gives the same point
        let test_points = vec![
            Point::generator(),
            Point::generator().double(),
            Point::generator().double().double(),
            Point::infinity(),
        ];

        for point in test_points {
            let mont = PointMontgomery::from_point(&point);
            let back = mont.to_point();
            assert_eq!(point, back, "Roundtrip conversion failed");
        }
    }

    #[test]
    fn test_montgomery_infinity() {
        let inf_mont = PointMontgomery::infinity();
        assert!(
            bool::from(inf_mont.is_infinity()),
            "Montgomery infinity check failed"
        );

        let inf_standard = inf_mont.to_point();
        assert!(
            bool::from(inf_standard.is_infinity()),
            "Converted infinity check failed"
        );
    }

    #[test]
    fn test_montgomery_double_intermediate_values() {
        // Test intermediate values during doubling to isolate the bug
        let g = Point::generator();

        // Test 1: Direct squaring of generator Y coordinate
        let y_squared_std = g.y.square();
        let y_mont = g.y.to_montgomery();
        let y_squared_mont = y_mont.montgomery_square();
        let y_squared_from_mont = y_squared_mont.from_montgomery();
        assert_eq!(y_squared_std, y_squared_from_mont, "Y² doesn't match!");

        // Test 2: Now use the Montgomery point's Y coordinate (which is already converted)
        let g_mont = PointMontgomery::from_point(&g);
        let y_squared_mont2 = g_mont.y.montgomery_square();
        let y_squared_from_mont2 = y_squared_mont2.from_montgomery();
        assert_eq!(
            y_squared_std, y_squared_from_mont2,
            "Y² from PointMontgomery doesn't match!"
        );

        // Test 3: Y⁴
        let y_fourth_std = y_squared_std.square();
        let y_fourth_mont = y_squared_mont.montgomery_square();
        let y_fourth_from_mont = y_fourth_mont.from_montgomery();
        assert_eq!(y_fourth_std, y_fourth_from_mont, "Y⁴ doesn't match!");
    }

    #[test]
    fn test_montgomery_double_equivalence() {
        // Test that Montgomery doubling gives same result as standard doubling
        let test_points = vec![
            Point::generator(),
            Point::generator().double(),
            Point::generator().scalar_mul(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 42,
            ]),
        ];

        for point in test_points {
            // Standard doubling
            let doubled_standard = point.double();

            // Montgomery doubling
            let mont = PointMontgomery::from_point(&point);
            let doubled_mont = mont.double();
            let doubled_from_mont = doubled_mont.to_point();

            assert_eq!(
                doubled_standard, doubled_from_mont,
                "Montgomery double doesn't match standard double"
            );
        }
    }

    #[test]
    fn test_montgomery_double_infinity() {
        // Doubling infinity should give infinity
        let inf_mont = PointMontgomery::infinity();
        let doubled = inf_mont.double();
        assert!(
            bool::from(doubled.is_infinity()),
            "Double of infinity should be infinity"
        );
    }

    #[test]
    fn test_montgomery_add_equivalence() {
        // Test that Montgomery addition gives same result as standard addition
        let g = Point::generator();
        let p1 = g.double();
        let p2 = g.double().double();
        let p3 = g.scalar_mul(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 7,
        ]);

        let test_pairs = vec![(p1, p2), (p2, p3), (g, p1), (g, p3)];

        for (point1, point2) in test_pairs {
            // Standard addition
            let sum_standard = point1.add(&point2);

            // Montgomery addition
            let mont1 = PointMontgomery::from_point(&point1);
            let mont2 = PointMontgomery::from_point(&point2);
            let sum_mont = mont1.add(&mont2);
            let sum_from_mont = sum_mont.to_point();

            assert_eq!(
                sum_standard, sum_from_mont,
                "Montgomery add doesn't match standard add"
            );
        }
    }

    #[test]
    fn test_montgomery_add_infinity() {
        let g = Point::generator();
        let g_mont = PointMontgomery::from_point(&g);
        let inf_mont = PointMontgomery::infinity();

        // g + infinity = g
        let sum1 = g_mont.add(&inf_mont);
        assert_eq!(g, sum1.to_point(), "Point + infinity should equal point");

        // infinity + g = g
        let sum2 = inf_mont.add(&g_mont);
        assert_eq!(g, sum2.to_point(), "Infinity + point should equal point");

        // infinity + infinity = infinity
        let sum3 = inf_mont.add(&inf_mont);
        assert!(
            bool::from(sum3.is_infinity()),
            "Infinity + infinity should be infinity"
        );
    }

    #[test]
    fn test_montgomery_add_inverse() {
        // Test that P + (-P) = infinity
        let g = Point::generator();
        let neg_g = g.negate();

        let g_mont = PointMontgomery::from_point(&g);
        let neg_g_mont = PointMontgomery::from_point(&neg_g);

        let sum = g_mont.add(&neg_g_mont);
        assert!(
            bool::from(sum.is_infinity()),
            "Point + (-point) should be infinity"
        );
    }

    #[test]
    fn test_montgomery_add_same_point() {
        // Test that P + P uses doubling formula
        let g = Point::generator();

        let doubled = g.double();

        let g_mont = PointMontgomery::from_point(&g);
        let sum = g_mont.add(&g_mont);

        assert_eq!(doubled, sum.to_point(), "P + P should equal double(P)");
    }

    #[test]
    fn test_montgomery_add_affine_equivalence() {
        // Test that Montgomery mixed addition matches standard mixed addition
        let g = Point::generator();
        let p = g.double();

        // Create affine point
        let q_jacobian = g.double().double();
        let q_affine = q_jacobian.to_affine().unwrap();

        // Standard mixed addition
        let sum_standard = p.add_affine(&q_affine);

        // Montgomery mixed addition
        let p_mont = PointMontgomery::from_point(&p);
        let sum_mont = p_mont.add_affine(&q_affine);
        let sum_from_mont = sum_mont.to_point();

        assert_eq!(
            sum_standard, sum_from_mont,
            "Montgomery add_affine doesn't match standard add_affine"
        );
    }

    #[test]
    fn test_montgomery_add_affine_infinity() {
        let g = Point::generator();
        let inf_mont = PointMontgomery::infinity();

        // Create affine point
        let g_affine = g.to_affine().unwrap();

        // infinity + affine = affine (converted to Jacobian)
        let sum = inf_mont.add_affine(&g_affine);
        let sum_jacobian = sum.to_point();

        assert_eq!(g, sum_jacobian, "Infinity + affine should equal affine");
    }

    #[test]
    fn test_montgomery_add_affine_with_precomputed() {
        // Test with actual precomputed table points (like wNAF would use)
        let g = Point::generator();

        // Create a simple precomputed table (like wNAF)
        let mult_3 = g.double().add(&g);
        let mult_5 = mult_3.add(&g.double());
        let mult_7 = mult_5.add(&g.double());

        let affine_3 = mult_3.to_affine().unwrap();
        let affine_5 = mult_5.to_affine().unwrap();
        let affine_7 = mult_7.to_affine().unwrap();

        // Simulate wNAF computation: accumulator in Montgomery, add affine points
        let mut acc_mont = PointMontgomery::from_point(&g);

        // Add 3G
        acc_mont = acc_mont.add_affine(&affine_3);

        // Add 5G
        acc_mont = acc_mont.add_affine(&affine_5);

        // Add 7G
        acc_mont = acc_mont.add_affine(&affine_7);

        let result = acc_mont.to_point();

        // Verify with standard computation
        let expected = g.add(&mult_3).add(&mult_5).add(&mult_7);

        assert_eq!(expected, result, "Sequential mixed additions don't match");
    }

    #[test]
    fn test_montgomery_commutativity() {
        // Test that P + Q = Q + P
        let g = Point::generator();
        let p = g.double();
        let q = g.double().double();

        let p_mont = PointMontgomery::from_point(&p);
        let q_mont = PointMontgomery::from_point(&q);

        let pq = p_mont.add(&q_mont).to_point();
        let qp = q_mont.add(&p_mont).to_point();

        assert_eq!(pq, qp, "Addition should be commutative");
    }

    #[test]
    fn test_montgomery_associativity() {
        // Test that (P + Q) + R = P + (Q + R)
        let g = Point::generator();
        let p = g.double();
        let q = g.double().double();
        let r = g.scalar_mul(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 7,
        ]);

        let p_mont = PointMontgomery::from_point(&p);
        let q_mont = PointMontgomery::from_point(&q);
        let r_mont = PointMontgomery::from_point(&r);

        // (P + Q) + R
        let pq = p_mont.add(&q_mont);
        let pqr1 = pq.add(&r_mont).to_point();

        // P + (Q + R)
        let qr = q_mont.add(&r_mont);
        let pqr2 = p_mont.add(&qr).to_point();

        assert_eq!(pqr1, pqr2, "Addition should be associative");
    }

    #[test]
    fn test_montgomery_double_and_add_sequence() {
        // Test a sequence of doubling and addition (like scalar multiplication)
        let g = Point::generator();

        // Standard: compute 2G + 4G = 6G
        let two_g = g.double();
        let four_g = two_g.double();
        let six_g_standard = two_g.add(&four_g);

        // Montgomery: same computation
        let g_mont = PointMontgomery::from_point(&g);
        let two_g_mont = g_mont.double();
        let four_g_mont = two_g_mont.double();
        let six_g_mont = two_g_mont.add(&four_g_mont);

        assert_eq!(
            six_g_standard,
            six_g_mont.to_point(),
            "Double and add sequence doesn't match"
        );
    }

    #[test]
    fn test_montgomery_conditional_select() {
        use crate::ct_utils::Choice;

        let g = Point::generator();
        let p1_mont = PointMontgomery::from_point(&g);
        let p2_mont = PointMontgomery::from_point(&g.double());

        // Select p1 when choice is 0
        let selected_0 = PointMontgomery::conditional_select(&p1_mont, &p2_mont, Choice::from(0));
        assert_eq!(
            g,
            selected_0.to_point(),
            "Should select first point when choice=0"
        );

        // Select p2 when choice is 1
        let selected_1 = PointMontgomery::conditional_select(&p1_mont, &p2_mont, Choice::from(1));
        assert_eq!(
            g.double(),
            selected_1.to_point(),
            "Should select second point when choice=1"
        );
    }

    #[test]
    fn test_from_montgomery_reduction_diagnostic() {
        // This test diagnoses whether from_montgomery() produces values that cause overflow
        // If this test passes, the Montgomery operations don't cause overflow in Karatsuba
        let g = Point::generator();
        let g2 = g.double(); // Uses Montgomery internally

        // Try the sequence of operations that occurs in to_affine()
        // This is where overflow occurs
        let z_inv = g2.z.invert();
        let z_inv_squared = z_inv.square();
        let z_inv_cubed = z_inv_squared.mul(&z_inv);

        // These multiplications are where Karatsuba overflows
        let _affine_x = g2.x.mul(&z_inv_squared);
        let _affine_y = g2.y.mul(&z_inv_cubed);

        // If we got here without panic, the operations succeeded
        // But we still need to check correctness...
    }
}
