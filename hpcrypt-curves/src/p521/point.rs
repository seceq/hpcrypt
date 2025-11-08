//! P-521 elliptic curve point arithmetic
//!
//! Implements point operations in Jacobian coordinates for the NIST P-521 curve.
//! All operations are designed for constant-time execution where possible.

use super::constants::{P521_B, P521_GX, P521_GY};
use super::field::FieldElement;
use super::scalar::Scalar;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// P-521 elliptic curve point in affine coordinates (x, y)
///
/// Represents a point on the curve: y² = x³ - 3x + b (mod p)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    /// X coordinate
    pub x: FieldElement,

    /// Y coordinate
    pub y: FieldElement,
}

/// P-521 elliptic curve point in Jacobian coordinates (X : Y : Z)
///
/// Represents the affine point (X/Z², Y/Z³) on the curve:
/// y² = x³ - 3x + b (mod p)
///
/// The point at infinity is represented by Z = 0.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl Point {
    /// Returns the point at infinity (identity element)
    #[inline]
    pub const fn infinity() -> Self {
        Point {
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the P-521 generator point (base point G)
    #[inline]
    pub const fn generator() -> Self {
        Point {
            x: FieldElement::from_limbs(P521_GX),
            y: FieldElement::from_limbs(P521_GY),
            z: FieldElement::one(),
        }
    }

    /// Checks if this point is the point at infinity
    #[inline]
    pub fn is_infinity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Creates a point from affine coordinates (x, y)
    ///
    /// Returns None if the point is not on the curve.
    pub fn from_affine(x: &FieldElement, y: &FieldElement) -> Option<Self> {
        let point = Point {
            x: *x,
            y: *y,
            z: FieldElement::one(),
        };

        if bool::from(point.is_on_curve()) {
            Some(point)
        } else {
            None
        }
    }

    /// Converts this point to affine coordinates
    ///
    /// Returns None if the point is at infinity.
    pub fn to_affine(&self) -> Option<AffinePoint> {
        if bool::from(self.is_infinity()) {
            return None;
        }

        // Compute Z^(-1)
        let z_inv = self.z.invert();

        // Compute Z^(-2) = (Z^(-1))^2
        let z_inv_sq = z_inv.square();

        // Compute Z^(-3) = Z^(-2) * Z^(-1)
        let z_inv_cube = z_inv_sq.mul(&z_inv);

        // x = X * Z^(-2)
        let x = self.x.mul(&z_inv_sq);

        // y = Y * Z^(-3)
        let y = self.y.mul(&z_inv_cube);

        Some(AffinePoint { x, y })
    }

    /// Creates a point from an affine point
    pub fn from_affine_point(affine: &AffinePoint) -> Option<Self> {
        Self::from_affine(&affine.x, &affine.y)
    }

    /// Checks if this point is on the curve
    ///
    /// Verifies: Y² = X³ + aXZ⁴ + bZ⁶
    /// For P-521 where a = -3: Y² = X³ - 3XZ⁴ + bZ⁶
    pub fn is_on_curve(&self) -> Choice {
        // The point at infinity is considered to be on the curve
        if bool::from(self.is_infinity()) {
            return Choice::from(1);
        }

        // For affine (Z=1): y² = x³ - 3x + b
        // For Jacobian (x = X/Z², y = Y/Z³): Y² = X³ - 3XZ⁴ + bZ⁶

        // Compute intermediate values
        let z2 = self.z.square();       // Z²
        let z4 = z2.square();           // Z⁴
        let z6 = z4.mul(&z2);           // Z⁶

        let y2 = self.y.square();       // Y²

        let x2 = self.x.square();       // X²
        let x3 = x2.mul(&self.x);       // X³

        // For P-521: a = -3
        // aXZ⁴ = -3XZ⁴
        let three = FieldElement::from_limbs([3, 0, 0, 0, 0, 0, 0, 0, 0]);
        let ax_z4 = self.x.mul(&z4).mul(&three).negate();

        // bZ⁶
        let b = FieldElement::from_limbs(P521_B);
        let b_z6 = b.mul(&z6);

        // Right-hand side: X³ + aXZ⁴ + bZ⁶
        // Since aXZ⁴ is already negated (a = -3), we add it
        let rhs = x3.add(&ax_z4).add(&b_z6);

        // Check if Y² = RHS
        y2.ct_eq(&rhs)
    }

    /// Point doubling: computes 2*P
    ///
    /// Uses the formula for doubling in Jacobian coordinates:
    /// - M = 3·(X + Z²)·(X - Z²)  [a=-3 optimization]
    /// - S = 4·X·Y²
    /// - X' = M² - 2·S
    /// - Y' = M·(S - X') - 8·Y⁴
    /// - Z' = 2·Y·Z
    pub fn double(&self) -> Self {
        // Handle point at infinity
        let is_inf = self.is_infinity();

        // If Y = 0, doubling gives infinity (tangent is vertical)
        let y_zero = self.y.is_zero();

        // Should return infinity if either condition is true
        let ret_inf = is_inf | y_zero;

        // Compute doubling formula (always, for constant-time)
        let y_squared = self.y.square();           // Y²
        let y_fourth = y_squared.square();         // Y⁴

        // S = 4·X·Y²
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let four = FieldElement::from_limbs([4, 0, 0, 0, 0, 0, 0, 0, 0]);
        let s = self.x.mul(&y_squared).mul(&four);

        // M = 3·(X + Z²)·(X - Z²)  [a=-3 optimization]
        let z_squared = self.z.square();           // Z²
        let x_plus_z2 = self.x.add(&z_squared);    // X + Z²
        let x_minus_z2 = self.x.sub(&z_squared);   // X - Z²
        let three = FieldElement::from_limbs([3, 0, 0, 0, 0, 0, 0, 0, 0]);
        let m = x_plus_z2.mul(&x_minus_z2).mul(&three);

        // X' = M² - 2·S
        let m_squared = m.square();
        let two_s = s.mul(&two);
        let x_new = m_squared.sub(&two_s);

        // Y' = M·(S - X') - 8·Y⁴
        let eight = FieldElement::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
        let eight_y4 = y_fourth.mul(&eight);
        let s_minus_x3 = s.sub(&x_new);
        let y_new = m.mul(&s_minus_x3).sub(&eight_y4);

        // Z' = 2·Y·Z
        let z_new = self.y.mul(&self.z).mul(&two);

        let result = Point {
            x: x_new,
            y: y_new,
            z: z_new,
        };

        // Constant-time select: return infinity if ret_inf is true, else result
        Point::conditional_select(&result, &Point::infinity(), ret_inf)
    }

    /// Point doubling with incomplete reduction for intermediate values.
    ///
    /// This variant uses `add_incomplete()` for intermediate additions where
    /// the result is immediately consumed by multiplication.
    ///
    /// Expected performance gain: 5-10% over standard `double()`.
    pub fn double_incomplete(&self) -> Self {
        let is_inf = self.is_infinity();
        let y_zero = self.y.is_zero();
        let ret_inf = is_inf | y_zero;

        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let three = FieldElement::from_limbs([3, 0, 0, 0, 0, 0, 0, 0, 0]);
        let four = FieldElement::from_limbs([4, 0, 0, 0, 0, 0, 0, 0, 0]);
        let eight = FieldElement::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);

        let y_squared = self.y.square();
        let y_fourth = y_squared.square();
        let s = self.x.mul(&y_squared).mul(&four);

        // Use incomplete reduction for x_plus_z2
        let z_squared = self.z.square();
        let x_plus_z2 = self.x.add_incomplete(&z_squared);
        let x_minus_z2 = self.x.sub(&z_squared);
        let m = x_plus_z2.mul(&x_minus_z2).mul(&three);

        let m_squared = m.square();
        let two_s = s.mul(&two);
        let x3 = m_squared.sub(&two_s);

        let eight_y4 = y_fourth.mul(&eight);
        let s_minus_x3 = s.sub(&x3);
        let y3 = m.mul(&s_minus_x3).sub(&eight_y4);

        let z3 = self.y.mul(&self.z).mul(&two);
        let result = Point { x: x3, y: y3, z: z3 };

        Point::conditional_select(&result, &Point::infinity(), ret_inf)
    }

    /// Point addition: computes P + Q
    ///
    /// Uses the general addition formula for Jacobian coordinates.
    /// This is a constant-time implementation that handles all special cases.
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
        let h_squared = h.square();           // H²
        let h_cubed = h_squared.mul(&h);      // H³

        let u1_h2 = u1.mul(&h_squared);       // U₁·H²
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let two_u1_h2 = u1_h2.mul(&two);      // 2·U₁·H²

        // X₃ = R² - H³ - 2·U₁·H²
        let r_squared = r.square();
        let x3 = r_squared.sub(&h_cubed).sub(&two_u1_h2);

        // Y₃ = R·(U₁·H² - X₃) - S₁·H³
        let s1_h3 = s1.mul(&h_cubed);
        let u1_h2_minus_x3 = u1_h2.sub(&x3);
        let y3 = r.mul(&u1_h2_minus_x3).sub(&s1_h3);

        // Z₃ = H·Z₁·Z₂
        let z3 = h.mul(&self.z).mul(&other.z);

        let add_result = Point { x: x3, y: y3, z: z3 };

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

    /// Mixed addition: adds a point in Jacobian coordinates with a point in affine coordinates.
    ///
    /// This is faster than regular addition when the second point is in affine form (Z=1),
    /// such as when using precomputed tables. Saves ~30% compared to full Jacobian addition.
    ///
    /// # Performance
    ///
    /// - Regular add: ~11 multiplications + 5 squarings
    /// - Mixed add: ~8 multiplications + 3 squarings
    ///
    /// # Arguments
    ///
    /// * `other` - Point in affine coordinates to add
    ///
    /// # Returns
    ///
    /// Result in Jacobian coordinates
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
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
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

        let add_result = Point { x: x3, y: y3, z: z3 };

        // Select the appropriate result based on special cases

        // If P is infinity, return Q (convert to Jacobian)
        let q_jacobian = Point::from_affine_point(other).unwrap_or(Point::infinity());
        let mut result = Point::conditional_select(&add_result, &q_jacobian, p_inf);

        // If points are equal, return double(P)
        let doubled = self.double();
        result = Point::conditional_select(&result, &doubled, points_equal);

        // If points are inverses, return infinity
        result = Point::conditional_select(&result, &Point::infinity(), points_inverse);

        result
    }

    /// Scalar multiplication: computes k*P
    ///
    /// Uses double-and-add algorithm with constant-time operations.
    ///
    /// # Security
    ///
    /// This implementation uses conditional selection to achieve constant-time
    /// execution, preventing timing attacks on the scalar value.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let mut result = Self::infinity();

        // Process bits from MSB to LSB using limbs directly
        // Limbs are stored in little-endian (limb[0] is LSB), so process from limb[8] down to limb[0]
        // limb[8] has 9 bits, limb[7-0] each have 64 bits

        let limbs = scalar.limbs();

        // Process limb[8] (top 9 bits)
        for bit_index in (0..9).rev() {
            result = result.double();
            let bit = Choice::from(((limbs[8] >> bit_index) & 1) as u8);
            let new_result = result.add(self);
            result = Self::conditional_select(&result, &new_result, bit);
        }

        // Process limbs[7..=0] (each has 64 bits)
        for limb_index in (0..8).rev() {
            for bit_index in (0..64).rev() {
                result = result.double();
                let bit = Choice::from(((limbs[limb_index] >> bit_index) & 1) as u8);
                let new_result = result.add(self);
                result = Self::conditional_select(&result, &new_result, bit);
            }
        }

        result
    }

    /// Negates this point: returns -P
    pub fn negate(&self) -> Self {
        Point {
            x: self.x,
            y: self.y.negate(),
            z: self.z,
        }
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
    fn test_generator_on_curve() {
        let g = Point::generator();
        assert!(!bool::from(g.is_infinity()));
        assert!(bool::from(g.is_on_curve()));
    }

    #[test]
    fn test_point_double() {
        let g = Point::generator();
        let g2 = g.double();

        assert!(!bool::from(g2.is_infinity()));
        assert!(bool::from(g2.is_on_curve()));
    }

    #[test]
    fn test_point_add() {
        let g = Point::generator();
        let g2 = g.double();
        let g3 = g.add(&g2);

        assert!(!bool::from(g3.is_infinity()));
        assert!(bool::from(g3.is_on_curve()));
    }

    #[test]
    fn test_add_infinity() {
        let g = Point::generator();
        let inf = Point::infinity();

        let result1 = g.add(&inf);
        let result2 = inf.add(&g);

        // G + ∞ = G
        assert!(!bool::from(result1.is_infinity()));
        assert!(!bool::from(result2.is_infinity()));
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = Point::generator();
        let zero = Scalar::zero();
        let result = g.scalar_mul(&zero);

        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = Point::generator();
        let one = Scalar::one();
        let result = g.scalar_mul(&one);

        // Should be equal to G (after converting to affine)
        assert!(!bool::from(result.is_infinity()));
        assert!(bool::from(result.is_on_curve()));
    }

    #[test]
    fn test_scalar_mul_two() {
        let g = Point::generator();
        let two = Scalar::from_u64(2);
        let result_mul = g.scalar_mul(&two);
        let result_double = g.double();

        // Both should be on curve
        assert!(bool::from(result_mul.is_on_curve()));
        assert!(bool::from(result_double.is_on_curve()));

        // Convert both to affine and compare coordinates
        let affine1 = result_mul.to_affine().expect("scalar_mul(2) should not be infinity");
        let affine2 = result_double.to_affine().expect("double() should not be infinity");

        // CRITICAL TEST: scalar_mul(2) must equal double()
        assert_eq!(affine1.x, affine2.x, "X coordinates don't match: scalar_mul(2) != double()");
        assert_eq!(affine1.y, affine2.y, "Y coordinates don't match: scalar_mul(2) != double()");
    }

    #[test]
    fn test_affine_conversion() {
        let g = Point::generator();
        let affine = g.to_affine().unwrap();

        // Should match generator coordinates
        let gx = FieldElement::from_limbs(P521_GX);
        let gy = FieldElement::from_limbs(P521_GY);

        assert_eq!(affine.x, gx);
        assert_eq!(affine.y, gy);
    }

    #[test]
    fn test_affine_roundtrip() {
        let g = Point::generator();

        // Convert to affine
        let affine = g.to_affine().expect("Generator should not be infinity");

        // Convert back to point
        let g2 = Point::from_affine(&affine.x, &affine.y).expect("Generator coordinates should create valid point");

        // Should be on curve
        assert!(bool::from(g2.is_on_curve()), "Reconstructed generator not on curve");

        // Coordinates should match
        let affine2 = g2.to_affine().unwrap();
        assert_eq!(affine.x, affine2.x, "X coordinates don't match");
        assert_eq!(affine.y, affine2.y, "Y coordinates don't match");
    }

    #[test]
    fn test_scalar_mul_affine_roundtrip() {
        let g = Point::generator();
        let k = Scalar::from_u64(12345);
        let p = g.scalar_mul(&k);

        // Convert to affine
        let affine = p.to_affine().expect("Point should not be infinity");

        // Convert back to point
        let p2 = Point::from_affine(&affine.x, &affine.y).expect("Coordinates should create valid point");

        // Should be on curve
        assert!(bool::from(p2.is_on_curve()), "Reconstructed point not on curve");

        // Coordinates should match
        let affine2 = p2.to_affine().unwrap();
        assert_eq!(affine.x, affine2.x, "X coordinates don't match");
        assert_eq!(affine.y, affine2.y, "Y coordinates don't match");
    }

    #[test]
    fn test_negate() {
        let g = Point::generator();
        let neg_g = g.negate();

        // G + (-G) = ∞
        let result = g.add(&neg_g);
        assert!(bool::from(result.is_infinity()));
    }

    #[test]
    fn test_scalar_mul_three() {
        let g = Point::generator();

        // Test scalar_mul(3)
        let three = Scalar::from_u64(3);
        let result = g.scalar_mul(&three);

        // Also compute as G + G + G
        let g_plus_g = g.add(&g);
        let manual = g_plus_g.add(&g);

        assert!(bool::from(result.is_on_curve()), "scalar_mul(3) should be on curve");
        assert!(bool::from(manual.is_on_curve()), "manual G+G+G should be on curve");

        let affine1 = result.to_affine().expect("scalar_mul(3) should not be infinity");
        let affine2 = manual.to_affine().expect("manual should not be infinity");

        assert_eq!(affine1.x.to_bytes(), affine2.x.to_bytes(), "X coordinates don't match: scalar_mul(3) != G+G+G");
        assert_eq!(affine1.y.to_bytes(), affine2.y.to_bytes(), "Y coordinates don't match: scalar_mul(3) != G+G+G");
    }
}
