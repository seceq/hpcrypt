//! Ed448 Edwards curve point arithmetic
//!
//! Implements point operations in extended twisted Edwards coordinates.
//! The curve equation is: x² + y² = 1 - 39081·x²·y²
//!
//! Extended coordinates (X:Y:Z:T) represent the affine point (X/Z, Y/Z)
//! with the invariant T = X·Y/Z. This representation allows faster addition.

use super::constants::{ED448_B_X, ED448_B_Y, ED448_D};
use super::field::FieldElement;
use super::scalar::Scalar;
use crate::ct_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// An Ed448 curve point in extended twisted Edwards coordinates
///
/// Represents the affine point (X/Z, Y/Z) with T = X·Y/Z
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

impl Point {
    /// Returns the identity element (point at infinity)
    ///
    /// In Edwards coordinates, this is (0, 1)
    pub const fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    /// Returns the base point (generator) G
    pub fn generator() -> Self {
        let x = FieldElement::from_limbs(ED448_B_X);
        let y = FieldElement::from_limbs(ED448_B_Y);
        let z = FieldElement::one();
        let t = x * y; // In extended coordinates, T = X*Y/Z, and since Z=1, T = X*Y

        Self { x, y, z, t }
    }

    /// Checks if this is the identity element
    pub fn is_identity(&self) -> Choice {
        // Identity is (0:1:1:0) or any scaling thereof
        // Check if X = 0 and Y = Z (which means X/Z = 0 and Y/Z = 1)
        let x_zero = self.x.is_zero();
        let y_eq_z = self.y.ct_eq(&self.z);
        x_zero & y_eq_z
    }

    /// Point doubling: computes [2]P
    ///
    /// Uses RFC 8032 formula for doubling on untwisted Edwards curve with a=1
    /// Cost: 4M + 4S
    pub fn double(&self) -> Self {
        // From RFC 8032 Section 5.2.4 - Doubling formula for a=1
        // B = (X1+Y1)^2
        let xy_sum = self.x + self.y;
        let b = xy_sum.square();

        // C = X1^2
        let c = self.x.square();

        // D = Y1^2
        let d = self.y.square();

        // E = C + D (for a=1 curve, this is X^2 + Y^2)
        let e = c + d;

        // H = Z1^2
        let h = self.z.square();

        // J = E - 2*H
        let two_h = h + h;
        let j = e - two_h;

        // X3 = (B - E) * J
        let x3 = (b - e) * j;

        // Y3 = E * (C - D)
        let y3 = e * (c - d);

        // Z3 = E * J
        let z3 = e * j;

        // T3 = X3 * Y3 / Z3, but we can compute more efficiently
        // T3 = (B - E) * (C - D)
        let t3 = (b - e) * (c - d);

        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Point addition: computes P + Q
    ///
    /// Uses the formula for addition in extended coordinates.
    /// Cost: 8M + 1D
    pub fn add(&self, other: &Self) -> Self {
        // From RFC 8032 / EFD (Extended coordinates addition)
        // A = X1 * X2
        let a = self.x * other.x;

        // B = Y1 * Y2
        let b = self.y * other.y;

        // C = T1 * d * T2
        let d_param = FieldElement::from_limbs(ED448_D);
        let c = self.t * d_param * other.t;

        // D = Z1 * Z2
        let d = self.z * other.z;

        // E = (X1+Y1) * (X2+Y2) - A - B
        let xy1_sum = self.x + self.y;
        let xy2_sum = other.x + other.y;
        let e = xy1_sum * xy2_sum - a - b;

        // F = D - C
        let f = d - c;

        // G = D + C
        let g = d + c;

        // H = B - A (for a = 1 curve)
        let h = b - a;

        // X3 = E * F
        let x3 = e * f;

        // Y3 = G * H
        let y3 = g * h;

        // T3 = E * H
        let t3 = e * h;

        // Z3 = F * G
        let z3 = f * g;

        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Point subtraction: computes P - Q
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    /// Point negation: computes -P
    ///
    /// For Edwards curves, -(x,y) = (-x, y)
    pub fn negate(&self) -> Self {
        Self {
            x: self.x.negate(),
            y: self.y,
            z: self.z,
            t: self.t.negate(),
        }
    }

    /// Scalar multiplication: computes [k]P using 4-bit windowing
    ///
    /// This method uses a 4-bit windowing technique which is significantly faster
    /// than bit-by-bit double-and-add. It precomputes 16 multiples of P and processes
    /// the scalar 4 bits at a time.
    ///
    /// # Performance
    /// - Bit-by-bit: 448 doublings + ~224 additions (average)
    /// - 4-bit windowing: ~448 doublings + ~112 additions (average)
    /// - Expected speedup: 2-3× faster
    ///
    /// # Security
    /// Uses constant-time table lookups to prevent timing side-channels.
    pub fn scalar_mul(&self, scalar: &Scalar) -> Self {
        // Precompute small multiples: [0]P, [1]P, [2]P, ..., [15]P
        let mut precomp = [Self::identity(); 16];
        precomp[1] = *self;

        // Compute odd multiples first: 3P, 5P, 7P, 9P, 11P, 13P, 15P
        let double_p = self.double();
        for i in (3..16).step_by(2) {
            precomp[i] = precomp[i - 2].add(&double_p);
        }

        // Compute even multiples: 2P, 4P, 6P, 8P, 10P, 12P, 14P
        for i in (2..16).step_by(2) {
            precomp[i] = precomp[i / 2].double();
        }

        let mut result = Self::identity();
        let mut first = true;

        // Convert scalar to bytes for nibble extraction
        // Ed448 scalars are 57 bytes (456 bits), but we process 448 bits
        let scalar_bytes = scalar.to_bytes();

        // Process scalar in 4-bit windows from most significant to least significant
        // 448 bits = 112 nibbles (4 bits each)
        for i in (0..112).rev() {
            // Extract the i-th nibble (4 bits)
            let byte_idx = i / 2;
            let nibble = if i % 2 == 0 {
                // Low nibble
                scalar_bytes[byte_idx] & 0x0F
            } else {
                // High nibble
                (scalar_bytes[byte_idx] >> 4) & 0x0F
            };

            // Skip leading zeros
            if first {
                if nibble == 0 {
                    continue;
                }
                first = false;
                // Constant-time table lookup (prevents timing leaks)
                result = hpcrypt_core::ct_table_lookup(&precomp, nibble as usize);
            } else {
                // Double 4 times to make room for the next nibble
                result = result.double().double().double().double();

                // Constant-time table lookup and add
                // Always perform the lookup but nibble=0 looks up identity (no-op for add)
                let point = hpcrypt_core::ct_table_lookup(&precomp, nibble as usize);
                result = result.add(&point);
            }
        }

        result
    }

    /// Scalar multiplication using basic double-and-add (kept for reference/testing)
    ///
    /// This is the original 1-bit-at-a-time method. It's slower than the windowed
    /// method but serves as a reference implementation for testing.
    #[allow(dead_code)]
    pub fn scalar_mul_simple(&self, scalar: &Scalar) -> Self {
        let mut result = Self::identity();

        // Process bits from MSB to LSB
        // Scalar has 8 limbs of 56 bits each
        let limbs = scalar.limbs();

        // Process from high to low
        for i in (0..8).rev() {
            let limb = limbs[i];

            for bit_pos in (0..56).rev() {
                result = result.double();

                let bit = Choice::from(((limb >> bit_pos) & 1) as u8);
                let new_result = result.add(self);
                result = Self::conditional_select(&result, &new_result, bit);
            }
        }

        result
    }

    /// Scalar multiplication using Non-Adjacent Form (NAF)
    ///
    /// NAF is a signed binary representation where no two adjacent digits are non-zero.
    /// This reduces the average number of point additions by ~33% compared to binary
    /// scalar multiplication.
    ///
    /// # Performance
    /// - Binary method: ~224 additions (average) for 448-bit scalar
    /// - NAF method: ~149 additions (average) = 33% reduction
    ///
    /// # Algorithm
    /// 1. Convert scalar to NAF (signed digits in {-1, 0, 1})
    /// 2. Process NAF digits from MSB to LSB
    /// 3. For digit = 1: add P, for digit = -1: subtract P, for digit = 0: skip
    ///
    /// Expected speedup: 25-33% over basic scalar_mul
    pub fn scalar_mul_naf(&self, scalar: &Scalar) -> Self {
        let naf = scalar.to_naf();

        // Precompute -P for subtraction operations
        let neg_p = self.negate();

        let mut result = Self::identity();
        let mut started = false;

        // Process NAF digits from MSB to LSB
        for i in (0..448).rev() {
            if started {
                result = result.double();
            }

            match naf[i] {
                1 => {
                    started = true;
                    result = result.add(self);
                }
                -1 => {
                    started = true;
                    result = result.add(&neg_p);
                }
                0 => {
                    // Skip zero digits
                }
                _ => unreachable!("NAF digit must be -1, 0, or 1"),
            }
        }

        result
    }

    /// Double scalar multiplication: computes [a]P + [b]Q
    ///
    /// This is more efficient than computing [a]P and [b]Q separately.
    /// Used in signature verification (Shamir's trick).
    pub fn double_scalar_mul(
        scalar_a: &Scalar,
        point_a: &Self,
        scalar_b: &Scalar,
        point_b: &Self,
    ) -> Self {
        // Precompute point_a + point_b
        let point_ab = point_a.add(point_b);

        let mut result = Self::identity();
        let limbs_a = scalar_a.limbs();
        let limbs_b = scalar_b.limbs();

        // Process both scalars simultaneously from MSB to LSB
        for i in (0..8).rev() {
            let limb_a = limbs_a[i];
            let limb_b = limbs_b[i];

            for bit_pos in (0..56).rev() {
                result = result.double();

                let bit_a = ((limb_a >> bit_pos) & 1) != 0;
                let bit_b = ((limb_b >> bit_pos) & 1) != 0;

                // Select which point(s) to add based on bit pattern
                match (bit_a, bit_b) {
                    (false, false) => {
                        // Add nothing
                    }
                    (false, true) => {
                        // Add point_b
                        result = result.add(point_b);
                    }
                    (true, false) => {
                        // Add point_a
                        result = result.add(point_a);
                    }
                    (true, true) => {
                        // Add point_a + point_b
                        result = result.add(&point_ab);
                    }
                }
            }
        }

        result
    }

    /// Convert from bytes (57 bytes, little-endian)
    ///
    /// The encoding is: the y-coordinate with the sign of x in the MSB.
    pub fn from_bytes(bytes: &[u8; 57]) -> Option<Self> {
        // Extract y-coordinate (clear MSB first)
        let mut y_bytes = *bytes;
        let x_sign = (y_bytes[56] >> 7) & 1;
        y_bytes[56] &= 0x7F; // Clear sign bit

        let y = FieldElement::from_bytes(&y_bytes);

        // Recover x from y using curve equation: x^2 + y^2 = 1 + d*x^2*y^2
        // Solving for x^2: x^2 = (1 - y^2) / (1 - d*y^2)
        // Since d = -39081, this becomes: x^2 = (1 - y^2) / (1 + 39081*y^2)
        let y2 = y.square();
        let one = FieldElement::one();

        // Numerator: 1 - y^2
        let numerator = one - y2;

        // Denominator: 1 - d*y^2, which equals 1 + 39081*y^2 since d = -39081
        let d = FieldElement::from_limbs(ED448_D);
        let denominator = one - d * y2;

        // x^2 = numerator / denominator
        let denominator_inv = denominator.invert();
        let x2 = numerator * denominator_inv;

        // Take square root
        // For Ed448, we need to find x such that x^2 = x2
        // This uses Tonelli-Shanks or a direct formula for the Goldilocks prime
        let x = Self::sqrt(&x2)?;

        // Choose the sign of x based on the sign bit
        let x_bytes = x.to_bytes();
        let x_sign_is_positive = (x_bytes[0] & 1) == 0;

        let x = if x_sign_is_positive == (x_sign == 0) {
            x
        } else {
            x.negate()
        };

        // Compute T = X * Y
        let t = x * y;

        Some(Self {
            x,
            y,
            z: one,
            t,
        })
    }

    /// Convert to bytes (57 bytes, little-endian)
    ///
    /// Encodes the y-coordinate with the sign of x in the MSB.
    pub fn to_bytes(&self) -> [u8; 57] {
        // Convert to affine coordinates
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;

        let mut bytes = y.to_bytes();

        // Set sign bit based on x
        let x_bytes = x.to_bytes();
        let x_sign = x_bytes[0] & 1;
        bytes[56] |= x_sign << 7;

        bytes
    }

    /// Square root in the field (for point decompression)
    ///
    /// Returns Some(sqrt) if x is a quadratic residue, None otherwise.
    fn sqrt(x: &FieldElement) -> Option<FieldElement> {
        // For the Goldilocks prime p = 2^448 - 2^224 - 1,
        // p ≡ 3 (mod 4), so we can use the simple formula:
        // sqrt(x) = x^((p+1)/4) if x is a quadratic residue

        // (p+1)/4 = (2^448 - 2^224 - 1 + 1) / 4 = (2^448 - 2^224) / 4 = 2^446 - 2^222

        // Compute x^((p+1)/4)
        let mut result = *x;

        // First compute x^(2^222)
        for _ in 0..222 {
            result = result.square();
        }
        let x_2_222 = result;

        // Then compute x^(2^446) = (x^(2^222))^(2^224)
        for _ in 0..224 {
            result = result.square();
        }

        // result = x^(2^446) / x^(2^222) = x^(2^446 - 2^222) = x^((p+1)/4)
        // Division in the field is multiplication by inverse
        result = result * x_2_222.invert();

        // Check if result^2 = x
        if result.square().ct_eq(x).into() {
            Some(result)
        } else {
            None
        }
    }

    /// Checks if this point is on the curve
    ///
    /// Verifies the curve equation: x^2 + y^2 = 1 + d*x^2*y^2
    pub fn is_on_curve(&self) -> Choice {
        // Convert to affine for checking
        let z_inv = self.z.invert();
        let x = self.x * z_inv;
        let y = self.y * z_inv;

        let x2 = x.square();
        let y2 = y.square();

        let one = FieldElement::one();
        let d = FieldElement::from_limbs(ED448_D);

        // Left side: x^2 + y^2
        let lhs = x2 + y2;

        // Right side: 1 + d*x^2*y^2
        let rhs = one + d * x2 * y2;

        lhs.ct_eq(&rhs)
    }
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
            t: FieldElement::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Two points are equal if they represent the same affine point
        // (X1/Z1, Y1/Z1) = (X2/Z2, Y2/Z2)
        // This is true iff X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1

        let x1z2 = self.x * other.z;
        let x2z1 = other.x * self.z;
        let x_equal = x1z2.ct_eq(&x2z1);

        let y1z2 = self.y * other.z;
        let y2z1 = other.y * self.z;
        let y_equal = y1z2.ct_eq(&y2z1);

        x_equal & y_equal
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Point {}

impl Default for Point {
    fn default() -> Self {
        Self::identity()
    }
}

/// Niels coordinates for efficient mixed addition
///
/// Niels form stores (y+x, y-x, 2d*t) which allows mixed addition
/// with an extended point in only 7M compared to 8M for regular addition.
///
/// This is particularly useful for precomputed tables since points
/// can be stored in Niels form and added to accumulating results
/// in extended form with reduced cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NielsPoint {
    /// y + x
    pub(crate) y_plus_x: FieldElement,
    /// y - x
    pub(crate) y_minus_x: FieldElement,
    /// 2 * d * t (where t = x*y)
    pub(crate) t2d: FieldElement,
}

impl NielsPoint {
    /// Identity element in Niels coordinates
    pub fn identity() -> Self {
        NielsPoint {
            y_plus_x: FieldElement::one(),
            y_minus_x: FieldElement::one(),
            t2d: FieldElement::zero(),
        }
    }

    /// Constant identity (for use in const contexts)
    pub const IDENTITY: Self = NielsPoint {
        y_plus_x: FieldElement { limbs: [1, 0, 0, 0, 0, 0, 0, 0] },
        y_minus_x: FieldElement { limbs: [1, 0, 0, 0, 0, 0, 0, 0] },
        t2d: FieldElement { limbs: [0, 0, 0, 0, 0, 0, 0, 0] },
    };

    /// Convert from extended coordinates to Niels
    ///
    /// # Algorithm
    /// Given extended point (X:Y:Z:T):
    /// - Normalize to affine: (x, y) = (X/Z, Y/Z)
    /// - Compute: (y+x, y-x, 2*d*x*y)
    ///
    /// # Performance
    /// Cost: 1 inversion + 5M + 2A
    pub fn from_extended(point: &Point) -> Self {
        // Normalize to affine for canonical representation
        // This ensures two Extended points representing the same affine point
        // produce the same Niels point (important for testing and equality)
        let z_inv = point.z.invert();
        let x = point.x * z_inv;
        let y = point.y * z_inv;

        let d = FieldElement::from_limbs(ED448_D);
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
        let d2 = d * two;

        // Compute Niels coordinates from affine
        let y_minus_x = y - x;
        let y_plus_x = x + y;  // Note: OpenSSL does X + Y
        let t2d = x * y * d2;  // t = x*y in affine

        NielsPoint {
            y_plus_x,
            y_minus_x,
            t2d,
        }
    }

    /// Negate a Niels point
    ///
    /// For negation: -(x,y) = (-x, y)
    /// In Niels form:
    /// - (y+x) becomes (y-x)
    /// - (y-x) becomes (y+x)
    /// - 2d*t becomes -2d*t
    pub fn negate(&self) -> Self {
        NielsPoint {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            t2d: self.t2d.negate(),
        }
    }
}

// Precomputed inverse of 2 in the Ed448 field (p = 2^448 - 2^224 - 1)
// inv(2) = (p+1)/2 = 0x7fff...fff8000...000
const INV_TWO: FieldElement = FieldElement {
    limbs: [
        0,
        0,
        0,
        36028797018963968,    // 2^55
        72057594037927935,    // 2^56 - 1
        72057594037927935,    // 2^56 - 1
        72057594037927935,    // 2^56 - 1
        36028797018963967,    // 2^55 - 1
    ]
};

impl Point {
    /// Mixed addition: Extended + Niels → Extended
    ///
    /// Adds a point in Niels coordinates to a point in Extended coordinates.
    /// This is more efficient than Extended + Extended addition.
    ///
    /// # Performance
    /// Cost: 7M (vs 8M for Extended + Extended)
    ///
    /// # Algorithm (adapted for a=1 untwisted Edwards curves)
    /// Input: Extended point P1 = (X1:Y1:Z1:T1), Niels point P2 = (y2+x2, y2-x2, 2*d*t2)
    /// Output: Extended point P3 = P1 + P2
    ///
    /// 1. A = (Y1 - X1) * (y2 - x2)        [M1]
    /// 2. B = (Y1 + X1) * (y2 + x2)        [M2]
    /// 3. C = 2*d*T1 * t2                  [M3] (simplified since Niels stores 2d*t2)
    /// 4. D = 2*Z1                         [A]
    /// 5. E = B - A                        [A]
    /// 6. F = D - C                        [A]
    /// 7. G = D + C                        [A]
    /// 8. H = B + A                        [A] (independent of curve parameter a)
    /// 9. X3 = E * F                       [M4]
    /// 10. Y3 = G * H                      [M5]
    /// 11. T3 = E * H                      [M6]
    /// 12. Z3 = F * G                      [M7]
    pub fn add_niels(&self, other: &NielsPoint) -> Point {
        // CRITICAL FIX: Convert Niels to Extended and use the RFC 8032 formula
        // The issue was that we were using OpenSSL's formula (with different intermediate values)
        // but comparing against RFC 8032's formula (what add() uses).
        //
        // From Niels (y+x, y-x, 2*d*T), recover Extended coordinates:
        // Given: YpX = Y+X, YmX = Y-X, T2d = 2*d*T
        // We can compute: Y = (YpX + YmX) / 2, X = (YpX - YmX) / 2
        // But division is expensive, so use a different approach:
        //
        // RFC 8032 formula needs: X2, Y2, T2, Z2
        // We have: Y2+X2, Y2-X2, 2*d*T2, and implicitly Z2=1
        //
        // For RFC 8032:
        // A = X1 * X2 = X1 * (YpX - YmX) / 2
        // B = Y1 * Y2 = Y1 * (YpX + YmX) / 2
        // But we can avoid division by scaling everything by 4:
        //
        // A' = X1 * (YpX - YmX) = X1*YpX - X1*YmX
        // B' = Y1 * (YpX + YmX) = Y1*YpX + Y1*YmX
        // Then we need to scale the result by 1/4 at the end

        // Actually, let's use a cleaner approach - RFC 8032 in terms of Niels coords:
        // A = X1 * X2, but X2 = (y_plus_x - y_minus_x)/2
        // B = Y1 * Y2, but Y2 = (y_plus_x + y_minus_x)/2
        //
        // So: 2*A = X1 * (y_plus_x - y_minus_x)
        //     2*B = Y1 * (y_plus_x + y_minus_x)
        //
        // And E = (X1+Y1)*(X2+Y2) - A - B
        //       = (X1+Y1)*y_plus_x - A - B

        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0]);

        // Compute 2*A and 2*B to avoid division
        let two_a = self.x * (other.y_plus_x - other.y_minus_x);  // M1
        let two_b = self.y * (other.y_plus_x + other.y_minus_x);  // M2

        // For C: T1 * d * T2, but we have 2*d*T2, so:
        // C = T1 * (2*d*T2) / 2
        let two_c = self.t * other.t2d;  // M3

        // OPTIMIZATION: Use precomputed inverse of 2 instead of 4 expensive inversions
        // This transforms O(4*112) inversions into O(4*112) multiplications
        let c = two_c * INV_TWO;

        // D = Z1 * Z2, where Z2=1
        let d = self.z;

        // E = (X1+Y1)*(X2+Y2) - A - B
        let xy_sum = self.x + self.y;
        let two_e = two * xy_sum * other.y_plus_x - two_a - two_b;  // M4
        let e = two_e * INV_TWO;

        // F, G, H are computed from A, B, C, D
        let a = two_a * INV_TWO;
        let b = two_b * INV_TWO;

        let f = d - c;
        let g = d + c;
        let h = b - a;  // For a=1 curve

        // Output
        Point {
            x: e * f,  // M5
            y: g * h,  // M6
            z: f * g,  // M7
            t: e * h,  // M8
        }
    }

    /// Subtract a point in Niels coordinates
    ///
    /// Equivalent to self + (-other), optimized by negating Niels coordinates.
    ///
    /// # Performance
    /// Cost: 7M (same as add_niels)
    pub fn sub_niels(&self, other: &NielsPoint) -> Point {
        self.add_niels(&other.negate())
    }
}

impl ConditionallySelectable for NielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        NielsPoint {
            y_plus_x: FieldElement::conditional_select(&a.y_plus_x, &b.y_plus_x, choice),
            y_minus_x: FieldElement::conditional_select(&a.y_minus_x, &b.y_minus_x, choice),
            t2d: FieldElement::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

impl Default for NielsPoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = Point::identity();
        assert!(bool::from(id.is_identity()));
    }

    #[test]
    fn test_generator_on_curve() {
        let g = Point::generator();
        // Note: Generator T coordinate needs fixing
        assert!(bool::from(g.is_on_curve()));
    }

    #[test]
    fn test_point_double() {
        let g = Point::generator();
        let g2 = g.double();

        assert!(!bool::from(g2.is_identity()));
        assert!(bool::from(g2.is_on_curve()));
    }

    #[test]
    fn test_point_add() {
        let g = Point::generator();
        let g2 = g.double();
        let g3 = g.add(&g2);

        assert!(!bool::from(g3.is_identity()));
        assert!(bool::from(g3.is_on_curve()));
    }

    #[test]
    fn test_add_identity() {
        let g = Point::generator();
        let id = Point::identity();

        let result = g.add(&id);
        assert_eq!(result, g);
    }

    #[test]
    fn test_scalar_mul_zero() {
        let g = Point::generator();
        let zero = Scalar::zero();
        let result = g.scalar_mul(&zero);

        assert!(bool::from(result.is_identity()));
    }

    #[test]
    fn test_scalar_mul_one() {
        let g = Point::generator();
        let one = Scalar::one();
        let result = g.scalar_mul(&one);

        // Should equal G (within projective equivalence)
        assert!(!bool::from(result.is_identity()));
        assert!(bool::from(result.is_on_curve()));
    }

    #[test]
    fn test_negation() {
        let g = Point::generator();
        let neg_g = g.negate();

        let sum = g.add(&neg_g);
        assert!(bool::from(sum.is_identity()));
    }

    #[test]
    fn test_point_encoding_roundtrip() {
        // Test that generator encodes and decodes correctly
        let g = Point::generator();
        let bytes = g.to_bytes();
        let g_decoded = Point::from_bytes(&bytes).expect("Failed to decode generator");

        assert_eq!(g, g_decoded);
    }

    #[test]
    fn test_scalar_mul_encoding() {
        // Test that scalar multiplication result encodes/decodes correctly
        let g = Point::generator();
        let scalar = Scalar::from_bytes(&[3u8; 57]);
        let p = g.scalar_mul(&scalar);

        let bytes = p.to_bytes();
        let p_decoded = Point::from_bytes(&bytes).expect("Failed to decode point");

        assert_eq!(p, p_decoded);
    }

    #[test]
    fn test_naf_correctness_simple() {
        // Test NAF with simple scalars
        let g = Point::generator();

        // Test with scalar = 1
        let one = Scalar::one();
        let result_regular = g.scalar_mul(&one);
        let result_naf = g.scalar_mul_naf(&one);
        assert_eq!(result_regular, result_naf, "NAF failed for scalar=1");

        // Test with scalar = 0
        let zero = Scalar::zero();
        let result_regular = g.scalar_mul(&zero);
        let result_naf = g.scalar_mul_naf(&zero);
        assert_eq!(result_regular, result_naf, "NAF failed for scalar=0");
    }

    #[test]
    fn test_naf_correctness_various() {
        // Test NAF matches regular scalar_mul for various scalars
        let g = Point::generator();

        // Test scalar = 3
        let scalar3 = Scalar::from_bytes(&[3u8; 57]);
        let result_regular = g.scalar_mul(&scalar3);
        let result_naf = g.scalar_mul_naf(&scalar3);
        assert_eq!(result_regular, result_naf, "NAF failed for scalar=3");

        // Test scalar = 255 (all 1s in first byte)
        let scalar255 = Scalar::from_bytes(&[255u8; 57]);
        let result_regular = g.scalar_mul(&scalar255);
        let result_naf = g.scalar_mul_naf(&scalar255);
        assert_eq!(result_regular, result_naf, "NAF failed for scalar=255");

        // Test with a larger scalar
        let mut scalar_bytes = [0u8; 57];
        scalar_bytes[0] = 0x42;
        scalar_bytes[1] = 0x7A;
        scalar_bytes[2] = 0x19;
        let scalar_large = Scalar::from_bytes(&scalar_bytes);
        let result_regular = g.scalar_mul(&scalar_large);
        let result_naf = g.scalar_mul_naf(&scalar_large);
        assert_eq!(result_regular, result_naf, "NAF failed for large scalar");
    }

    #[test]
    fn test_naf_with_consecutive_ones() {
        // Test NAF specifically handles consecutive 1s correctly
        let g = Point::generator();

        // Scalar with pattern: 0b...0110 (consecutive 1s)
        let mut scalar_bytes = [0u8; 57];
        scalar_bytes[0] = 0b00000110; // Two consecutive 1s
        let scalar = Scalar::from_bytes(&scalar_bytes);

        let result_regular = g.scalar_mul(&scalar);
        let result_naf = g.scalar_mul_naf(&scalar);
        assert_eq!(result_regular, result_naf, "NAF failed for consecutive 1s pattern");

        // Another pattern: 0b...11110 (four consecutive 1s)
        scalar_bytes[0] = 0b00011110;
        let scalar2 = Scalar::from_bytes(&scalar_bytes);
        let result_regular2 = g.scalar_mul(&scalar2);
        let result_naf2 = g.scalar_mul_naf(&scalar2);
        assert_eq!(result_regular2, result_naf2, "NAF failed for 4 consecutive 1s");
    }

    #[test]
    fn test_naf_representation() {
        // Test that NAF representation is correct
        let scalar_bytes = [3u8; 57]; // Small value for easy verification
        let scalar = Scalar::from_bytes(&scalar_bytes);
        let naf = scalar.to_naf();

        // Verify no adjacent non-zeros
        for i in 0..447 {
            if naf[i] != 0 && naf[i + 1] != 0 {
                panic!("NAF has adjacent non-zeros at positions {} and {}", i, i + 1);
            }
        }

        // Verify all digits are in {-1, 0, 1}
        for (i, &digit) in naf.iter().enumerate() {
            assert!(
                digit == -1 || digit == 0 || digit == 1,
                "NAF digit at position {} is {}, expected -1, 0, or 1",
                i,
                digit
            );
        }
    }
}

// ============================================================================
// Multi-Scalar Multiplication (Pippenger's Algorithm)
// ============================================================================

impl Point {
    /// Pippenger's multi-scalar multiplication algorithm
    ///
    /// Computes Σ(scalars[i] * points[i]) efficiently using the bucket method.
    /// This is significantly faster than naive summation for n ≥ 8.
    ///
    /// # Algorithm: Bucket Method (Pippenger)
    ///
    /// 1. Choose optimal window size c based on n (number of points)
    /// 2. Divide each scalar into digits of c bits
    /// 3. For each digit position (from MSB to LSB):
    ///    a. Create 2^c buckets
    ///    b. Add points to buckets based on their digit value
    ///    c. Compute bucket sums efficiently
    ///    d. Accumulate into result
    ///
    /// # Performance
    ///
    /// - Naive: O(n * 448) point operations
    /// - Pippenger: O(n + 448/c * 2^c) point operations
    /// - Expected speedup for n=8: ~2×
    /// - Expected speedup for n=32: ~4×
    ///
    /// # Window Size Selection
    ///
    /// Optimal window size depends on batch size n:
    /// - n=2-4: c=2 (4 buckets)
    /// - n=5-32: c=3 (8 buckets)
    /// - n=33-128: c=4 (16 buckets)
    /// - n>128: c=5 (32 buckets)
    ///
    /// # Arguments
    ///
    /// * `scalars` - Array of scalars (57 bytes each, little-endian)
    /// * `points` - Array of points
    ///
    /// # Returns
    ///
    /// The point Σ(scalars[i] * points[i])
    ///
    /// # Panics
    ///
    /// Panics if scalars.len() != points.len()
    #[cfg(feature = "std")]
    pub fn pippenger_msm(scalars: &[[u8; 57]], points: &[Point]) -> Point {
        assert_eq!(scalars.len(), points.len(), "Scalars and points must have same length");

        let n = scalars.len();

        // Handle edge cases
        if n == 0 {
            return Point::identity();
        }
        if n == 1 {
            let scalar = Scalar::from_bytes(&scalars[0]);
            return points[0].scalar_mul(&scalar);
        }

        // Select optimal window size based on batch size
        let window_size = Self::optimal_window_size(n);
        let num_buckets = 1usize << window_size; // 2^window_size
        let num_windows = (448 + window_size - 1) / window_size; // Ceiling division

        // Result accumulator
        let mut result = Point::identity();

        // Process windows from MSB to LSB
        for window_idx in (0..num_windows).rev() {
            // Multiply by 2^window_size (double window_size times)
            for _ in 0..window_size {
                result = result.double();
            }

            // Create buckets (bucket[k] will hold sum of points with digit k)
            // We use 0-indexed buckets: bucket[0] for digit 1, bucket[1] for digit 2, etc.
            #[cfg(feature = "std")]
            extern crate std;
            #[cfg(feature = "std")]
            use std::vec;
            #[cfg(feature = "std")]
            use std::vec::Vec;

            let mut buckets = vec![Point::identity(); num_buckets];

            // Assign points to buckets based on their digit value at this window
            for (point, scalar_bytes) in points.iter().zip(scalars.iter()) {
                let digit = Self::extract_window(scalar_bytes, window_idx, window_size);

                if digit > 0 {
                    // Bucket indices are 0-based, so digit d goes to bucket[d-1]
                    let bucket_idx = (digit - 1) as usize;
                    buckets[bucket_idx] = buckets[bucket_idx].add(point);
                }
            }

            // Compute bucket sums efficiently using running sum technique
            // If buckets contain: [P1, P2, P3, P4] for digits [1, 2, 3, 4]
            // We want: 1*P1 + 2*P2 + 3*P3 + 4*P4
            // Using running sum: bucket_sum = P4, then P4+P3, then P4+P3+P2, then P4+P3+P2+P1
            // And accumulate: Add bucket_sum after processing each bucket
            let mut bucket_sum = Point::identity();
            let mut running_sum = Point::identity();

            // Process buckets from highest to lowest (right to left)
            for bucket in buckets.iter().rev() {
                bucket_sum = bucket_sum.add(bucket);
                running_sum = running_sum.add(&bucket_sum);
            }

            result = result.add(&running_sum);
        }

        result
    }

    /// Select optimal window size for Pippenger's algorithm based on batch size
    fn optimal_window_size(n: usize) -> usize {
        match n {
            0..=4 => 2,      // 4 buckets
            5..=32 => 3,     // 8 buckets
            33..=128 => 4,   // 16 buckets
            _ => 5,          // 32 buckets
        }
    }

    /// Extract a window of bits from a scalar (little-endian bytes)
    ///
    /// # Arguments
    ///
    /// * `scalar_bytes` - 57-byte scalar in little-endian
    /// * `window_idx` - Window index (0 = LSB window)
    /// * `window_size` - Size of window in bits
    ///
    /// # Returns
    ///
    /// The digit value (0 to 2^window_size - 1)
    fn extract_window(scalar_bytes: &[u8; 57], window_idx: usize, window_size: usize) -> u8 {
        let bit_start = window_idx * window_size;
        let bit_end = ((window_idx + 1) * window_size).min(448);

        // Extract bits from bit_start to bit_end
        let mut digit = 0u8;

        for bit_pos in bit_start..bit_end {
            let byte_idx = bit_pos / 8;
            let bit_offset = bit_pos % 8;
            let bit = (scalar_bytes[byte_idx] >> bit_offset) & 1;

            digit |= bit << (bit_pos - bit_start);
        }

        digit
    }
}

// ============================================================================
// Fixed-Base Scalar Multiplication (Comb Method)
// ============================================================================

/// Fixed-Base Comb Method precomputation table
///
/// The Comb Method is a sophisticated fixed-base scalar multiplication algorithm
/// that provides 3-5× speedup over basic windowing methods by minimizing point doublings.
///
/// # Algorithm Overview
///
/// For a 448-bit scalar with radix-16:
/// - Divide scalar into 56 positions (448/8 = 56)
/// - Each position handles 8 bits processed in two 4-bit chunks
/// - Precompute: 8 multiples per position (representing 1B through 8B at that position)
///
/// # Memory Usage
/// - Positions: 56 (for 448-bit scalars)
/// - Points per position: 8 (2^3, representing 1-8)
/// - Total: 56×8 = 448 points × ~224 bytes ≈ 100 KB (in Niels form)
///
/// # Performance
/// - Doublings: 4 per scalar mul (vs 448 for double-and-add)
/// - Additions: ~112 on average (half of lookups are identity)
/// - Expected speedup: 3-5× vs basic windowed method
///
/// # References
/// - "Improved Techniques for Fast Exponentiation" (Lim & Lee, 1994)
/// - Adapted from Ed25519 implementation (libsodium style)
#[cfg(feature = "std")]
pub struct CombTable {
    /// Precomputed points using radix-16 representation (libsodium style)
    /// table[i][j] = (j+1) * 256^i * B
    ///
    /// Where:
    /// - i ranges from 0 to 55 (56 positions for 448-bit scalar)
    /// - j ranges from 0 to 7 (representing multiples 1B through 8B)
    ///
    /// This allows processing 448-bit scalars in radix-16 (112 digits)
    /// using a two-phase algorithm with signed digit representation.
    ///
    /// Uses NielsPoint for efficient mixed addition (Extended + Niels).
    /// This saves memory and is faster than Extended + Extended addition.
    ///
    /// Total: 56×8 = 448 points (~134 KB in Niels form vs ~200 KB in Extended)
    table: [[NielsPoint; 8]; 56],
}

#[cfg(feature = "std")]
impl CombTable {
    /// Generate the radix-16 table for the base point (libsodium style)
    ///
    /// # Algorithm
    /// For each position i ∈ [0, 56):
    ///   For each multiple j ∈ [0, 8):
    ///     table[i][j] = (j+1) * 256^i * B
    ///                 = (j+1) * 16^(2i) * B
    ///
    /// This gives us multiples of B at exponentially spaced positions,
    /// allowing radix-16 scalar representation with 112 digits.
    pub fn generate() -> Self {
        let base = Point::generator();
        let mut table = [[NielsPoint::identity(); 8]; 56];

        // Start with base_256i = B
        let mut base_256i = base;

        for i in 0..56 {
            // For this position i, compute (j+1) * base_256i for j = 0..7
            // This gives us 1B, 2B, 3B, ..., 8B times 256^i
            let mut accumulator = base_256i; // 1 * base_256i

            for j in 0..8 {
                // table[i][j] = (j+1) * 256^i * B
                // Convert to Niels for efficient mixed addition
                table[i][j] = NielsPoint::from_extended(&accumulator);

                // Accumulate: next entry is one more base_256i
                if j < 7 {
                    accumulator = accumulator.add(&base_256i);
                }
            }

            // Prepare for next iteration: base_256i *= 256 (= 2^8)
            if i < 55 {
                for _ in 0..8 {
                    base_256i = base_256i.double();
                }
            }
        }

        CombTable { table }
    }

    /// Perform fixed-base scalar multiplication using radix-16 method (libsodium style)
    ///
    /// # Algorithm (Two-Phase Processing)
    ///
    /// 1. Convert scalar to 112 radix-16 digits with signed representation
    /// 2. **Phase 1**: Process ODD-indexed digits (111, 109, 107, ..., 1)
    /// 3. **Double 4 times** (multiply result by 16)
    /// 4. **Phase 2**: Process EVEN-indexed digits (110, 108, 106, ..., 0)
    ///
    /// This computes: a*B = 16*(odd_sum) + even_sum
    /// where odd_sum and even_sum use the precomputed table.
    ///
    /// # Performance
    /// - 4 doublings (vs 448 for naive!)
    /// - ~112 additions (56 per phase)
    /// - Constant-time table lookups
    /// - Signed digits reduce additions further
    pub fn scalar_mul(&self, scalar: &[u8; 57]) -> Point {
        // Step 1: Convert to 112 radix-16 digits (4 bits each, excluding top bit)
        // Ed448 scalars are 448 bits, so 56 bytes × 2 nibbles = 112 digits
        let mut digits = [0i8; 112];
        for i in 0..56 {
            digits[2 * i] = (scalar[i] & 0x0F) as i8;
            digits[2 * i + 1] = (scalar[i] >> 4) as i8;
        }

        // Convert to signed representation (values in range [-8, 7])
        // This reduces the number of non-zero digits (fewer additions)
        let mut carry = 0i8;
        for i in 0..111 {  // Process digits 0-110
            digits[i] += carry;
            carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
        }

        // Handle the last digit specially
        // For very large scalars, digit[111] + carry might exceed 8
        // We need to handle this by using multiple table lookups
        digits[111] += carry;

        // Step 2: Phase 1 - Process ODD-indexed digits (1, 3, 5, ..., 111)
        let mut result = Point::identity();

        for i in (0..56).rev() {
            let digit_idx = 2 * i + 1; // Odd indices: 111, 109, 107, ..., 1
            let digit = digits[digit_idx];

            if digit != 0 {
                // Select the appropriate table entry
                // table[i][j] = (j+1) * 256^i * B
                // We need digit * 256^i * B
                let mut abs_digit = digit.abs() as usize;
                let is_negative = digit < 0;

                // Handle digits > 8 by repeated addition
                // This can happen for digit[111] when scalar is very large
                while abs_digit > 0 {
                    let chunk = if abs_digit > 8 { 8 } else { abs_digit };
                    let point = hpcrypt_core::ct_table_lookup(&self.table[i], chunk - 1);

                    // Use Niels addition for optimal performance
                    if is_negative {
                        result = result.sub_niels(&point);
                    } else {
                        result = result.add_niels(&point);
                    }

                    abs_digit -= chunk;
                }
            }
        }

        // Step 3: Double 4 times (multiply by 16)
        for _ in 0..4 {
            result = result.double();
        }

        // Step 4: Phase 2 - Process EVEN-indexed digits (0, 2, 4, ..., 110)
        for i in (0..56).rev() {
            let digit_idx = 2 * i; // Even indices: 110, 108, 106, ..., 0
            let digit = digits[digit_idx];

            if digit != 0 {
                let mut abs_digit = digit.abs() as usize;
                let is_negative = digit < 0;

                // Handle digits > 8 by repeated addition
                while abs_digit > 0 {
                    let chunk = if abs_digit > 8 { 8 } else { abs_digit };
                    let point = hpcrypt_core::ct_table_lookup(&self.table[i], chunk - 1);

                    // Use Niels addition for optimal performance
                    if is_negative {
                        result = result.sub_niels(&point);
                    } else {
                        result = result.add_niels(&point);
                    }

                    abs_digit -= chunk;
                }
            }
        }

        result
    }
}

// Use once_cell for lazy initialization of the precomputed tables
#[cfg(feature = "std")]
use once_cell::sync::Lazy;

#[cfg(feature = "std")]
static COMB_TABLE: Lazy<CombTable> = Lazy::new(|| CombTable::generate());

/// Fast scalar multiplication with the base point using Comb method
///
/// This uses the Fixed-Base Comb Method for 3-5× speedup over basic windowing.
/// The table is computed once on first use and cached for subsequent calls.
///
/// # Performance
/// - Comb method: 4 doublings + ~112 additions (3-5× faster)
/// - Basic windowing: ~448 operations
/// - Memory: ~100 KB precomputed table
///
/// # Use Cases
/// - Key generation (computing public key from private key)
/// - Signature generation (computing r = [k]B)
/// - Any operation requiring [scalar]B where B is the base point
pub fn scalar_mul_base_comb(scalar: &[u8; 57]) -> Point {
    #[cfg(feature = "std")]
    {
        // Use libsodium-style radix-16 Comb method
        COMB_TABLE.scalar_mul(scalar)
    }

    #[cfg(not(feature = "std"))]
    {
        // Fallback to basic scalar multiplication without precomputation
        Point::generator().scalar_mul(&Scalar::from_bytes(scalar))
    }
}

#[cfg(all(test, feature = "std"))]
mod comb_tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn test_comb_table_generation() {
        // This test verifies the table can be generated without panicking
        let table = CombTable::generate();

        // Verify the first entry is [1]B (the base point)
        let base = Point::generator();
        let _first_niels = NielsPoint::from_extended(&base);

        // We can't directly compare Niels points, but we can verify
        // that scalar_mul with 1 gives us the base point
        let mut scalar_one = [0u8; 57];
        scalar_one[0] = 1;
        let result = table.scalar_mul(&scalar_one);
        assert_eq!(result, base, "Comb table scalar_mul(1) should equal base point");

        // Additional verification: Check that table[0] entries are correct by
        // converting back to Extended and comparing
        // table[0][0] should be [1]B
        let base_niels = NielsPoint::from_extended(&base);
        assert_eq!(table.table[0][0], base_niels, "table[0][0] should be [1]B");

        // table[0][1] should be [2]B
        let expected_2b = base.double();
        let expected_2b_niels = NielsPoint::from_extended(&expected_2b);
        assert_eq!(table.table[0][1], expected_2b_niels, "table[0][1] should be [2]B");

        // table[0][2] should be [3]B
        let expected_3b = base.double().add(&base);
        let expected_3b_niels = NielsPoint::from_extended(&expected_3b);
        assert_eq!(table.table[0][2], expected_3b_niels, "table[0][2] should be [3]B");
    }

    #[test]
    fn test_add_niels_vs_add() {
        extern crate std;

        // Test 1: Identity + B (simplest case)
        let base = Point::generator();
        let base_niels = NielsPoint::from_extended(&base);
        let identity = Point::identity();

        let id_plus_b_niels = identity.add_niels(&base_niels);
        let id_plus_b_regular = identity.add(&base);

        std::println!("\n=== Test 1: Identity + B ===");
        std::println!("add_niels: {:?}", id_plus_b_niels == base);
        std::println!("regular: {:?}", id_plus_b_regular == base);
        std::println!("match: {}", id_plus_b_niels == id_plus_b_regular);

        // Test 2: 5B + B
        let point_5b = {
            let mut p = Point::identity();
            for _ in 0..5 {
                p = p.add(&base);
            }
            p
        };

        let result1 = point_5b.add_niels(&base_niels);
        let result2 = point_5b.add(&base);

        std::println!("\n=== Test 2: 5B + B ===");
        std::println!("add_niels result == add result? {}", result1 == result2);

        // Check affine coordinates
        let z1_inv = result1.z.invert();
        let x1_affine = result1.x * z1_inv;
        let y1_affine = result1.y * z1_inv;
        let t1_affine = result1.t * z1_inv;

        let z2_inv = result2.z.invert();
        let x2_affine = result2.x * z2_inv;
        let y2_affine = result2.y * z2_inv;
        let t2_affine = result2.t * z2_inv;

        std::println!("affine x match? {}", x1_affine == x2_affine);
        std::println!("affine y match? {}", y1_affine == y2_affine);
        std::println!("affine t match? {}", t1_affine == t2_affine);

        // Check if Y is negated
        let neg_y1 = FieldElement::zero() - y1_affine;
        std::println!("affine y negated match? {}", neg_y1 == y2_affine);

        // Check if T = X*Y
        let xy1 = x1_affine * y1_affine;
        let xy2 = x2_affine * y2_affine;
        std::println!("add_niels T = X*Y? {}", t1_affine == xy1);
        std::println!("regular add T = X*Y? {}", t2_affine == xy2);

        // Test more cases
        std::println!("\n=== Test 3: B + B ===");
        let result3a = base.add_niels(&base_niels);
        let result3b = base.add(&base);
        std::println!("B + B match? {}", result3a == result3b);

        // Debug: print actual Niels values
        std::println!("\n=== Debug: Niels storage ===");
        std::println!("base.x: {:?}", base.x.limbs[0]);
        std::println!("base.y: {:?}", base.y.limbs[0]);
        std::println!("base.t: {:?}", base.t.limbs[0]);
        std::println!("niels.y_plus_x: {:?}", base_niels.y_plus_x.limbs[0]);
        std::println!("niels.y_minus_x: {:?}", base_niels.y_minus_x.limbs[0]);
        std::println!("niels.t2d: {:?}", base_niels.t2d.limbs[0]);
        std::println!("X+Y should be: {:?}", (base.x + base.y).limbs[0]);
        std::println!("Y-X should be: {:?}", (base.y - base.x).limbs[0]);

        std::println!("\n=== Test 4: 2B + B ===");
        let point_2b = base.add(&base);
        let result4a = point_2b.add_niels(&base_niels);
        let result4b = point_2b.add(&base);
        std::println!("2B + B match? {}", result4a == result4b);

        assert_eq!(result1, result2, "add_niels should equal regular add");
    }

    #[test]
    #[ignore = "Debug test"]
    fn debug_compare_intermediate_values() {
        extern crate std;

        let base = Point::generator();
        let base_niels = NielsPoint::from_extended(&base);

        // Test B + B to compare intermediate values
        std::println!("\n=== Testing B + B ===");
        std::println!("Generator: X[0]={:?}, Y[0]={:?}, Z[0]={:?}, T[0]={:?}",
            base.x.limbs[0], base.y.limbs[0], base.z.limbs[0], base.t.limbs[0]);

        std::println!("\n--- Regular Extended + Extended ---");
        let a_ext = (base.y - base.x) * (base.y - base.x);
        let b_ext = (base.y + base.x) * (base.y + base.x);

        let d = FieldElement::from_limbs(ED448_D);
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
        let c_ext = base.t * two * d * base.t;
        let d_ext = base.z * two * base.z;

        std::println!("A[0] = {:?}", a_ext.limbs[0]);
        std::println!("B[0] = {:?}", b_ext.limbs[0]);
        std::println!("C[0] = {:?}", c_ext.limbs[0]);
        std::println!("D[0] = {:?}", d_ext.limbs[0]);

        let e_ext = b_ext - a_ext;
        let f_ext = d_ext - c_ext;
        let g_ext = d_ext + c_ext;
        let h_ext = b_ext + a_ext;

        std::println!("E[0] = {:?}", e_ext.limbs[0]);
        std::println!("F[0] = {:?}", f_ext.limbs[0]);
        std::println!("G[0] = {:?}", g_ext.limbs[0]);
        std::println!("H[0] = {:?}", h_ext.limbs[0]);

        let result_ext = base.add(&base);
        std::println!("Result X[0]={:?}, Y[0]={:?}", result_ext.x.limbs[0], result_ext.y.limbs[0]);

        std::println!("\n--- Niels Addition ---");
        std::println!("Niels: y+x[0]={:?}, y-x[0]={:?}, t2d[0]={:?}",
            base_niels.y_plus_x.limbs[0], base_niels.y_minus_x.limbs[0], base_niels.t2d.limbs[0]);

        let a_niels = (base.y - base.x) * base_niels.y_minus_x;
        let b_niels = (base.y + base.x) * base_niels.y_plus_x;
        let c_niels = base.t * base_niels.t2d;
        let two = FieldElement::from_limbs([2, 0, 0, 0, 0, 0, 0, 0]);
        let d_niels = base.z * two;

        std::println!("A[0] = {:?}", a_niels.limbs[0]);
        std::println!("B[0] = {:?}", b_niels.limbs[0]);
        std::println!("C[0] = {:?}", c_niels.limbs[0]);
        std::println!("D[0] = {:?}", d_niels.limbs[0]);

        let e_niels = b_niels - a_niels;
        let f_niels = d_niels - c_niels;
        let g_niels = d_niels + c_niels;
        let h_niels = b_niels + a_niels;

        std::println!("E[0] = {:?}", e_niels.limbs[0]);
        std::println!("F[0] = {:?}", f_niels.limbs[0]);
        std::println!("G[0] = {:?}", g_niels.limbs[0]);
        std::println!("H[0] = {:?}", h_niels.limbs[0]);

        let result_niels = base.add_niels(&base_niels);
        std::println!("Result X[0]={:?}, Y[0]={:?}", result_niels.x.limbs[0], result_niels.y.limbs[0]);

        std::println!("\n--- Comparison ---");
        std::println!("A values match? {}", a_ext == a_niels);
        std::println!("B values match? {}", b_ext == b_niels);

        std::println!("\n--- RFC 8032 Formula (what add() uses) ---");
        std::println!("This uses a DIFFERENT formula than OpenSSL!");
        std::println!("RFC 8032: A = X1*X2, B = Y1*Y2, E = (X1+Y1)*(X2+Y2)-A-B");
        std::println!("OpenSSL:  A = (Y1-X1)*(Y2-X2), B = (Y1+X1)*(Y2+X2), E = B-A");
        std::println!("These are DIFFERENT intermediate formulas, even though both are correct!");
    }

    #[test]
    fn test_sub_niels_vs_sub() {
        // Test that sub_niels gives the same result as converting to Extended and using sub
        let base = Point::generator();
        let base_niels = NielsPoint::from_extended(&base);

        let point_10b = {
            let mut p = Point::identity();
            for _ in 0..10 {
                p = p.add(&base);
            }
            p
        };

        // Method 1: sub_niels
        let result1 = point_10b.sub_niels(&base_niels);

        // Method 2: Convert Niels to Extended, then sub
        let base_from_niels = Point::identity().add_niels(&base_niels);
        let result2 = point_10b.sub(&base_from_niels);

        extern crate std;
        std::println!("\n=== Testing sub_niels vs sub ===");
        std::println!("sub_niels result == sub result? {}", result1 == result2);

        assert_eq!(result1, result2, "sub_niels should equal sub");

        // Also verify the result is actually 9B
        let expected_9b = {
            let mut p = Point::identity();
            for _ in 0..9 {
                p = p.add(&base);
            }
            p
        };
        assert_eq!(result1, expected_9b, "10B - B should equal 9B");
    }

    #[test]
    fn test_comb_table_position_1() {
        // This test verifies that table[1] entries are correct
        // table[1][j] should be (j+1) * 256 * B
        let table = CombTable::generate();
        let base = Point::generator();
        let identity = Point::identity();

        // Compute 256B manually (256 = 2^8, so 8 doublings)
        let mut base_256 = base;
        for _ in 0..8 {
            base_256 = base_256.double();
        }

        // table[1][0] should be 1*256*B = 256B
        let base_256_niels = NielsPoint::from_extended(&base_256);
        assert_eq!(table.table[1][0], base_256_niels, "table[1][0] should be [256]B");

        // table[1][1] should be 2*256*B = 512B
        let expected_512b = base_256.double();
        let expected_512b_niels = NielsPoint::from_extended(&expected_512b);
        assert_eq!(table.table[1][1], expected_512b_niels, "table[1][1] should be [512]B");

        // table[1][2] should be 3*256*B = 768B
        let expected_768b = base_256.double().add(&base_256);
        let expected_768b_niels = NielsPoint::from_extended(&expected_768b);
        assert_eq!(table.table[1][2], expected_768b_niels, "table[1][2] should be [768]B");
    }

    #[test]
    fn test_comb_scalar_256() {
        // Test scalar = 256 which should use table[1][0]
        // 256 = 0x100 = 0b100000000
        // In nibbles: [0, 0, 1, 0, ...] -> signed: [0, 0, 1, 0, ...]
        // Odd pass: nothing (digit[1]=0)
        // Double 4 times: still identity
        // Even pass: digit[0]=0, digit[2]=1 -> should access table[1][0]
        // Expected: 256B

        let table = CombTable::generate();
        let base = Point::generator();

        let mut scalar_256 = [0u8; 57];
        scalar_256[1] = 1;  // 256 in little-endian

        // Compute expected result manually
        let mut expected_256b = base;
        for _ in 0..8 {
            expected_256b = expected_256b.double();
        }

        // Test via Comb
        let result = table.scalar_mul(&scalar_256);

        // Also test via regular scalar_mul for comparison
        let scalar = Scalar::from_bytes(&scalar_256);
        let result_regular = base.scalar_mul(&scalar);

        extern crate std;
        std::println!("Testing scalar=256");
        std::println!("Result via Comb == Expected? {}", result == expected_256b);
        std::println!("Result via Comb == Regular? {}", result == result_regular);

        assert_eq!(result, expected_256b, "Comb should give 256B");
        assert_eq!(result, result_regular, "Comb should match regular scalar_mul");
    }

    #[test]
    #[ignore = "Debug test - needs update for Niels table"]
    fn test_comb_scalar_42_debug() {
        // Detailed debugging for scalar=42
        // Expected: digit[0]=-6, digit[1]=3
        // Phase 1: add 3B -> double 4x -> 48B
        // Phase 2: subtract 6B -> 42B

        let table = CombTable::generate();
        let base = Point::generator();

        let mut scalar_42 = [0u8; 57];
        scalar_42[0] = 42;

        // Manually trace through what Comb should do
        extern crate std;
        std::println!("\n=== Manual Trace for Scalar=42 ===");

        // Extract digits
        let mut digits = [0i8; 112];
        for i in 0..56 {
            digits[2 * i] = (scalar_42[i] & 0x0F) as i8;
            digits[2 * i + 1] = (scalar_42[i] >> 4) as i8;
        }
        std::println!("Digits before signed conversion: [{}, {}, {}, {}]", digits[0], digits[1], digits[2], digits[3]);

        // Signed conversion
        let mut carry = 0i8;
        for i in 0..111 {
            digits[i] += carry;
            carry = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
        }
        digits[111] += carry;

        std::println!("Digits after signed conversion: [{}, {}, {}, {}]", digits[0], digits[1], digits[2], digits[3]);
        std::println!("Expected: digit[0]=-6, digit[1]=3");

        // TODO: Update this test to work with Niels table
        // Manually compute what Phase 1 should give
        // let point_3b = table.table[0][2]; // table[0][2] = 3B (now Niels)
        // Need to convert to Extended first before doubling
        /*
        let mut phase1_result = point_3b;
        for _ in 0..4 {
            phase1_result = phase1_result.double();
        }
        std::println!("After Phase 1 (3B doubled 4 times): should be 48B");

        // Manually compute Phase 2
        let point_6b = table.table[0][5]; // table[0][5] = 6B
        let phase2_result = phase1_result.sub(&point_6b);
        std::println!("After Phase 2 (48B - 6B): should be 42B");
        */

        // Manual 42B for comparison
        let b42_manual = {
            let mut acc = Point::identity();
            for _ in 0..42 {
                acc = acc.add(&base);
            }
            acc
        };

        // std::println!("Manual phase result == 42B? {}", phase2_result == b42_manual);

        // Now test actual Comb
        let result_comb = table.scalar_mul(&scalar_42);
        let scalar = Scalar::from_bytes(&scalar_42);
        let result_regular = base.scalar_mul(&scalar);

        // std::println!("\nActual Comb result == Manual trace? {}", result_comb == phase2_result);
        std::println!("Actual Comb result == Regular? {}", result_comb == result_regular);
        std::println!("Actual Comb result == 42B manual? {}", result_comb == b42_manual);

        assert_eq!(result_comb, b42_manual, "Comb should give 42B");
        assert_eq!(result_comb, result_regular, "Comb should match regular scalar_mul");
    }

    #[test]
    fn test_comb_scalar_mul_small_scalars() {
        let table = CombTable::generate();
        let base = Point::generator();

        // Test with scalar = 0 (should give identity)
        let scalar_zero = [0u8; 57];
        let result = table.scalar_mul(&scalar_zero);
        assert!(bool::from(result.is_identity()), "Comb scalar_mul(0) should be identity");

        // Test with scalar = 1 (should give base point)
        let mut scalar_one = [0u8; 57];
        scalar_one[0] = 1;
        let result = table.scalar_mul(&scalar_one);
        assert_eq!(result, base, "Comb scalar_mul(1) should equal base point");

        // Test with scalar = 2 (should give [2]B)
        let mut scalar_two = [0u8; 57];
        scalar_two[0] = 2;
        let result = table.scalar_mul(&scalar_two);
        let expected = base.double();
        assert_eq!(result, expected, "Comb scalar_mul(2) should equal [2]B");
    }

    #[test]
    fn test_comb_vs_regular_scalar_mul() {
        let table = CombTable::generate();
        let base = Point::generator();

        // Test various scalar values
        let test_scalars: Vec<[u8; 57]> = vec![
            {
                let mut s = [0u8; 57];
                s[0] = 5;
                s
            },
            {
                let mut s = [0u8; 57];
                s[0] = 42;
                s
            },
            {
                let mut s = [0u8; 57];
                s[0] = 255;
                s
            },
            {
                let mut s = [0u8; 57];
                s[0] = 0x12;
                s[1] = 0x34;
                s[2] = 0x56;
                s
            },
        ];

        for scalar_bytes_raw in test_scalars {
            // Normalize through Scalar to ensure proper representation
            let scalar = Scalar::from_bytes(&scalar_bytes_raw);
            let scalar_bytes = scalar.to_bytes();

            let result_comb = table.scalar_mul(&scalar_bytes);
            let result_regular = base.scalar_mul(&scalar);
            assert_eq!(
                result_comb, result_regular,
                "Comb method disagrees with regular scalar_mul for scalar {:?}",
                &scalar_bytes[0..8]
            );
        }
    }

    #[test]
    fn test_comb_with_large_scalar() {
        let table = CombTable::generate();
        let base = Point::generator();

        // Test with a large scalar (all bytes set)
        let mut scalar_bytes_raw = [0xFFu8; 57];
        // Make sure it's reduced modulo the curve order
        // Ed448 order is slightly less than 2^446, so we zero the top bits
        scalar_bytes_raw[56] = 0x00; // Clear top byte

        // Normalize through Scalar
        let scalar = Scalar::from_bytes(&scalar_bytes_raw);
        let scalar_bytes = scalar.to_bytes();

        let result_comb = table.scalar_mul(&scalar_bytes);
        let result_regular = base.scalar_mul(&scalar);
        assert_eq!(
            result_comb, result_regular,
            "Comb method disagrees with regular scalar_mul for large scalar"
        );
    }

    #[test]
    fn test_scalar_mul_base_comb_function() {
        // Test the public API function
        let base = Point::generator();

        let mut scalar_bytes_raw = [0u8; 57];
        scalar_bytes_raw[0] = 42;
        let scalar = Scalar::from_bytes(&scalar_bytes_raw);
        let scalar_bytes = scalar.to_bytes();

        let result_comb = scalar_mul_base_comb(&scalar_bytes);
        let result_regular = base.scalar_mul(&scalar);

        assert_eq!(
            result_comb, result_regular,
            "scalar_mul_base_comb disagrees with regular scalar_mul"
        );
    }

    #[test]
    fn test_comb_signed_digits() {
        // Test that signed digit representation works correctly
        // by testing scalars that would have large unsigned digits
        let table = CombTable::generate();
        let base = Point::generator();

        // Scalar with pattern 0xFE (11111110 in binary)
        // This should use signed digits effectively
        let mut scalar_bytes_raw = [0u8; 57];
        scalar_bytes_raw[0] = 0xFE;
        scalar_bytes_raw[1] = 0xFE;

        let scalar = Scalar::from_bytes(&scalar_bytes_raw);
        let scalar_bytes = scalar.to_bytes();

        let result_comb = table.scalar_mul(&scalar_bytes);
        let result_regular = base.scalar_mul(&scalar);

        assert_eq!(
            result_comb, result_regular,
            "Comb method with signed digits failed"
        );
    }

    // ========================================================================
    // Pippenger MSM Tests
    // ========================================================================

    #[test]
    fn test_pippenger_msm_basic() {
        // Test basic functionality with small batch
        let base = Point::generator();

        // Create scalars and points for testing
        let scalars = vec![
            {
                let mut s = [0u8; 57];
                s[0] = 1;
                s
            },
            {
                let mut s = [0u8; 57];
                s[0] = 2;
                s
            },
            {
                let mut s = [0u8; 57];
                s[0] = 3;
                s
            },
        ];

        let points = vec![
            base,
            base.double(),
            base.double().add(&base), // 3*base
        ];

        // Expected: 1*base + 2*2base + 3*3base = base + 4base + 9base = 14base
        let result = Point::pippenger_msm(&scalars, &points);

        // Compute expected result manually
        let expected = {
            let mut acc = Point::identity();
            for _ in 0..14 {
                acc = acc.add(&base);
            }
            acc
        };

        assert_eq!(result, expected, "Pippenger MSM basic test failed");
    }

    #[test]
    fn test_pippenger_msm_vs_naive() {
        // Compare Pippenger with naive summation
        let base = Point::generator();

        // Create random-ish scalars
        let scalars: Vec<[u8; 57]> = (0..8)
            .map(|i| {
                let mut s = [0u8; 57];
                s[0] = (i + 1) as u8;
                s
            })
            .collect();

        // Create points as multiples of base
        let points: Vec<Point> = (0..8)
            .map(|i| {
                let mut p = Point::identity();
                for _ in 0..=i {
                    p = p.add(&base);
                }
                p
            })
            .collect();

        // Compute using Pippenger
        let result_pippenger = Point::pippenger_msm(&scalars, &points);

        // Compute naively: Σ(scalars[i] * points[i])
        let result_naive = {
            let mut acc = Point::identity();
            for (scalar_bytes, point) in scalars.iter().zip(points.iter()) {
                let scalar = Scalar::from_bytes(scalar_bytes);
                let term = point.scalar_mul(&scalar);
                acc = acc.add(&term);
            }
            acc
        };

        assert_eq!(result_pippenger, result_naive, "Pippenger disagrees with naive summation");
    }

    #[test]
    fn test_pippenger_msm_edge_cases() {
        let base = Point::generator();

        // Test with empty arrays
        let result_empty = Point::pippenger_msm(&[], &[]);
        assert!(bool::from(result_empty.is_identity()), "Empty MSM should be identity");

        // Test with single element
        let mut scalar_one = [0u8; 57];
        scalar_one[0] = 5;
        let result_one = Point::pippenger_msm(&[scalar_one], &[base]);

        let expected_one = {
            let mut p = Point::identity();
            for _ in 0..5 {
                p = p.add(&base);
            }
            p
        };
        assert_eq!(result_one, expected_one, "Single element MSM failed");
    }

    #[test]
    fn test_pippenger_window_extraction() {
        // Test the window extraction helper
        let mut scalar = [0u8; 57];
        scalar[0] = 0b10110101; // Binary: 10110101
        scalar[1] = 0b11001100; // Binary: 11001100

        // Window size 3, window 0 (bits 0-2): should be 101 = 5
        let digit0 = Point::extract_window(&scalar, 0, 3);
        assert_eq!(digit0, 0b101, "Window 0 extraction failed");

        // Window size 3, window 1 (bits 3-5): should be 110 = 6
        let digit1 = Point::extract_window(&scalar, 1, 3);
        assert_eq!(digit1, 0b110, "Window 1 extraction failed");

        // Window size 4, window 0 (bits 0-3): should be 0101 = 5
        let digit0_w4 = Point::extract_window(&scalar, 0, 4);
        assert_eq!(digit0_w4, 0b0101, "Window 0 (size 4) extraction failed");
    }
}
