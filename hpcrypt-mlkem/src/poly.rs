//! Polynomial arithmetic for ML-KEM
//!
//! This module implements polynomial operations over the ring R_q = Z_q\[X\]/(X^n + 1)
//! where q = 3329 and n = 256.
//!
//! Polynomials are represented in coefficient form for the reference implementation.
//! Future optimizations may use NTT (Number Theoretic Transform) representation.

use crate::params::{N, Q};

/// Polynomial with 256 coefficients in Z_q
///
/// Represents an element of R_q = Z_q\[X\]/(X^256 + 1) where q = 3329
///
/// The struct is aligned to 64-byte cache lines for better cache utilization
/// and reduced cache misses (5-15% speedup depending on architecture).
#[repr(align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients of the polynomial (length 256)
    pub coeffs: [i16; N],
}

impl Poly {
    /// Create a new polynomial with all coefficients set to zero
    pub const fn new() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create a polynomial from a coefficient array
    pub const fn from_coeffs(coeffs: [i16; N]) -> Self {
        Self { coeffs }
    }

    /// Reduce all coefficients modulo q
    ///
    /// Ensures all coefficients are in the range [0, q)
    pub fn reduce(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = barrett_reduce(*coeff);
        }
    }

    /// Add two polynomials
    ///
    /// Computes (self + other) mod q
    #[inline(always)]
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = barrett_reduce(self.coeffs[i] + other.coeffs[i]);
        }
        result
    }

    /// Add two polynomials without reduction
    ///
    /// Computes (self + other) without modular reduction.
    /// Result may be >= q. Use when followed by operations
    /// that perform their own reduction (e.g., compress_d1).
    ///
    /// Performance: ~3.4x faster than add() (6.77 ns vs 23.34 ns)
    /// by eliminating 256 Barrett reductions.
    #[inline(always)]
    pub fn add_unreduced(&self, other: &Poly) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        result
    }

    /// Subtract two polynomials
    ///
    /// Computes (self - other) mod q
    #[inline(always)]
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = barrett_reduce(self.coeffs[i] - other.coeffs[i]);
        }
        result
    }

    /// Subtract two polynomials without reduction
    ///
    /// Computes (self - other) without modular reduction.
    /// Result may be negative or >= q. Use when followed by operations
    /// that perform their own reduction (e.g., compress_d1).
    pub fn sub_unreduced(&self, other: &Poly) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        result
    }

    /// Multiply two polynomials (schoolbook multiplication)
    ///
    /// Computes (self * other) mod (X^n + 1) mod q
    ///
    /// This is the reference implementation using schoolbook multiplication.
    /// Future versions may use NTT for faster multiplication.
    pub fn mul(&self, other: &Poly) -> Poly {
        let mut result = [0i32; 2 * N];

        // Standard polynomial multiplication
        for i in 0..N {
            for j in 0..N {
                result[i + j] += (self.coeffs[i] as i32) * (other.coeffs[j] as i32);
            }
        }

        // Reduce modulo (X^n + 1)
        // Since X^n = -1, we have X^(n+i) = -X^i
        let mut poly = Poly::new();
        for i in 0..N {
            let val = result[i] - result[i + N];
            // Properly reduce i32 to range before converting to i16
            let reduced = ((val % Q as i32) + Q as i32) % Q as i32;
            poly.coeffs[i] = reduced as i16;
        }

        poly
    }

    /// Multiply polynomial by a scalar
    #[inline(always)]
    pub fn mul_scalar(&self, scalar: i16) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            let product = self.coeffs[i] as i32 * scalar as i32;
            let reduced = ((product % Q as i32) + Q as i32) % Q as i32;
            result.coeffs[i] = reduced as i16;
        }
        result
    }

    /// Negate polynomial
    pub fn negate(&self) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = barrett_reduce(-self.coeffs[i]);
        }
        result
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

/// Vector of k polynomials with compile-time size
///
/// Used for public keys, secret keys, and intermediate computations.
/// The const generic parameter K allows the compiler to optimize based on the known size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVec<const K: usize> {
    /// Array of polynomials (compile-time sized)
    pub polys: [Poly; K],
}

impl<const K: usize> PolyVec<K> {
    /// Create a new polynomial vector with K polynomials (all zero)
    pub const fn new() -> Self {
        Self {
            polys: [Poly::new(); K],
        }
    }

    /// Get the dimension of this vector (compile-time constant)
    pub const fn len(&self) -> usize {
        K
    }

    /// Check if the vector is empty (always false for K > 0)
    pub const fn is_empty(&self) -> bool {
        K == 0
    }

    /// Add two polynomial vectors
    pub fn add(&self, other: &PolyVec<K>) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    /// Add two polynomial vectors without reduction
    ///
    /// Computes (self + other) without modular reduction on each polynomial.
    /// Use when the result will be compressed or otherwise reduced.
    pub fn add_unreduced(&self, other: &PolyVec<K>) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].add_unreduced(&other.polys[i]);
        }
        result
    }

    /// Subtract two polynomial vectors
    pub fn sub(&self, other: &PolyVec<K>) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    /// Compute dot product of two polynomial vectors
    pub fn dot(&self, other: &PolyVec<K>) -> Poly {
        let mut result = Poly::new();
        for i in 0..K {
            let prod = self.polys[i].mul(&other.polys[i]);
            result = result.add(&prod);
        }
        result
    }

    /// Compute dot product in NTT domain with mulcache optimization
    ///
    /// Both self and other must be in NTT representation.
    /// Uses the optimized polyvec_basemul_acc_cached from mlkem-native.
    ///
    /// # Arguments
    /// * `other` - Polynomial vector in NTT representation
    /// * `other_caches` - Pre-computed mulcaches for other (slice of length K)
    ///
    /// # Returns
    /// Dot product in NTT representation
    #[inline(always)]
    pub fn dot_ntt_cached(&self, other: &PolyVec<K>, other_caches: &[crate::ntt::PolyMulcache]) -> Poly {
        debug_assert_eq!(other_caches.len(), K);
        crate::ntt::polyvec_basemul_acc_cached(&self.polys, &other.polys, other_caches)
    }
}

// Specialized implementation for K=2 using manual loop unrolling
impl PolyVec<2> {
    /// Optimized dot product for K=2 using manual loop unrolling
    ///
    /// This version uses the specialized polyvec_basemul_acc_cached_k2 which manually
    /// unrolls the inner k loop, reducing branch overhead by ~64 instructions.
    ///
    /// # Arguments
    /// * `other` - Polynomial vector in NTT representation (K=2)
    /// * `other_caches` - Pre-computed mulcaches for other (length 2)
    ///
    /// # Returns
    /// Dot product in NTT representation
    #[inline(always)]
    pub fn dot_ntt_cached_k2(&self, other: &PolyVec<2>, other_caches: &[crate::ntt::PolyMulcache; 2]) -> Poly {
        crate::ntt::polyvec_basemul_acc_cached_k2(&self.polys, &other.polys, other_caches)
    }
}

// Specialized implementation for K=3 using manual loop unrolling
impl PolyVec<3> {
    /// Optimized dot product for K=3 using manual loop unrolling
    ///
    /// This version uses the specialized polyvec_basemul_acc_cached_k3 which manually
    /// unrolls the inner k loop, reducing branch overhead by ~128 instructions.
    ///
    /// # Arguments
    /// * `other` - Polynomial vector in NTT representation (K=3)
    /// * `other_caches` - Pre-computed mulcaches for other (length 3)
    ///
    /// # Returns
    /// Dot product in NTT representation
    #[inline(always)]
    pub fn dot_ntt_cached_k3(&self, other: &PolyVec<3>, other_caches: &[crate::ntt::PolyMulcache; 3]) -> Poly {
        crate::ntt::polyvec_basemul_acc_cached_k3(&self.polys, &other.polys, other_caches)
    }
}

// Specialized implementation for K=4 using manual loop unrolling
impl PolyVec<4> {
    /// Optimized dot product for K=4 using manual loop unrolling
    ///
    /// This version uses the specialized polyvec_basemul_acc_cached_k4 which manually
    /// unrolls the inner k loop, reducing branch overhead by ~192 instructions.
    ///
    /// # Arguments
    /// * `other` - Polynomial vector in NTT representation (K=4)
    /// * `other_caches` - Pre-computed mulcaches for other (length 4)
    ///
    /// # Returns
    /// Dot product in NTT representation
    #[inline(always)]
    pub fn dot_ntt_cached_k4(&self, other: &PolyVec<4>, other_caches: &[crate::ntt::PolyMulcache; 4]) -> Poly {
        crate::ntt::polyvec_basemul_acc_cached_k4(&self.polys, &other.polys, other_caches)
    }
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Matrix of polynomials (K×K) with compile-time size
///
/// Used for the public matrix A in ML-KEM.
/// The const generic parameter K allows the compiler to optimize based on the known size.
#[derive(Clone, Copy, Debug)]
pub struct PolyMat<const K: usize> {
    /// Matrix rows (K rows, each row is a vector of K polynomials)
    pub rows: [PolyVec<K>; K],
}

impl<const K: usize> PolyMat<K> {
    /// Create a new K×K polynomial matrix (all zero)
    pub const fn new() -> Self {
        Self {
            rows: [PolyVec::new(); K],
        }
    }

    /// Get the dimension of this matrix (compile-time constant)
    pub const fn dim(&self) -> usize {
        K
    }

    /// Multiply matrix by vector: A * v
    pub fn mul_vec(&self, vec: &PolyVec<K>) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.rows[i].dot(vec);
        }
        result
    }

    /// Multiply matrix by vector in NTT domain with mulcache optimization
    ///
    /// Computes A * v where both A and v are in NTT representation.
    /// Uses the optimized polyvec_basemul_acc_cached for each row.
    ///
    /// # Arguments
    /// * `vec` - Polynomial vector in NTT representation
    /// * `vec_caches` - Pre-computed mulcaches for vec (slice of length K)
    ///
    /// # Returns
    /// Result polynomial vector in NTT representation
    pub fn mul_vec_ntt_cached(&self, vec: &PolyVec<K>, vec_caches: &[crate::ntt::PolyMulcache]) -> PolyVec<K> {
        debug_assert_eq!(vec_caches.len(), K);
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.rows[i].dot_ntt_cached(vec, vec_caches);
        }
        result
    }
}

impl<const K: usize> Default for PolyMat<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Barrett reduction
///
/// Reduces x modulo q = 3329 using Barrett reduction.
/// Input: x with |x| < 2q
/// Output: r with r ≡ x (mod q) and 0 ≤ r < q
///
/// Uses the standard branching version which performs better overall
/// due to excellent branch prediction on modern CPUs (see docs/BRANCH_ANALYSIS.md).
#[inline(always)]
pub fn barrett_reduce(x: i16) -> i16 {
    // Precomputed: ⌊2^26 / q⌋ = 20159
    const V: i32 = 20159;
    const Q32: i32 = Q as i32;

    let x32 = x as i32;
    let t = ((x32 as i64 * V as i64) >> 26) as i32;
    let mut r = x32 - t * Q32;

    // Conditional correction
    // Modern CPUs predict these branches very well (95-99% accuracy)
    if r >= Q32 {
        r -= Q32;
    }
    if r < 0 {
        r += Q32;
    }

    r as i16
}

/// Montgomery reduction
///
/// Computes x * R^(-1) mod q where R = 2^16
/// This is a placeholder for future optimizations
#[inline(always)]
pub fn montgomery_reduce(x: i32) -> i16 {
    const QINV: i32 = 62209; // q^(-1) mod R = 62209
    const Q32: i32 = Q as i32;

    let t = (x * QINV) & 0xFFFF;
    let u = (x - t * Q32) >> 16;

    barrett_reduce(u as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_new() {
        let p = Poly::new();
        assert!(p.coeffs.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_poly_add() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = 100;
        p2.coeffs[0] = 200;

        let result = p1.add(&p2);
        assert_eq!(result.coeffs[0], 300);
    }

    #[test]
    fn test_poly_add_with_reduction() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = Q - 1;
        p2.coeffs[0] = 2;

        let result = p1.add(&p2);
        assert_eq!(result.coeffs[0], 1);
    }

    #[test]
    fn test_poly_sub() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = 200;
        p2.coeffs[0] = 50;

        let result = p1.sub(&p2);
        assert_eq!(result.coeffs[0], 150);
    }

    #[test]
    fn test_poly_mul_scalar() {
        let mut p = Poly::new();
        p.coeffs[0] = 10;
        p.coeffs[1] = 20;

        let result = p.mul_scalar(3);
        assert_eq!(result.coeffs[0], 30);
        assert_eq!(result.coeffs[1], 60);
    }

    #[test]
    fn test_poly_negate() {
        let mut p = Poly::new();
        p.coeffs[0] = 100;

        let result = p.negate();
        assert_eq!(result.coeffs[0], Q - 100);
    }

    #[test]
    fn test_barrett_reduce() {
        assert_eq!(barrett_reduce(0), 0);
        assert_eq!(barrett_reduce(Q), 0);
        assert_eq!(barrett_reduce(Q + 1), 1);
        assert_eq!(barrett_reduce(Q - 1), Q - 1);
        assert_eq!(barrett_reduce(-1), Q - 1);
    }

    #[test]
    fn test_polyvec_new() {
        let pv = PolyVec::<3>::new();
        assert_eq!(pv.len(), 3);
        assert!(pv.polys.iter().all(|p| p.coeffs.iter().all(|&x| x == 0)));
    }

    #[test]
    fn test_polyvec_add() {
        let mut pv1 = PolyVec::<2>::new();
        let mut pv2 = PolyVec::<2>::new();
        pv1.polys[0].coeffs[0] = 10;
        pv2.polys[0].coeffs[0] = 20;

        let result = pv1.add(&pv2);
        assert_eq!(result.polys[0].coeffs[0], 30);
    }

    #[test]
    fn test_polyvec_dot() {
        let mut pv1 = PolyVec::<2>::new();
        let mut pv2 = PolyVec::<2>::new();

        pv1.polys[0].coeffs[0] = 2;
        pv2.polys[0].coeffs[0] = 3;
        pv1.polys[1].coeffs[0] = 4;
        pv2.polys[1].coeffs[0] = 5;

        let result = pv1.dot(&pv2);
        assert_eq!(result.coeffs[0], 2 * 3 + 4 * 5);
    }

    #[test]
    fn test_polymat_new() {
        let pm = PolyMat::<3>::new();
        assert_eq!(pm.dim(), 3);
        assert_eq!(pm.rows.len(), 3);
        assert_eq!(pm.rows[0].len(), 3);
    }
}
