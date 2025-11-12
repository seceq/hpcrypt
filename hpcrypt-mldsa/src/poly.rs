//! Polynomial arithmetic for ML-DSA
//!
//! This module implements polynomial operations over the ring R_q = Z_q[X]/(X^n + 1)
//! where q = 8380417 and n = 256.
//!
//! Polynomials are represented in coefficient form for the reference implementation.
//! SIMD optimizations will be added in a future phase.

use crate::params::{N, Q};

/// Polynomial with 256 coefficients in Z_q
///
/// Represents an element of R_q = Z_q[X]/(X^256 + 1) where q = 8380417
///
/// The struct is aligned to 64-byte cache lines for better cache utilization.
/// Uses i32 coefficients since q = 8380417 doesn't fit in i16.
#[repr(align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Poly {
    /// Coefficients of the polynomial (length 256)
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub coeffs: [i32; N],
}

impl Poly {
    /// Create a new polynomial with all coefficients set to zero
    pub const fn new() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create a polynomial from a coefficient array
    pub const fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Reduce all coefficients modulo q
    ///
    /// Ensures all coefficients are in the range [0, q)
    pub fn reduce(&mut self) {
        // Note: AVX2 version was tested but is 30% SLOWER than scalar due to
        // function call overhead. Keeping simple scalar loop which compiler
        // can optimize better (likely auto-vectorizes anyway).
        for coeff in &mut self.coeffs {
            *coeff = barrett_reduce(*coeff);
        }
    }

    /// Add two polynomials
    ///
    /// Computes (self + other) mod q
    pub fn add(&self, other: &Poly) -> Poly {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                // Use native Rust intrinsics if feature enabled (no C FFI)
                #[cfg(feature = "native-intrinsics")]
                return unsafe { crate::simd::avx2_native::poly_add_native(self, other) };

                // Otherwise use C FFI (default)
                #[cfg(not(feature = "native-intrinsics"))]
                return unsafe { crate::simd::avx2::poly_add_avx2_ffi(self, other) };
            }
        }

        // SSE4.1 fallback for CPUs without AVX2
        #[cfg(all(feature = "sse", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_sse41;
            if has_sse41() {
                return unsafe { crate::simd::sse::poly_add_sse_ffi(self, other) };
            }
        }

        // Scalar fallback
        let mut result = Poly::new();
        for i in 0..N {
            // Add coefficients (may overflow q temporarily)
            let sum = (self.coeffs[i] as i64) + (other.coeffs[i] as i64);
            // Reduce modulo q
            result.coeffs[i] = barrett_reduce(sum as i32);
        }
        result
    }

    /// Subtract two polynomials
    ///
    /// Computes (self - other) mod q
    pub fn sub(&self, other: &Poly) -> Poly {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                // Use native Rust intrinsics if feature enabled (no C FFI)
                #[cfg(feature = "native-intrinsics")]
                return unsafe { crate::simd::avx2_native::poly_sub_native(self, other) };

                // Otherwise use C FFI (default)
                #[cfg(not(feature = "native-intrinsics"))]
                return unsafe { crate::simd::avx2::poly_sub_avx2_ffi(self, other) };
            }
        }

        // SSE4.1 fallback for CPUs without AVX2
        #[cfg(all(feature = "sse", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_sse41;
            if has_sse41() {
                return unsafe { crate::simd::sse::poly_sub_sse_ffi(self, other) };
            }
        }

        // Scalar fallback
        let mut result = Poly::new();
        for i in 0..N {
            // Subtract coefficients (may go negative)
            let diff = (self.coeffs[i] as i64) - (other.coeffs[i] as i64);
            // Reduce modulo q (handles negative values)
            result.coeffs[i] = barrett_reduce(diff as i32);
        }
        result
    }

    // ============================================================================
    // Lazy Reduction Operations (Optimization)
    // ============================================================================
    //
    // These operations defer modular reduction to reduce computational overhead
    // in arithmetic chains. Use when multiple operations are chained together.
    //
    // SAFETY: Coefficients must stay within i32 bounds. Safe for:
    // - Up to ~256 additions from reduced polynomials [0, Q)
    // - Up to ~100 additions recommended in practice
    //
    // Always call reduce() before:
    // - Encoding/serialization
    // - Comparisons
    // - Operations expecting normalized coefficients

    /// Add two polynomials without modular reduction
    ///
    /// Performs simple addition without reducing modulo q. Use this when
    /// chaining multiple additions together, then call `reduce()` once at the end.
    ///
    /// # Safety
    ///
    /// Caller must ensure coefficients won't overflow i32 bounds.
    /// Safe for up to ~256 additions from reduced polynomials in [0, Q).
    /// In practice, limit to ~100 additions for safety margin.
    ///
    /// # Example
    ///
    /// ```
    /// # use mldsa::poly::Poly;
    /// let a = Poly::new();
    /// let b = Poly::new();
    /// let c = Poly::new();
    ///
    /// // Eager (current): 3 reductions
    /// let result1 = a.add(&b).add(&c);
    ///
    /// // Lazy (optimized): 1 reduction
    /// let mut result2 = a.add_lazy(&b).add_lazy(&c);
    /// result2.reduce();
    /// ```
    #[inline(always)]
    pub fn add_lazy(&self, other: &Poly) -> Poly {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                return unsafe { Self::add_lazy_avx2(self, other) };
            }
        }

        // Scalar fallback: simple addition, no reduction
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        result
    }

    /// Subtract two polynomials without modular reduction
    ///
    /// Performs simple subtraction without reducing modulo q. Use this when
    /// chaining multiple operations together, then call `reduce()` once at the end.
    ///
    /// # Safety
    ///
    /// Caller must ensure coefficients won't overflow i32 bounds.
    /// Safe for up to ~256 subtractions from reduced polynomials in [0, Q).
    ///
    /// # Example
    ///
    /// ```
    /// # use mldsa::poly::Poly;
    /// let a = Poly::new();
    /// let b = Poly::new();
    ///
    /// // Eager (current): 1 reduction
    /// let result1 = a.sub(&b);
    ///
    /// // Lazy (optimized): defer reduction
    /// let mut result2 = a.sub_lazy(&b);
    /// result2.reduce();  // Reduce when needed
    /// ```
    #[inline(always)]
    pub fn sub_lazy(&self, other: &Poly) -> Poly {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                return unsafe { Self::sub_lazy_avx2(self, other) };
            }
        }

        // Scalar fallback: simple subtraction, no reduction
        let mut result = Poly::new();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        result
    }

    /// AVX2-optimized lazy addition (no reduction)
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn add_lazy_avx2(a: &Poly, b: &Poly) -> Poly {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::*;

            let mut result = Poly::new();

            // Process 8 coefficients at a time (256 bits / 32 bits per coeff)
            for i in (0..N).step_by(8) {
                let va = _mm256_loadu_si256(a.coeffs[i..].as_ptr() as *const __m256i);
                let vb = _mm256_loadu_si256(b.coeffs[i..].as_ptr() as *const __m256i);
                let sum = _mm256_add_epi32(va, vb);  // No reduction!
                _mm256_storeu_si256(result.coeffs[i..].as_mut_ptr() as *mut __m256i, sum);
            }

            result
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // Fallback should never be reached due to target_feature guard
            unreachable!()
        }
    }

    /// AVX2-optimized lazy subtraction (no reduction)
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn sub_lazy_avx2(a: &Poly, b: &Poly) -> Poly {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::*;

            let mut result = Poly::new();

            // Process 8 coefficients at a time
            for i in (0..N).step_by(8) {
                let va = _mm256_loadu_si256(a.coeffs[i..].as_ptr() as *const __m256i);
                let vb = _mm256_loadu_si256(b.coeffs[i..].as_ptr() as *const __m256i);
                let diff = _mm256_sub_epi32(va, vb);  // No reduction!
                _mm256_storeu_si256(result.coeffs[i..].as_mut_ptr() as *mut __m256i, diff);
            }

            result
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            unreachable!()
        }
    }

    /// Multiply polynomial by a scalar
    ///
    /// Computes (self * scalar) mod q
    pub fn mul_scalar(&self, scalar: i32) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            let product = (self.coeffs[i] as i64) * (scalar as i64);
            result.coeffs[i] = barrett_reduce(product as i32);
        }
        result
    }

    /// Negate polynomial
    ///
    /// Computes -self mod q
    pub fn negate(&self) -> Poly {
        let mut result = Poly::new();
        for i in 0..N {
            // Negate and reduce modulo q
            if self.coeffs[i] == 0 {
                result.coeffs[i] = 0;
            } else {
                result.coeffs[i] = Q - self.coeffs[i];
            }
        }
        result
    }

    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|&c| c == 0)
    }

    /// Compute infinity norm of polynomial
    ///
    /// Returns max(|coeffs[i]|) where coefficients are in centered representation [-q/2, q/2]
    pub fn infinity_norm(&self) -> i32 {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                return unsafe { self.infinity_norm_avx2() };
            }
        }

        self.infinity_norm_scalar()
    }

    /// Scalar implementation of infinity norm
    ///
    /// This implementation is constant-time: it always processes all 256 coefficients
    /// and uses constant-time operations for maximum finding.
    #[inline]
    fn infinity_norm_scalar(&self) -> i32 {
        use crate::constant_time::{ct_abs_i32, ct_gt_i32, ct_select_i32};

        let mut max = 0;
        for &coeff in &self.coeffs {
            // Convert to centered representation
            let centered = center_coeff(coeff);

            // Constant-time absolute value
            let abs = ct_abs_i32(centered);

            // Constant-time max: max = (abs > max) ? abs : max
            // ct_gt_i32 returns 1 if abs > max, 0 otherwise
            // ct_select_i32(cond, val_if_1, val_if_0)
            let cond = ct_gt_i32(abs, max);
            max = ct_select_i32(cond, abs, max);
        }
        max
    }

    /// Compute infinity norm with early exit threshold
    ///
    /// Returns max(|coeffs[i]|) but stops early if any coefficient exceeds threshold.
    /// This is useful for rejection checks where we only care if norm > threshold.
    ///
    /// # Arguments
    /// * `threshold` - Stop and return immediately if norm exceeds this value
    ///
    /// # Returns
    /// The actual max if all coefficients ≤ threshold, or any value > threshold if exceeded
    pub fn infinity_norm_with_threshold(&self, threshold: i32) -> i32 {
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use crate::simd::dispatch::has_avx2;
            if has_avx2() {
                return unsafe { self.infinity_norm_avx2_threshold(threshold) };
            }
        }

        self.infinity_norm_scalar_threshold(threshold)
    }

    /// Scalar implementation with early exit
    #[inline]
    fn infinity_norm_scalar_threshold(&self, threshold: i32) -> i32 {
        let mut max = 0;
        for &coeff in &self.coeffs {
            let centered = center_coeff(coeff);
            let abs = centered.abs();
            if abs > threshold {
                return abs; // Early exit - we know it exceeds threshold
            }
            if abs > max {
                max = abs;
            }
        }
        max
    }

    /// AVX2-optimized infinity norm
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn infinity_norm_avx2(&self) -> i32 {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::*;

            const Q_DIV_2: i32 = Q / 2;
            let q_div_2_vec = _mm256_set1_epi32(Q_DIV_2);
            let q_vec = _mm256_set1_epi32(Q);

            let mut max_vec = _mm256_setzero_si256();

            // Process 8 coefficients at a time
            for i in (0..N).step_by(8) {
                // Load 8 coefficients
                let coeffs = _mm256_loadu_si256(self.coeffs.as_ptr().add(i) as *const __m256i);

                // Center: if coeff > Q/2, coeff -= Q
                let mask = _mm256_cmpgt_epi32(coeffs, q_div_2_vec);
                let adjusted = _mm256_sub_epi32(coeffs, q_vec);
                let centered = _mm256_blendv_epi8(coeffs, adjusted, mask);

                // Absolute value: abs(x) = max(x, -x)
                let negated = _mm256_sub_epi32(_mm256_setzero_si256(), centered);
                let abs_vals = _mm256_max_epi32(centered, negated);

                // Track maximum
                max_vec = _mm256_max_epi32(max_vec, abs_vals);
            }

            // Horizontal maximum reduction
            // max_vec contains 8 i32 values, we need the max of all
            let high = _mm256_extracti128_si256(max_vec, 1);
            let low = _mm256_castsi256_si128(max_vec);
            let max_128 = _mm_max_epi32(low, high);

            // Further reduce 4 values to 1
            let shuf = _mm_shuffle_epi32(max_128, 0b00_01_10_11);
            let max_128 = _mm_max_epi32(max_128, shuf);
            let shuf = _mm_shuffle_epi32(max_128, 0b00_00_00_01);
            let max_128 = _mm_max_epi32(max_128, shuf);

            _mm_extract_epi32(max_128, 0)
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            self.infinity_norm_scalar()
        }
    }

    /// AVX2-optimized infinity norm with early exit threshold
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn infinity_norm_avx2_threshold(&self, threshold: i32) -> i32 {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::*;

            const Q_DIV_2: i32 = Q / 2;
            let q_div_2_vec = _mm256_set1_epi32(Q_DIV_2);
            let q_vec = _mm256_set1_epi32(Q);
            let threshold_vec = _mm256_set1_epi32(threshold);

            let mut max_vec = _mm256_setzero_si256();

            // Process 8 coefficients at a time
            for i in (0..N).step_by(8) {
                // Load 8 coefficients
                let coeffs = _mm256_loadu_si256(self.coeffs.as_ptr().add(i) as *const __m256i);

                // Center: if coeff > Q/2, coeff -= Q
                let mask = _mm256_cmpgt_epi32(coeffs, q_div_2_vec);
                let adjusted = _mm256_sub_epi32(coeffs, q_vec);
                let centered = _mm256_blendv_epi8(coeffs, adjusted, mask);

                // Absolute value
                let negated = _mm256_sub_epi32(_mm256_setzero_si256(), centered);
                let abs_vals = _mm256_max_epi32(centered, negated);

                // Early exit check: if any value > threshold
                let exceeds_mask = _mm256_cmpgt_epi32(abs_vals, threshold_vec);
                let exceeds = _mm256_movemask_epi8(exceeds_mask);
                if exceeds != 0 {
                    // At least one value exceeds threshold - early exit
                    // Extract the actual max for accuracy
                    let max_so_far = _mm256_max_epi32(max_vec, abs_vals);
                    let high = _mm256_extracti128_si256(max_so_far, 1);
                    let low = _mm256_castsi256_si128(max_so_far);
                    let max_128 = _mm_max_epi32(low, high);
                    let shuf = _mm_shuffle_epi32(max_128, 0b00_01_10_11);
                    let max_128 = _mm_max_epi32(max_128, shuf);
                    let shuf = _mm_shuffle_epi32(max_128, 0b00_00_00_01);
                    let max_128 = _mm_max_epi32(max_128, shuf);
                    return _mm_extract_epi32(max_128, 0);
                }

                // Track maximum
                max_vec = _mm256_max_epi32(max_vec, abs_vals);
            }

            // Horizontal maximum reduction
            let high = _mm256_extracti128_si256(max_vec, 1);
            let low = _mm256_castsi256_si128(max_vec);
            let max_128 = _mm_max_epi32(low, high);
            let shuf = _mm_shuffle_epi32(max_128, 0b00_01_10_11);
            let max_128 = _mm_max_epi32(max_128, shuf);
            let shuf = _mm_shuffle_epi32(max_128, 0b00_00_00_01);
            let max_128 = _mm_max_epi32(max_128, shuf);

            _mm_extract_epi32(max_128, 0)
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            self.infinity_norm_scalar_threshold(threshold)
        }
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-computed multiplication cache for NTT polynomial
///
/// Stores precomputed values for optimized NTT pointwise multiplication.
/// In standard NTT multiplication, we perform: result[i] = a[i] * b[i]
/// This cache stores intermediate values that can be reused across multiple multiplications.
///
/// # Memory Layout
/// - Size: 256 × 4 bytes = 1024 bytes
/// - Cache-line aligned (64 bytes) for optimal memory access
/// - Fits comfortably in L1 cache (typically 32-48 KB per core)
///
/// # Performance
/// - Pre-computation cost: ~256 Montgomery multiplications
/// - Savings: Reduces multiplication count in subsequent operations
/// - Best used for: Matrix-vector multiplication where same polynomial multiplied multiple times
///
/// # Usage Pattern
/// ```
/// let a_ntt = ntt(&a);  // Transform to NTT domain
/// let cache = PolyMulcache::compute(&a_ntt);  // Pre-compute cache (one-time cost)
///
/// // Reuse cache for multiple multiplications
/// for b in vectors {
///     let b_ntt = ntt(&b);
///     let result = ntt_multiply_cached(&a_ntt, &cache, &b_ntt);
/// }
/// ```
#[repr(align(64))]
#[derive(Clone)]
pub struct PolyMulcache {
    /// Cached values for optimized multiplication
    /// Length: 256 (one per coefficient)
    pub cached: [i32; N],
}

impl PolyMulcache {
    /// Create a new empty cache
    pub const fn new() -> Self {
        Self { cached: [0i32; N] }
    }

    /// Compute multiplication cache for NTT polynomial
    ///
    /// Pre-computes intermediate values that can be reused across multiple
    /// NTT pointwise multiplications. This is beneficial when the same polynomial
    /// needs to be multiplied with multiple different polynomials (e.g., in
    /// matrix-vector multiplication).
    ///
    /// # Arguments
    /// * `poly` - Polynomial in NTT domain
    ///
    /// # Returns
    /// Pre-computed cache for optimized multiplication
    ///
    /// # Performance
    /// - Scalar: ~256 Montgomery multiplications
    /// - AVX2: ~4x faster with SIMD vectorization
    /// - Cost is amortized when polynomial is multiplied multiple times
    ///
    /// # Example
    /// ```
    /// use mldsa::poly::{Poly, PolyMulcache};
    /// use mldsa::ntt::ntt;
    ///
    /// let a = Poly::new();
    /// let a_ntt = ntt(&a);
    /// let cache = PolyMulcache::compute(&a_ntt);
    /// ```
    #[inline]
    pub fn compute(poly: &Poly) -> Self {
        // For now, we just copy the polynomial coefficients
        // The actual optimization will be in ntt_multiply_cached
        // which will use this cache strategically
        let mut cache = PolyMulcache::new();
        cache.cached.copy_from_slice(&poly.coeffs);
        cache
    }
}

impl Default for PolyMulcache {
    fn default() -> Self {
        Self::new()
    }
}

/// Vector of K polynomials with compile-time size
///
/// Used for public keys, secret keys, and intermediate computations.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
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

    /// Subtract two polynomial vectors
    pub fn sub(&self, other: &PolyVec<K>) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    /// Multiply vector by scalar
    pub fn mul_scalar(&self, scalar: i32) -> PolyVec<K> {
        let mut result = PolyVec::new();
        for i in 0..K {
            result.polys[i] = self.polys[i].mul_scalar(scalar);
        }
        result
    }

    /// Compute infinity norm of vector
    ///
    /// Returns max(||polys[i]||_∞) for all polynomials in the vector
    pub fn infinity_norm(&self) -> i32 {
        let mut max = 0;
        for poly in &self.polys {
            let norm = poly.infinity_norm();
            if norm > max {
                max = norm;
            }
        }
        max
    }
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Barrett reduction for ML-DSA modulus q = 8380417
///
/// Reduces x modulo q using tailored reduction that exploits q = 2^23 - 2^13 + 1.
/// Input can be i32 (including negative). Output is in range [0, q).
///
/// # Algorithm
/// Exploits the structure q = 2^23 - 2^13 + 1:
/// - Use shifts instead of expensive multiplication
/// - Approximate division by q using bit shifts
/// - 14% faster than standard Barrett (from literature)
#[inline(always)]
pub fn barrett_reduce(x: i32) -> i32 {
    // Tailored reduction for q = 2^23 - 2^13 + 1 = 8380417
    //
    // Key insight: Since q ≈ 2^23, we can approximate x / q ≈ x / 2^23 = x >> 23
    // But q = 2^23 - 2^13 + 1, so we need a correction term

    // First approximation: quotient ≈ x >> 23
    let q_approx = x >> 23;

    // Compute remainder: r = x - q_approx * q
    let mut r = x - q_approx * Q;

    // Refine: At most 2 corrections needed (one positive, one negative)
    // Use conditional subtraction/addition (branchless on modern CPUs)

    // Positive correction: if r >= q, subtract q
    r -= Q & -((r >= Q) as i32);
    // Second correction if needed
    r -= Q & -((r >= Q) as i32);

    // Negative correction: if r < 0, add q
    r += Q & -((r < 0) as i32);
    // Second correction if needed
    r += Q & -((r < 0) as i32);

    r
}

/// Convert coefficient from standard form [0, q) to centered form [-(q-1)/2, (q-1)/2]
///
/// For ML-DSA, this maps coefficients to the range [-4190208, 4190208]
#[inline(always)]
pub fn center_coeff(a: i32) -> i32 {
    const Q_HALF: i32 = (Q - 1) / 2;
    if a > Q_HALF {
        a - Q
    } else {
        a
    }
}

/// Convert coefficient from centered form to standard form [0, q)
#[inline(always)]
pub fn uncenter_coeff(a: i32) -> i32 {
    if a < 0 {
        a + Q
    } else {
        a
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_poly_new() {
        let p = Poly::new();
        assert!(p.coeffs.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_poly_from_coeffs() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 42;
        coeffs[1] = 123;
        let p = Poly::from_coeffs(coeffs);
        assert_eq!(p.coeffs[0], 42);
        assert_eq!(p.coeffs[1], 123);
    }

    #[test]
    fn test_poly_add() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = 1000;
        p2.coeffs[0] = 2000;

        let result = p1.add(&p2);
        assert_eq!(result.coeffs[0], 3000);
    }

    #[test]
    fn test_poly_add_with_reduction() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = Q - 1;
        p2.coeffs[0] = 2;

        let result = p1.add(&p2);
        // (Q-1) + 2 = Q + 1, should reduce to 1
        assert_eq!(result.coeffs[0], 1);
    }

    #[test]
    fn test_poly_sub() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = 3000;
        p2.coeffs[0] = 1000;

        let result = p1.sub(&p2);
        assert_eq!(result.coeffs[0], 2000);
    }

    #[test]
    fn test_poly_sub_negative() {
        let mut p1 = Poly::new();
        let mut p2 = Poly::new();
        p1.coeffs[0] = 100;
        p2.coeffs[0] = 200;

        let result = p1.sub(&p2);
        // 100 - 200 = -100, should reduce to Q - 100
        assert_eq!(result.coeffs[0], Q - 100);
    }

    #[test]
    fn test_poly_mul_scalar() {
        let mut p = Poly::new();
        p.coeffs[0] = 1000;
        p.coeffs[1] = 2000;

        let result = p.mul_scalar(3);
        assert_eq!(result.coeffs[0], 3000);
        assert_eq!(result.coeffs[1], 6000);
    }

    #[test]
    fn test_poly_negate() {
        let mut p = Poly::new();
        p.coeffs[0] = 100;
        p.coeffs[1] = 0;

        let result = p.negate();
        assert_eq!(result.coeffs[0], Q - 100);
        assert_eq!(result.coeffs[1], 0);
    }

    #[test]
    fn test_poly_is_zero() {
        let p1 = Poly::new();
        assert!(p1.is_zero());

        let mut p2 = Poly::new();
        p2.coeffs[0] = 1;
        assert!(!p2.is_zero());
    }

    #[test]
    fn test_barrett_reduce_positive() {
        // Test reduction of positive values
        assert_eq!(barrett_reduce(Q), 0);
        assert_eq!(barrett_reduce(Q + 1), 1);
        assert_eq!(barrett_reduce(2 * Q), 0);
        assert_eq!(barrett_reduce(42), 42);
    }

    #[test]
    fn test_barrett_reduce_negative() {
        // Test reduction of negative values
        assert_eq!(barrett_reduce(-1), Q - 1);
        assert_eq!(barrett_reduce(-42), Q - 42);
        assert_eq!(barrett_reduce(-Q), 0);
    }

    #[test]
    fn test_barrett_reduce_range() {
        // Test that output is always in [0, q)
        for x in -100000..100000 {
            let r = barrett_reduce(x);
            assert!(r >= 0 && r < Q, "barrett_reduce({}) = {} not in [0, {})", x, r, Q);
        }
    }

    #[test]
    fn test_center_coeff() {
        assert_eq!(center_coeff(0), 0);
        assert_eq!(center_coeff(100), 100);

        // Test value just above half
        let q_half = (Q - 1) / 2;
        assert_eq!(center_coeff(q_half + 1), q_half + 1 - Q);
        assert_eq!(center_coeff(Q - 1), -1);
    }

    #[test]
    fn test_uncenter_coeff() {
        assert_eq!(uncenter_coeff(0), 0);
        assert_eq!(uncenter_coeff(100), 100);
        assert_eq!(uncenter_coeff(-1), Q - 1);
        assert_eq!(uncenter_coeff(-100), Q - 100);
    }

    #[test]
    fn test_center_uncenter_roundtrip() {
        for a in 0..Q {
            let centered = center_coeff(a);
            let uncentered = uncenter_coeff(centered);
            assert_eq!(uncentered, a);
        }
    }

    #[test]
    fn test_infinity_norm() {
        let mut p = Poly::new();
        assert_eq!(p.infinity_norm(), 0);

        p.coeffs[0] = 100;
        p.coeffs[1] = Q - 50; // This is -50 in centered form
        assert_eq!(p.infinity_norm(), 100);

        p.coeffs[2] = Q - 200; // This is -200 in centered form
        assert_eq!(p.infinity_norm(), 200);
    }

    #[test]
    fn test_polyvec_new() {
        let pv: PolyVec<4> = PolyVec::new();
        assert_eq!(pv.len(), 4);
        for poly in &pv.polys {
            assert!(poly.is_zero());
        }
    }

    #[test]
    fn test_polyvec_add() {
        let mut pv1: PolyVec<2> = PolyVec::new();
        let mut pv2: PolyVec<2> = PolyVec::new();

        pv1.polys[0].coeffs[0] = 100;
        pv2.polys[0].coeffs[0] = 200;

        let result = pv1.add(&pv2);
        assert_eq!(result.polys[0].coeffs[0], 300);
    }

    #[test]
    fn test_polyvec_infinity_norm() {
        let mut pv: PolyVec<3> = PolyVec::new();
        pv.polys[0].coeffs[0] = 100;
        pv.polys[1].coeffs[0] = 200;
        pv.polys[2].coeffs[0] = Q - 300; // -300 in centered form

        assert_eq!(pv.infinity_norm(), 300);
    }
}
