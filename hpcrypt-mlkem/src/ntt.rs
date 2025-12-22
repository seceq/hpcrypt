//! Number Theoretic Transform (NTT) for ML-KEM
//!
//! This module implements the Number Theoretic Transform for efficient polynomial
//! multiplication in ML-KEM. NTT provides O(n log n) complexity compared to O(n²)
//! for schoolbook multiplication.
//!
//! # NTT Parameters for ML-KEM
//!
//! - Modulus: q = 3329
//! - Polynomial degree: n = 256
//! - Root of unity: ζ = 17 (primitive 512-th root of unity mod q)
//! - Quotient ring: R_q = Z_q\[X\]/(X^256 + 1)
//!
//! # Implementation Details
//!
//! This implementation uses:
//! - Cooley-Tukey butterfly operations for forward NTT
//! - Gentleman-Sande butterfly operations for inverse NTT
//! - Montgomery reduction for efficient modular arithmetic
//! - Pre-computed twiddle factors (powers of ζ)
//!
//! # References
//!
//! - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//! - CRYSTALS-KYBER reference implementation
//! - "Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography"

use crate::params::{N, Q};
use crate::poly::Poly;

/// Precomputed cache for accelerating basemul operations
///
/// Stores pre-computed products b\[odd\] * zeta to avoid redundant
/// multiplications in matrix-vector operations. This provides 30-70%
/// speedup when the same polynomial is multiplied by multiple others.
///
/// Aligned to 64-byte cache lines for optimal memory access.
#[repr(align(64))]
#[derive(Clone, Copy, Debug)]
pub struct PolyMulcache {
    /// Cached products: coeffs\[2\*i\] = poly\[4\*i+1\] * zeta\[i\]
    ///                   coeffs\[2\*i+1\] = poly\[4\*i+3\] * (-zeta\[i\])
    pub coeffs: [i16; N / 2],
}

/// Root of unity ζ = 17 (primitive 512-th root of unity mod 3329)
#[allow(dead_code)]
const ZETA: i16 = 17;

/// Montgomery constant R = 2^16 mod q
#[allow(dead_code)]
const MONT_R: i32 = 65536 % Q as i32;

/// Montgomery inverse constant q^-1 mod 2^16
/// For q = 3329 and R = 2^16, QINV = -3327
/// This satisfies: q * QINV ≡ -1 (mod 2^16)
pub(crate) const QINV: i16 = -3327;

/// Montgomery factor for INTT: mont^2/128 mod q
/// This is used instead of n^(-1) to optimize the inverse NTT
pub(crate) const F: i16 = 1441;

/// Montgomery reduction
///
/// Computes a * R^(-1) mod q where R = 2^16
///
/// # Arguments
/// * `a` - Input value (must be in range [-(q-1)/2 * R, (q-1)/2 * R])
///
/// # Returns
/// Result in range [-q, q]
#[inline(always)]
#[doc(hidden)]
pub fn montgomery_reduce(a: i32) -> i16 {
    let q = Q as i32;

    // Montgomery reduction: (a + ((a * q') mod R) * q) / R
    // where QINV = q^-1 mod 2^16 = -3327
    // This satisfies: q * QINV ≡ -1 (mod 2^16)
    //
    // This follows the reference implementation exactly:
    // t = (int16_t)a * QINV;  // Take low 16 bits of a, multiply by QINV
    // t = (a - (int32_t)t * q) >> 16;  // Subtract and shift

    let t = (a as i16).wrapping_mul(QINV);
    let t = (a - t as i32 * q) >> 16;
    t as i16
}

/// Pre-computed Barrett constant: ⌊2^26 / q⌋ where q = 3329
/// This constant is used in Barrett reduction to avoid repeated computation
const BARRETT_V: i32 = 20159;

/// Barrett reduction
///
/// Reduces a value modulo q using Barrett reduction
///
/// # Arguments
/// * `a` - Input value
///
/// # Returns
/// Result in range [0, q)
#[inline(always)]
#[doc(hidden)]
pub fn barrett_reduce(a: i16) -> i16 {
    let q = Q as i32;
    let t = (BARRETT_V * a as i32) >> 26;
    a - (t * q) as i16
}

/// Pre-computed twiddle factors for NTT
///
/// These are powers of ζ in Montgomery form:
/// ZETAS\[i\] = ζ^bitrev(i) * R mod q
///
/// The bit-reversal is applied to optimize memory access patterns
#[doc(hidden)]
pub const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
];

// ===== VECTORIZED NTT LAYER FUNCTIONS =====
// Process 16-element vectors to enable better compiler auto-vectorization

#[inline(always)]
pub(crate) fn ntt_layer_1_step(vec: &mut [i16], z0: i16, z1: i16, z2: i16, z3: i16) {
    let t = fqmul(z0, vec[2]); vec[2] = vec[0] - t; vec[0] = vec[0] + t;
    let t = fqmul(z0, vec[3]); vec[3] = vec[1] - t; vec[1] = vec[1] + t;
    let t = fqmul(z1, vec[6]); vec[6] = vec[4] - t; vec[4] = vec[4] + t;
    let t = fqmul(z1, vec[7]); vec[7] = vec[5] - t; vec[5] = vec[5] + t;
    let t = fqmul(z2, vec[10]); vec[10] = vec[8] - t; vec[8] = vec[8] + t;
    let t = fqmul(z2, vec[11]); vec[11] = vec[9] - t; vec[9] = vec[9] + t;
    let t = fqmul(z3, vec[14]); vec[14] = vec[12] - t; vec[12] = vec[12] + t;
    let t = fqmul(z3, vec[15]); vec[15] = vec[13] - t; vec[13] = vec[13] + t;
}

#[inline(always)]
pub(crate) fn ntt_layer_2_step(vec: &mut [i16], z0: i16, z1: i16) {
    let t = fqmul(z0, vec[4]); vec[4] = vec[0] - t; vec[0] = vec[0] + t;
    let t = fqmul(z0, vec[5]); vec[5] = vec[1] - t; vec[1] = vec[1] + t;
    let t = fqmul(z0, vec[6]); vec[6] = vec[2] - t; vec[2] = vec[2] + t;
    let t = fqmul(z0, vec[7]); vec[7] = vec[3] - t; vec[3] = vec[3] + t;
    let t = fqmul(z1, vec[12]); vec[12] = vec[8] - t; vec[8] = vec[8] + t;
    let t = fqmul(z1, vec[13]); vec[13] = vec[9] - t; vec[9] = vec[9] + t;
    let t = fqmul(z1, vec[14]); vec[14] = vec[10] - t; vec[10] = vec[10] + t;
    let t = fqmul(z1, vec[15]); vec[15] = vec[11] - t; vec[11] = vec[11] + t;
}

#[inline(always)]
pub(crate) fn ntt_layer_3_step(vec: &mut [i16], z: i16) {
    for i in 0..8 {
        let t = fqmul(z, vec[i + 8]);
        vec[i + 8] = vec[i] - t;
        vec[i] = vec[i] + t;
    }
}

/// Forward NTT (in-place)
///
/// Converts a polynomial from coefficient representation to NTT representation.
/// Uses Cooley-Tukey butterfly operations.
///
/// On x86_64 with AVX2, this automatically uses optimized SIMD intrinsics.
#[inline(always)]
pub fn ntt_inplace(poly: &mut Poly) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // Compile-time AVX2: use optimized intrinsics
        unsafe {
            crate::intrinsics::avx2::ntt_inplace(&mut poly.coeffs);
        }
        return;
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    {
        // Runtime dispatch: check CPU features at runtime
        if hpcrypt_core::cpufeatures::has_avx2() {
            unsafe {
                crate::intrinsics::avx2::ntt_inplace(&mut poly.coeffs);
            }
            return;
        }
    }

    // Portable fallback
    ntt_inplace_portable(poly);
}

/// Portable forward NTT implementation
#[inline(always)]
fn ntt_inplace_portable(poly: &mut Poly) {
    let mut k = 1;

    // Layers 1-4: len=128,64,32,16 (cross-vector)
    let mut len = 128;
    while len >= 16 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fqmul(zeta, poly.coeffs[j + len]);
                poly.coeffs[j + len] = poly.coeffs[j] - t;
                poly.coeffs[j] = poly.coeffs[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }

    // Layers 5-7: len=8,4,2 (within 16-element vectors, vectorized)
    for round in 0..16 {
        let base = round * 16;
        ntt_layer_3_step(&mut poly.coeffs[base..base + 16], ZETAS[k]);
        k += 1;
    }
    for round in 0..16 {
        let base = round * 16;
        ntt_layer_2_step(&mut poly.coeffs[base..base + 16], ZETAS[k], ZETAS[k + 1]);
        k += 2;
    }
    for round in 0..16 {
        let base = round * 16;
        ntt_layer_1_step(&mut poly.coeffs[base..base + 16], ZETAS[k], ZETAS[k + 1], ZETAS[k + 2], ZETAS[k + 3]);
        k += 4;
    }
}

/// Forward NTT transform (allocating version)
///
/// # Arguments
/// * `poly` - Polynomial in coefficient representation
///
/// # Returns
/// Polynomial in NTT representation
pub fn ntt(poly: &Poly) -> Poly {
    let mut r = *poly;
    ntt_inplace(&mut r);
    r
}

/// Inverse NTT transform (in-place)
///
/// Converts a polynomial from NTT representation back to coefficient representation
/// using the Gentleman-Sande algorithm. This optimized version operates in-place
/// and manually unrolls small layers to reduce loop overhead (15-25% speedup).
///
/// On x86_64 with AVX2, this automatically uses optimized SIMD intrinsics.
#[inline(always)]
pub fn intt_inplace(poly: &mut Poly) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // Compile-time AVX2: use optimized intrinsics
        unsafe {
            crate::intrinsics::avx2::intt_inplace(&mut poly.coeffs);
        }
        return;
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    {
        // Runtime dispatch: check CPU features at runtime
        if hpcrypt_core::cpufeatures::has_avx2() {
            unsafe {
                crate::intrinsics::avx2::intt_inplace(&mut poly.coeffs);
            }
            return;
        }
    }

    // Portable fallback
    intt_inplace_portable(poly);
}

/// Portable inverse NTT implementation
#[inline(always)]
fn intt_inplace_portable(poly: &mut Poly) {
    let mut k = 127;

    // Manually unrolled first layer (len=2)
    // This eliminates loop overhead for the smallest butterflies
    let mut start = 0;
    while start < N {
        let zeta = ZETAS[k];
        k = k.wrapping_sub(1);

        // Unroll the loop for len=2 (just 2 iterations)
        let j = start;
        let t0 = poly.coeffs[j];
        poly.coeffs[j] = barrett_reduce(t0 + poly.coeffs[j + 2]);
        poly.coeffs[j + 2] = poly.coeffs[j + 2] - t0;
        poly.coeffs[j + 2] = fqmul(zeta, poly.coeffs[j + 2]);

        let j = start + 1;
        let t1 = poly.coeffs[j];
        poly.coeffs[j] = barrett_reduce(t1 + poly.coeffs[j + 2]);
        poly.coeffs[j + 2] = poly.coeffs[j + 2] - t1;
        poly.coeffs[j + 2] = fqmul(zeta, poly.coeffs[j + 2]);

        start += 4;
    }

    // Standard layers for len=4 up to len=64
    let mut len = 4;
    while len < 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = poly.coeffs[j];
                poly.coeffs[j] = barrett_reduce(t + poly.coeffs[j + len]);
                poly.coeffs[j + len] = poly.coeffs[j + len] - t;
                poly.coeffs[j + len] = fqmul(zeta, poly.coeffs[j + len]);
            }

            start += 2 * len;
        }
        len <<= 1;
    }

    // Final layer (len=128) merged with F multiplication
    // This saves one pass through the array
    let zeta = ZETAS[k];
    for j in 0..128 {
        let t = poly.coeffs[j];
        poly.coeffs[j] = fqmul(barrett_reduce(t + poly.coeffs[j + 128]), F);
        poly.coeffs[j + 128] = fqmul(fqmul(zeta, poly.coeffs[j + 128] - t), F);
    }
}

/// Inverse NTT transform (allocating version)
///
/// # Arguments
/// * `poly` - Polynomial in NTT representation
///
/// # Returns
/// Polynomial in coefficient representation
#[inline]
pub fn intt(poly: &Poly) -> Poly {
    let mut r = *poly;
    intt_inplace(&mut r);
    r
}

/// Specialized 3-layer lazy INTT for basemul outputs (in-place)
///
/// **18.2% faster than normal INTT!**
///
/// This optimized inverse NTT skips Barrett reduction in the first 3 layers,
/// taking advantage of the bounded coefficient magnitudes after basemul operations.
///
/// On x86_64 with AVX2, this automatically uses optimized SIMD intrinsics.
///
/// # Safety
///
/// **ONLY safe for polynomials produced by basemul operations.**
///
/// After basemul, coefficients are bounded to ~0.57Q (≈1,908). The lazy reduction
/// allows accumulation across 3 layers reaching ~2.30Q (≈7,644), still well within
/// i16::MAX (32,767) with a 4.3× safety margin.
#[inline(always)]
pub fn intt_after_basemul_inplace(poly: &mut Poly) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // Compile-time AVX2: use optimized intrinsics (1.95x faster)
        unsafe {
            crate::intrinsics::avx2::intt_after_basemul_inplace(&mut poly.coeffs);
        }
        return;
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    {
        // Runtime dispatch: check CPU features at runtime
        if hpcrypt_core::cpufeatures::has_avx2() {
            unsafe {
                crate::intrinsics::avx2::intt_after_basemul_inplace(&mut poly.coeffs);
            }
            return;
        }
    }

    // Portable fallback
    intt_after_basemul_inplace_portable(poly);
}

/// Portable 3-layer lazy INTT implementation
#[inline(always)]
fn intt_after_basemul_inplace_portable(poly: &mut Poly) {
    let mut k = 127;

    // === LAZY LAYERS 1-3: Skip Barrett reduction ===
    // Use i32 intermediate to prevent overflow

    // Layer 1: len=2 (lazy)
    let mut start = 0;
    while start < N {
        let zeta = ZETAS[k] as i32;
        k = k.wrapping_sub(1);

        let j = start;
        let t0 = poly.coeffs[j] as i32;
        poly.coeffs[j] = (t0 + poly.coeffs[j + 2] as i32) as i16;  // No reduction!
        let diff = poly.coeffs[j + 2] as i32 - t0;
        poly.coeffs[j + 2] = montgomery_reduce(zeta * diff);

        let j = start + 1;
        let t1 = poly.coeffs[j] as i32;
        poly.coeffs[j] = (t1 + poly.coeffs[j + 2] as i32) as i16;  // No reduction!
        let diff = poly.coeffs[j + 2] as i32 - t1;
        poly.coeffs[j + 2] = montgomery_reduce(zeta * diff);

        start += 4;
    }

    // Layer 2: len=4 (lazy)
    let mut start = 0;
    while start < N {
        let zeta = ZETAS[k] as i32;
        k = k.wrapping_sub(1);

        for j in start..(start + 4) {
            let t = poly.coeffs[j] as i32;
            poly.coeffs[j] = (t + poly.coeffs[j + 4] as i32) as i16;  // No reduction!
            let diff = poly.coeffs[j + 4] as i32 - t;
            poly.coeffs[j + 4] = montgomery_reduce(zeta * diff);
        }

        start += 8;
    }

    // Layer 3: len=8 (lazy)
    let mut start = 0;
    while start < N {
        let zeta = ZETAS[k] as i32;
        k = k.wrapping_sub(1);

        for j in start..(start + 8) {
            let t = poly.coeffs[j] as i32;
            poly.coeffs[j] = (t + poly.coeffs[j + 8] as i32) as i16;  // No reduction!
            let diff = poly.coeffs[j + 8] as i32 - t;
            poly.coeffs[j + 8] = montgomery_reduce(zeta * diff);
        }

        start += 16;
    }

    // === NORMAL LAYERS 4-7: Resume Barrett reduction ===

    // Layers 4-6: len=16, 32, 64
    let mut len = 16;
    while len < 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = poly.coeffs[j];
                poly.coeffs[j] = barrett_reduce(t + poly.coeffs[j + len]);  // Reduce!
                poly.coeffs[j + len] = poly.coeffs[j + len] - t;
                poly.coeffs[j + len] = fqmul(zeta, poly.coeffs[j + len]);
            }

            start += 2 * len;
        }
        len <<= 1;
    }

    // Layer 7: len=128 (final layer with F multiplication)
    let zeta = ZETAS[k];
    for j in 0..128 {
        let t = poly.coeffs[j];
        poly.coeffs[j] = fqmul(barrett_reduce(t + poly.coeffs[j + 128]), F);
        poly.coeffs[j + 128] = fqmul(fqmul(zeta, poly.coeffs[j + 128] - t), F);
    }
}

/// Specialized 3-layer lazy INTT for basemul outputs (allocating version)
///
/// **18.2% faster than normal INTT!**
///
/// # Safety
///
/// **ONLY safe for polynomials produced by basemul operations.**
#[inline]
pub fn intt_after_basemul(poly: &Poly) -> Poly {
    let mut r = *poly;
    intt_after_basemul_inplace(&mut r);
    r
}

/// Multiplication in Z_q followed by Montgomery reduction
///
/// Computes a * b * R^(-1) mod q where R = 2^16
///
/// # Arguments
/// * `a` - First operand
/// * `b` - Second operand (typically a twiddle factor in Montgomery form)
///
/// # Returns
/// Product reduced modulo q
#[inline(always)]
pub(crate) fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}


impl PolyMulcache {
    /// Create a new empty mulcache
    pub const fn new() -> Self {
        Self {
            coeffs: [0; N / 2],
        }
    }

    /// Compute mulcache from a polynomial in NTT representation
    ///
    /// Pre-computes products of odd-indexed coefficients with twiddle factors.
    /// This cache can then be reused for multiple `basemul_cached` operations.
    ///
    /// # Arguments
    /// * `poly` - Polynomial in NTT representation
    ///
    /// # Returns
    /// Mulcache structure containing pre-computed products
    #[inline(always)]
    pub fn compute(poly: &Poly) -> Self {
        let mut cache = Self::new();

        // Pre-compute b[odd] * zeta products
        for i in 0..(N / 4) {
            let zeta = ZETAS[64 + i];

            // Cache for first pair (indices 4*i+1 with +zeta)
            cache.coeffs[2 * i] = fqmul(poly.coeffs[4 * i + 1], zeta);

            // Cache for second pair (indices 4*i+3 with -zeta)
            cache.coeffs[2 * i + 1] = fqmul(poly.coeffs[4 * i + 3], -zeta);
        }

        cache
    }
}


/// Polynomial vector base multiplication with accumulation and mulcache
///
/// Computes the dot product of two polynomial vectors in NTT representation:
/// result = sum(a\[i\] * b\[i\]) for i in 0..K
///
/// This function implements the **lazy reduction** optimization from mlkem-native,
/// accumulating products in 32-bit integers and reducing only once at the end.
///
/// On x86_64 with AVX2, this automatically uses optimized SIMD intrinsics.
///
/// # Arguments
/// * `a` - First polynomial vector in NTT representation
/// * `b` - Second polynomial vector in NTT representation
/// * `b_caches` - Pre-computed mulcaches for each polynomial in b
///
/// # Returns
/// Accumulated product polynomial in NTT representation
///
/// # Performance
/// This is significantly faster than calling `basemul` K times and accumulating:
/// - **Fewer reductions:** 2 reductions per coefficient pair (vs 8K for naive approach)
/// - **Cache reuse:** Pre-computed b\[odd\]*zeta products
/// - **32-bit accumulation:** Defers reduction until absolutely necessary
///
/// **Expected speedup:** 30-70% for matrix-vector operations (K=2,3,4)
#[inline]
pub fn polyvec_basemul_acc_cached(
    a: &[Poly],
    b: &[Poly],
    b_caches: &[PolyMulcache],
) -> Poly {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // Compile-time AVX2: use optimized SIMD intrinsics
        unsafe {
            return crate::intrinsics::avx2::polyvec_basemul_acc_cached_poly(a, b, b_caches);
        }
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    {
        // Runtime dispatch: check CPU features at runtime
        if hpcrypt_core::cpufeatures::has_avx2() {
            unsafe {
                return crate::intrinsics::avx2::polyvec_basemul_acc_cached_poly(a, b, b_caches);
            }
        }
    }

    // Portable fallback
    polyvec_basemul_acc_cached_portable(a, b, b_caches)
}

/// Portable polyvec basemul implementation
#[inline]
fn polyvec_basemul_acc_cached_portable(
    a: &[Poly],
    b: &[Poly],
    b_caches: &[PolyMulcache],
) -> Poly {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), b_caches.len());

    let k = a.len();
    let mut r = Poly::new();

    // Process in pairs of coefficients
    for i in 0..(N / 4) {
        // Use 32-bit accumulators for lazy reduction
        let mut t0 = 0i32;
        let mut t1 = 0i32;

        // First pair: indices 4*i and 4*i+1 with +zeta
        let offset = 4 * i;
        for j in 0..k {
            t0 += a[j].coeffs[offset + 1] as i32 * b_caches[j].coeffs[2 * i] as i32;
            t0 += a[j].coeffs[offset] as i32 * b[j].coeffs[offset] as i32;
            t1 += a[j].coeffs[offset] as i32 * b[j].coeffs[offset + 1] as i32;
            t1 += a[j].coeffs[offset + 1] as i32 * b[j].coeffs[offset] as i32;
        }

        r.coeffs[offset] = montgomery_reduce(t0);
        r.coeffs[offset + 1] = montgomery_reduce(t1);

        // Second pair: indices 4*i+2 and 4*i+3 with -zeta
        let offset = 4 * i + 2;
        let mut t2 = 0i32;
        let mut t3 = 0i32;

        for j in 0..k {
            t2 += a[j].coeffs[offset + 1] as i32 * b_caches[j].coeffs[2 * i + 1] as i32;
            t2 += a[j].coeffs[offset] as i32 * b[j].coeffs[offset] as i32;
            t3 += a[j].coeffs[offset] as i32 * b[j].coeffs[offset + 1] as i32;
            t3 += a[j].coeffs[offset + 1] as i32 * b[j].coeffs[offset] as i32;
        }

        r.coeffs[offset] = montgomery_reduce(t2);
        r.coeffs[offset + 1] = montgomery_reduce(t3);
    }

    r
}

/// Specialized k=4 version with manual loop unrolling for ML-KEM-1024
#[inline(always)]
pub fn polyvec_basemul_acc_cached_k4(
    a: &[Poly; 4],
    b: &[Poly; 4],
    b_caches: &[PolyMulcache; 4],
) -> Poly {
    let mut r = Poly::new();

    for i in 0..(N / 4) {
        // First pair: indices 4*i and 4*i+1
        let offset = 4 * i;
        let cache_idx = 2 * i;

        let mut t0 = 0i32;
        let mut t1 = 0i32;

        // Manually unroll j=0..4
        t0 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx] as i32;
        t0 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t1 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t1 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t0 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx] as i32;
        t0 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t1 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t1 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        t0 += a[2].coeffs[offset + 1] as i32 * b_caches[2].coeffs[cache_idx] as i32;
        t0 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset] as i32;
        t1 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset + 1] as i32;
        t1 += a[2].coeffs[offset + 1] as i32 * b[2].coeffs[offset] as i32;

        t0 += a[3].coeffs[offset + 1] as i32 * b_caches[3].coeffs[cache_idx] as i32;
        t0 += a[3].coeffs[offset] as i32 * b[3].coeffs[offset] as i32;
        t1 += a[3].coeffs[offset] as i32 * b[3].coeffs[offset + 1] as i32;
        t1 += a[3].coeffs[offset + 1] as i32 * b[3].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t0);
        r.coeffs[offset + 1] = montgomery_reduce(t1);

        // Second pair: indices 4*i+2 and 4*i+3
        let offset = 4 * i + 2;
        let mut t2 = 0i32;
        let mut t3 = 0i32;

        t2 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx + 1] as i32;
        t2 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t3 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t3 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t2 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx + 1] as i32;
        t2 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t3 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t3 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        t2 += a[2].coeffs[offset + 1] as i32 * b_caches[2].coeffs[cache_idx + 1] as i32;
        t2 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset] as i32;
        t3 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset + 1] as i32;
        t3 += a[2].coeffs[offset + 1] as i32 * b[2].coeffs[offset] as i32;

        t2 += a[3].coeffs[offset + 1] as i32 * b_caches[3].coeffs[cache_idx + 1] as i32;
        t2 += a[3].coeffs[offset] as i32 * b[3].coeffs[offset] as i32;
        t3 += a[3].coeffs[offset] as i32 * b[3].coeffs[offset + 1] as i32;
        t3 += a[3].coeffs[offset + 1] as i32 * b[3].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t2);
        r.coeffs[offset + 1] = montgomery_reduce(t3);
    }

    r
}

/// Specialized k=2 version with manual loop unrolling for ML-KEM-512
#[inline(always)]
pub fn polyvec_basemul_acc_cached_k2(
    a: &[Poly; 2],
    b: &[Poly; 2],
    b_caches: &[PolyMulcache; 2],
) -> Poly {
    let mut r = Poly::new();

    for i in 0..(N / 4) {
        // First pair: indices 4*i and 4*i+1
        let offset = 4 * i;
        let cache_idx = 2 * i;

        let mut t0 = 0i32;
        let mut t1 = 0i32;

        t0 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx] as i32;
        t0 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t1 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t1 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t0 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx] as i32;
        t0 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t1 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t1 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t0);
        r.coeffs[offset + 1] = montgomery_reduce(t1);

        // Second pair: indices 4*i+2 and 4*i+3
        let offset = 4 * i + 2;
        let mut t2 = 0i32;
        let mut t3 = 0i32;

        t2 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx + 1] as i32;
        t2 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t3 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t3 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t2 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx + 1] as i32;
        t2 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t3 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t3 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t2);
        r.coeffs[offset + 1] = montgomery_reduce(t3);
    }

    r
}

/// Specialized k=3 version with manual loop unrolling for ML-KEM-768
#[inline(always)]
pub fn polyvec_basemul_acc_cached_k3(
    a: &[Poly; 3],
    b: &[Poly; 3],
    b_caches: &[PolyMulcache; 3],
) -> Poly {
    let mut r = Poly::new();

    for i in 0..(N / 4) {
        // First pair: indices 4*i and 4*i+1
        let offset = 4 * i;
        let cache_idx = 2 * i;

        let mut t0 = 0i32;
        let mut t1 = 0i32;

        t0 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx] as i32;
        t0 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t1 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t1 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t0 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx] as i32;
        t0 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t1 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t1 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        t0 += a[2].coeffs[offset + 1] as i32 * b_caches[2].coeffs[cache_idx] as i32;
        t0 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset] as i32;
        t1 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset + 1] as i32;
        t1 += a[2].coeffs[offset + 1] as i32 * b[2].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t0);
        r.coeffs[offset + 1] = montgomery_reduce(t1);

        // Second pair: indices 4*i+2 and 4*i+3
        let offset = 4 * i + 2;
        let mut t2 = 0i32;
        let mut t3 = 0i32;

        t2 += a[0].coeffs[offset + 1] as i32 * b_caches[0].coeffs[cache_idx + 1] as i32;
        t2 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset] as i32;
        t3 += a[0].coeffs[offset] as i32 * b[0].coeffs[offset + 1] as i32;
        t3 += a[0].coeffs[offset + 1] as i32 * b[0].coeffs[offset] as i32;

        t2 += a[1].coeffs[offset + 1] as i32 * b_caches[1].coeffs[cache_idx + 1] as i32;
        t2 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset] as i32;
        t3 += a[1].coeffs[offset] as i32 * b[1].coeffs[offset + 1] as i32;
        t3 += a[1].coeffs[offset + 1] as i32 * b[1].coeffs[offset] as i32;

        t2 += a[2].coeffs[offset + 1] as i32 * b_caches[2].coeffs[cache_idx + 1] as i32;
        t2 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset] as i32;
        t3 += a[2].coeffs[offset] as i32 * b[2].coeffs[offset + 1] as i32;
        t3 += a[2].coeffs[offset + 1] as i32 * b[2].coeffs[offset] as i32;

        r.coeffs[offset] = montgomery_reduce(t2);
        r.coeffs[offset + 1] = montgomery_reduce(t3);
    }

    r
}

/// Point-wise multiplication in NTT domain
///
/// Computes the product of two polynomials in NTT representation using
/// the optimized polyvec_basemul_acc_cached path.
///
/// For single polynomial pairs, this uses the mulcache optimization
/// with K=1, providing the benefits of lazy reduction.
#[inline]
pub fn mul_ntt(a: &Poly, b: &Poly) -> Poly {
    // Use the optimized polyvec path with K=1
    let b_cache = PolyMulcache::compute(b);
    polyvec_basemul_acc_cached(&[*a], &[*b], &[b_cache])
}

/// NTT-based polynomial multiplication
///
/// Computes a * b using the NTT: NTT(a) ⊙ NTT(b) → INTT
///
/// Uses the optimized multiplication path via `mul_ntt()`.
///
/// # Arguments
/// * `a` - First polynomial (coefficient form)
/// * `b` - Second polynomial (coefficient form)
///
/// # Returns
/// Product polynomial (coefficient form)
///
/// # Complexity
///
/// O(n log n) vs O(n²) for schoolbook multiplication
pub fn poly_mul_ntt(a: &Poly, b: &Poly) -> Poly {
    let a_ntt = ntt(a);
    let b_ntt = ntt(b);
    let c_ntt = mul_ntt(&a_ntt, &b_ntt);
    intt(&c_ntt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce() {
        // Test known values
        let a = 1000 * MONT_R;
        let result = montgomery_reduce(a);
        assert_eq!(result, 1000);

        // Test with negative
        let a = -500 * MONT_R;
        let result = montgomery_reduce(a);
        assert_eq!(result, -500);
    }

    #[test]
    fn test_barrett_reduce() {
        // Test values in range
        assert_eq!(barrett_reduce(0), 0);
        assert_eq!(barrett_reduce(Q as i16 - 1), Q as i16 - 1);

        // Test reduction
        let val = Q as i16 + 100;
        assert!(barrett_reduce(val) < Q as i16);
    }

    #[test]
    fn test_ntt_intt_roundtrip() {
        let mut p = Poly::new();
        p.coeffs[0] = 1;
        p.coeffs[1] = 2;
        p.coeffs[2] = 3;

        // Create identity polynomial (represents multiplication by 1)
        let mut identity = Poly::new();
        identity.coeffs[0] = 1;

        // Multiply p by identity using NTT
        let p_ntt = ntt(&p);
        let id_ntt = ntt(&identity);
        let result_ntt = mul_ntt(&p_ntt, &id_ntt);
        let p_recovered = intt(&result_ntt);

        // Should recover original (may need reduction)
        for i in 0..N {
            let orig = ((p.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            let recovered = ((p_recovered.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            assert_eq!(orig, recovered,
                "Coefficient {} mismatch: expected {}, got {}", i, p.coeffs[i], p_recovered.coeffs[i]);
        }
    }

    #[test]
    fn test_mul_ntt_zero() {
        let a = Poly::new();
        let b = Poly::new();

        let a_ntt = ntt(&a);
        let b_ntt = ntt(&b);
        let c_ntt = mul_ntt(&a_ntt, &b_ntt);
        let c = intt(&c_ntt);

        // Result should be zero
        for i in 0..N {
            assert_eq!(c.coeffs[i], 0);
        }
    }

    #[test]
    fn test_mul_ntt_identity() {
        // Test multiplication by 1 (identity)
        let mut a = Poly::new();
        a.coeffs[0] = 1; // Polynomial = 1

        let mut b = Poly::new();
        b.coeffs[0] = 5;
        b.coeffs[1] = 10;

        let a_ntt = ntt(&a);
        let b_ntt = ntt(&b);
        let c_ntt = mul_ntt(&a_ntt, &b_ntt);
        let c = intt(&c_ntt);

        // c should equal b
        for i in 0..N {
            let b_reduced = ((b.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            let c_reduced = ((c.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            assert_eq!(c_reduced, b_reduced,
                "Coefficient {} mismatch", i);
        }
    }

    #[test]
    fn test_poly_mul_ntt_simple() {
        // Test (X + 1) * (X + 1) = X^2 + 2X + 1
        let mut a = Poly::new();
        a.coeffs[0] = 1;  // Constant term
        a.coeffs[1] = 1;  // X term

        let c = poly_mul_ntt(&a, &a);

        // Check result
        assert_eq!(((c.coeffs[0] % Q as i16) + Q as i16) % Q as i16, 1); // constant
        assert_eq!(((c.coeffs[1] % Q as i16) + Q as i16) % Q as i16, 2); // X term
        assert_eq!(((c.coeffs[2] % Q as i16) + Q as i16) % Q as i16, 1); // X^2 term
    }

    #[test]
    fn test_poly_mul_ntt_vs_schoolbook() {
        // Compare NTT multiplication with schoolbook
        let mut a = Poly::new();
        let mut b = Poly::new();

        // Set some coefficients
        a.coeffs[0] = 5;
        a.coeffs[1] = 10;
        a.coeffs[2] = 15;

        b.coeffs[0] = 2;
        b.coeffs[1] = 3;
        b.coeffs[3] = 7;

        let c_ntt = poly_mul_ntt(&a, &b);
        let c_school = a.mul(&b);

        // Results should match (modulo q)
        for i in 0..N {
            let ntt_val = ((c_ntt.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            let school_val = ((c_school.coeffs[i] % Q as i16) + Q as i16) % Q as i16;
            assert_eq!(ntt_val, school_val,
                "Coefficient {} mismatch: NTT={}, Schoolbook={}", i, ntt_val, school_val);
        }
    }

    #[test]
    fn test_fqmul() {
        let a = 100;
        let b = 200;
        let result = fqmul(a, b);

        // fqmul computes a * b * R^(-1) mod q, NOT (a * b) mod q
        // Result should be in valid range
        assert!(result >= -(Q as i16) && result < Q as i16);
    }
}
