//! Rolling Macros for NEON SIMD Operations
//!
//! These macros provide clean, readable unrolled loops for common NEON operations.
//! Using macros instead of manual unrolling improves code maintainability while
//! preserving the performance benefits of unrolling.

/// Load 4 consecutive vectors from memory (4x unrolled)
///
/// # Example
/// ```ignore
/// load_4x!(v, src, i, vld1q_s32);
/// // Expands to:
/// // let v0 = vld1q_s32(src.as_ptr().add(i * 4));
/// // let v1 = vld1q_s32(src.as_ptr().add((i + 1) * 4));
/// // let v2 = vld1q_s32(src.as_ptr().add((i + 2) * 4));
/// // let v3 = vld1q_s32(src.as_ptr().add((i + 3) * 4));
/// ```
/// Note: load_4x macro removed - Rust doesn't support ## token concatenation
/// Use explicit variable names instead:
/// let v0 = vld1q_s32(src.as_ptr().add(i * 4));
/// let v1 = vld1q_s32(src.as_ptr().add((i + 1) * 4));
/// etc.

/// Store 4 consecutive vectors to memory (4x unrolled)
#[macro_export]
macro_rules! store_4x {
    ($dst:expr, $i:expr, $v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        vst1q_s32($dst.as_mut_ptr().add($i * 4), $v0);
        vst1q_s32($dst.as_mut_ptr().add(($i + 1) * 4), $v1);
        vst1q_s32($dst.as_mut_ptr().add(($i + 2) * 4), $v2);
        vst1q_s32($dst.as_mut_ptr().add(($i + 3) * 4), $v3);
    };
}

/// Apply a unary operation to 4 vectors (4x unrolled)
///
/// # Example
/// ```ignore
/// apply_4x!(r, reduce32_neon, v0, v1, v2, v3);
/// // Expands to:
/// // let r0 = reduce32_neon(v0);
/// // let r1 = reduce32_neon(v1);
/// // let r2 = reduce32_neon(v2);
/// // let r3 = reduce32_neon(v3);
/// ```
/// Note: apply_4x macro removed - Rust doesn't support ## token concatenation
/// Use explicit variable names instead:
/// let r0 = op(v0);
/// let r1 = op(v1);
/// etc.

/// Apply a binary operation to 4 pairs of vectors (4x unrolled)
/// Note: apply_binary_4x macro removed - Rust doesn't support ## token concatenation
/// Use explicit variable names instead:
/// let r0 = op(a0, b0);
/// let r1 = op(a1, b1);
/// etc.

/// 4x unrolled loop over VECS_PER_POLY with load, operation, and store
///
/// This is the most common pattern: load 4 vectors, apply operation, store results.
///
/// # Parameters
/// - `$arr`: The mutable array to process
/// - `$op`: The operation to apply (takes int32x4_t, returns int32x4_t)
///
/// # Example
/// ```ignore
/// unroll_4x_inplace!(coeffs, reduce32_neon);
/// ```
#[macro_export]
macro_rules! unroll_4x_inplace {
    ($arr:expr, $op:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            // Load 4 vectors
            let v0 = vld1q_s32($arr.as_ptr().add(i * 4));
            let v1 = vld1q_s32($arr.as_ptr().add((i + 1) * 4));
            let v2 = vld1q_s32($arr.as_ptr().add((i + 2) * 4));
            let v3 = vld1q_s32($arr.as_ptr().add((i + 3) * 4));

            // Apply operation
            let r0 = $op(v0);
            let r1 = $op(v1);
            let r2 = $op(v2);
            let r3 = $op(v3);

            // Store results
            vst1q_s32($arr.as_mut_ptr().add(i * 4), r0);
            vst1q_s32($arr.as_mut_ptr().add((i + 1) * 4), r1);
            vst1q_s32($arr.as_mut_ptr().add((i + 2) * 4), r2);
            vst1q_s32($arr.as_mut_ptr().add((i + 3) * 4), r3);

            i += 4;
        }
    }};
}

/// 4x unrolled loop for binary operations (a op b -> c)
///
/// # Parameters
/// - `$a`: Source array a
/// - `$b`: Source array b
/// - `$c`: Destination array c
/// - `$op`: Binary operation (takes two int32x4_t, returns int32x4_t)
#[macro_export]
macro_rules! unroll_4x_binary {
    ($a:expr, $b:expr, $c:expr, $op:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            // Load from a
            let a0 = vld1q_s32($a.as_ptr().add(i * 4));
            let a1 = vld1q_s32($a.as_ptr().add((i + 1) * 4));
            let a2 = vld1q_s32($a.as_ptr().add((i + 2) * 4));
            let a3 = vld1q_s32($a.as_ptr().add((i + 3) * 4));

            // Load from b
            let b0 = vld1q_s32($b.as_ptr().add(i * 4));
            let b1 = vld1q_s32($b.as_ptr().add((i + 1) * 4));
            let b2 = vld1q_s32($b.as_ptr().add((i + 2) * 4));
            let b3 = vld1q_s32($b.as_ptr().add((i + 3) * 4));

            // Apply operation
            let c0 = $op(a0, b0);
            let c1 = $op(a1, b1);
            let c2 = $op(a2, b2);
            let c3 = $op(a3, b3);

            // Store to c
            vst1q_s32($c.as_mut_ptr().add(i * 4), c0);
            vst1q_s32($c.as_mut_ptr().add((i + 1) * 4), c1);
            vst1q_s32($c.as_mut_ptr().add((i + 2) * 4), c2);
            vst1q_s32($c.as_mut_ptr().add((i + 3) * 4), c3);

            i += 4;
        }
    }};
}

/// 4x unrolled accumulate: dst += op(a, b)
///
/// Common pattern for multiply-accumulate operations.
#[macro_export]
macro_rules! unroll_4x_acc {
    ($a:expr, $b:expr, $c:expr, $op:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            // Load from all three arrays
            let a0 = vld1q_s32($a.as_ptr().add(i * 4));
            let a1 = vld1q_s32($a.as_ptr().add((i + 1) * 4));
            let a2 = vld1q_s32($a.as_ptr().add((i + 2) * 4));
            let a3 = vld1q_s32($a.as_ptr().add((i + 3) * 4));

            let b0 = vld1q_s32($b.as_ptr().add(i * 4));
            let b1 = vld1q_s32($b.as_ptr().add((i + 1) * 4));
            let b2 = vld1q_s32($b.as_ptr().add((i + 2) * 4));
            let b3 = vld1q_s32($b.as_ptr().add((i + 3) * 4));

            let c0 = vld1q_s32($c.as_ptr().add(i * 4));
            let c1 = vld1q_s32($c.as_ptr().add((i + 1) * 4));
            let c2 = vld1q_s32($c.as_ptr().add((i + 2) * 4));
            let c3 = vld1q_s32($c.as_ptr().add((i + 3) * 4));

            // Multiply and accumulate
            let r0 = vaddq_s32(c0, $op(a0, b0));
            let r1 = vaddq_s32(c1, $op(a1, b1));
            let r2 = vaddq_s32(c2, $op(a2, b2));
            let r3 = vaddq_s32(c3, $op(a3, b3));

            // Store results
            vst1q_s32($c.as_mut_ptr().add(i * 4), r0);
            vst1q_s32($c.as_mut_ptr().add((i + 1) * 4), r1);
            vst1q_s32($c.as_mut_ptr().add((i + 2) * 4), r2);
            vst1q_s32($c.as_mut_ptr().add((i + 3) * 4), r3);

            i += 4;
        }
    }};
}

/// 4x unrolled in-place accumulate: dst op= src
#[macro_export]
macro_rules! unroll_4x_acc_inplace {
    ($dst:expr, $src:expr, $op:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            // Load from both arrays
            let d0 = vld1q_s32($dst.as_ptr().add(i * 4));
            let d1 = vld1q_s32($dst.as_ptr().add((i + 1) * 4));
            let d2 = vld1q_s32($dst.as_ptr().add((i + 2) * 4));
            let d3 = vld1q_s32($dst.as_ptr().add((i + 3) * 4));

            let s0 = vld1q_s32($src.as_ptr().add(i * 4));
            let s1 = vld1q_s32($src.as_ptr().add((i + 1) * 4));
            let s2 = vld1q_s32($src.as_ptr().add((i + 2) * 4));
            let s3 = vld1q_s32($src.as_ptr().add((i + 3) * 4));

            // Apply operation
            let r0 = $op(d0, s0);
            let r1 = $op(d1, s1);
            let r2 = $op(d2, s2);
            let r3 = $op(d3, s3);

            // Store results
            vst1q_s32($dst.as_mut_ptr().add(i * 4), r0);
            vst1q_s32($dst.as_mut_ptr().add((i + 1) * 4), r1);
            vst1q_s32($dst.as_mut_ptr().add((i + 2) * 4), r2);
            vst1q_s32($dst.as_mut_ptr().add((i + 3) * 4), r3);

            i += 4;
        }
    }};
}

/// Load all 64 vectors into array (4x unrolled)
#[macro_export]
macro_rules! load_poly_4x {
    ($v:expr, $src:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            $v[i] = vld1q_s32($src.as_ptr().add(i * 4));
            $v[i + 1] = vld1q_s32($src.as_ptr().add((i + 1) * 4));
            $v[i + 2] = vld1q_s32($src.as_ptr().add((i + 2) * 4));
            $v[i + 3] = vld1q_s32($src.as_ptr().add((i + 3) * 4));
            i += 4;
        }
    }};
}

/// Store all 64 vectors from array (4x unrolled)
#[macro_export]
macro_rules! store_poly_4x {
    ($dst:expr, $v:expr) => {{
        let mut i = 0;
        while i < VECS_PER_POLY {
            vst1q_s32($dst.as_mut_ptr().add(i * 4), $v[i]);
            vst1q_s32($dst.as_mut_ptr().add((i + 1) * 4), $v[i + 1]);
            vst1q_s32($dst.as_mut_ptr().add((i + 2) * 4), $v[i + 2]);
            vst1q_s32($dst.as_mut_ptr().add((i + 3) * 4), $v[i + 3]);
            i += 4;
        }
    }};
}

/// 2x unrolled NTT butterfly (for inter-vector levels)
///
/// Processes two butterflies in parallel for better ILP.
#[macro_export]
macro_rules! butterfly_2x {
    ($v:expr, $butterfly_fn:expr, $i0:expr, $j0:expr, $i1:expr, $j1:expr, $zeta:expr, $zeta_shoup:expr) => {{
        let (lo0, hi0) = $butterfly_fn($v[$i0], $v[$j0], $zeta, $zeta_shoup);
        let (lo1, hi1) = $butterfly_fn($v[$i1], $v[$j1], $zeta, $zeta_shoup);
        $v[$i0] = lo0;
        $v[$j0] = hi0;
        $v[$i1] = lo1;
        $v[$j1] = hi1;
    }};
}

/// 4x unrolled NTT butterfly
#[macro_export]
macro_rules! butterfly_4x {
    ($v:expr, $butterfly_fn:expr, $base:expr, $dist:expr, $zeta:expr, $zeta_shoup:expr) => {{
        let (lo0, hi0) = $butterfly_fn($v[$base], $v[$base + $dist], $zeta, $zeta_shoup);
        let (lo1, hi1) = $butterfly_fn($v[$base + 1], $v[$base + $dist + 1], $zeta, $zeta_shoup);
        let (lo2, hi2) = $butterfly_fn($v[$base + 2], $v[$base + $dist + 2], $zeta, $zeta_shoup);
        let (lo3, hi3) = $butterfly_fn($v[$base + 3], $v[$base + $dist + 3], $zeta, $zeta_shoup);
        $v[$base] = lo0;
        $v[$base + $dist] = hi0;
        $v[$base + 1] = lo1;
        $v[$base + $dist + 1] = hi1;
        $v[$base + 2] = lo2;
        $v[$base + $dist + 2] = hi2;
        $v[$base + 3] = lo3;
        $v[$base + $dist + 3] = hi3;
    }};
}

/// Scale and store 4 vectors with Montgomery multiplication (fused operation)
#[macro_export]
macro_rules! scale_store_4x {
    ($dst:expr, $v:expr, $i:expr, $scale:expr, $scale_shoup:expr, $mul_fn:expr) => {{
        let r0 = $mul_fn($v[$i], $scale, $scale_shoup);
        let r1 = $mul_fn($v[$i + 1], $scale, $scale_shoup);
        let r2 = $mul_fn($v[$i + 2], $scale, $scale_shoup);
        let r3 = $mul_fn($v[$i + 3], $scale, $scale_shoup);
        vst1q_s32($dst.as_mut_ptr().add($i * 4), r0);
        vst1q_s32($dst.as_mut_ptr().add(($i + 1) * 4), r1);
        vst1q_s32($dst.as_mut_ptr().add(($i + 2) * 4), r2);
        vst1q_s32($dst.as_mut_ptr().add(($i + 3) * 4), r3);
    }};
}

// Re-export macros for use in other modules
pub use store_4x;
pub use unroll_4x_inplace;
pub use unroll_4x_binary;
pub use unroll_4x_acc;
pub use unroll_4x_acc_inplace;
pub use load_poly_4x;
pub use store_poly_4x;
pub use butterfly_2x;
pub use butterfly_4x;
pub use scale_store_4x;
