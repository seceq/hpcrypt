//! Comprehensive Tests and Benchmarks for AVX2 Implementation
//!
//! This module provides thorough testing of all AVX2 optimized routines,
//! including correctness verification against reference implementations,
//! property-based testing, and performance benchmarks.

#![cfg(test)]

use super::*;
use super::consts::{N, Q, D, ALPHA_44, ALPHA_65, GAMMA1_44, GAMMA1_65, ETA_44, ETA_65, TAU_44, TAU_65};

// ============================================================================
// Test Utilities
// ============================================================================

/// Generate deterministic test polynomial
fn test_poly(seed: u32) -> [i32; N] {
    let mut poly = [0i32; N];
    let mut state = seed;
    for i in 0..N {
        // Simple LCG for deterministic test data
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        poly[i] = ((state >> 16) as i32) % Q;
    }
    poly
}

/// Generate polynomial with small coefficients
fn small_poly(seed: u32, bound: i32) -> [i32; N] {
    let mut poly = [0i32; N];
    let mut state = seed;
    for i in 0..N {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        poly[i] = ((state >> 16) as i32 % (2 * bound + 1)) - bound;
    }
    poly
}

/// Reference modular reduction (for testing)
fn reduce_mod_q(x: i32) -> i32 {
    let mut r = x % Q;
    if r < 0 {
        r += Q;
    }
    r
}

/// Reference NTT butterfly (for testing)
fn ref_butterfly(a: &mut i32, b: &mut i32, zeta: i32) {
    let t = (((*b as i64) * (zeta as i64)) % (Q as i64)) as i32;
    *b = reduce_mod_q(*a - t);
    *a = reduce_mod_q(*a + t);
}

// ============================================================================
// Reduction Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_reduce32_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use reduce::reduce32_avx2;

        // Test with various input ranges
        let test_cases: [i32; 8] = [
            0, Q - 1, Q, Q + 1, 2 * Q, 2 * Q - 1, -Q, -Q + 1,
        ];

        let input = _mm256_loadu_si256(test_cases.as_ptr() as *const __m256i);
        let result = reduce32_avx2(input);

        let mut output = [0i32; 8];
        _mm256_storeu_si256(output.as_mut_ptr() as *mut __m256i, result);

        for i in 0..8 {
            let expected = reduce_mod_q(test_cases[i]);
            // Result should be congruent mod Q
            assert_eq!(
                (output[i] % Q + Q) % Q,
                expected,
                "reduce32 mismatch at index {}: input={}, output={}, expected={}",
                i, test_cases[i], output[i], expected
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_caddq_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use reduce::caddq_avx2;

        // Test with negative values
        let test_cases: [i32; 8] = [-1, -Q/2, -Q+1, 0, 1, Q/2, Q-1, Q];

        let input = _mm256_loadu_si256(test_cases.as_ptr() as *const __m256i);
        let result = caddq_avx2(input);

        let mut output = [0i32; 8];
        _mm256_storeu_si256(output.as_mut_ptr() as *mut __m256i, result);

        for i in 0..8 {
            let expected = if test_cases[i] < 0 {
                test_cases[i] + Q
            } else {
                test_cases[i]
            };
            assert_eq!(
                output[i], expected,
                "caddq mismatch at index {}: input={}, output={}, expected={}",
                i, test_cases[i], output[i], expected
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_barrett_reduce_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use reduce::barrett_reduce_avx2;

        // Test with values up to Q^2 (which fits in i64)
        let test_cases: [i32; 8] = [
            0, Q - 1, Q, 2 * Q, 1000000, 5000000, Q / 2, Q + Q / 2,
        ];

        let input = _mm256_loadu_si256(test_cases.as_ptr() as *const __m256i);
        let result = barrett_reduce_avx2(input);

        let mut output = [0i32; 8];
        _mm256_storeu_si256(output.as_mut_ptr() as *mut __m256i, result);

        for i in 0..8 {
            let expected = reduce_mod_q(test_cases[i]);
            assert!(
                output[i] >= 0 && output[i] < 2 * Q,
                "Barrett reduction out of range at index {}: input={}, output={}",
                i, test_cases[i], output[i]
            );
            assert_eq!(
                (output[i] % Q + Q) % Q, expected,
                "Barrett reduction incorrect at index {}: input={}, output={}, expected={}",
                i, test_cases[i], output[i], expected
            );
        }
    }
}

// ============================================================================
// NTT Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_ntt_invntt_roundtrip() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use super::reduce::from_montgomery_avx2;
        use super::consts::{QINV, Q as Q_CONST};

        let original = test_poly(12345);
        let mut poly = original;

        ntt::ntt(&mut poly);
        ntt::invntt(&mut poly);

        // InvNTT returns values in Montgomery form, convert to standard form
        let q = _mm256_set1_epi32(Q_CONST);
        let qinv = _mm256_set1_epi32(QINV);
        for i in (0..N).step_by(8) {
            let v = _mm256_loadu_si256(poly.as_ptr().add(i) as *const __m256i);
            let converted = from_montgomery_avx2(v, qinv, q);
            _mm256_storeu_si256(poly.as_mut_ptr().add(i) as *mut __m256i, converted);
        }

        // After NTT followed by InvNTT, we should get back the original
        // (modulo reduction to canonical form)
        for i in 0..N {
            let recovered = (poly[i] % Q + Q) % Q;
            let expected = (original[i] % Q + Q) % Q;
            assert_eq!(
                recovered, expected,
                "NTT roundtrip failed at index {}: original={}, recovered={}",
                i, original[i], poly[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_ntt_linearity() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // NTT(a + b) should equal NTT(a) + NTT(b)
        let a = test_poly(111);
        let b = test_poly(222);

        // Compute NTT(a + b)
        let mut sum = [0i32; N];
        for i in 0..N {
            sum[i] = (a[i] + b[i]) % Q;
        }
        let mut ntt_sum = sum;
        ntt::ntt(&mut ntt_sum);

        // Compute NTT(a) + NTT(b)
        let mut ntt_a = a;
        let mut ntt_b = b;
        ntt::ntt(&mut ntt_a);
        ntt::ntt(&mut ntt_b);

        let mut sum_ntt = [0i32; N];
        for i in 0..N {
            sum_ntt[i] = (ntt_a[i] + ntt_b[i]) % Q;
        }

        // Compare
        for i in 0..N {
            let expected = (ntt_sum[i] % Q + Q) % Q;
            let actual = (sum_ntt[i] % Q + Q) % Q;
            assert_eq!(
                expected, actual,
                "NTT linearity failed at index {}: NTT(a+b)={}, NTT(a)+NTT(b)={}",
                i, expected, actual
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_ntt_multiply_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // For small polynomials, verify multiplication is correct
        let mut a = [0i32; N];
        let mut b = [0i32; N];

        // Simple test: a = [1, 0, 0, ...], b = [1, 2, 3, 0, ...]
        a[0] = 1;
        b[0] = 1;
        b[1] = 2;
        b[2] = 3;

        let mut ntt_a = a;
        let mut ntt_b = b;
        ntt::ntt(&mut ntt_a);
        ntt::ntt(&mut ntt_b);

        let mut ntt_c = [0i32; N];
        ntt::ntt_multiply(&ntt_a, &ntt_b, &mut ntt_c);

        let mut c = ntt_c;
        ntt::invntt(&mut c);

        // a * b = [1, 2, 3, 0, ...] (since a = 1)
        let c0 = (c[0] % Q + Q) % Q;
        let c1 = (c[1] % Q + Q) % Q;
        let c2 = (c[2] % Q + Q) % Q;

        assert_eq!(c0, 1, "NTT multiply failed: c[0]={}", c0);
        assert_eq!(c1, 2, "NTT multiply failed: c[1]={}", c1);
        assert_eq!(c2, 3, "NTT multiply failed: c[2]={}", c2);
    }
}

// ============================================================================
// Polynomial Arithmetic Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_poly_add_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let a = test_poly(100);
        let b = test_poly(200);
        let mut c = [0i32; N];

        poly::poly_add(&a, &b, &mut c);

        for i in 0..N {
            let expected = (a[i] + b[i]) % Q;
            let actual = c[i] % Q;
            assert_eq!(
                actual, expected,
                "poly_add mismatch at index {}: a={}, b={}, c={}",
                i, a[i], b[i], c[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_poly_sub_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let a = test_poly(300);
        let b = test_poly(400);
        let mut c = [0i32; N];

        poly::poly_sub(&a, &b, &mut c);

        for i in 0..N {
            let expected = ((a[i] - b[i]) % Q + Q) % Q;
            let actual = ((c[i] % Q) + Q) % Q;
            assert_eq!(
                actual, expected,
                "poly_sub mismatch at index {}: a={}, b={}, c={}",
                i, a[i], b[i], c[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_infinity_norm_avx2_threshold() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // Test with centered coefficients (values in [0, Q) range that need centering)
        let mut poly = [0i32; N];
        poly[0] = 100;
        poly[50] = Q - 150;  // Centered: -150
        poly[100] = 200;
        poly[200] = Q - 250; // Centered: -250

        let norm = poly::infinity_norm_avx2_threshold(&poly, i32::MAX);
        assert_eq!(norm, 250, "Infinity norm incorrect: expected 250, got {}", norm);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_poly_chknorm() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let mut poly = [0i32; N];
        for i in 0..N {
            poly[i] = (i as i32) % 100; // Max value 99
        }

        // poly_chknorm returns true if any coefficient exceeds the threshold (norm violation)
        // With max value 99 and threshold 100, no violation occurs -> returns false
        assert!(!poly::poly_chknorm(&poly, 100), "Should not exceed norm of 100");
        // With max value 99 and threshold 50, violation occurs -> returns true
        assert!(poly::poly_chknorm(&poly, 50), "Should exceed norm of 50");
    }
}

// ============================================================================
// Rounding Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_power2round_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let input = test_poly(500);
        let mut r1 = [0i32; N];
        let mut r0 = [0i32; N];

        rounding::power2round(&input, &mut r1, &mut r0);

        // Verify: input = r1 * 2^D + r0
        let two_d = 1 << D;
        for i in 0..N {
            let a = (input[i] % Q + Q) % Q;
            let reconstructed = (r1[i] * two_d + r0[i]) % Q;
            let reconstructed = (reconstructed + Q) % Q;
            assert_eq!(
                a, reconstructed,
                "Power2Round reconstruction failed at index {}: input={}, r1={}, r0={}, reconstructed={}",
                i, a, r1[i], r0[i], reconstructed
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_decompose_correctness() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let input = test_poly(600);
        let mut r1 = [0i32; N];
        let mut r0 = [0i32; N];

        rounding::decompose(&input, &mut r1, &mut r0, ALPHA_65);

        // Verify: input ≡ r1 * alpha + r0 (mod Q)
        for i in 0..N {
            let a = (input[i] % Q + Q) % Q;
            let reconstructed = ((r1[i] as i64 * ALPHA_65 as i64 + r0[i] as i64) % Q as i64 + Q as i64) % Q as i64;
            assert_eq!(
                a as i64, reconstructed,
                "Decompose reconstruction failed at index {}: input={}, r1={}, r0={}",
                i, a, r1[i], r0[i]
            );

            // r0 should be in range [-alpha/2, alpha/2]
            let half_alpha = ALPHA_65 / 2;
            assert!(
                r0[i] >= -half_alpha && r0[i] <= half_alpha,
                "r0 out of range at index {}: r0={}, expected in [{}, {}]",
                i, r0[i], -half_alpha, half_alpha
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_highbits_lowbits_consistency() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let input = test_poly(700);
        let mut hi = [0i32; N];
        let mut lo = [0i32; N];
        let mut r1 = [0i32; N];
        let mut r0 = [0i32; N];

        rounding::highbits(&input, &mut hi, ALPHA_65);
        rounding::lowbits(&input, &mut lo, ALPHA_65);
        rounding::decompose(&input, &mut r1, &mut r0, ALPHA_65);

        // HighBits should match r1 from Decompose
        for i in 0..N {
            assert_eq!(
                hi[i], r1[i],
                "HighBits mismatch at index {}: highbits={}, decompose.r1={}",
                i, hi[i], r1[i]
            );
        }

        // LowBits should match r0 from Decompose
        for i in 0..N {
            assert_eq!(
                lo[i], r0[i],
                "LowBits mismatch at index {}: lowbits={}, decompose.r0={}",
                i, lo[i], r0[i]
            );
        }
    }
}

// ============================================================================
// Hint Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_make_hint_use_hint_consistency() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // If we make a hint from (z, r) and then use it, we should recover
        // the correct high bits
        let r = test_poly(800);
        let z = small_poly(801, 1000); // Small z values

        let mut h = [0i32; N];
        let _count = hints::make_hint(&z, &r, &mut h, ALPHA_65);

        // Compute r + z (mod Q)
        let mut r_plus_z = [0i32; N];
        for i in 0..N {
            let sum = (r[i] as i64 + z[i] as i64) % Q as i64;
            r_plus_z[i] = ((sum + Q as i64) % Q as i64) as i32;
        }

        // HighBits(r + z) should equal UseHint(h, r)
        let mut hi_r_plus_z = [0i32; N];
        rounding::highbits(&r_plus_z, &mut hi_r_plus_z, ALPHA_65);

        let mut use_hint_result = [0i32; N];
        hints::use_hint(&h, &r, &mut use_hint_result, ALPHA_65);

        for i in 0..N {
            assert_eq!(
                hi_r_plus_z[i], use_hint_result[i],
                "MakeHint/UseHint consistency failed at index {}: HighBits(r+z)={}, UseHint(h,r)={}",
                i, hi_r_plus_z[i], use_hint_result[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_count_hints() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let mut h = [0i32; N];
        h[10] = 1;
        h[50] = 1;
        h[100] = 1;
        h[200] = 1;
        h[255] = 1;

        let count = hints::count_hints(&h);
        assert_eq!(count, 5, "count_hints incorrect: expected 5, got {}", count);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_verify_hint_format() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // Valid hints
        let mut h = [0i32; N];
        h[10] = 1;
        h[20] = 1;
        assert!(hints::verify_hint_format(&h), "Valid hints should pass format check");

        // Invalid hints (value > 1)
        h[30] = 2;
        assert!(!hints::verify_hint_format(&h), "Invalid hints should fail format check");
    }
}

// ============================================================================
// Packing Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_pack_unpack_t0() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let half_power = 1 << (D - 1); // 4096
        let mut original = [0i32; N];
        for i in 0..N {
            // t0 is in range [-(half_power-1), half_power] = [-4095, 4096]
            // The value -4096 is NOT valid because pack_t0 stores 4096 - t0,
            // and 4096 - (-4096) = 8192 which overflows 13 bits
            original[i] = ((i as i32 * 13) % (2 * half_power)) - half_power + 1;
        }

        let mut bytes = [0u8; 416];
        packing::pack_t0(&original, &mut bytes);

        let mut recovered = [0i32; N];
        packing::unpack_t0(&bytes, &mut recovered);

        for i in 0..N {
            assert_eq!(
                original[i], recovered[i],
                "t0 pack/unpack mismatch at index {}: original={}, recovered={}",
                i, original[i], recovered[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_pack_unpack_z_19() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let gamma1 = 1 << 19;
        let mut original = [0i32; N];
        for i in 0..N {
            original[i] = ((i as i32 * 1000) % (2 * gamma1)) - gamma1 + 1;
        }

        let mut bytes = [0u8; 640];
        packing::pack_z_19(&original, &mut bytes);

        let mut recovered = [0i32; N];
        packing::unpack_z_19(&bytes, &mut recovered);

        for i in 0..N {
            assert_eq!(
                original[i], recovered[i],
                "z_19 pack/unpack mismatch at index {}: original={}, recovered={}",
                i, original[i], recovered[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_pack_unpack_eta4() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let mut original = [0i32; N];
        for i in 0..N {
            original[i] = ((i % 9) as i32) - 4; // Values in [-4, 4]
        }

        let mut bytes = [0u8; 128];
        packing::pack_eta4(&original, &mut bytes);

        let mut recovered = [0i32; N];
        packing::unpack_eta4(&bytes, &mut recovered);

        for i in 0..N {
            assert_eq!(
                original[i], recovered[i],
                "eta4 pack/unpack mismatch at index {}: original={}, recovered={}",
                i, original[i], recovered[i]
            );
        }
    }
}

// ============================================================================
// Sampling Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_rej_uniform_bounds() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // Create random-ish bytes
        let mut bytes = [0u8; 1024];
        for i in 0..bytes.len() {
            bytes[i] = ((i * 37 + 13) % 256) as u8;
        }

        let mut coeffs = [0i32; N];
        // rej_uniform(a, ctr, buf, buflen) -> usize
        let count = sampling::rej_uniform(&mut coeffs, 0, &bytes, bytes.len());

        // All accepted coefficients should be in [0, Q)
        for i in 0..count {
            assert!(
                coeffs[i] >= 0 && coeffs[i] < Q,
                "rej_uniform produced out-of-range coefficient at index {}: {}",
                i, coeffs[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_rej_eta_bounds() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let mut bytes = [0u8; 512];
        for i in 0..bytes.len() {
            bytes[i] = ((i * 41 + 7) % 256) as u8;
        }

        let mut coeffs = [0i32; N];
        // rej_eta(a, ctr, buf, buflen, eta) -> usize
        let count = sampling::rej_eta(&mut coeffs, 0, &bytes, bytes.len(), ETA_65 as i32);

        // All accepted coefficients should be in [-eta, eta]
        for i in 0..count {
            assert!(
                coeffs[i] >= -(ETA_65 as i32) && coeffs[i] <= ETA_65 as i32,
                "rej_eta produced out-of-range coefficient at index {}: {}, eta={}",
                i, coeffs[i], ETA_65
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_sample_in_ball_properties() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // Need at least tau*2 + (tau+7)/8 bytes for the AVX2 implementation
        // For TAU_65=49: 49*2 + (49+7)/8 = 98 + 7 = 105 bytes
        let mut seed = [0u8; 128];
        for i in 0..128 {
            seed[i] = (i * 7 + 13) as u8; // Deterministic but varied values
        }
        let mut c = [0i32; N];

        sampling::sample_in_ball(&mut c, &seed, TAU_65);

        // Check that exactly TAU_65 coefficients are non-zero
        let mut nonzero_count = 0;
        for &coeff in &c {
            if coeff != 0 {
                nonzero_count += 1;
            }
        }
        assert_eq!(
            nonzero_count, TAU_65,
            "sample_in_ball should have exactly {} non-zero coefficients, got {}",
            TAU_65, nonzero_count
        );

        // Check that all non-zero coefficients are ±1
        for i in 0..N {
            assert!(
                c[i] == 0 || c[i] == 1 || c[i] == -1,
                "sample_in_ball coefficient at {} should be 0, 1, or -1, got {}",
                i, c[i]
            );
        }
    }
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_ntt_multiply_commutative() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let a = test_poly(1000);
        let b = test_poly(2000);

        let mut ntt_a = a;
        let mut ntt_b = b;
        ntt::ntt(&mut ntt_a);
        ntt::ntt(&mut ntt_b);

        // a * b
        let mut ab = [0i32; N];
        ntt::ntt_multiply(&ntt_a, &ntt_b, &mut ab);
        ntt::invntt(&mut ab);

        // b * a
        let mut ba = [0i32; N];
        ntt::ntt_multiply(&ntt_b, &ntt_a, &mut ba);
        ntt::invntt(&mut ba);

        for i in 0..N {
            let ab_norm = (ab[i] % Q + Q) % Q;
            let ba_norm = (ba[i] % Q + Q) % Q;
            assert_eq!(
                ab_norm, ba_norm,
                "Polynomial multiplication not commutative at index {}: a*b={}, b*a={}",
                i, ab_norm, ba_norm
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_poly_add_sub_inverse() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let a = test_poly(3000);
        let b = test_poly(4000);

        // (a + b) - b should equal a
        let mut sum = [0i32; N];
        poly::poly_add(&a, &b, &mut sum);

        let mut result = [0i32; N];
        poly::poly_sub(&sum, &b, &mut result);

        for i in 0..N {
            let expected = (a[i] % Q + Q) % Q;
            let actual = (result[i] % Q + Q) % Q;
            assert_eq!(
                expected, actual,
                "Add/sub inverse failed at index {}: a={}, (a+b)-b={}",
                i, a[i], result[i]
            );
        }
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_zero_polynomial() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let zero = [0i32; N];
        let mut result = zero;

        // NTT of zero should be zero
        ntt::ntt(&mut result);
        for i in 0..N {
            assert_eq!(result[i], 0, "NTT of zero not zero at index {}", i);
        }

        // InvNTT should also give zero
        ntt::invntt(&mut result);
        for i in 0..N {
            assert_eq!(result[i], 0, "InvNTT of zero not zero at index {}", i);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_constant_polynomial() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use super::reduce::from_montgomery_avx2;
        use super::consts::{QINV, Q as Q_CONST};

        let constant = 42;
        let mut poly = [constant; N];
        let original = poly;

        ntt::ntt(&mut poly);
        ntt::invntt(&mut poly);

        // Convert from Montgomery form
        let q = _mm256_set1_epi32(Q_CONST);
        let qinv = _mm256_set1_epi32(QINV);
        for i in (0..N).step_by(8) {
            let v = _mm256_loadu_si256(poly.as_ptr().add(i) as *const __m256i);
            let converted = from_montgomery_avx2(v, qinv, q);
            _mm256_storeu_si256(poly.as_mut_ptr().add(i) as *mut __m256i, converted);
        }

        for i in 0..N {
            let expected = (original[i] % Q + Q) % Q;
            let actual = (poly[i] % Q + Q) % Q;
            assert_eq!(
                expected, actual,
                "Constant polynomial roundtrip failed at index {}: original={}, result={}",
                i, original[i], poly[i]
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_boundary_values() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use super::reduce::from_montgomery_avx2;
        use super::consts::{QINV, Q as Q_CONST};

        // Test with Q-1 values
        let mut poly = [Q - 1; N];
        let original = poly;

        ntt::ntt(&mut poly);
        ntt::invntt(&mut poly);

        // Convert from Montgomery form
        let q = _mm256_set1_epi32(Q_CONST);
        let qinv = _mm256_set1_epi32(QINV);
        for i in (0..N).step_by(8) {
            let v = _mm256_loadu_si256(poly.as_ptr().add(i) as *const __m256i);
            let converted = from_montgomery_avx2(v, qinv, q);
            _mm256_storeu_si256(poly.as_mut_ptr().add(i) as *mut __m256i, converted);
        }

        for i in 0..N {
            let expected = (original[i] % Q + Q) % Q;
            let actual = (poly[i] % Q + Q) % Q;
            assert_eq!(
                expected, actual,
                "Boundary value test failed at index {}: original={}, result={}",
                i, original[i], poly[i]
            );
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
#[cfg(target_arch = "x86_64")]
fn test_full_signature_arithmetic() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        // Simulate part of the signing process:
        // 1. Sample secret key polynomial s1
        // 2. Compute NTT(s1)
        // 3. Sample random matrix element
        // 4. Multiply and accumulate

        let s1 = small_poly(5000, 2); // eta=2 secret
        let a = test_poly(6000); // Random matrix element

        let mut ntt_s1 = s1;
        ntt::ntt(&mut ntt_s1);

        let mut ntt_a = a;
        ntt::ntt(&mut ntt_a);

        // t = A * s (in NTT domain)
        let mut ntt_t = [0i32; N];
        ntt::ntt_multiply(&ntt_a, &ntt_s1, &mut ntt_t);

        // Convert back
        let mut t = ntt_t;
        ntt::invntt(&mut t);

        // Decompose t
        let mut t1 = [0i32; N];
        let mut t0 = [0i32; N];
        rounding::power2round(&t, &mut t1, &mut t0);

        // Verify reconstruction
        let two_d = 1 << D;
        for i in 0..N {
            let reconstructed = ((t1[i] as i64 * two_d as i64 + t0[i] as i64) % Q as i64 + Q as i64) % Q as i64;
            let original = (t[i] as i64 % Q as i64 + Q as i64) % Q as i64;
            assert_eq!(
                original, reconstructed,
                "Signature arithmetic reconstruction failed at index {}",
                i
            );
        }
    }
}

// ============================================================================
// Diagnostic Tests - Compare AVX2 with Scalar
// ============================================================================

/// Reference scalar Montgomery reduction (matches the one in ntt.rs)
fn scalar_montgomery_reduce(a: i64) -> i32 {
    const QINV_U32: u32 = 58728449;
    const Q_I32: i32 = 8380417;

    let t = ((a as i32 as i64) * (QINV_U32 as i64)) as i32;
    let t = ((a - (t as i64) * (Q_I32 as i64)) >> 32) as i32;
    t
}

/// Reference scalar radix-2 forward NTT (Cooley-Tukey)
fn scalar_ntt_radix2(coeffs: &mut [i32; N]) {
    use super::consts::ZETAS;
    const Q_I32: i32 = 8380417;

    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = scalar_montgomery_reduce((zeta as i64) * (coeffs[j + len] as i64));
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Reference scalar radix-2 inverse NTT (Gentleman-Sande)
/// Note: Output is in Montgomery form! Call from_montgomery_scalar to convert to standard form.
fn scalar_invntt_radix2(coeffs: &mut [i32; N]) {
    use super::consts::{ZETAS, F};

    let mut k = 256usize;
    let mut len = 1usize;

    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            for j in start..start + len {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = t - coeffs[j + len];
                coeffs[j + len] = scalar_montgomery_reduce((zeta as i64) * (coeffs[j + len] as i64));
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Scale by F
    for j in 0..N {
        coeffs[j] = scalar_montgomery_reduce((F as i64) * (coeffs[j] as i64));
    }
}

/// Convert from Montgomery form to standard form
fn from_montgomery_scalar(a: i32) -> i32 {
    let result = scalar_montgomery_reduce(a as i64);
    if result < 0 {
        result + Q
    } else {
        result
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_fqmul_vs_scalar_montgomery() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        use core::arch::x86_64::*;
        use super::reduce::fqmul;
        use super::consts::{Q, QINV};

        let q = _mm256_set1_epi32(Q);
        let qinv = _mm256_set1_epi32(QINV);

        // Test with various values
        let test_a: [i32; 8] = [1, 100, 1000, 10000, 100000, 1000000, Q - 1, Q / 2];
        let test_b: [i32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let a = _mm256_loadu_si256(test_a.as_ptr() as *const __m256i);
        let b = _mm256_loadu_si256(test_b.as_ptr() as *const __m256i);

        let result_avx2 = fqmul(a, b, qinv, q);

        let mut output = [0i32; 8];
        _mm256_storeu_si256(output.as_mut_ptr() as *mut __m256i, result_avx2);

        for i in 0..8 {
            let prod = (test_a[i] as i64) * (test_b[i] as i64);
            let expected = scalar_montgomery_reduce(prod);

            // Both should be congruent mod Q
            let avx2_mod = ((output[i] % Q) + Q) % Q;
            let scalar_mod = ((expected % Q) + Q) % Q;

            assert_eq!(
                avx2_mod, scalar_mod,
                "fqmul mismatch at index {}: a={}, b={}, avx2={} (mod Q: {}), scalar={} (mod Q: {})",
                i, test_a[i], test_b[i], output[i], avx2_mod, expected, scalar_mod
            );
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_avx2_ntt_vs_scalar_ntt() {
    if !hpcrypt_core::cpufeatures::has_avx2() {
        return;
    }

    unsafe {
        let original = test_poly(12345);

        // AVX2 NTT
        let mut poly_avx2 = original;
        ntt::ntt(&mut poly_avx2);

        // Scalar radix-2 NTT
        let mut poly_scalar = original;
        scalar_ntt_radix2(&mut poly_scalar);

        // Compare first few coefficients for debugging
        let mut mismatches = 0;
        for i in 0..N {
            let avx2_mod = ((poly_avx2[i] % Q) + Q) % Q;
            let scalar_mod = ((poly_scalar[i] % Q) + Q) % Q;

            if avx2_mod != scalar_mod {
                if mismatches < 10 {
                    eprintln!(
                        "NTT mismatch at index {}: avx2={} (mod: {}), scalar={} (mod: {})",
                        i, poly_avx2[i], avx2_mod, poly_scalar[i], scalar_mod
                    );
                }
                mismatches += 1;
            }
        }

        assert_eq!(mismatches, 0, "AVX2 NTT differs from scalar NTT in {} positions", mismatches);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_scalar_ntt_roundtrip() {
    // Verify that the scalar radix-2 NTT itself is correct
    let original = test_poly(12345);

    let mut poly = original;
    scalar_ntt_radix2(&mut poly);
    scalar_invntt_radix2(&mut poly);

    // Convert from Montgomery form to standard form
    for i in 0..N {
        poly[i] = from_montgomery_scalar(poly[i]);
    }

    for i in 0..N {
        let expected = ((original[i] % Q) + Q) % Q;
        let actual = ((poly[i] % Q) + Q) % Q;

        assert_eq!(
            expected, actual,
            "Scalar NTT roundtrip failed at index {}: original={}, result={}",
            i, original[i], poly[i]
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_radix2_vs_radix4_ntt() {
    // Compare radix-2 forward NTT with the crate's radix-4 forward NTT
    use crate::poly::Poly;
    use crate::ntt::ntt_scalar as radix4_ntt;

    let original = test_poly(12345);

    // Radix-2 forward NTT
    let mut poly_radix2 = original;
    scalar_ntt_radix2(&mut poly_radix2);

    // Radix-4 forward NTT (from the crate)
    let mut poly_struct = Poly::new();
    poly_struct.coeffs.copy_from_slice(&original);
    let poly_radix4 = radix4_ntt(&poly_struct);

    // Compare
    let mut mismatches = 0;
    for i in 0..N {
        let r2 = ((poly_radix2[i] % Q) + Q) % Q;
        let r4 = ((poly_radix4.coeffs[i] % Q) + Q) % Q;

        if r2 != r4 {
            if mismatches < 10 {
                eprintln!(
                    "NTT mismatch at index {}: radix2={} (mod: {}), radix4={} (mod: {})",
                    i, poly_radix2[i], r2, poly_radix4.coeffs[i], r4
                );
            }
            mismatches += 1;
        }
    }

    if mismatches > 0 {
        eprintln!("Total mismatches: {}", mismatches);
    }
    assert_eq!(mismatches, 0, "Radix-2 NTT differs from radix-4 NTT in {} positions", mismatches);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_radix2_fwd_with_crate_inv() {
    // Test: radix-2 forward NTT followed by crate's inverse NTT
    use crate::poly::Poly;
    use crate::ntt::inv_ntt as crate_invntt;

    // Local from_montgomery helper (same as montgomery_reduce for single coefficient)
    fn from_montgomery(a: i32) -> i32 {
        crate::ntt::montgomery_reduce(a as i64)
    }

    let original = test_poly(12345);

    // Radix-2 forward NTT
    let mut poly_array = original;
    scalar_ntt_radix2(&mut poly_array);

    // Use crate's inverse NTT
    let mut poly_struct = Poly::new();
    poly_struct.coeffs.copy_from_slice(&poly_array);
    let mut recovered_struct = crate_invntt(&poly_struct);

    // Convert from Montgomery form
    for i in 0..N {
        recovered_struct.coeffs[i] = from_montgomery(recovered_struct.coeffs[i]);
    }

    // Compare
    let mut mismatches = 0;
    for i in 0..N {
        let expected = ((original[i] % Q) + Q) % Q;
        let actual = ((recovered_struct.coeffs[i] % Q) + Q) % Q;

        if expected != actual {
            if mismatches < 10 {
                eprintln!(
                    "Roundtrip mismatch at index {}: original={}, recovered={}",
                    i, expected, actual
                );
            }
            mismatches += 1;
        }
    }

    assert_eq!(mismatches, 0, "Radix-2 fwd + crate inv roundtrip failed in {} positions", mismatches);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_my_invntt_vs_crate_invntt() {
    // Compare my radix-2 inverse NTT with the crate's inverse NTT on same input
    use crate::poly::Poly;
    use crate::ntt::inv_ntt as crate_invntt;

    let original = test_poly(12345);

    // Apply forward NTT
    let mut poly_array = original;
    scalar_ntt_radix2(&mut poly_array);

    // My inverse NTT
    let mut poly_mine = poly_array;
    scalar_invntt_radix2(&mut poly_mine);

    // Crate's inverse NTT
    let mut poly_struct = Poly::new();
    poly_struct.coeffs.copy_from_slice(&poly_array);
    let poly_crate = crate_invntt(&poly_struct);

    // Compare
    let mut mismatches = 0;
    for i in 0..N {
        let mine = ((poly_mine[i] % Q) + Q) % Q;
        let crate_val = ((poly_crate.coeffs[i] % Q) + Q) % Q;

        if mine != crate_val {
            if mismatches < 10 {
                eprintln!(
                    "InvNTT mismatch at index {}: mine={}, crate={}",
                    i, mine, crate_val
                );
            }
            mismatches += 1;
        }
    }

    if mismatches > 0 {
        eprintln!("Total invNTT mismatches: {}", mismatches);
    }
    assert_eq!(mismatches, 0, "My invNTT differs from crate invNTT in {} positions", mismatches);
}
