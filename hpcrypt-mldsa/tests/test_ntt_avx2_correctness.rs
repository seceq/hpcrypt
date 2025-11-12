//! AVX2 NTT Correctness Tests
//!
//! This test module verifies that the AVX2 SIMD implementation of NTT
//! produces identical results to the Rust scalar implementation.

#[cfg(all(test, feature = "avx2", target_arch = "x86_64"))]
mod avx2_tests {
    use mldsa::poly::Poly;
    use mldsa::ntt::{ntt_scalar, ZETAS};
    use mldsa::simd::dispatch::ntt_simd;
    use mldsa::simd::avx2::init_qdata;
    use mldsa::params::N;

    #[test]
    fn test_ntt_avx2_vs_scalar_zeros() {
        // Initialize qdata for AVX2
        unsafe { init_qdata(); }

        // Test with zero polynomial
        let poly = Poly::new();
        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for zero polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_ones() {
        unsafe { init_qdata(); }

        // Test with all-ones polynomial
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = 1;
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for ones polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_sequential() {
        unsafe { init_qdata(); }

        // Test with sequential values [0, 1, 2, 3, ..., 255]
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = i as i32;
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for sequential polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_random_small() {
        unsafe { init_qdata(); }

        // Test with small random values
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = ((i * 7919) % 1000) as i32;
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for small random polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_large_values() {
        unsafe { init_qdata(); }

        // Test with values close to Q
        const Q: i32 = 8380417;
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = Q - 1000 + ((i * 13) % 1000) as i32;
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for large values polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_negative_values() {
        unsafe { init_qdata(); }

        // Test with negative values
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = -((i * 100) as i32);
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for negative values polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_alternating_signs() {
        unsafe { init_qdata(); }

        // Test with alternating positive/negative values
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = if i % 2 == 0 { 1000 } else { -1000 };
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for alternating signs polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_powers_of_two() {
        unsafe { init_qdata(); }

        // Test with powers of 2
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = 1 << (i % 20); // Keep values reasonable
        }

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for powers of two polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_sparse() {
        unsafe { init_qdata(); }

        // Test with sparse polynomial (mostly zeros)
        let mut poly = Poly::new();
        poly.coeffs[0] = 12345;
        poly.coeffs[64] = -54321;
        poly.coeffs[128] = 98765;
        poly.coeffs[192] = -11111;
        poly.coeffs[255] = 22222;

        let poly_scalar = ntt_scalar(&poly);
        let poly_avx2 = ntt_simd(&poly);

        for i in 0..N {
            assert_eq!(
                poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                "Mismatch at coefficient {} for sparse polynomial: scalar={}, avx2={}",
                i, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
            );
        }
    }

    #[test]
    fn test_ntt_avx2_vs_scalar_multiple_runs() {
        unsafe { init_qdata(); }

        // Test that multiple NTT calls produce consistent results
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = ((i * 12345 + 67890) % 10000) as i32;
        }

        // Run NTT multiple times and ensure consistency
        for run in 0..5 {
            let poly_scalar = ntt_scalar(&poly);
            let poly_avx2 = ntt_simd(&poly);

            for i in 0..N {
                assert_eq!(
                    poly_scalar.coeffs[i], poly_avx2.coeffs[i],
                    "Mismatch at coefficient {} on run {}: scalar={}, avx2={}",
                    i, run, poly_scalar.coeffs[i], poly_avx2.coeffs[i]
                );
            }
        }
    }
}

#[cfg(not(all(feature = "avx2", target_arch = "x86_64")))]
mod no_avx2_tests {
    #[test]
    fn test_avx2_not_available() {
        // This test just ensures the module compiles when AVX2 is not available
        println!("AVX2 tests skipped - feature not enabled or not on x86_64");
    }
}
