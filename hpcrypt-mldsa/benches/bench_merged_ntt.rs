//! Benchmark for Merged NTT Layers optimization
//!
//! This benchmark compares standard NTT vs merged NTT (with manually unrolled smallest layers).
//! The merged version eliminates loop overhead for len=4, 2, 1 layers while keeping standard
//! loops for larger layers where LLVM optimizes well.
//!
//! Expected improvement: 5-25% based on ML-KEM analysis

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_mldsa::ntt::{inv_ntt, inv_ntt_merged, ntt, ntt_merged};
use hpcrypt_mldsa::poly::Poly;

/// Helper: Create a test polynomial with small coefficients for testing
fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    // Use small values to avoid modular reduction complications in testing
    for i in 0..256 {
        // Simple pseudo-random formula that produces small values
        poly.coeffs[i] = ((seed + (i as i32)) * 1103515245 + 12345) % 1000;
    }
    poly
}

/// Benchmark: Forward NTT (standard vs merged)
fn bench_forward_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("forward_ntt");

    let poly = create_test_poly(1000);

    // Baseline: Standard NTT with nested loops
    group.bench_function("ntt_standard", |b| {
        b.iter(|| {
            let result = ntt(black_box(&poly));
            black_box(&result);
        });
    });

    // Optimized: Merged NTT with manually unrolled smallest layers
    group.bench_function("ntt_merged", |b| {
        b.iter(|| {
            let result = ntt_merged(black_box(&poly));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Inverse NTT (standard vs merged)
fn bench_inverse_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("inverse_ntt");

    let poly = create_test_poly(2000);
    let poly_ntt = ntt(&poly); // Pre-transform to NTT domain

    // Baseline: Standard inverse NTT
    group.bench_function("inv_ntt_standard", |b| {
        b.iter(|| {
            let result = inv_ntt(black_box(&poly_ntt));
            black_box(&result);
        });
    });

    // Optimized: Merged inverse NTT
    group.bench_function("inv_ntt_merged", |b| {
        b.iter(|| {
            let result = inv_ntt_merged(black_box(&poly_ntt));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Full NTT roundtrip (forward + inverse)
fn bench_ntt_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_roundtrip");

    let poly = create_test_poly(3000);

    // Baseline: Standard NTT roundtrip
    group.bench_function("standard_roundtrip", |b| {
        b.iter(|| {
            let ntt_poly = ntt(black_box(&poly));
            let result = inv_ntt(&ntt_poly);
            black_box(&result);
        });
    });

    // Optimized: Merged NTT roundtrip
    group.bench_function("merged_roundtrip", |b| {
        b.iter(|| {
            let ntt_poly = ntt_merged(black_box(&poly));
            let result = inv_ntt_merged(&ntt_poly);
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Matrix-vector multiply pattern (realistic workload)
///
/// Simulates ML-DSA signing where we transform multiple polynomials
/// from matrix A and vector y, then transform results back.
fn bench_matrix_vector_pattern(c: &mut Criterion) {
    let l = 5; // ML-DSA-65 parameter

    let mut group = c.benchmark_group("matrix_vector_transform");

    // Create test vectors
    let vector_polys: Vec<Poly> = (0..l)
        .map(|i| create_test_poly((i as i32) * 1000))
        .collect();

    // Baseline: Standard NTT for all polynomials
    group.bench_function("standard_vector_ntt", |b| {
        b.iter(|| {
            let mut ntt_polys = Vec::with_capacity(l);
            for poly in &vector_polys {
                let poly_ntt = ntt(black_box(poly));
                ntt_polys.push(poly_ntt);
            }

            // Transform back (simulating result computation)
            let mut results = Vec::with_capacity(l);
            for poly_ntt in &ntt_polys {
                let result = inv_ntt(poly_ntt);
                results.push(result);
            }

            black_box(&results);
        });
    });

    // Optimized: Merged NTT for all polynomials
    group.bench_function("merged_vector_ntt", |b| {
        b.iter(|| {
            let mut ntt_polys = Vec::with_capacity(l);
            for poly in &vector_polys {
                let poly_ntt = ntt_merged(black_box(poly));
                ntt_polys.push(poly_ntt);
            }

            // Transform back (simulating result computation)
            let mut results = Vec::with_capacity(l);
            for poly_ntt in &ntt_polys {
                let result = inv_ntt_merged(poly_ntt);
                results.push(result);
            }

            black_box(&results);
        });
    });

    group.finish();
}

/// Benchmark: Rejection loop pattern (most realistic for signing)
///
/// In ML-DSA signing, we often perform NTT roundtrips in a rejection loop.
/// This benchmark simulates 10 rejection iterations.
fn bench_rejection_loop_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("rejection_loop");

    let num_iterations: usize = 10; // Simulate 10 rejection iterations
    let polys: Vec<Poly> = (0..num_iterations)
        .map(|i| create_test_poly((i as i32) * 100))
        .collect();

    // Baseline: Standard NTT in rejection loop
    group.bench_function("standard_rejection", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_iterations);
            for poly in &polys {
                // Forward NTT (transform sampled polynomial)
                let poly_ntt = ntt(black_box(poly));

                // ... matrix multiply happens here ...

                // Inverse NTT (transform result)
                let result = inv_ntt(&poly_ntt);

                // ... rejection check happens here ...
                results.push(result);
            }
            black_box(&results);
        });
    });

    // Optimized: Merged NTT in rejection loop
    group.bench_function("merged_rejection", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_iterations);
            for poly in &polys {
                // Forward NTT (transform sampled polynomial)
                let poly_ntt = ntt_merged(black_box(poly));

                // ... matrix multiply happens here ...

                // Inverse NTT (transform result)
                let result = inv_ntt_merged(&poly_ntt);

                // ... rejection check happens here ...
                results.push(result);
            }
            black_box(&results);
        });
    });

    group.finish();
}

/// Benchmark: Large-scale batch processing (K×L matrix)
///
/// Simulates transforming an entire K×L matrix as in ML-DSA-65 (6×5 = 30 polynomials)
fn bench_batch_transform(c: &mut Criterion) {
    let k = 6; // ML-DSA-65 K parameter
    let l = 5; // ML-DSA-65 L parameter
    let total = k * l;

    let mut group = c.benchmark_group("batch_transform");

    let matrix_polys: Vec<Poly> = (0..total)
        .map(|i| create_test_poly((i as i32) * 50))
        .collect();

    // Baseline: Standard NTT for entire matrix
    group.bench_function("standard_batch", |b| {
        b.iter(|| {
            let mut ntt_polys = Vec::with_capacity(total);
            for poly in &matrix_polys {
                let poly_ntt = ntt(black_box(poly));
                ntt_polys.push(poly_ntt);
            }
            black_box(&ntt_polys);
        });
    });

    // Optimized: Merged NTT for entire matrix
    group.bench_function("merged_batch", |b| {
        b.iter(|| {
            let mut ntt_polys = Vec::with_capacity(total);
            for poly in &matrix_polys {
                let poly_ntt = ntt_merged(black_box(poly));
                ntt_polys.push(poly_ntt);
            }
            black_box(&ntt_polys);
        });
    });

    group.finish();
}

/// Benchmark: Correctness verification (ensure merged NTT gives same results)
///
/// This is not a performance benchmark - it verifies that merged NTT
/// produces identical results to standard NTT.
fn verify_correctness() {
    use hpcrypt_mldsa::ntt::from_montgomery;

    for seed in 0..10 {
        let poly = create_test_poly(seed);

        // Forward NTT
        let standard_ntt = ntt(&poly);
        let merged_ntt = ntt_merged(&poly);

        // Check forward NTT results match
        for i in 0..256 {
            assert_eq!(
                standard_ntt.coeffs[i], merged_ntt.coeffs[i],
                "Forward NTT mismatch at index {} for seed {}",
                i, seed
            );
        }

        // Inverse NTT
        let standard_inv = inv_ntt(&standard_ntt);
        let merged_inv = inv_ntt_merged(&merged_ntt);

        // Check inverse NTT results match
        for i in 0..256 {
            assert_eq!(
                standard_inv.coeffs[i], merged_inv.coeffs[i],
                "Inverse NTT mismatch at index {} for seed {}",
                i, seed
            );
        }

        // Check roundtrip (should recover original polynomial)
        // Note: inv_ntt returns Montgomery form, need to convert back
        // Also need to ensure values are in same canonical form (mod Q)
        const Q: i32 = 8380417;
        for i in 0..256 {
            let recovered = from_montgomery(merged_inv.coeffs[i]);
            // Both values should be equivalent mod Q
            let orig_mod = poly.coeffs[i].rem_euclid(Q);
            let recovered_mod = recovered.rem_euclid(Q);
            assert_eq!(
                orig_mod, recovered_mod,
                "Roundtrip mismatch at index {} for seed {}: orig={} recovered={}",
                i, seed, poly.coeffs[i], recovered
            );
        }
    }
    println!("✓ Correctness verification passed for 10 test cases");
}

// Run correctness check before benchmarks
#[ctor::ctor]
fn init() {
    verify_correctness();
}

criterion_group!(
    benches,
    bench_forward_ntt,
    bench_inverse_ntt,
    bench_ntt_roundtrip,
    bench_matrix_vector_pattern,
    bench_rejection_loop_pattern,
    bench_batch_transform
);
criterion_main!(benches);
