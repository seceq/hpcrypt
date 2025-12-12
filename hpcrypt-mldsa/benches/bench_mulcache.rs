//! Benchmark for Multiplication Cache (Mulcache) optimization
//!
//! This benchmark compares standard NTT multiplication vs. cached NTT multiplication.
//! The cache optimization pre-computes values that can be reused across multiple
//! multiplications, which is beneficial for matrix-vector operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_mldsa::ntt::{ntt, ntt_multiply, ntt_multiply_cached};
use hpcrypt_mldsa::poly::{Poly, PolyMulcache};

/// Helper: Create a test polynomial with pseudo-random coefficients
fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    let q = 8380417i32;
    for i in 0..256 {
        // Simple pseudo-random formula
        let val = (((seed as i64) + (i as i64)) * 1103515245 + 12345) % (q as i64);
        poly.coeffs[i] = if val > (q as i64) / 2 {
            (val - (q as i64)) as i32
        } else {
            val as i32
        };
    }
    poly
}

/// Benchmark: Cache computation overhead
fn bench_cache_compute(c: &mut Criterion) {
    let poly = create_test_poly(1000);
    let poly_ntt = ntt(&poly);

    c.bench_function("cache_compute", |b| {
        b.iter(|| {
            let cache = PolyMulcache::compute(black_box(&poly_ntt));
            black_box(&cache);
        });
    });
}

/// Benchmark: Single polynomial multiply (baseline vs cached)
fn bench_single_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_multiply");

    let a = create_test_poly(1000);
    let b = create_test_poly(2000);
    let a_ntt = ntt(&a);
    let b_ntt = ntt(&b);
    let a_cache = PolyMulcache::compute(&a_ntt);

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let result = ntt_multiply(black_box(&a_ntt), black_box(&b_ntt));
            black_box(&result);
        });
    });

    group.bench_function("cached", |b| {
        b.iter(|| {
            let result =
                ntt_multiply_cached(black_box(&a_ntt), black_box(&a_cache), black_box(&b_ntt));
            black_box(&result);
        });
    });

    group.bench_function("cached_with_compute", |b| {
        b.iter(|| {
            let cache = PolyMulcache::compute(black_box(&a_ntt));
            let result = ntt_multiply_cached(black_box(&a_ntt), &cache, black_box(&b_ntt));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Two sequential multiplications (amortize cache cost)
fn bench_two_multiplies(c: &mut Criterion) {
    let mut group = c.benchmark_group("two_multiplies");

    let a = create_test_poly(1000);
    let b1 = create_test_poly(2000);
    let b2 = create_test_poly(3000);
    let a_ntt = ntt(&a);
    let b1_ntt = ntt(&b1);
    let b2_ntt = ntt(&b2);
    let a_cache = PolyMulcache::compute(&a_ntt);

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let result1 = ntt_multiply(black_box(&a_ntt), black_box(&b1_ntt));
            let result2 = ntt_multiply(black_box(&a_ntt), black_box(&b2_ntt));
            black_box((&result1, &result2));
        });
    });

    group.bench_function("cached", |b| {
        b.iter(|| {
            let cache = PolyMulcache::compute(black_box(&a_ntt));
            let result1 = ntt_multiply_cached(black_box(&a_ntt), &cache, black_box(&b1_ntt));
            let result2 = ntt_multiply_cached(black_box(&a_ntt), &cache, black_box(&b2_ntt));
            black_box((&result1, &result2));
        });
    });

    group.finish();
}

/// Benchmark: Matrix-vector multiply pattern (realistic workload)
///
/// This simulates the pattern in ML-DSA signing where we compute:
/// w = A × y
/// where A is a K×L matrix and y is a vector of L polynomials.
///
/// For ML-DSA-65: K=6, L=5 → 30 polynomial multiplications
/// For ML-DSA-87: K=8, L=7 → 56 polynomial multiplications
fn bench_matrix_vector(c: &mut Criterion) {
    for &l in &[5, 7] {
        // ML-DSA-65 (L=5), ML-DSA-87 (L=7)
        let mut group = c.benchmark_group(format!("matrix_vector_L{}", l));

        // Create test data: one row of matrix A (L polynomials) and vector y (L polynomials)
        let matrix_row: Vec<Poly> = (0..l)
            .map(|i| {
                let poly = create_test_poly((i as i32) * 1000);
                ntt(&poly)
            })
            .collect();

        let y_vec: Vec<Poly> = (0..l)
            .map(|i| {
                let poly = create_test_poly((i as i32) * 2000);
                ntt(&poly)
            })
            .collect();

        // Baseline: standard ntt_multiply without cache
        group.bench_function("baseline", |b| {
            b.iter(|| {
                let mut acc = Poly::new();
                for j in 0..l {
                    let prod = ntt_multiply(black_box(&matrix_row[j]), black_box(&y_vec[j]));
                    // Simple addition (no lazy reduction for fair comparison)
                    for i in 0..256 {
                        acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
                    }
                }
                black_box(&acc);
            });
        });

        // Cached: pre-compute caches for matrix row, then multiply
        group.bench_function("cached", |b| {
            b.iter(|| {
                // Pre-compute caches for matrix row
                let caches: Vec<_> = matrix_row
                    .iter()
                    .map(|a| PolyMulcache::compute(a))
                    .collect();

                // Matrix-vector multiply using caches
                let mut acc = Poly::new();
                for j in 0..l {
                    let prod = ntt_multiply_cached(
                        black_box(&matrix_row[j]),
                        black_box(&caches[j]),
                        black_box(&y_vec[j]),
                    );
                    // Simple addition
                    for i in 0..256 {
                        acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
                    }
                }
                black_box(&acc);
            });
        });

        // Pre-computed: caches are computed once outside the benchmark loop
        // This shows the performance when caches can be truly reused
        let pre_caches: Vec<_> = matrix_row
            .iter()
            .map(|a| PolyMulcache::compute(a))
            .collect();

        group.bench_function("cached_precomputed", |b| {
            b.iter(|| {
                let mut acc = Poly::new();
                for j in 0..l {
                    let prod = ntt_multiply_cached(
                        black_box(&matrix_row[j]),
                        black_box(&pre_caches[j]),
                        black_box(&y_vec[j]),
                    );
                    // Simple addition
                    for i in 0..256 {
                        acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
                    }
                }
                black_box(&acc);
            });
        });

        group.finish();
    }
}

/// Benchmark: Repeated matrix-vector multiply (signature rejection loop)
///
/// In ML-DSA signing, we often need to multiply the same matrix A with different
/// y vectors in a rejection sampling loop. This is where mulcache shines.
fn bench_repeated_matrix_vector(c: &mut Criterion) {
    let l = 5; // ML-DSA-65
    let num_iterations = 10; // Simulate 10 rejection loop iterations

    let mut group = c.benchmark_group("repeated_matrix_vector");

    // Create test data
    let matrix_row: Vec<Poly> = (0..l)
        .map(|i| {
            let poly = create_test_poly((i as i32) * 1000);
            ntt(&poly)
        })
        .collect();

    let y_vecs: Vec<Vec<Poly>> = (0..num_iterations)
        .map(|iter| {
            (0..l)
                .map(|j| {
                    let poly = create_test_poly((iter as i32) * 10000 + (j as i32) * 100);
                    ntt(&poly)
                })
                .collect()
        })
        .collect();

    // Baseline: no caching
    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_iterations);
            for y_vec in &y_vecs {
                let mut acc = Poly::new();
                for j in 0..l {
                    let prod = ntt_multiply(black_box(&matrix_row[j]), black_box(&y_vec[j]));
                    for i in 0..256 {
                        acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
                    }
                }
                results.push(acc);
            }
            black_box(&results);
        });
    });

    // Cached: compute caches once, reuse for all iterations
    group.bench_function("cached", |b| {
        b.iter(|| {
            // Pre-compute caches ONCE
            let caches: Vec<_> = matrix_row
                .iter()
                .map(|a| PolyMulcache::compute(a))
                .collect();

            // Reuse caches for all iterations
            let mut results = Vec::with_capacity(num_iterations);
            for y_vec in &y_vecs {
                let mut acc = Poly::new();
                for j in 0..l {
                    let prod = ntt_multiply_cached(
                        black_box(&matrix_row[j]),
                        black_box(&caches[j]),
                        black_box(&y_vec[j]),
                    );
                    for i in 0..256 {
                        acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
                    }
                }
                results.push(acc);
            }
            black_box(&results);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cache_compute,
    bench_single_multiply,
    bench_two_multiplies,
    bench_matrix_vector,
    bench_repeated_matrix_vector
);
criterion_main!(benches);
