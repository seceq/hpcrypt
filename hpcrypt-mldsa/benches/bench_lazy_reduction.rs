//! Benchmark for lazy reduction optimization
//!
//! This benchmark compares eager reduction (current) vs lazy reduction (proposed)
//! for polynomial arithmetic chains, especially in matrix-vector multiplication.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_mldsa::ntt::{inv_ntt, ntt};
use hpcrypt_mldsa::poly::Poly;

/// Helper: Polynomial multiplication via NTT
/// a and b should already be in NTT form
fn poly_multiply(a_ntt: &Poly, b_ntt: &Poly) -> Poly {
    // Pointwise multiplication in NTT domain
    let mut result_ntt = Poly::new();
    for i in 0..256 {
        // Coefficients are already in NTT domain, just multiply pointwise
        result_ntt.coeffs[i] =
            ((a_ntt.coeffs[i] as i64) * (b_ntt.coeffs[i] as i64) % 8380417) as i32;
    }
    // Transform back to coefficient domain
    inv_ntt(&result_ntt)
}

/// Helper: Create a random-looking polynomial with coefficients in [0, Q)
fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    for i in 0..256 {
        // Simple pseudo-random formula (not cryptographically secure, just for benchmarking)
        poly.coeffs[i] = ((seed + i as i32) * 1103515245 + 12345) % 8380417;
        if poly.coeffs[i] < 0 {
            poly.coeffs[i] += 8380417;
        }
    }
    poly
}

/// Benchmark: Polynomial addition chains (current eager reduction)
fn bench_add_chain_eager(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_chain_eager");

    // Test different chain lengths
    for &chain_len in &[2, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::from_parameter(chain_len),
            &chain_len,
            |b, &len| {
                let polys: Vec<Poly> = (0..len)
                    .map(|i| create_test_poly(i as i32 * 1000))
                    .collect();

                b.iter(|| {
                    let mut result = polys[0].clone();
                    for i in 1..len {
                        result = result.add(black_box(&polys[i])); // Eager: reduces inside add()
                    }
                    black_box(&result);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Polynomial addition chains with lazy reduction (OPTIMIZED)
fn bench_add_chain_lazy(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_chain_lazy");

    // Test different chain lengths
    for &chain_len in &[2, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::from_parameter(chain_len),
            &chain_len,
            |b, &len| {
                let polys: Vec<Poly> = (0..len)
                    .map(|i| create_test_poly(i as i32 * 1000))
                    .collect();

                b.iter(|| {
                    let mut result = polys[0].clone();
                    for i in 1..len {
                        result = result.add_lazy(black_box(&polys[i])); // Lazy: no reduction!
                    }
                    result.reduce(); // Single reduction at the end
                    black_box(&result);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Matrix-vector multiplication pattern (current)
///
/// Simulates: w_i = A[i,0]*y[0] + A[i,1]*y[1] + ... + A[i,L-1]*y[L-1]
/// This is the hot path in ML-DSA signing.
fn bench_matrix_vector_mul_eager(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_vector_mul_eager");

    // Test with L=5 (ML-DSA-65) and L=7 (ML-DSA-87)
    for &l in &[5, 7] {
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            // Create matrix row and vector
            let matrix_row: Vec<Poly> = (0..l)
                .map(|i| ntt(&create_test_poly(i as i32 * 1000)))
                .collect();
            let y_vec: Vec<Poly> = (0..l)
                .map(|i| ntt(&create_test_poly(i as i32 * 2000)))
                .collect();

            b.iter(|| {
                // Accumulate products with eager reduction (current implementation)
                let mut acc0 = Poly::new();
                let mut acc1 = Poly::new();
                let mut acc2 = Poly::new();
                let mut acc3 = Poly::new();

                let mut j = 0;
                while j + 4 <= l {
                    let prod0 = poly_multiply(&matrix_row[j], &y_vec[j]);
                    let prod1 = poly_multiply(&matrix_row[j + 1], &y_vec[j + 1]);
                    let prod2 = poly_multiply(&matrix_row[j + 2], &y_vec[j + 2]);
                    let prod3 = poly_multiply(&matrix_row[j + 3], &y_vec[j + 3]);

                    // Eager reduction: each add() reduces internally
                    acc0 = acc0.add(&prod0);
                    acc1 = acc1.add(&prod1);
                    acc2 = acc2.add(&prod2);
                    acc3 = acc3.add(&prod3);

                    j += 4;
                }

                // Combine accumulators (more eager reductions)
                let mut w_i = acc0.add(&acc1).add(&acc2).add(&acc3);

                // Handle remainder
                while j < l {
                    let prod = poly_multiply(&matrix_row[j], &y_vec[j]);
                    w_i = w_i.add(&prod);
                    j += 1;
                }

                // Final reduction (redundant in current implementation)
                w_i.reduce();

                black_box(&w_i);
            });
        });
    }

    group.finish();
}

/// Benchmark: Matrix-vector multiplication with lazy reduction (OPTIMIZED)
///
/// Simulates: w_i = A[i,0]*y[0] + A[i,1]*y[1] + ... + A[i,L-1]*y[L-1]
/// Uses lazy reduction to defer all reductions until the end.
fn bench_matrix_vector_mul_lazy(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_vector_mul_lazy");

    // Test with L=5 (ML-DSA-65) and L=7 (ML-DSA-87)
    for &l in &[5, 7] {
        group.bench_with_input(BenchmarkId::from_parameter(l), &l, |b, &l| {
            // Create matrix row and vector
            let matrix_row: Vec<Poly> = (0..l)
                .map(|i| ntt(&create_test_poly(i as i32 * 1000)))
                .collect();
            let y_vec: Vec<Poly> = (0..l)
                .map(|i| ntt(&create_test_poly(i as i32 * 2000)))
                .collect();

            b.iter(|| {
                // Accumulate products with LAZY reduction (optimized)
                let mut acc0 = Poly::new();
                let mut acc1 = Poly::new();
                let mut acc2 = Poly::new();
                let mut acc3 = Poly::new();

                let mut j = 0;
                while j + 4 <= l {
                    let prod0 = poly_multiply(&matrix_row[j], &y_vec[j]);
                    let prod1 = poly_multiply(&matrix_row[j + 1], &y_vec[j + 1]);
                    let prod2 = poly_multiply(&matrix_row[j + 2], &y_vec[j + 2]);
                    let prod3 = poly_multiply(&matrix_row[j + 3], &y_vec[j + 3]);

                    // Lazy reduction: no reduction in add_lazy()
                    acc0 = acc0.add_lazy(&prod0);
                    acc1 = acc1.add_lazy(&prod1);
                    acc2 = acc2.add_lazy(&prod2);
                    acc3 = acc3.add_lazy(&prod3);

                    j += 4;
                }

                // Combine accumulators with lazy reduction
                let mut w_i = acc0.add_lazy(&acc1).add_lazy(&acc2).add_lazy(&acc3);

                // Handle remainder
                while j < l {
                    let prod = poly_multiply(&matrix_row[j], &y_vec[j]);
                    w_i = w_i.add_lazy(&prod);
                    j += 1;
                }

                // Single reduction at the end!
                w_i.reduce();

                black_box(&w_i);
            });
        });
    }

    group.finish();
}

/// Benchmark: Single polynomial addition (for comparison)
fn bench_single_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_poly_add");

    let poly1 = create_test_poly(1000);
    let poly2 = create_test_poly(2000);

    group.bench_function("add_eager", |b| {
        b.iter(|| {
            let result = poly1.add(black_box(&poly2));
            black_box(&result);
        });
    });

    group.bench_function("add_lazy", |b| {
        b.iter(|| {
            let mut result = poly1.add_lazy(black_box(&poly2));
            result.reduce();
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Single polynomial subtraction (for comparison)
fn bench_single_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_poly_sub");

    let poly1 = create_test_poly(1000);
    let poly2 = create_test_poly(2000);

    group.bench_function("sub_eager", |b| {
        b.iter(|| {
            let result = poly1.sub(black_box(&poly2));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Polynomial reduce operation
fn bench_reduce(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_reduce");

    let mut poly = create_test_poly(1000);
    // Make coefficients larger to test reduction performance
    for coeff in &mut poly.coeffs {
        *coeff = *coeff * 4; // Could be up to 4*Q
    }

    group.bench_function("reduce", |b| {
        b.iter(|| {
            let mut p = poly.clone();
            p.reduce();
            black_box(&p);
        });
    });

    group.finish();
}

/// Benchmark: Barrett reduction (single coefficient)
fn bench_barrett_reduce(c: &mut Criterion) {
    let mut group = c.benchmark_group("barrett_reduce");

    group.bench_function("barrett_reduce_single", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            // Benchmark 256 barrett reductions (one polynomial's worth)
            for i in 0..256 {
                sum += hpcrypt_mldsa::poly::barrett_reduce(black_box(i * 100000));
            }
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_add,
    bench_single_sub,
    bench_reduce,
    bench_barrett_reduce,
    bench_add_chain_eager,
    bench_add_chain_lazy,
    bench_matrix_vector_mul_eager,
    bench_matrix_vector_mul_lazy
);
criterion_main!(benches);
