//! Benchmark for matrix-vector multiplication optimization
//!
//! Tests the performance of matrix_vector_mul_ntt with different strategies:
//! 1. Baseline: Single accumulator (current implementation)
//! 2. Optimized: Multiple accumulators for ILP

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mldsa::ntt::{ntt, matrix_vector_mul_ntt, matrix_vector_mul_ntt_optimized};
use mldsa::poly::Poly;
use mldsa::params::{N, Q};

/// Generate a deterministic pseudo-random polynomial for testing
fn generate_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    for i in 0..N {
        poly.coeffs[i] = ((seed * 1103515245 + i as i32 * 12345) % Q + Q) % Q;
    }
    poly
}

/// Generate test matrix A
fn generate_test_matrix(k: usize, l: usize) -> Vec<Vec<Poly>> {
    let mut matrix = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            row.push(generate_test_poly((i * 100 + j * 10) as i32));
        }
        matrix.push(row);
    }
    matrix
}

/// Generate test vector in NTT domain
fn generate_test_vector_ntt(l: usize) -> Vec<Poly> {
    let mut vector = Vec::with_capacity(l);
    for i in 0..l {
        let poly = generate_test_poly((i * 7) as i32);
        vector.push(ntt(&poly));
    }
    vector
}

/// Benchmark ML-DSA-65 matrix multiplication (k=6, l=5) - Compare baseline vs optimized
fn bench_matrix_mul_ml_dsa_65(c: &mut Criterion) {
    const K: usize = 6;  // ML-DSA-65
    const L: usize = 5;

    let matrix_a = generate_test_matrix(K, L);
    let v_ntt = generate_test_vector_ntt(L);

    c.bench_function("matrix_mul_baseline_ml_dsa_65", |b| {
        b.iter(|| {
            black_box(matrix_vector_mul_ntt(
                black_box(&matrix_a),
                black_box(&v_ntt),
                black_box(K),
                black_box(L),
            ))
        });
    });

    c.bench_function("matrix_mul_optimized_ml_dsa_65", |b| {
        b.iter(|| {
            black_box(matrix_vector_mul_ntt_optimized(
                black_box(&matrix_a),
                black_box(&v_ntt),
                black_box(K),
                black_box(L),
            ))
        });
    });
}

/// Benchmark different ML-DSA sizes - Baseline vs Optimized
fn bench_matrix_mul_all_sizes(c: &mut Criterion) {
    // ML-DSA-44: k=4, l=4
    {
        const K: usize = 4;
        const L: usize = 4;
        let matrix_a = generate_test_matrix(K, L);
        let v_ntt = generate_test_vector_ntt(L);

        c.bench_function("baseline_ml_dsa_44", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });

        c.bench_function("optimized_ml_dsa_44", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt_optimized(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });
    }

    // ML-DSA-65: k=6, l=5
    {
        const K: usize = 6;
        const L: usize = 5;
        let matrix_a = generate_test_matrix(K, L);
        let v_ntt = generate_test_vector_ntt(L);

        c.bench_function("baseline_ml_dsa_65", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });

        c.bench_function("optimized_ml_dsa_65", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt_optimized(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });
    }

    // ML-DSA-87: k=8, l=7
    {
        const K: usize = 8;
        const L: usize = 7;
        let matrix_a = generate_test_matrix(K, L);
        let v_ntt = generate_test_vector_ntt(L);

        c.bench_function("baseline_ml_dsa_87", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });

        c.bench_function("optimized_ml_dsa_87", |b| {
            b.iter(|| {
                black_box(matrix_vector_mul_ntt_optimized(
                    black_box(&matrix_a),
                    black_box(&v_ntt),
                    black_box(K),
                    black_box(L),
                ))
            });
        });
    }
}

criterion_group!(benches, bench_matrix_mul_ml_dsa_65, bench_matrix_mul_all_sizes);
criterion_main!(benches);
