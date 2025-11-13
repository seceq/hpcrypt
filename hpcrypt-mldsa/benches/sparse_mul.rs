//! Benchmark for Sparse Polynomial Multiplication
//!
//! Compares sparse multiplication vs NTT-based multiplication for challenge polynomials

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mldsa::ntt::poly_mul_ntt;
use mldsa::params::{N, Q};
use mldsa::poly::Poly;
use mldsa::sampling::sample_in_ball;
use mldsa::sparse_mul::{sparse_poly_multiply, SparsePoly};

fn bench_sparse_vs_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_multiply");

    // Test with different tau values (ML-DSA parameter sets)
    let tau_values = vec![(39, "ML-DSA-44"), (49, "ML-DSA-65"), (60, "ML-DSA-87")];

    for (tau, name) in tau_values {
        // Create challenge polynomial with tau non-zero coefficients
        let seed = [0x42u8; 32];
        let c = sample_in_ball(&seed, tau);
        let c_sparse = SparsePoly::from_challenge(&c);

        // Create random dense polynomial
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = ((i * 12345 + 67890) % Q as usize) as i32;
        }

        // Benchmark NTT multiplication
        group.bench_with_input(BenchmarkId::new("ntt", name), &(&c, &p), |b, (c, p)| {
            b.iter(|| black_box(poly_mul_ntt(c, p)))
        });

        // Benchmark sparse multiplication
        group.bench_with_input(
            BenchmarkId::new("sparse", name),
            &(&c_sparse, &p),
            |b, (c_sparse, p)| b.iter(|| black_box(sparse_poly_multiply(c_sparse, p))),
        );
    }

    group.finish();
}

fn bench_sparse_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_extraction");

    let tau = 60; // ML-DSA-87 (worst case)
    let seed = [0x42u8; 32];
    let poly = sample_in_ball(&seed, tau);

    group.bench_function("from_challenge", |b| {
        b.iter(|| black_box(SparsePoly::from_challenge(&poly)))
    });

    group.finish();
}

criterion_group!(benches, bench_sparse_vs_ntt, bench_sparse_extraction);
criterion_main!(benches);
