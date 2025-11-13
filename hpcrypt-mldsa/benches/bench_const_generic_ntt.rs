//! Benchmark for const generic NTT specialization
//!
//! This benchmark compares the current NTT implementation (runtime loops)
//! vs. const generic specialized NTT (compile-time layer unrolling).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mldsa::ntt::{inv_ntt, inv_ntt_specialized, ntt, ntt_specialized};
use mldsa::poly::Poly;

/// Helper: Create a test polynomial with coefficients in [-Q/2, Q/2)
fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    let q = 8380417i32;
    for i in 0..256 {
        // Simple pseudo-random formula
        let val = ((seed + i as i32) * 1103515245 + 12345) % q;
        poly.coeffs[i] = if val > q / 2 { val - q } else { val };
    }
    poly
}

/// Benchmark: NTT comparison (baseline vs specialized)
fn bench_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_comparison");

    let poly = create_test_poly(1000);

    group.bench_function("ntt_baseline", |b| {
        b.iter(|| {
            let result = ntt(black_box(&poly));
            black_box(&result);
        });
    });

    group.bench_function("ntt_specialized", |b| {
        b.iter(|| {
            let result = ntt_specialized(black_box(&poly));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Inverse NTT comparison (baseline vs specialized)
fn bench_inv_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("inv_ntt_comparison");

    let poly = create_test_poly(1000);
    let ntt_poly = ntt(&poly);

    group.bench_function("inv_ntt_baseline", |b| {
        b.iter(|| {
            let result = inv_ntt(black_box(&ntt_poly));
            black_box(&result);
        });
    });

    group.bench_function("inv_ntt_specialized", |b| {
        b.iter(|| {
            let result = inv_ntt_specialized(black_box(&ntt_poly));
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: NTT roundtrip (forward + inverse)
fn bench_ntt_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_roundtrip");

    let poly = create_test_poly(1000);

    group.bench_function("ntt_roundtrip_baseline", |b| {
        b.iter(|| {
            let ntt_poly = ntt(black_box(&poly));
            let result = inv_ntt(&ntt_poly);
            black_box(&result);
        });
    });

    group.finish();
}

/// Benchmark: Batch NTT (simulates matrix-vector multiply pattern)
fn bench_batch_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_ntt");

    // Test with K×L parameter sizes for ML-DSA-65 (6×5 = 30 polynomials)
    let polys: Vec<Poly> = (0..30).map(|i| create_test_poly(i * 1000)).collect();

    group.bench_function("batch_ntt_30_polys", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(polys.len());
            for poly in &polys {
                results.push(ntt(black_box(poly)));
            }
            black_box(&results);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ntt_comparison,
    bench_inv_ntt_comparison,
    bench_ntt_roundtrip,
    bench_batch_ntt
);
criterion_main!(benches);
