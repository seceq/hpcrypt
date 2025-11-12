// Benchmark to demonstrate performance impact of optimizations
// This validates that the rolling macros and other optimizations are working

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mldsa::poly::Poly;
use mldsa::ntt::{ntt_scalar, inv_ntt, ntt_merged, inv_ntt_merged};
use mldsa::params::N;

fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    for i in 0..N {
        poly.coeffs[i] = (seed.wrapping_mul((i as i32) + 1)) % 8380417;
    }
    poly
}

// Benchmark comparing standard NTT vs merged NTT with rolling macros
fn bench_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Optimization Comparison");

    let poly = create_test_poly(42);

    // Standard NTT (baseline)
    group.bench_function("standard_ntt", |b| {
        b.iter(|| {
            black_box(ntt_scalar(black_box(&poly)))
        })
    });

    // Merged NTT with rolling macros (optimized)
    group.bench_function("merged_ntt_with_rolling_macros", |b| {
        b.iter(|| {
            black_box(ntt_merged(black_box(&poly)))
        })
    });

    group.finish();
}

// Benchmark inverse NTT comparison
fn bench_inv_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Inverse NTT Comparison");

    let poly = create_test_poly(42);
    let ntt_poly = ntt_scalar(&poly);

    // Standard inverse NTT
    group.bench_function("standard_inv_ntt", |b| {
        b.iter(|| {
            black_box(inv_ntt(black_box(&ntt_poly)))
        })
    });

    // Merged inverse NTT with rolling macros
    group.bench_function("merged_inv_ntt_with_rolling_macros", |b| {
        b.iter(|| {
            black_box(inv_ntt_merged(black_box(&ntt_poly)))
        })
    });

    group.finish();
}

// Benchmark full NTT roundtrip
fn bench_ntt_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Roundtrip Comparison");

    let poly = create_test_poly(42);

    // Standard roundtrip
    group.bench_function("standard_roundtrip", |b| {
        b.iter(|| {
            let ntt_poly = ntt_scalar(black_box(&poly));
            black_box(inv_ntt(&ntt_poly))
        })
    });

    // Optimized roundtrip with rolling macros
    group.bench_function("optimized_roundtrip_with_macros", |b| {
        b.iter(|| {
            let ntt_poly = ntt_merged(black_box(&poly));
            black_box(inv_ntt_merged(&ntt_poly))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ntt_comparison,
    bench_inv_ntt_comparison,
    bench_ntt_roundtrip
);
criterion_main!(benches);
