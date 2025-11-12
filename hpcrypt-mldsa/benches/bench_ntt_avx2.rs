//! Benchmark comparing AVX2 SIMD NTT vs Rust scalar NTT

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mldsa::poly::Poly;
use mldsa::ntt::ntt_scalar;
use mldsa::params::N;

#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
use mldsa::simd::dispatch::ntt_simd;
#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
use mldsa::simd::avx2::init_qdata;

fn bench_ntt_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_scalar");

    // Test with various polynomial patterns
    let test_cases = vec![
        ("zeros", Poly::new()),
        ("sequential", {
            let mut p = Poly::new();
            for i in 0..N {
                p.coeffs[i] = i as i32;
            }
            p
        }),
        ("random_small", {
            let mut p = Poly::new();
            for i in 0..N {
                p.coeffs[i] = ((i * 7919) % 1000) as i32;
            }
            p
        }),
    ];

    for (name, poly) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &poly, |b, p| {
            b.iter(|| {
                let result = ntt_scalar(black_box(p));
                black_box(result);
            });
        });
    }

    group.finish();
}

#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
fn bench_ntt_avx2(c: &mut Criterion) {
    // Initialize qdata once
    init_qdata();

    let mut group = c.benchmark_group("ntt_avx2");

    // Test with various polynomial patterns
    let test_cases = vec![
        ("zeros", Poly::new()),
        ("sequential", {
            let mut p = Poly::new();
            for i in 0..N {
                p.coeffs[i] = i as i32;
            }
            p
        }),
        ("random_small", {
            let mut p = Poly::new();
            for i in 0..N {
                p.coeffs[i] = ((i * 7919) % 1000) as i32;
            }
            p
        }),
    ];

    for (name, poly) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &poly, |b, p| {
            b.iter(|| {
                let result = ntt_simd(black_box(p));
                black_box(result);
            });
        });
    }

    group.finish();
}

#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
fn bench_ntt_comparison(c: &mut Criterion) {
    // Initialize qdata once
    init_qdata();

    let mut group = c.benchmark_group("ntt_comparison");

    // Use a realistic polynomial (random small values)
    let poly = {
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = ((i * 7919) % 1000) as i32;
        }
        p
    };

    group.bench_function("scalar", |b| {
        b.iter(|| {
            let result = ntt_scalar(black_box(&poly));
            black_box(result);
        });
    });

    group.bench_function("avx2", |b| {
        b.iter(|| {
            let result = ntt_simd(black_box(&poly));
            black_box(result);
        });
    });

    group.finish();
}

#[cfg(not(all(feature = "avx2", target_arch = "x86_64")))]
fn bench_ntt_avx2(_c: &mut Criterion) {
    // AVX2 not available
}

#[cfg(not(all(feature = "avx2", target_arch = "x86_64")))]
fn bench_ntt_comparison(_c: &mut Criterion) {
    // AVX2 not available
}

criterion_group!(
    benches,
    bench_ntt_scalar,
    bench_ntt_avx2,
    bench_ntt_comparison
);
criterion_main!(benches);
