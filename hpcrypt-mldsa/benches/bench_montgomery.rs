//\! Benchmark for Montgomery Reduction optimization validation
//\! 
//\! This validates the performance gain of Montgomery reduction vs standard modular reduction

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mldsa::params::Q;

/// Standard modular reduction using % operator
#[inline]
fn standard_reduce(x: i64) -> i32 {
    (x % (Q as i64)) as i32
}

/// Barrett reduction (alternative to Montgomery)
#[inline]
fn barrett_reduce(x: i64) -> i32 {
    const BARRETT_MULTIPLIER: i64 = 5039; // Precomputed: floor(2^28 / Q)
    const BARRETT_SHIFT: i32 = 28;
    
    let q = (((x * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) * (Q as i64)) as i32;
    (x as i32) - q
}

/// Montgomery reduction (current implementation)
/// Converts from Montgomery domain: (a * R^-1) mod Q
#[inline]
fn montgomery_reduce(a: i64) -> i32 {
    const QINV: i64 = 58728449; // Q^-1 mod 2^32
    let t = (a * QINV) & ((1i64 << 32) - 1);
    let t = (t * (Q as i64)) >> 32;
    ((a >> 32) as i32) - (t as i32)
}

fn bench_reduction_methods(c: &mut Criterion) {
    let test_values: Vec<i64> = vec![
        1234567890,
        -987654321,
        Q as i64 * 1000 + 42,
        -(Q as i64 * 500 + 100),
        i32::MAX as i64,
        i32::MIN as i64,
    ];

    let mut group = c.benchmark_group("reduction_methods");

    group.bench_function("standard_modular", |b| {
        b.iter(|| {
            for &val in &test_values {
                black_box(standard_reduce(black_box(val)));
            }
        })
    });

    group.bench_function("barrett_reduction", |b| {
        b.iter(|| {
            for &val in &test_values {
                black_box(barrett_reduce(black_box(val)));
            }
        })
    });

    group.bench_function("montgomery_reduction", |b| {
        b.iter(|| {
            for &val in &test_values {
                black_box(montgomery_reduce(black_box(val)));
            }
        })
    });

    group.finish();
}

fn bench_single_reduction(c: &mut Criterion) {
    let val: i64 = 1234567890;
    
    let mut group = c.benchmark_group("single_reduction");

    group.bench_function("standard", |b| {
        b.iter(|| black_box(standard_reduce(black_box(val))))
    });

    group.bench_function("barrett", |b| {
        b.iter(|| black_box(barrett_reduce(black_box(val))))
    });

    group.bench_function("montgomery", |b| {
        b.iter(|| black_box(montgomery_reduce(black_box(val))))
    });

    group.finish();
}

fn bench_multiply_reduce_chain(c: &mut Criterion) {
    let a: i32 = 12345;
    let b: i32 = 67890;

    let mut group = c.benchmark_group("multiply_reduce_chain");

    group.bench_function("standard", |bencher| {
        bencher.iter(|| {
            let mut result = black_box(a);
            for _ in 0..10 {
                result = standard_reduce((result as i64) * (b as i64));
            }
            black_box(result)
        })
    });

    group.bench_function("montgomery", |bencher| {
        bencher.iter(|| {
            let mut result = black_box(a);
            for _ in 0..10 {
                result = montgomery_reduce((result as i64) * (b as i64));
            }
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_reduction_methods, bench_single_reduction, bench_multiply_reduce_chain);
criterion_main!(benches);
