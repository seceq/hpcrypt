//! Benchmark for fixed-base scalar multiplication optimization
//! 
//! This benchmark measures the performance improvement from using
//! precomputed tables for fixed-base (generator) scalar multiplication.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::ed25519::{EdwardsPoint, Scalar};

/// Benchmark baseline: regular scalar multiplication with generator
fn bench_ed25519_baseline_generator_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_generator_scalar_mul");
    
    // Test with different scalar patterns
    let test_cases = vec![
        ("small_scalar", Scalar::from_bytes([
            1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ])),
        ("medium_scalar", Scalar::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ])),
        ("large_scalar", Scalar::from_bytes([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
        ])),
    ];

    for (name, scalar) in test_cases {
        group.bench_with_input(BenchmarkId::new("baseline", name), &scalar, |b, s| {
            let generator = EdwardsPoint::generator();
            b.iter(|| {
                black_box(generator.scalar_mul(black_box(s)))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_ed25519_baseline_generator_mul);
criterion_main!(benches);
