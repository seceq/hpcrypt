//! Ed25519 Lazy Reduction Benchmark
//!
//! This benchmark measures the performance impact of lazy reduction
//! for Ed25519 field arithmetic operations.
//!
//! Expected improvement: 10-15% for point operations based on reducing
//! the number of full reductions from ~15 to ~6-8 per operation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::ed25519::{EdwardsPoint, Scalar};
use hpcrypt_curves::field25519::FieldElement;

// ============================================================================
// BASELINE: Current Implementation Benchmarks
// ============================================================================

fn bench_field_operations_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_field_baseline");
    group.sample_size(1000);

    let a = FieldElement::from_bytes(&[0x42; 32]);
    let b = FieldElement::from_bytes(&[0x7A; 32]);

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(a.add(&b)));
    });

    group.bench_function("sub", |bencher| {
        bencher.iter(|| black_box(a.sub(&b)));
    });

    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(a.mul(&b)));
    });

    group.bench_function("square", |bencher| {
        bencher.iter(|| black_box(a.square()));
    });

    // Common pattern: chained operations
    group.bench_function("add_chain_3ops", |bencher| {
        bencher.iter(|| {
            let r1 = a.add(&b);
            let r2 = r1.add(&a);
            black_box(r2.add(&b))
        });
    });

    group.bench_function("mul_add_pattern", |bencher| {
        bencher.iter(|| {
            let r1 = a.mul(&b);
            black_box(r1.add(&a))
        });
    });

    group.finish();
}

fn bench_point_operations_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_point_baseline");
    group.sample_size(100);

    let scalar1 = Scalar::from_bytes(&[1u8; 32]);
    let p = EdwardsPoint::generator().scalar_mul(&scalar1.to_bytes());

    group.bench_function("double", |bencher| {
        bencher.iter(|| black_box(p.double()));
    });

    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(p.add(&p)));
    });

    // Doubling chain (common in scalar multiplication)
    group.bench_function("double_chain_4x", |bencher| {
        bencher.iter(|| {
            let mut r = p;
            r = r.double();
            r = r.double();
            r = r.double();
            black_box(r.double())
        });
    });

    group.finish();
}

fn bench_scalar_multiplication_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_scalar_mul_baseline");
    group.sample_size(50);

    let scalar = Scalar::from_bytes(&[0x42; 32]);
    let point = EdwardsPoint::generator();

    group.bench_function("variable_base", |bencher| {
        bencher.iter(|| black_box(point.scalar_mul(&scalar.to_bytes())));
    });

    group.finish();
}

// ============================================================================
// Multi-Operation Sequences (Where Lazy Reduction Helps Most)
// ============================================================================

fn bench_operation_sequences(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_sequences_baseline");
    group.sample_size(1000);

    let a = FieldElement::from_bytes(&[0x42; 32]);
    let b = FieldElement::from_bytes(&[0x7A; 32]);
    let c = FieldElement::from_bytes(&[0x13; 32]);

    // Simulates point doubling formula: a² + b²
    group.bench_function("square_add_pattern", |bencher| {
        bencher.iter(|| {
            let a_sq = a.square();
            black_box(a_sq.add(&b.square()))
        });
    });

    // Simulates common pattern: (a + b)² - c
    group.bench_function("add_square_sub_pattern", |bencher| {
        bencher.iter(|| {
            let sum = a.add(&b);
            let sq = sum.square();
            black_box(sq.sub(&c))
        });
    });

    // Simulates: a * b + c (common in point formulas)
    group.bench_function("mul_add_pattern_complex", |bencher| {
        bencher.iter(|| {
            let prod = a.mul(&b);
            black_box(prod.add(&c))
        });
    });

    // Simulates: (a - b) * (a + b) (difference of squares)
    group.bench_function("diff_of_squares", |bencher| {
        bencher.iter(|| {
            let sum = a.add(&b);
            let diff = a.sub(&b);
            black_box(sum.mul(&diff))
        });
    });

    group.finish();
}

// ============================================================================
// Reduction-Heavy Workloads
// ============================================================================

fn bench_reduction_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_reduction_heavy");
    group.sample_size(500);

    let elements: Vec<FieldElement> = (0..10)
        .map(|i| FieldElement::from_bytes(&[i as u8; 32]))
        .collect();

    // Sum 10 field elements (9 additions, each with reduction currently)
    group.bench_function("sum_10_elements", |bencher| {
        bencher.iter(|| {
            let mut sum = elements[0];
            for elem in &elements[1..] {
                sum = sum.add(elem);
            }
            black_box(sum)
        });
    });

    // Compute Σ(aᵢ²) for i=0..9
    group.bench_function("sum_of_squares_10", |bencher| {
        bencher.iter(|| {
            let mut sum = FieldElement::zero();
            for elem in &elements {
                sum = sum.add(&elem.square());
            }
            black_box(sum)
        });
    });

    group.finish();
}

criterion_group!(
    baseline_benches,
    bench_field_operations_baseline,
    bench_point_operations_baseline,
    bench_scalar_multiplication_baseline,
    bench_operation_sequences,
    bench_reduction_heavy,
);

criterion_main!(baseline_benches);
