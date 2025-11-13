//! Benchmark for decompose operation optimization
//!
//! Tests whether const generic specialization or magic constant division
//! can improve performance over the current runtime parameter approach.
//!
//! Expected: LLVM should already optimize constant divisions, but we validate empirically.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mldsa::params::Q;
use mldsa::rounding::{decompose, high_bits, low_bits};

/// Test data: representative coefficient values
fn create_test_values() -> Vec<i32> {
    let mut values = Vec::new();

    // Edge cases
    values.push(0);
    values.push(1);
    values.push(Q - 1);

    // Typical values distributed across the range
    for i in 0..1000 {
        let val = ((i * 1234567) % Q as usize) as i32;
        values.push(val);
    }

    values
}

/// Baseline: Current implementation with runtime alpha parameter
fn bench_decompose_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose_baseline");
    let test_values = create_test_values();

    // ML-DSA-44: alpha = 190464
    group.bench_function("alpha_190464", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                let (r1, r0) = decompose(black_box(r), black_box(190464));
                sum = sum.wrapping_add(r1).wrapping_add(r0);
            }
            black_box(sum);
        });
    });

    // ML-DSA-65/87: alpha = 523776
    group.bench_function("alpha_523776", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                let (r1, r0) = decompose(black_box(r), black_box(523776));
                sum = sum.wrapping_add(r1).wrapping_add(r0);
            }
            black_box(sum);
        });
    });

    group.finish();
}

/// Test const generic version (if LLVM can optimize better)
#[inline(always)]
fn decompose_const<const ALPHA: i32>(r: i32) -> (i32, i32) {
    debug_assert!(r >= 0 && r < Q, "r must be in [0, q)");
    debug_assert!(ALPHA > 0 && ALPHA < Q, "alpha must be in valid range");

    // Centered remainder: r1 = ⌊(r + 127) / α⌋
    let mut r1 = (r + 127) / ALPHA;

    // Compute r0 = r - r1 * α
    let mut r0 = r - r1 * ALPHA;

    // Adjust if r0 is too large
    if r0 > ALPHA / 2 {
        r1 += 1;
        r0 -= ALPHA;
    }

    // Special case: if r1 = (q-1)/α, set r1 = 0 and adjust r0
    let max_r1 = (Q - 1) / ALPHA;
    if r1 == max_r1 {
        r1 = 0;
        r0 -= 1;
    }

    (r1, r0)
}

fn bench_decompose_const_generic(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose_const_generic");
    let test_values = create_test_values();

    // ML-DSA-44: alpha = 190464
    group.bench_function("alpha_190464", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                let (r1, r0) = decompose_const::<190464>(black_box(r));
                sum = sum.wrapping_add(r1).wrapping_add(r0);
            }
            black_box(sum);
        });
    });

    // ML-DSA-65/87: alpha = 523776
    group.bench_function("alpha_523776", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                let (r1, r0) = decompose_const::<523776>(black_box(r));
                sum = sum.wrapping_add(r1).wrapping_add(r0);
            }
            black_box(sum);
        });
    });

    group.finish();
}

/// Test high_bits and low_bits functions (which call decompose internally)
fn bench_high_low_bits(c: &mut Criterion) {
    let mut group = c.benchmark_group("high_low_bits");
    let test_values = create_test_values();

    // high_bits with alpha = 190464
    group.bench_function("high_bits_190464", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                sum = sum.wrapping_add(high_bits(black_box(r), black_box(190464)));
            }
            black_box(sum);
        });
    });

    // low_bits with alpha = 190464
    group.bench_function("low_bits_190464", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &r in &test_values {
                sum = sum.wrapping_add(low_bits(black_box(r), black_box(190464)));
            }
            black_box(sum);
        });
    });

    group.finish();
}

/// Single decompose call (to measure per-call overhead)
fn bench_single_decompose(c: &mut Criterion) {
    c.bench_function("single_decompose_190464", |b| {
        b.iter(|| {
            let (r1, r0) = decompose(black_box(100000), black_box(190464));
            black_box((r1, r0));
        });
    });

    c.bench_function("single_decompose_const_190464", |b| {
        b.iter(|| {
            let (r1, r0) = decompose_const::<190464>(black_box(100000));
            black_box((r1, r0));
        });
    });
}

/// Realistic workload: decompose for all coefficients in a polynomial (256 coefficients)
fn bench_poly_decompose(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_decompose");

    // Create polynomial-sized data
    let poly_coeffs: Vec<i32> = (0..256)
        .map(|i| ((i * 12345 + 6789) % Q as usize) as i32)
        .collect();

    // Baseline: runtime parameter
    group.bench_function("baseline_190464", |b| {
        b.iter(|| {
            let mut r1_sum = 0i32;
            let mut r0_sum = 0i32;
            for &coeff in &poly_coeffs {
                let (r1, r0) = decompose(black_box(coeff), black_box(190464));
                r1_sum = r1_sum.wrapping_add(r1);
                r0_sum = r0_sum.wrapping_add(r0);
            }
            black_box((r1_sum, r0_sum));
        });
    });

    // Const generic version
    group.bench_function("const_generic_190464", |b| {
        b.iter(|| {
            let mut r1_sum = 0i32;
            let mut r0_sum = 0i32;
            for &coeff in &poly_coeffs {
                let (r1, r0) = decompose_const::<190464>(black_box(coeff));
                r1_sum = r1_sum.wrapping_add(r1);
                r0_sum = r0_sum.wrapping_add(r0);
            }
            black_box((r1_sum, r0_sum));
        });
    });

    group.finish();
}

/// Test with different alpha values to see if there's variation
fn bench_alpha_variation(c: &mut Criterion) {
    let mut group = c.benchmark_group("alpha_variation");
    let test_value = 100000i32;

    let alphas = vec![("190464", 190464), ("523776", 523776)];

    for (name, alpha) in alphas {
        group.bench_with_input(BenchmarkId::new("runtime", name), &alpha, |b, &alpha| {
            b.iter(|| {
                let (r1, r0) = decompose(black_box(test_value), black_box(alpha));
                black_box((r1, r0));
            });
        });
    }

    // Const generic versions
    group.bench_function("const_190464", |b| {
        b.iter(|| {
            let (r1, r0) = decompose_const::<190464>(black_box(test_value));
            black_box((r1, r0));
        });
    });

    group.bench_function("const_523776", |b| {
        b.iter(|| {
            let (r1, r0) = decompose_const::<523776>(black_box(test_value));
            black_box((r1, r0));
        });
    });

    group.finish();
}

/// Verify correctness of const generic version
fn verify_correctness() {
    println!("Verifying const generic decompose correctness...");

    let test_values = create_test_values();
    let alphas = vec![190464, 523776];

    for alpha in alphas {
        for &r in &test_values {
            let (r1_baseline, r0_baseline) = decompose(r, alpha);

            let (r1_const, r0_const) = if alpha == 190464 {
                decompose_const::<190464>(r)
            } else {
                decompose_const::<523776>(r)
            };

            assert_eq!(
                r1_baseline, r1_const,
                "r1 mismatch for r={}, alpha={}",
                r, alpha
            );
            assert_eq!(
                r0_baseline, r0_const,
                "r0 mismatch for r={}, alpha={}",
                r, alpha
            );
        }
    }

    println!(
        "✓ Correctness verification passed for {} test values × 2 alpha values",
        test_values.len()
    );
}

// Run correctness check before benchmarks
#[ctor::ctor]
fn init() {
    verify_correctness();
}

criterion_group!(
    benches,
    bench_decompose_baseline,
    bench_decompose_const_generic,
    bench_high_low_bits,
    bench_single_decompose,
    bench_poly_decompose,
    bench_alpha_variation
);
criterion_main!(benches);
