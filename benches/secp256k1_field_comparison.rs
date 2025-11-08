//! Benchmark comparing secp256k1 field implementations
//!
//! This benchmark tests three implementations:
//! 1. Field52: 52-bit lazy reduction (current default)
//! 2. Montgomery CIOS: 64-bit Montgomery multiplication
//! 3. FieldElement: Standard 64-bit field arithmetic
//!
//! Run with: cargo bench --bench secp256k1_field_comparison

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::secp256k1::{
    field52::FieldElement52, field_montgomery_native::MontgomeryFieldElement,
    field_ops::FieldElement,
};

/// Benchmark single field multiplication
fn bench_single_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Single Multiplication");

    // 52-bit lazy reduction
    let a_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);
    let b_52 = FieldElement52::from_limbs([
        0xABCDEF1234567,
        0x0123456789ABC,
        0x4444333322221,
        0x8888777766665,
        0xCCCCBBBBAAAA9,
    ]);

    group.bench_function("52-bit Lazy Reduction", |b| {
        b.iter(|| black_box(a_52.mul(&b_52)));
    });

    // Montgomery CIOS
    let a_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let b_mont_limbs = [
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.mul(&b_montgomery)));
    });

    // Standard 64-bit field arithmetic
    let a_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);
    let b_std = FieldElement::from_limbs([
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ]);

    group.bench_function("Standard 64-bit", |b| {
        b.iter(|| black_box(a_std.mul(&b_std)));
    });

    group.finish();
}

/// Benchmark batch multiplications (chain of operations)
fn bench_batch_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Batch Multiplications");

    let a_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);
    let b_52 = FieldElement52::from_limbs([
        0xABCDEF1234567,
        0x0123456789ABC,
        0x4444333322221,
        0x8888777766665,
        0xCCCCBBBBAAAA9,
    ]);

    let a_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let b_mont_limbs = [
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    let a_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);
    let b_std = FieldElement::from_limbs([
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ]);

    for count in [10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("52-bit Lazy", count),
            count,
            |bench, &count| {
                bench.iter(|| {
                    let mut result = a_52;
                    for _ in 0..count {
                        result = result.mul(&b_52);
                    }
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Montgomery CIOS", count),
            count,
            |bench, &count| {
                bench.iter(|| {
                    let mut result = a_montgomery;
                    for _ in 0..count {
                        result = result.mul(&b_montgomery);
                    }
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Standard 64-bit", count),
            count,
            |bench, &count| {
                bench.iter(|| {
                    let mut result = a_std;
                    for _ in 0..count {
                        result = result.mul(&b_std);
                    }
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark field squaring
fn bench_squaring(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Squaring");

    let a_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);

    group.bench_function("52-bit Lazy Reduction", |b| {
        b.iter(|| black_box(a_52.square()));
    });

    let a_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.square()));
    });

    let a_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);

    group.bench_function("Standard 64-bit", |b| {
        b.iter(|| black_box(a_std.square()));
    });

    group.finish();
}

/// Benchmark addition (should favor lazy reduction)
fn bench_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Addition");

    let a_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);
    let b_52 = FieldElement52::from_limbs([
        0xABCDEF1234567,
        0x0123456789ABC,
        0x4444333322221,
        0x8888777766665,
        0xCCCCBBBBAAAA9,
    ]);

    group.bench_function("52-bit Lazy Reduction", |b| {
        b.iter(|| black_box(a_52.add(&b_52)));
    });

    let a_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let b_mont_limbs = [
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.add(&b_montgomery)));
    });

    let a_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);
    let b_std = FieldElement::from_limbs([
        0xABCDEF1234567890,
        0x0123456789ABCDEF,
        0x4444333322221111,
        0x8888777766665555,
    ]);

    group.bench_function("Standard 64-bit", |b| {
        b.iter(|| black_box(a_std.add(&b_std)));
    });

    group.finish();
}

/// Benchmark addition chains (should heavily favor lazy reduction)
fn bench_addition_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Addition Chain (100 ops)");

    let a_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);

    group.bench_function("52-bit Lazy Reduction", |b| {
        b.iter(|| {
            let mut result = a_52;
            for _ in 0..100 {
                result = result.add(&a_52);
            }
            black_box(result)
        });
    });

    let a_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| {
            let mut result = a_montgomery;
            for _ in 0..100 {
                result = result.add(&a_montgomery);
            }
            black_box(result)
        });
    });

    let a_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);

    group.bench_function("Standard 64-bit", |b| {
        b.iter(|| {
            let mut result = a_std;
            for _ in 0..100 {
                result = result.add(&a_std);
            }
            black_box(result)
        });
    });

    group.finish();
}

/// Real-world workload: Simulate scalar multiplication field operations
/// Typical pattern: lots of squares + some multiplications
fn bench_scalar_mul_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Scalar Mul Simulation");
    group.sample_size(50);

    let x_52 = FieldElement52::from_limbs([
        0x1234567890ABC,
        0xFEDCBA0987654,
        0x1111222233334,
        0x5555666677778,
        0x9999AAAABBBBC,
    ]);

    group.bench_function("52-bit Lazy Reduction", |b| {
        b.iter(|| {
            let mut t = x_52;
            // Simulate 20 iterations of double-and-add
            for _ in 0..20 {
                t = t.square(); // Point doubling
                t = t.mul(&x_52); // Point addition
            }
            black_box(t)
        });
    });

    let x_mont_limbs = [
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ];
    let x_montgomery = MontgomeryFieldElement::to_montgomery(&x_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| {
            let mut t = x_montgomery;
            for _ in 0..20 {
                t = t.square();
                t = t.mul(&x_montgomery);
            }
            black_box(t)
        });
    });

    let x_std = FieldElement::from_limbs([
        0x1234567890ABCDEF,
        0xFEDCBA0987654321,
        0x1111222233334444,
        0x5555666677778888,
    ]);

    group.bench_function("Standard 64-bit", |b| {
        b.iter(|| {
            let mut t = x_std;
            for _ in 0..20 {
                t = t.square();
                t = t.mul(&x_std);
            }
            black_box(t)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_multiplication,
    bench_batch_multiplication,
    bench_squaring,
    bench_addition,
    bench_addition_chain,
    bench_scalar_mul_simulation,
);
criterion_main!(benches);
