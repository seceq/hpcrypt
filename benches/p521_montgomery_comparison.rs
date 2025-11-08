//! Benchmark comparing P-521 Montgomery vs Native Mersenne Reduction
//!
//! This benchmark empirically tests whether Montgomery arithmetic provides
//! any performance benefit for P-521 despite the Mersenne prime advantage.
//!
//! Run with: cargo bench --bench p521_montgomery_comparison

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::p521::{field_montgomery_native::MontgomeryFieldElement, FieldElement};

/// Benchmark single field multiplication
fn bench_single_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 Single Multiplication");

    // Native Mersenne reduction
    let a_native = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);
    let b_native = FieldElement::from_limbs([
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ]);

    group.bench_function("Native Mersenne", |b| {
        b.iter(|| black_box(a_native.mul(&b_native)));
    });

    // Montgomery CIOS - use same limb values
    let a_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let b_mont_limbs = [
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.mul(&b_montgomery)));
    });

    group.finish();
}

/// Benchmark batch multiplications (chain of operations)
fn bench_batch_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 Batch Multiplications");

    let a_native = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);
    let b_native = FieldElement::from_limbs([
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ]);

    let a_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let b_mont_limbs = [
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    for count in [10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("Native Mersenne", count),
            count,
            |bench, &count| {
                bench.iter(|| {
                    let mut result = a_native;
                    for _ in 0..count {
                        result = result.mul(&b_native);
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
    }

    group.finish();
}

/// Benchmark field squaring
fn bench_squaring(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 Squaring");

    let a_native = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);

    group.bench_function("Native Mersenne", |b| {
        b.iter(|| black_box(a_native.square()));
    });

    let a_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.square()));
    });

    group.finish();
}

// Note: Inversion benchmark skipped - Montgomery implementation doesn't have invert() yet
// Inversion would use the same GCD/Fermat algorithm regardless of representation

/// Benchmark addition (should be identical for both)
fn bench_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 Addition");

    let a_native = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);
    let b_native = FieldElement::from_limbs([
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ]);

    group.bench_function("Native Mersenne", |b| {
        b.iter(|| black_box(a_native.add(&b_native)));
    });

    let a_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let b_mont_limbs = [
        0xabcdef1234567890,
        0x0123456789abcdef,
        0x4444333322221111,
        0x8888777766665555,
        0xccccbbbbaaaa9999,
        0xaaaaffffeeeedddd,
        0xeeeeddddccccbbbb,
        0x3333222211110000,
        0x00000000000001aa,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let b_montgomery = MontgomeryFieldElement::to_montgomery(&b_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| black_box(a_montgomery.add(&b_montgomery)));
    });

    group.finish();
}

/// Benchmark byte conversion overhead (Montgomery only - native uses different encoding)
fn bench_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 Byte Conversion");

    let a_native = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);

    group.bench_function("Native to_bytes", |b| {
        b.iter(|| black_box(a_native.to_bytes()));
    });

    let bytes_native = a_native.to_bytes();

    group.bench_function("Native from_bytes", |b| {
        b.iter(|| black_box(FieldElement::from_bytes(&bytes_native)));
    });

    let a_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let a_montgomery = MontgomeryFieldElement::to_montgomery(&a_mont_limbs);
    let bytes_mont = a_montgomery.to_bytes();

    group.bench_function("Montgomery to_bytes", |b| {
        b.iter(|| black_box(a_montgomery.to_bytes()));
    });

    group.bench_function("Montgomery from_bytes", |b| {
        b.iter(|| black_box(MontgomeryFieldElement::from_bytes(&bytes_mont)));
    });

    group.finish();
}

/// Real-world workload: Simulate ECDH shared secret computation
/// This involves multiple multiplications and a final inversion
fn bench_ecdh_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-521 ECDH Simulation");
    group.sample_size(20);

    let x = FieldElement::from_limbs([
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ]);

    group.bench_function("Native Mersenne", |b| {
        b.iter(|| {
            // Simulate several multiplications + squarings typical in scalar multiplication
            let mut t = x;
            for _ in 0..10 {
                t = t.square();
                t = t.mul(&x);
            }
            black_box(t)
        });
    });

    let x_mont_limbs = [
        0x1234567890abcdef,
        0xfedcba0987654321,
        0x1111222233334444,
        0x5555666677778888,
        0x9999aaaabbbbcccc,
        0xddddeeeeffffaaaa,
        0xbbbbccccddddeeee,
        0xffff111122223333,
        0x00000000000001ff,
    ];
    let x_montgomery = MontgomeryFieldElement::to_montgomery(&x_mont_limbs);

    group.bench_function("Montgomery CIOS", |b| {
        b.iter(|| {
            let mut t = x_montgomery;
            for _ in 0..10 {
                t = t.square();
                t = t.mul(&x_montgomery);
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
    bench_conversion,
    bench_ecdh_simulation,
);
criterion_main!(benches);
