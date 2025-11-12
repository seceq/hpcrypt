//! Internal benchmarks for loop unrolling optimization
//!
//! These benchmarks compare manual unrolled implementations against
//! macro-generated unrolled implementations to validate performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Import internal field types
use hpcrypt_curves::p256::FieldElement as P256FieldElement;
use hpcrypt_curves::p384::FieldElement as P384FieldElement;
use hpcrypt_curves::p521::FieldElement as P521FieldElement;

// --- P-256 Benchmarks ---

fn bench_p256_add_manual(c: &mut Criterion) {
    let a = P256FieldElement::from_bytes(&[1u8; 32]).unwrap();
    let b = P256FieldElement::from_bytes(&[2u8; 32]).unwrap();

    c.bench_function("P-256 add (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).add_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

fn bench_p256_sub_manual(c: &mut Criterion) {
    let a = P256FieldElement::from_bytes(&[255u8; 32]).unwrap();
    let b = P256FieldElement::from_bytes(&[2u8; 32]).unwrap();

    c.bench_function("P-256 sub (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).sub_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

// --- P-384 Benchmarks ---

fn bench_p384_add_manual(c: &mut Criterion) {
    let a = P384FieldElement::from_bytes(&[1u8; 48]).unwrap();
    let b = P384FieldElement::from_bytes(&[2u8; 48]).unwrap();

    c.bench_function("P-384 add (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).add_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

fn bench_p384_sub_manual(c: &mut Criterion) {
    let a = P384FieldElement::from_bytes(&[255u8; 48]).unwrap();
    let b = P384FieldElement::from_bytes(&[2u8; 48]).unwrap();

    c.bench_function("P-384 sub (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).sub_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

// --- P-521 Benchmarks ---

fn bench_p521_add_manual(c: &mut Criterion) {
    let a = P521FieldElement::from_bytes(&[1u8; 66]).unwrap();
    let b = P521FieldElement::from_bytes(&[2u8; 66]).unwrap();

    c.bench_function("P-521 add (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).add_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

fn bench_p521_sub_manual(c: &mut Criterion) {
    let a = P521FieldElement::from_bytes(&[255u8; 66]).unwrap();
    let b = P521FieldElement::from_bytes(&[2u8; 66]).unwrap();

    c.bench_function("P-521 sub (current manual)", |bench| {
        bench.iter(|| {
            let (result, _) = black_box(&a).sub_no_reduce(black_box(&b));
            black_box(result)
        });
    });
}

criterion_group!(
    p256_benches,
    bench_p256_add_manual,
    bench_p256_sub_manual
);

criterion_group!(
    p384_benches,
    bench_p384_add_manual,
    bench_p384_sub_manual
);

criterion_group!(
    p521_benches,
    bench_p521_add_manual,
    bench_p521_sub_manual
);

criterion_main!(p256_benches, p384_benches, p521_benches);
