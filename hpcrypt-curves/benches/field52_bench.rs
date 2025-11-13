// Benchmark comparing 64-bit (4 limbs) vs 52-bit (5 limbs) field arithmetic

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::secp256k1::{FieldElement, FieldElement52};

fn bench_field_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_field");

    // Test values
    let a_64 = FieldElement::from_u64(0x123456789ABCDEF0);
    let b_64 = FieldElement::from_u64(0xFEDCBA9876543210);

    let a_52 = FieldElement52::from_u64(0x123456789ABCDEF0);
    let b_52 = FieldElement52::from_u64(0xFEDCBA9876543210);

    // Addition
    group.bench_function(BenchmarkId::new("add", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.add(&b_64)));
    });

    group.bench_function(BenchmarkId::new("add", "52-bit"), |bencher| {
        bencher.iter(|| black_box(a_52.add(&b_52)));
    });

    // Subtraction
    group.bench_function(BenchmarkId::new("sub", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.sub(&b_64)));
    });

    group.bench_function(BenchmarkId::new("sub", "52-bit"), |bencher| {
        bencher.iter(|| black_box(a_52.sub(&b_52)));
    });

    // Multiplication
    group.bench_function(BenchmarkId::new("mul", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.mul(&b_64)));
    });

    group.bench_function(BenchmarkId::new("mul", "52-bit_karatsuba"), |bencher| {
        bencher.iter(|| black_box(a_52.mul(&b_52)));
    });

    // Squaring
    group.bench_function(BenchmarkId::new("square", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.square()));
    });

    group.bench_function(BenchmarkId::new("square", "52-bit"), |bencher| {
        bencher.iter(|| black_box(a_52.square()));
    });

    // Doubling
    group.bench_function(BenchmarkId::new("double", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.double()));
    });

    group.bench_function(BenchmarkId::new("double", "52-bit"), |bencher| {
        bencher.iter(|| black_box(a_52.double()));
    });

    // Negation
    group.bench_function(BenchmarkId::new("neg", "64-bit"), |bencher| {
        bencher.iter(|| black_box(a_64.neg()));
    });

    group.bench_function(BenchmarkId::new("neg", "52-bit"), |bencher| {
        bencher.iter(|| black_box(a_52.neg()));
    });

    group.finish();
}

fn bench_lazy_reduction(c: &mut Criterion) {
    let mut group = c.benchmark_group("lazy_reduction");

    let a_52 = FieldElement52::from_u64(1);

    // Benchmark benefit of lazy reduction
    group.bench_function("100_adds_with_reduction", |bencher| {
        bencher.iter(|| {
            let mut sum = a_52;
            for _ in 0..100 {
                sum = sum.add(&a_52);
            }
            black_box(sum)
        });
    });

    group.bench_function("100_adds_lazy_then_reduce", |bencher| {
        bencher.iter(|| {
            let mut sum = a_52;
            for _ in 0..100 {
                sum = sum.add_lazy(&a_52);
            }
            black_box(sum.normalized())
        });
    });

    group.finish();
}

fn bench_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("inversion");

    let a_64 = FieldElement::from_u64(42);
    let a_52 = FieldElement52::from_u64(42);

    group.bench_function("invert_64bit", |bencher| {
        bencher.iter(|| black_box(a_64.invert().unwrap()));
    });

    group.bench_function("invert_52bit", |bencher| {
        bencher.iter(|| black_box(a_52.invert().unwrap()));
    });

    group.finish();
}

fn bench_combined_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined_ops");

    let a_64 = FieldElement::from_u64(123);
    let b_64 = FieldElement::from_u64(456);
    let c_64 = FieldElement::from_u64(789);

    let a_52 = FieldElement52::from_u64(123);
    let b_52 = FieldElement52::from_u64(456);
    let c_52 = FieldElement52::from_u64(789);

    // Simulate a typical elliptic curve operation:
    // result = a * b + c * d (common in point doubling/addition)
    group.bench_function("mul_add_chain_64bit", |bencher| {
        bencher.iter(|| {
            let t1 = a_64.mul(&b_64);
            let t2 = b_64.mul(&c_64);
            black_box(t1.add(&t2))
        });
    });

    group.bench_function("mul_add_chain_52bit", |bencher| {
        bencher.iter(|| {
            let t1 = a_52.mul(&b_52);
            let t2 = b_52.mul(&c_52);
            black_box(t1.add(&t2))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_field_ops,
    bench_lazy_reduction,
    bench_inversion,
    bench_combined_operations
);
criterion_main!(benches);
