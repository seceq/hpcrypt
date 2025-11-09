// Benchmark comparing different squaring implementations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_curves::secp256k1::{FieldElement, FieldElement52};

fn bench_64bit_squaring(c: &mut Criterion) {
    let mut group = c.benchmark_group("64bit_squaring");

    let test_value = FieldElement::from_u64(0x123456789ABCDEF0);

    group.bench_function("square_current", |bencher| {
        bencher.iter(|| black_box(test_value.square()));
    });

    group.bench_function("square_unrolled", |bencher| {
        bencher.iter(|| black_box(test_value.square_unrolled()));
    });

    // Compare with mul(self, self) to show squaring advantage
    group.bench_function("mul_self_self", |bencher| {
        bencher.iter(|| black_box(test_value.mul(&test_value)));
    });

    group.finish();
}

fn bench_52bit_squaring(c: &mut Criterion) {
    let mut group = c.benchmark_group("52bit_squaring");

    let test_value = FieldElement52::from_u64(0x123456789ABCDEF0);

    group.bench_function("square_current", |bencher| {
        bencher.iter(|| black_box(test_value.square()));
    });

    group.bench_function("square_unrolled", |bencher| {
        bencher.iter(|| black_box(test_value.square_unrolled()));
    });

    group.bench_function("square_karatsuba", |bencher| {
        bencher.iter(|| black_box(test_value.square_karatsuba()));
    });

    // Compare with mul(self, self)
    group.bench_function("mul_self_self", |bencher| {
        bencher.iter(|| black_box(test_value.mul(&test_value)));
    });

    group.finish();
}

fn bench_squaring_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("squaring_chain");

    // Simulate repeated squaring (common in exponentiation)
    let test_value_64 = FieldElement::from_u64(42);
    let test_value_52 = FieldElement52::from_u64(42);

    group.bench_function("64bit_10_squares_current", |bencher| {
        bencher.iter(|| {
            let mut x = test_value_64;
            for _ in 0..10 {
                x = x.square();
            }
            black_box(x)
        });
    });

    group.bench_function("64bit_10_squares_unrolled", |bencher| {
        bencher.iter(|| {
            let mut x = test_value_64;
            for _ in 0..10 {
                x = x.square_unrolled();
            }
            black_box(x)
        });
    });

    group.bench_function("52bit_10_squares_current", |bencher| {
        bencher.iter(|| {
            let mut x = test_value_52;
            for _ in 0..10 {
                x = x.square();
            }
            black_box(x)
        });
    });

    group.bench_function("52bit_10_squares_unrolled", |bencher| {
        bencher.iter(|| {
            let mut x = test_value_52;
            for _ in 0..10 {
                x = x.square_unrolled();
            }
            black_box(x)
        });
    });

    group.bench_function("52bit_10_squares_karatsuba", |bencher| {
        bencher.iter(|| {
            let mut x = test_value_52;
            for _ in 0..10 {
                x = x.square_karatsuba();
            }
            black_box(x)
        });
    });

    group.finish();
}

fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_mul_square");

    // Simulate realistic EC operation pattern: a^2 + b*c
    let a_64 = FieldElement::from_u64(123);
    let b_64 = FieldElement::from_u64(456);
    let c_64 = FieldElement::from_u64(789);

    let a_52 = FieldElement52::from_u64(123);
    let b_52 = FieldElement52::from_u64(456);
    let c_52 = FieldElement52::from_u64(789);

    group.bench_function("64bit_pattern_current", |bencher| {
        bencher.iter(|| {
            let t1 = a_64.square();
            let t2 = b_64.mul(&c_64);
            black_box(t1.add(&t2))
        });
    });

    group.bench_function("64bit_pattern_unrolled", |bencher| {
        bencher.iter(|| {
            let t1 = a_64.square_unrolled();
            let t2 = b_64.mul(&c_64);
            black_box(t1.add(&t2))
        });
    });

    group.bench_function("52bit_pattern_current", |bencher| {
        bencher.iter(|| {
            let t1 = a_52.square();
            let t2 = b_52.mul(&c_52);
            black_box(t1.add(&t2))
        });
    });

    group.bench_function("52bit_pattern_unrolled", |bencher| {
        bencher.iter(|| {
            let t1 = a_52.square_unrolled();
            let t2 = b_52.mul(&c_52);
            black_box(t1.add(&t2))
        });
    });

    group.bench_function("52bit_pattern_karatsuba", |bencher| {
        bencher.iter(|| {
            let t1 = a_52.square_karatsuba();
            let t2 = b_52.mul(&c_52);
            black_box(t1.add(&t2))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_64bit_squaring,
    bench_52bit_squaring,
    bench_squaring_chain,
    bench_mixed_operations
);
criterion_main!(benches);
