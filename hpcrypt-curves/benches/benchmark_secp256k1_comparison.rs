// Comprehensive benchmark comparing secp256k1 field arithmetic implementations
//
// This benchmark compares three implementations:
// 1. field_ops.rs - Karatsuba multiplication + NIST-style reduction
// 2. field52.rs - 52-bit lazy reduction (current optimized implementation)
// 3. field_montgomery_native.rs - CIOS Montgomery multiplication (new)
//
// We test various use cases to understand when each implementation excels.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_curves::secp256k1::{
    field_ops::FieldElement as KaratsubaField,
    field52::FieldElement52 as LazyField,
    field_montgomery_native::MontgomeryFieldElement as MontgomeryField,
};

// Test values for benchmarking
fn get_test_values_karatsuba() -> (KaratsubaField, KaratsubaField) {
    let a = KaratsubaField::from_limbs([
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798,
    ]);
    let b = KaratsubaField::from_limbs([
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8,
    ]);
    (a, b)
}

fn get_test_values_lazy() -> (LazyField, LazyField) {
    // Convert from u64 limbs to bytes, then to 52-bit representation
    let a_u64: [u64; 4] = [
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798,
    ];
    let b_u64: [u64; 4] = [
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8,
    ];

    // Convert to bytes (little-endian)
    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];
    for i in 0..4 {
        a_bytes[i*8..(i+1)*8].copy_from_slice(&a_u64[i].to_le_bytes());
        b_bytes[i*8..(i+1)*8].copy_from_slice(&b_u64[i].to_le_bytes());
    }

    let a = LazyField::from_bytes(&a_bytes);
    let b = LazyField::from_bytes(&b_bytes);
    (a, b)
}

fn get_test_values_montgomery() -> (MontgomeryField, MontgomeryField) {
    let a_limbs = [
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798,
    ];
    let b_limbs = [
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8,
    ];

    let a = MontgomeryField::to_montgomery(&a_limbs);
    let b = MontgomeryField::to_montgomery(&b_limbs);
    (a, b)
}

// === Single Operation Benchmarks ===

fn bench_single_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_single_mul");

    // Karatsuba
    let (a, b) = get_test_values_karatsuba();
    group.bench_function("karatsuba", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result)
        });
    });

    // 52-bit lazy
    let (a, b) = get_test_values_lazy();
    group.bench_function("52bit_lazy", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result)
        });
    });

    // Montgomery (with conversion overhead)
    let a_limbs = [0x79BE667EF9DCBBAC, 0x55A06295CE870B07, 0x029BFCDB2DCE28D9, 0x59F2815B16F81798];
    let b_limbs = [0x483ADA7726A3C465, 0x5DA4FBFC0E1108A8, 0xFD17B448A6855419, 0x9C47D08FFB10D4B8];
    group.bench_function("montgomery_with_conversion", |bencher| {
        bencher.iter(|| {
            let a = MontgomeryField::to_montgomery(black_box(&a_limbs));
            let b = MontgomeryField::to_montgomery(black_box(&b_limbs));
            let result = a.mul(&b);
            let _normal = result.from_montgomery();
            black_box(result)
        });
    });

    // Montgomery (already converted - best case)
    let (a, b) = get_test_values_montgomery();
    group.bench_function("montgomery_raw", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).mul(black_box(&b));
            black_box(result)
        });
    });

    group.finish();
}

fn bench_single_squaring(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_single_square");

    // Karatsuba
    let (a, _) = get_test_values_karatsuba();
    group.bench_function("karatsuba", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).square();
            black_box(result)
        });
    });

    // 52-bit lazy
    let (a, _) = get_test_values_lazy();
    group.bench_function("52bit_lazy", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).square();
            black_box(result)
        });
    });

    // Montgomery
    let (a, _) = get_test_values_montgomery();
    group.bench_function("montgomery_raw", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).square();
            black_box(result)
        });
    });

    group.finish();
}

fn bench_single_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_single_add");

    // Karatsuba
    let (a, b) = get_test_values_karatsuba();
    group.bench_function("karatsuba", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).add(black_box(&b));
            black_box(result)
        });
    });

    // 52-bit lazy (should excel here)
    let (a, b) = get_test_values_lazy();
    group.bench_function("52bit_lazy", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).add(black_box(&b));
            black_box(result)
        });
    });

    // Montgomery
    let (a, b) = get_test_values_montgomery();
    group.bench_function("montgomery_raw", |bencher| {
        bencher.iter(|| {
            let result = black_box(&a).add(black_box(&b));
            black_box(result)
        });
    });

    group.finish();
}

// === Batch Operation Benchmarks ===

fn bench_batch_multiplications(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_batch_mul");

    for count in [5, 10, 20].iter() {
        // Karatsuba
        let (a, b) = get_test_values_karatsuba();
        group.bench_with_input(BenchmarkId::new("karatsuba", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = a;
                for _ in 0..n {
                    result = result.mul(&b);
                }
                black_box(result)
            });
        });

        // 52-bit lazy
        let (a, b) = get_test_values_lazy();
        group.bench_with_input(BenchmarkId::new("52bit_lazy", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = a;
                for _ in 0..n {
                    result = result.mul(&b);
                }
                black_box(result)
            });
        });

        // Montgomery (with conversion overhead amortized)
        let a_limbs = [0x79BE667EF9DCBBAC, 0x55A06295CE870B07, 0x029BFCDB2DCE28D9, 0x59F2815B16F81798];
        let b_limbs = [0x483ADA7726A3C465, 0x5DA4FBFC0E1108A8, 0xFD17B448A6855419, 0x9C47D08FFB10D4B8];
        group.bench_with_input(BenchmarkId::new("montgomery", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = MontgomeryField::to_montgomery(&a_limbs);
                let b = MontgomeryField::to_montgomery(&b_limbs);
                for _ in 0..n {
                    result = result.mul(&b);
                }
                let _normal = result.from_montgomery();
                black_box(result)
            });
        });
    }

    group.finish();
}

// === Mixed Operation Benchmarks (Realistic ECC workload) ===

fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_mixed_ops");

    // Simulate typical ECC point doubling workload:
    // - Multiple multiplications
    // - Multiple squarings
    // - Several additions/subtractions

    // Karatsuba
    let (a, b) = get_test_values_karatsuba();
    group.bench_function("karatsuba", |bencher| {
        bencher.iter(|| {
            let t1 = a.square();           // x^2
            let t2 = t1.mul(&a);           // x^3
            let t3 = t2.add(&b);           // x^3 + b
            let t4 = t3.square();          // (x^3 + b)^2
            let t5 = t4.mul(&t1);          // (x^3 + b)^2 * x^2
            let result = t5.sub(&t3);      // result
            black_box(result)
        });
    });

    // 52-bit lazy
    let (a, b) = get_test_values_lazy();
    group.bench_function("52bit_lazy", |bencher| {
        bencher.iter(|| {
            let t1 = a.square();
            let t2 = t1.mul(&a);
            let t3 = t2.add(&b);
            let t4 = t3.square();
            let t5 = t4.mul(&t1);
            let result = t5.sub(&t3);
            black_box(result)
        });
    });

    // Montgomery
    let (a, b) = get_test_values_montgomery();
    group.bench_function("montgomery", |bencher| {
        bencher.iter(|| {
            let t1 = a.square();
            let t2 = t1.mul(&a);
            let t3 = t2.add(&b);
            let t4 = t3.square();
            let t5 = t4.mul(&t1);
            let result = t5.sub(&t3);
            black_box(result)
        });
    });

    group.finish();
}

// === Chain of Squares (Inversion workload) ===

fn bench_square_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_square_chain");

    // Simulate part of modular inversion using Fermat's little theorem
    // This is multiplication-heavy

    for count in [10, 20, 50].iter() {
        // Karatsuba
        let (a, _) = get_test_values_karatsuba();
        group.bench_with_input(BenchmarkId::new("karatsuba", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = a;
                for _ in 0..n {
                    result = result.square();
                }
                black_box(result)
            });
        });

        // 52-bit lazy
        let (a, _) = get_test_values_lazy();
        group.bench_with_input(BenchmarkId::new("52bit_lazy", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = a;
                for _ in 0..n {
                    result = result.square();
                }
                black_box(result)
            });
        });

        // Montgomery
        let (a, _) = get_test_values_montgomery();
        group.bench_with_input(BenchmarkId::new("montgomery", count), count, |bencher, &n| {
            bencher.iter(|| {
                let mut result = a;
                for _ in 0..n {
                    result = result.square();
                }
                black_box(result)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_multiplication,
    bench_single_squaring,
    bench_single_addition,
    bench_batch_multiplications,
    bench_mixed_operations,
    bench_square_chain,
);

criterion_main!(benches);
