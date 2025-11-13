// Benchmark comparing P-256 field arithmetic: normal vs lazy reduction
//
// This benchmark compares two implementations:
// 1. field.rs - Standard field arithmetic (immediate reduction)
// 2. field_lazy.rs - Lazy reduction (defers reduction)
//
// Expected benefits: lazy reduction should be 10-30% faster for add/sub chains
// which are common in ECC point operations (point doubling, addition formulas)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_curves::p256::{FieldElement, LazyFieldElement};

// Test values for benchmarking
fn get_test_values() -> (FieldElement, FieldElement) {
    // P-256 generator x, y coordinates
    let a = FieldElement::from_limbs([
        0xF4A13945D898C296,
        0x77037D812DEB33A0,
        0xF8BCE6E563A440F2,
        0x6B17D1F2E12C4247,
    ]);
    let b = FieldElement::from_limbs([
        0xCBB6406837BF51F5,
        0x2BCE33576B315ECE,
        0x8EE7EB4A7C0F9E16,
        0x4FE342E2FE1A7F9B,
    ]);
    (a, b)
}

fn get_test_values_lazy() -> (LazyFieldElement, LazyFieldElement) {
    let (a, b) = get_test_values();
    (
        LazyFieldElement::from_canonical(&a),
        LazyFieldElement::from_canonical(&b),
    )
}

//
// Test 1: Single operations
//

fn bench_single_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_add_single");

    // Normal addition
    group.bench_function("normal", |b| {
        let (a, bb) = get_test_values();
        b.iter(|| {
            let result = black_box(a) + black_box(bb);
            black_box(result)
        });
    });

    // Lazy addition (with normalization)
    group.bench_function("lazy", |b| {
        let (a, bb) = get_test_values_lazy();
        b.iter(|| {
            let result = black_box(a).add_lazy(&black_box(bb));
            let normalized = result.normalize();
            black_box(normalized)
        });
    });

    // Lazy addition (without normalization - raw performance)
    group.bench_function("lazy_raw", |b| {
        let (a, bb) = get_test_values_lazy();
        b.iter(|| {
            let result = black_box(a).add_lazy(&black_box(bb));
            black_box(result)
        });
    });

    group.finish();
}

fn bench_single_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_sub_single");

    // Normal subtraction
    group.bench_function("normal", |b| {
        let (a, bb) = get_test_values();
        b.iter(|| {
            let result = black_box(a) - black_box(bb);
            black_box(result)
        });
    });

    // Lazy subtraction (with normalization)
    group.bench_function("lazy", |b| {
        let (a, bb) = get_test_values_lazy();
        b.iter(|| {
            let result = black_box(a).sub_lazy(&black_box(bb));
            let normalized = result.normalize();
            black_box(normalized)
        });
    });

    // Lazy subtraction (without normalization - raw performance)
    group.bench_function("lazy_raw", |b| {
        let (a, bb) = get_test_values_lazy();
        b.iter(|| {
            let result = black_box(a).sub_lazy(&black_box(bb));
            black_box(result)
        });
    });

    group.finish();
}

//
// Test 2: Add/Sub chains (realistic ECC workload)
//

fn bench_add_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_add_chain");

    for chain_len in [5, 10, 20].iter() {
        // Normal addition chain
        group.bench_with_input(
            BenchmarkId::new("normal", chain_len),
            chain_len,
            |b, &len| {
                let (a, bb) = get_test_values();
                b.iter(|| {
                    let mut acc = black_box(a);
                    for _ in 0..len {
                        acc = acc + black_box(bb);
                    }
                    black_box(acc)
                });
            },
        );

        // Lazy addition chain (normalize at end)
        group.bench_with_input(BenchmarkId::new("lazy", chain_len), chain_len, |b, &len| {
            let (a, bb) = get_test_values_lazy();
            b.iter(|| {
                let mut acc = black_box(a);
                for _ in 0..len {
                    acc = acc.add_lazy(&black_box(bb));
                }
                let normalized = acc.normalize();
                black_box(normalized)
            });
        });
    }

    group.finish();
}

//
// Test 3: Mixed operations (simulating ECC point doubling)
//
// Typical point doubling formula uses:
// - Multiple additions/subtractions
// - A few multiplications
// - Some doublings
//
// Here we test just the add/sub portion

fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_mixed_ops");

    // Simulated ECC point doubling workload:
    // 4 additions, 2 subtractions, 1 doubling
    group.bench_function("normal", |b| {
        let (a, bb) = get_test_values();
        b.iter(|| {
            let t1 = black_box(a) + black_box(bb);
            let t2 = t1 + black_box(a);
            let t3 = t2 - black_box(bb);
            let t4 = t3 + t3; // double
            let t5 = t4 + black_box(a);
            let t6 = t5 - black_box(bb);
            black_box(t6)
        });
    });

    group.bench_function("lazy", |b| {
        let (a, bb) = get_test_values_lazy();
        b.iter(|| {
            let t1 = black_box(a).add_lazy(&black_box(bb));
            let t2 = t1.add_lazy(&black_box(a));
            let t3 = t2.sub_lazy(&black_box(bb));
            let t4 = t3.double_lazy();
            let t5 = t4.add_lazy(&black_box(a));
            let t6 = t5.sub_lazy(&black_box(bb));
            let result = t6.normalize();
            black_box(result)
        });
    });

    group.finish();
}

//
// Test 4: Triple operation (used in ECC formulas)
//

fn bench_triple(c: &mut Criterion) {
    let mut group = c.benchmark_group("p256_triple");

    group.bench_function("normal", |b| {
        let (a, _) = get_test_values();
        b.iter(|| {
            let doubled = black_box(a) + black_box(a);
            let tripled = doubled + black_box(a);
            black_box(tripled)
        });
    });

    group.bench_function("lazy", |b| {
        let (a, _) = get_test_values_lazy();
        b.iter(|| {
            let tripled = black_box(a).triple_lazy();
            let result = tripled.normalize();
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_single_add,
    bench_single_sub,
    bench_add_chain,
    bench_mixed_operations,
    bench_triple,
);

criterion_main!(benches);
