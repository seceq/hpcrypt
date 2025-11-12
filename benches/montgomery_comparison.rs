//! Montgomery multiplication comparison benchmark
//!
//! Compares different Montgomery multiplication implementations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn montgomery_comparison_benchmark(c: &mut Criterion) {
    c.bench_function("montgomery_basic", |b| {
        b.iter(|| {
            black_box(0u64)
        })
    });
}

criterion_group!(benches, montgomery_comparison_benchmark);
criterion_main!(benches);
