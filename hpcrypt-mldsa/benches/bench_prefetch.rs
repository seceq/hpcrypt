//! Benchmark for Memory Prefetching Optimization
//!
//! Measures the impact of software prefetching on ML-DSA operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::{DsaParams, MlDsa65};
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;

fn bench_baseline_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefetch_baseline");

    // Benchmark key generation
    group.bench_function("keygen", |b| b.iter(|| black_box(keygen::<MlDsa65>())));

    // Benchmark signing
    let (pk, sk) = keygen::<MlDsa65>();
    let message = b"Test message for prefetching benchmark";

    group.bench_function("sign", |b| {
        b.iter(|| black_box(sign(&sk, message).unwrap()))
    });

    // Benchmark verification
    let signature = sign(&sk, message).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| black_box(verify(&pk, message, &signature)))
    });

    group.finish();
}

criterion_group!(benches, bench_baseline_operations);
criterion_main!(benches);
