//! SHA-1 Optimization Benchmarks
//!
//! This benchmark file tracks the performance improvements of various SHA-1 optimizations.
//! Each optimization is benchmarked independently to validate the performance gains.
//!
//! Optimization phases:
//! - Baseline: Current implementation
//! - Phase 1.1: 16-word circular buffer with on-demand message schedule
//! - Phase 1.2: Eliminate buffer cloning
//! - Phase 1.3: Optimize boolean functions
//! - Phase 1.4: Add inline annotations
//! - Phase 2: Macro-based loop unrolling with rolling pattern

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::sha1;

/// Benchmark SHA-1 on various input sizes
fn bench_sha1_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha1_by_size");

    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| sha1(black_box(&data)))
        });
    }

    group.finish();
}

/// Benchmark SHA-1 single block (64 bytes) - critical for understanding per-block overhead
fn bench_sha1_single_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha1_single_block");
    let data = vec![0u8; 64];
    group.throughput(Throughput::Bytes(64));

    group.bench_function("64_bytes", |b| b.iter(|| sha1(black_box(&data))));

    group.finish();
}

/// Benchmark SHA-1 on medium-sized data (typical use case)
fn bench_sha1_1kb(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha1_1kb");
    let data = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("1kb", |b| b.iter(|| sha1(black_box(&data))));

    group.finish();
}

/// Benchmark SHA-1 on large data (throughput test)
fn bench_sha1_1mb(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha1_1mb");
    group.sample_size(20); // Fewer samples for large data
    let data = vec![0u8; 1024 * 1024];
    group.throughput(Throughput::Bytes(1024 * 1024));

    group.bench_function("1mb", |b| b.iter(|| sha1(black_box(&data))));

    group.finish();
}

/// Benchmark incremental vs one-shot hashing
fn bench_sha1_incremental(c: &mut Criterion) {
    use hpcrypt_hash::Sha1;

    let mut group = c.benchmark_group("sha1_incremental");
    let data = vec![0u8; 10240]; // 10 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("one_shot", |b| b.iter(|| sha1(black_box(&data))));

    group.bench_function("incremental_1kb_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha1::new();
            for chunk in data.chunks(1024) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.bench_function("incremental_64b_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha1::new();
            for chunk in data.chunks(64) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha1_single_block,
    bench_sha1_1kb,
    bench_sha1_1mb,
    bench_sha1_sizes,
    bench_sha1_incremental
);
criterion_main!(benches);
