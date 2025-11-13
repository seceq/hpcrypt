//! Final SHA-2 Performance Benchmark
//! Measures actual performance of optimized implementations

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hpcrypt_hash::{sha256, sha384, sha512, Sha256};

fn bench_sha256_final(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_final");

    // Small message (single block)
    let data_small = vec![0u8; 64];
    group.throughput(Throughput::Bytes(64));
    group.bench_function("64B_single_block", |b| {
        b.iter(|| sha256(black_box(&data_small)))
    });

    // Medium message (16 blocks = 1KB)
    let data_medium = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB_16_blocks", |b| {
        b.iter(|| sha256(black_box(&data_medium)))
    });

    // Large message (1024 blocks = 64KB)
    let data_large = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB_1024_blocks", |b| {
        b.iter(|| sha256(black_box(&data_large)))
    });

    group.finish();
}

fn bench_sha512_final(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_final");

    // Small message (single block)
    let data_small = vec![0u8; 128];
    group.throughput(Throughput::Bytes(128));
    group.bench_function("128B_single_block", |b| {
        b.iter(|| sha512(black_box(&data_small)))
    });

    // Medium message (8 blocks = 1KB)
    let data_medium = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB_8_blocks", |b| {
        b.iter(|| sha512(black_box(&data_medium)))
    });

    // Large message (512 blocks = 64KB)
    let data_large = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB_512_blocks", |b| {
        b.iter(|| sha512(black_box(&data_large)))
    });

    group.finish();
}

fn bench_sha384_final(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha384_final");

    // Medium message
    let data_medium = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB", |b| b.iter(|| sha384(black_box(&data_medium))));

    // Large message
    let data_large = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB", |b| b.iter(|| sha384(black_box(&data_large))));

    group.finish();
}

fn bench_incremental_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_overhead");
    let data = vec![0u8; 4096];

    group.throughput(Throughput::Bytes(4096));

    // One-shot
    group.bench_function("sha256_oneshot", |b| b.iter(|| sha256(black_box(&data))));

    // Incremental with 64-byte chunks
    group.bench_function("sha256_incremental_64B", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
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
    bench_sha256_final,
    bench_sha512_final,
    bench_sha384_final,
    bench_incremental_overhead
);
criterion_main!(benches);
