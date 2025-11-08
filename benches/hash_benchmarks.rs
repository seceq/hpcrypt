//! Hash function benchmarks
//!
//! Compare performance of different hash functions across various input sizes

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::{blake3, blake2b, sha256, Sha3_256};

fn bench_hashes_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_small_1kb");
    let data = vec![0u8; 1024]; // 1 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("blake3", |b| {
        b.iter(|| blake3(black_box(&data)))
    });

    group.bench_function("blake2b", |b| {
        b.iter(|| blake2b(black_box(&data)))
    });

    group.bench_function("sha256", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.finish();
}

fn bench_hashes_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_medium_64kb");
    let data = vec![0u8; 64 * 1024]; // 64 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("blake3", |b| {
        b.iter(|| blake3(black_box(&data)))
    });

    group.bench_function("blake2b", |b| {
        b.iter(|| blake2b(black_box(&data)))
    });

    group.bench_function("sha256", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.finish();
}

fn bench_hashes_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_large_1mb");
    group.sample_size(10); // Fewer samples for large data
    let data = vec![0u8; 1024 * 1024]; // 1 MB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("blake3", |b| {
        b.iter(|| blake3(black_box(&data)))
    });

    group.bench_function("blake2b", |b| {
        b.iter(|| blake2b(black_box(&data)))
    });

    group.bench_function("sha256", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.finish();
}

fn bench_incremental_vs_oneshot(c: &mut Criterion) {
    use hpcrypt_hash::Blake3;
    
    let mut group = c.benchmark_group("blake3_incremental");
    let data = vec![0u8; 10240]; // 10 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("one_shot", |b| {
        b.iter(|| blake3(black_box(&data)))
    });

    group.bench_function("incremental", |b| {
        b.iter(|| {
            let mut hasher = Blake3::new();
            for chunk in data.chunks(1024) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hashes_small,
    bench_hashes_medium,
    bench_hashes_large,
    bench_incremental_vs_oneshot
);
criterion_main!(benches);
