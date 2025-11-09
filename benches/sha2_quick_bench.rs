//! Quick SHA-2 Performance Benchmark
//! Tests Phase 1 optimizations: circular buffer + padding with .fill()

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hpcrypt_hash::{sha256, sha512, sha384};

fn bench_sha256_optimized(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_phase1");

    // 1 KB
    let data_1k = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB", |b| b.iter(|| sha256(black_box(&data_1k))));

    // 64 KB
    let data_64k = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB", |b| b.iter(|| sha256(black_box(&data_64k))));

    group.finish();
}

fn bench_sha512_optimized(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_phase1");

    // 1 KB
    let data_1k = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB", |b| b.iter(|| sha512(black_box(&data_1k))));

    // 64 KB
    let data_64k = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB", |b| b.iter(|| sha512(black_box(&data_64k))));

    group.finish();
}

fn bench_sha384_optimized(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha384_phase1");

    // 1 KB
    let data_1k = vec![0u8; 1024];
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1KB", |b| b.iter(|| sha384(black_box(&data_1k))));

    // 64 KB
    let data_64k = vec![0u8; 65536];
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("64KB", |b| b.iter(|| sha384(black_box(&data_64k))));

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_optimized,
    bench_sha512_optimized,
    bench_sha384_optimized
);
criterion_main!(benches);
