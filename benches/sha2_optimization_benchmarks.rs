//! SHA-2 Optimization Benchmarks
//!
//! Comprehensive benchmarking suite to validate each optimization technique
//! before applying changes to production code.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::{sha256, sha384, sha512};

/// Benchmark SHA-256 across different input sizes
fn bench_sha256_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_baseline");

    for size in [64, 128, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark SHA-512 across different input sizes
fn bench_sha512_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_baseline");

    for size in [128, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha512(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark SHA-384 across different input sizes
fn bench_sha384_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha384_baseline");

    for size in [128, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha384(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark single block processing (compression function focus)
fn bench_sha256_single_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_single_block");
    let data = vec![0u8; 64]; // Exactly one block
    group.throughput(Throughput::Bytes(64));

    group.bench_function("64_bytes", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    group.finish();
}

/// Benchmark single block processing for SHA-512
fn bench_sha512_single_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_single_block");
    let data = vec![0u8; 128]; // Exactly one block
    group.throughput(Throughput::Bytes(128));

    group.bench_function("128_bytes", |b| {
        b.iter(|| sha512(black_box(&data)))
    });

    group.finish();
}

/// Benchmark incremental hashing (streaming API)
fn bench_sha256_incremental(c: &mut Criterion) {
    use hpcrypt_hash::Sha256;

    let mut group = c.benchmark_group("sha256_incremental");
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // One-shot
    group.bench_function("one_shot", |b| {
        b.iter(|| sha256(black_box(&data)))
    });

    // Incremental (64-byte chunks)
    group.bench_function("incremental_64b_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            for chunk in data.chunks(64) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    // Incremental (256-byte chunks)
    group.bench_function("incremental_256b_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            for chunk in data.chunks(256) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.finish();
}

/// Benchmark incremental hashing for SHA-512
fn bench_sha512_incremental(c: &mut Criterion) {
    use hpcrypt_hash::Sha512;

    let mut group = c.benchmark_group("sha512_incremental");
    let data = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // One-shot
    group.bench_function("one_shot", |b| {
        b.iter(|| sha512(black_box(&data)))
    });

    // Incremental (128-byte chunks)
    group.bench_function("incremental_128b_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            for chunk in data.chunks(128) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    // Incremental (512-byte chunks)
    group.bench_function("incremental_512b_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            for chunk in data.chunks(512) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.finish();
}

/// Benchmark small messages (padding overhead focus)
fn bench_sha256_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_small_messages");

    for size in [0, 1, 8, 16, 32, 55, 56, 63].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark small messages for SHA-512
fn bench_sha512_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_small_messages");

    for size in [0, 1, 8, 16, 32, 64, 111, 112, 127].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha512(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark multi-block processing (cache effects)
fn bench_sha256_multiblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_multiblock");

    // Test different block counts
    for blocks in [1, 2, 4, 8, 16, 32, 64, 128, 256].iter() {
        let size = blocks * 64;
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(blocks), &data, |b, data| {
            b.iter(|| sha256(black_box(data)))
        });
    }

    group.finish();
}

/// Benchmark multi-block processing for SHA-512
fn bench_sha512_multiblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_multiblock");

    // Test different block counts
    for blocks in [1, 2, 4, 8, 16, 32, 64, 128, 256].iter() {
        let size = blocks * 128;
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(blocks), &data, |b, data| {
            b.iter(|| sha512(black_box(data)))
        });
    }

    group.finish();
}

criterion_group!(
    sha2_baseline,
    bench_sha256_sizes,
    bench_sha512_sizes,
    bench_sha384_sizes,
    bench_sha256_single_block,
    bench_sha512_single_block,
);

criterion_group!(
    sha2_incremental,
    bench_sha256_incremental,
    bench_sha512_incremental,
);

criterion_group!(
    sha2_edge_cases,
    bench_sha256_small_messages,
    bench_sha512_small_messages,
);

criterion_group!(
    sha2_multiblock,
    bench_sha256_multiblock,
    bench_sha512_multiblock,
);

criterion_main!(
    sha2_baseline,
    sha2_incremental,
    sha2_edge_cases,
    sha2_multiblock,
);
