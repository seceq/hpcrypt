//! SHA3 family benchmarks
//!
//! Benchmark SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256
//! across various input sizes and usage patterns

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

// Benchmark all SHA3 variants on small inputs (1KB)
fn bench_sha3_variants_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_variants_1kb");
    let data = vec![0u8; 1024]; // 1 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha3_224", |b| {
        b.iter(|| Sha3_224::digest(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.bench_function("sha3_384", |b| {
        b.iter(|| Sha3_384::digest(black_box(&data)))
    });

    group.bench_function("sha3_512", |b| {
        b.iter(|| Sha3_512::digest(black_box(&data)))
    });

    group.finish();
}

// Benchmark all SHA3 variants on medium inputs (64KB)
fn bench_sha3_variants_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_variants_64kb");
    let data = vec![0u8; 64 * 1024]; // 64 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha3_224", |b| {
        b.iter(|| Sha3_224::digest(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.bench_function("sha3_384", |b| {
        b.iter(|| Sha3_384::digest(black_box(&data)))
    });

    group.bench_function("sha3_512", |b| {
        b.iter(|| Sha3_512::digest(black_box(&data)))
    });

    group.finish();
}

// Benchmark all SHA3 variants on large inputs (1MB)
fn bench_sha3_variants_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_variants_1mb");
    group.sample_size(10); // Fewer samples for large data
    let data = vec![0u8; 1024 * 1024]; // 1 MB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("sha3_224", |b| {
        b.iter(|| Sha3_224::digest(black_box(&data)))
    });

    group.bench_function("sha3_256", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.bench_function("sha3_384", |b| {
        b.iter(|| Sha3_384::digest(black_box(&data)))
    });

    group.bench_function("sha3_512", |b| {
        b.iter(|| Sha3_512::digest(black_box(&data)))
    });

    group.finish();
}

// Benchmark SHA3-256: one-shot vs incremental
fn bench_sha3_256_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256_incremental");
    let data = vec![0u8; 10240]; // 10 KB
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("one_shot", |b| {
        b.iter(|| Sha3_256::digest(black_box(&data)))
    });

    group.bench_function("incremental_1kb_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha3_256::new();
            for chunk in data.chunks(1024) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.bench_function("incremental_small_chunks", |b| {
        b.iter(|| {
            let mut hasher = Sha3_256::new();
            for chunk in data.chunks(64) {
                hasher.update(black_box(chunk));
            }
            hasher.finalize()
        })
    });

    group.finish();
}

// Benchmark SHAKE128 with various output lengths
fn bench_shake128_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_output_sizes");
    let data = vec![0u8; 1024]; // 1 KB input

    for output_size in [16, 32, 64, 128, 256].iter() {
        group.throughput(Throughput::Bytes(*output_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(output_size),
            output_size,
            |b, &size| {
                let mut output = vec![0u8; size];
                b.iter(|| {
                    let mut shake = Shake128::new();
                    shake.update(black_box(&data));
                    shake.finalize(black_box(&mut output));
                })
            },
        );
    }

    group.finish();
}

// Benchmark SHAKE256 with various output lengths
fn bench_shake256_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_output_sizes");
    let data = vec![0u8; 1024]; // 1 KB input

    for output_size in [16, 32, 64, 128, 256].iter() {
        group.throughput(Throughput::Bytes(*output_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(output_size),
            output_size,
            |b, &size| {
                let mut output = vec![0u8; size];
                b.iter(|| {
                    let mut shake = Shake256::new();
                    shake.update(black_box(&data));
                    shake.finalize(black_box(&mut output));
                })
            },
        );
    }

    group.finish();
}

// Benchmark SHAKE128 vs SHAKE256 on same output size
fn bench_shake_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_vs_shake256_32bytes");
    let data = vec![0u8; 1024]; // 1 KB
    let mut output = vec![0u8; 32]; // 32 bytes output
    group.throughput(Throughput::Bytes(32));

    group.bench_function("shake128", |b| {
        b.iter(|| {
            let mut shake = Shake128::new();
            shake.update(black_box(&data));
            shake.finalize(black_box(&mut output));
        })
    });

    group.bench_function("shake256", |b| {
        b.iter(|| {
            let mut shake = Shake256::new();
            shake.update(black_box(&data));
            shake.finalize(black_box(&mut output));
        })
    });

    group.finish();
}

// Benchmark variable input sizes for SHA3-256
fn bench_sha3_256_input_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256_input_sizes");

    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| Sha3_256::digest(black_box(&data)))
        });
    }

    group.finish();
}

// Benchmark empty input (edge case)
fn bench_empty_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_empty_input");

    group.bench_function("sha3_224", |b| b.iter(|| Sha3_224::digest(black_box(b""))));

    group.bench_function("sha3_256", |b| b.iter(|| Sha3_256::digest(black_box(b""))));

    group.bench_function("sha3_384", |b| b.iter(|| Sha3_384::digest(black_box(b""))));

    group.bench_function("sha3_512", |b| b.iter(|| Sha3_512::digest(black_box(b""))));

    group.finish();
}

criterion_group!(
    benches,
    bench_sha3_variants_small,
    bench_sha3_variants_medium,
    bench_sha3_variants_large,
    bench_sha3_256_incremental,
    bench_shake128_output_sizes,
    bench_shake256_output_sizes,
    bench_shake_comparison,
    bench_sha3_256_input_sizes,
    bench_empty_input
);
criterion_main!(benches);
