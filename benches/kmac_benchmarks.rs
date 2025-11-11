//! KMAC128 and KMAC256 performance benchmarks
//!
//! Measures throughput for various input sizes and output lengths

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::kmac::{kmac128, kmac256, Kmac128, Kmac256};

// Helper to generate test data
fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

// KMAC128 benchmarks with varying input sizes
fn bench_kmac128_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_input_sizes");
    let key = b"benchmark-key-32-bytes-long!";

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut kmac = Kmac128::new(black_box(key), b"");
                kmac.update(black_box(data));
                black_box(kmac.finalize(32))
            });
        });
    }
    group.finish();
}

// KMAC256 benchmarks with varying input sizes
fn bench_kmac256_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_input_sizes");
    let key = b"benchmark-key-32-bytes-long!";

    for size in [64, 256, 1024, 4096, 16384, 65536] {
        let data = generate_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut kmac = Kmac256::new(black_box(key), b"");
                kmac.update(black_box(data));
                black_box(kmac.finalize(32))
            });
        });
    }
    group.finish();
}

// Compare KMAC128 vs KMAC256 on same data
fn bench_kmac_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_comparison");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("KMAC128-1KB", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"");
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.bench_function("KMAC256-1KB", |b| {
        b.iter(|| {
            let mut kmac = Kmac256::new(black_box(key), b"");
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.finish();
}

// Benchmark variable output lengths
fn bench_kmac128_output_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_output_lengths");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    for output_len in [16, 32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::from_parameter(output_len),
            &output_len,
            |b, &len| {
                b.iter(|| {
                    let mut output = vec![0u8; len];
                    let mut kmac = Kmac128::new(black_box(key), b"");
                    kmac.update(black_box(&data));
                    kmac.finalize(black_box(&mut output));
                    black_box(output)
                });
            },
        );
    }
    group.finish();
}

// Benchmark convenience functions
fn bench_kmac_convenience(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_convenience_functions");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("kmac128_convenience", |b| {
        b.iter(|| {
            black_box(kmac128(
                black_box(key),
                black_box(&data),
                b"",
                32,
            ))
        });
    });

    group.bench_function("kmac256_convenience", |b| {
        b.iter(|| {
            black_box(kmac256(
                black_box(key),
                black_box(&data),
                b"",
                64,
            ))
        });
    });

    group.finish();
}

// Benchmark incremental updates
fn bench_kmac128_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_incremental");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("single_update", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"");
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.bench_function("multiple_updates_64b", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"");
            for chunk in data.chunks(64) {
                kmac.update(black_box(chunk));
            }
            black_box(kmac.finalize(32))
        });
    });

    group.bench_function("multiple_updates_16b", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"");
            for chunk in data.chunks(16) {
                kmac.update(black_box(chunk));
            }
            black_box(kmac.finalize(32))
        });
    });

    group.finish();
}

// Benchmark MAC verification
fn bench_kmac_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_verification");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    // Pre-generate MAC
    let mac = kmac128(key, &data, b"", 32);

    group.bench_function("verify_correct", |b| {
        b.iter(|| {
            black_box(Kmac128::verify(
                black_box(key),
                black_box(&data),
                b"",
                black_box(&mac)
            ))
        });
    });

    group.finish();
}

// Benchmark with customization strings
fn bench_kmac_customization(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_customization");
    let key = b"benchmark-key";
    let data = generate_data(1024);

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("no_customization", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"");
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.bench_function("short_customization", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), b"app");
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.bench_function("long_customization", |b| {
        let custom = b"very-long-customization-string-for-domain-separation-purposes";
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(key), custom);
            kmac.update(black_box(&data));
            black_box(kmac.finalize(32))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kmac128_sizes,
    bench_kmac256_sizes,
    bench_kmac_comparison,
    bench_kmac128_output_lengths,
    bench_kmac_convenience,
    bench_kmac128_incremental,
    bench_kmac_verification,
    bench_kmac_customization,
);
criterion_main!(benches);
