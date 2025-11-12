// KMAC Optimization Benchmarks
// Tests each optimization technique individually to measure performance gains

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::{Kmac128, Kmac256};

// Benchmark KMAC128 with various message sizes
fn bench_kmac128_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac128_baseline");

    let key = vec![0u8; 32];
    let customization = b"";

    // Small message (32 bytes)
    group.bench_function("32_bytes", |b| {
        let message = vec![0u8; 32];
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(32),
            ))
        });
    });

    // Medium message (1 KB)
    group.bench_function("1kb", |b| {
        let message = vec![0u8; 1024];
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(32),
            ))
        });
    });

    // Large message (16 KB)
    group.bench_function("16kb", |b| {
        let message = vec![0u8; 16384];
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(32),
            ))
        });
    });

    group.finish();
}

// Benchmark KMAC256 with various message sizes
fn bench_kmac256_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac256_baseline");

    let key = vec![0u8; 32];
    let customization = b"";

    // Small message (32 bytes)
    group.bench_function("32_bytes", |b| {
        let message = vec![0u8; 32];
        b.iter(|| {
            black_box(Kmac256::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(64),
            ))
        });
    });

    // Medium message (1 KB)
    group.bench_function("1kb", |b| {
        let message = vec![0u8; 1024];
        b.iter(|| {
            black_box(Kmac256::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(64),
            ))
        });
    });

    // Large message (16 KB)
    group.bench_function("16kb", |b| {
        let message = vec![0u8; 16384];
        b.iter(|| {
            black_box(Kmac256::mac(
                black_box(&key),
                black_box(&message),
                black_box(customization),
                black_box(64),
            ))
        });
    });

    group.finish();
}

// Benchmark incremental API
fn bench_kmac_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_incremental");

    let key = vec![0u8; 32];
    let customization = b"";

    // KMAC128 incremental updates
    group.bench_function("kmac128_4x256bytes", |b| {
        b.iter(|| {
            let mut kmac = Kmac128::new(black_box(&key), black_box(customization));
            for _ in 0..4 {
                let chunk = vec![0u8; 256];
                kmac.update(black_box(&chunk));
            }
            black_box(kmac.finalize(32))
        });
    });

    // KMAC256 incremental updates
    group.bench_function("kmac256_4x256bytes", |b| {
        b.iter(|| {
            let mut kmac = Kmac256::new(black_box(&key), black_box(customization));
            for _ in 0..4 {
                let chunk = vec![0u8; 256];
                kmac.update(black_box(&chunk));
            }
            black_box(kmac.finalize(64))
        });
    });

    group.finish();
}

// Benchmark different output lengths
fn bench_kmac_output_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_output_lengths");

    let key = vec![0u8; 32];
    let message = vec![0u8; 1024];
    let customization = b"";

    for &output_len in &[16, 32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::new("kmac128", output_len),
            &output_len,
            |b, &len| {
                b.iter(|| {
                    black_box(Kmac128::mac(
                        black_box(&key),
                        black_box(&message),
                        black_box(customization),
                        black_box(len),
                    ))
                });
            },
        );
    }

    group.finish();
}

// Benchmark key sizes
fn bench_kmac_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_key_sizes");

    let message = vec![0u8; 1024];
    let customization = b"";

    for &key_len in &[16, 32, 64, 128] {
        let key = vec![0u8; key_len];
        group.bench_with_input(
            BenchmarkId::new("kmac128", key_len),
            &key,
            |b, k| {
                b.iter(|| {
                    black_box(Kmac128::mac(
                        black_box(k),
                        black_box(&message),
                        black_box(customization),
                        black_box(32),
                    ))
                });
            },
        );
    }

    group.finish();
}

// Benchmark with customization strings
fn bench_kmac_customization(c: &mut Criterion) {
    let mut group = c.benchmark_group("kmac_customization");

    let key = vec![0u8; 32];
    let message = vec![0u8; 1024];

    // Empty customization
    group.bench_function("empty", |b| {
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(b""),
                black_box(32),
            ))
        });
    });

    // Short customization
    group.bench_function("short", |b| {
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(b"app"),
                black_box(32),
            ))
        });
    });

    // Long customization
    group.bench_function("long", |b| {
        let custom = b"My Application Domain Separation String v1.0";
        b.iter(|| {
            black_box(Kmac128::mac(
                black_box(&key),
                black_box(&message),
                black_box(custom),
                black_box(32),
            ))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kmac128_baseline,
    bench_kmac256_baseline,
    bench_kmac_incremental,
    bench_kmac_output_lengths,
    bench_kmac_key_sizes,
    bench_kmac_customization,
);
criterion_main!(benches);
