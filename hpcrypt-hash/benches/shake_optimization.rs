use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hpcrypt_hash::{Shake128, Shake256, TurboShake128, TurboShake256, XofFunction};

/// Benchmark SHAKE128 with 32-byte output (common use case)
fn shake128_32b_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_32b_output");
    group.throughput(Throughput::Bytes(3)); // "abc" input

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut hasher = Shake128::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 32];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.finish();
}

/// Benchmark SHAKE128 with various output sizes to measure squeezing impact
fn shake128_various_outputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_output_sizes");

    for size in [1, 8, 16, 32, 64, 168, 336, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut hasher = Shake128::new();
                hasher.update(black_box(b"abc"));
                let mut output = vec![0u8; size];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark SHAKE128 with large input to measure absorption/block processing
fn shake128_large_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_large_input");

    for size in [168, 336, 1024, 4096, 16384].iter() {
        let data = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Shake128::new();
                hasher.update(black_box(data));
                let mut output = [0u8; 32];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark SHAKE128 incremental hashing
fn shake128_incremental(c: &mut Criterion) {
    let data = b"The quick brown fox jumps over the lazy dog";

    c.bench_function("shake128_incremental", |b| {
        b.iter(|| {
            let mut hasher = Shake128::new();
            hasher.update(black_box(&data[..10]));
            hasher.update(black_box(&data[10..20]));
            hasher.update(black_box(&data[20..30]));
            hasher.update(black_box(&data[30..]));
            let mut output = [0u8; 32];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });
}

/// Benchmark SHAKE256 with 64-byte output
fn shake256_64b_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_64b_output");
    group.throughput(Throughput::Bytes(3));

    group.bench_function("baseline", |b| {
        b.iter(|| {
            let mut hasher = Shake256::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 64];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.finish();
}

/// Benchmark SHAKE256 with various output sizes
fn shake256_various_outputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_output_sizes");

    for size in [1, 8, 16, 32, 64, 136, 272, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut hasher = Shake256::new();
                hasher.update(black_box(b"abc"));
                let mut output = vec![0u8; size];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark SHAKE256 with large input
fn shake256_large_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_large_input");

    for size in [136, 272, 1024, 4096, 16384].iter() {
        let data = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Shake256::new();
                hasher.update(black_box(data));
                let mut output = [0u8; 64];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark empty input (edge case)
fn shake_empty_input(c: &mut Criterion) {
    c.bench_function("shake128_empty", |b| {
        b.iter(|| {
            let mut hasher = Shake128::new();
            let mut output = [0u8; 32];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    c.bench_function("shake256_empty", |b| {
        b.iter(|| {
            let mut hasher = Shake256::new();
            let mut output = [0u8; 64];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });
}

// ===== Phase 3: TurboSHAKE Benchmarks =====

/// Benchmark TurboSHAKE128 vs SHAKE128 (expect ~2x speedup)
fn turboshake128_vs_shake128(c: &mut Criterion) {
    let mut group = c.benchmark_group("turboshake128_vs_shake128");
    group.throughput(Throughput::Bytes(32));

    group.bench_function("SHAKE128", |b| {
        b.iter(|| {
            let mut hasher = Shake128::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 32];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.bench_function("TurboSHAKE128", |b| {
        b.iter(|| {
            let mut hasher = TurboShake128::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 32];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.finish();
}

/// Benchmark TurboSHAKE256 vs SHAKE256 (expect ~2x speedup)
fn turboshake256_vs_shake256(c: &mut Criterion) {
    let mut group = c.benchmark_group("turboshake256_vs_shake256");
    group.throughput(Throughput::Bytes(64));

    group.bench_function("SHAKE256", |b| {
        b.iter(|| {
            let mut hasher = Shake256::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 64];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.bench_function("TurboSHAKE256", |b| {
        b.iter(|| {
            let mut hasher = TurboShake256::new();
            hasher.update(black_box(b"abc"));
            let mut output = [0u8; 64];
            hasher.clone().finalize(&mut output);
            black_box(output);
        });
    });

    group.finish();
}

/// Benchmark TurboSHAKE with various output sizes
fn turboshake128_various_outputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("turboshake128_output_sizes");

    for size in [1, 8, 16, 32, 64, 168, 336, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let mut hasher = TurboShake128::new();
                hasher.update(black_box(b"abc"));
                let mut output = vec![0u8; size];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark TurboSHAKE with large inputs
fn turboshake128_large_input(c: &mut Criterion) {
    let mut group = c.benchmark_group("turboshake128_large_input");

    for size in [168, 336, 1024, 4096, 16384].iter() {
        let data = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = TurboShake128::new();
                hasher.update(black_box(data));
                let mut output = [0u8; 32];
                hasher.clone().finalize(&mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    shake128_32b_output,
    shake128_various_outputs,
    shake128_large_input,
    shake128_incremental,
    shake256_64b_output,
    shake256_various_outputs,
    shake256_large_input,
    shake_empty_input,
    // Phase 3: TurboSHAKE benchmarks
    turboshake128_vs_shake128,
    turboshake256_vs_shake256,
    turboshake128_various_outputs,
    turboshake128_large_input,
);

criterion_main!(benches);
