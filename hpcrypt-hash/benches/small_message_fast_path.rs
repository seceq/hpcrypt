use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hpcrypt_hash::{Shake128, Shake256};

/// Benchmark small message fast path vs baseline for SHAKE128
fn bench_shake128_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_small_message_comparison");

    // Test various small message sizes
    let sizes = vec![
        ("empty", 0),
        ("1byte", 1),
        ("8bytes", 8),
        ("16bytes", 16),
        ("32bytes", 32),
        ("64bytes", 64),
        ("100bytes", 100),
        ("128bytes", 128),  // Near RATE boundary
        ("160bytes", 160),  // Just below RATE (168)
    ];

    for (name, size) in sizes {
        let input = vec![0xABu8; size];
        let mut output = [0u8; 32];

        // Baseline: normal update + finalize
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("baseline", name), &input, |b, input| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.update(black_box(input));
                shake.finalize(black_box(&mut output));
                black_box(&output);
            });
        });

        // Fast path: finalize_small_message
        if size + 2 <= 168 {  // Only test fast path for messages that fit
            group.bench_with_input(BenchmarkId::new("fast_path", name), &input, |b, input| {
                b.iter(|| {
                    let mut shake = Shake128::new();
                    shake.finalize_small_message(black_box(input), black_box(&mut output));
                    black_box(&output);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark small message fast path vs baseline for SHAKE256
fn bench_shake256_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_small_message_comparison");

    // Test various small message sizes
    let sizes = vec![
        ("empty", 0),
        ("1byte", 1),
        ("8bytes", 8),
        ("16bytes", 16),
        ("32bytes", 32),
        ("64bytes", 64),
        ("100bytes", 100),
        ("128bytes", 128),  // Just below RATE (136)
    ];

    for (name, size) in sizes {
        let input = vec![0xABu8; size];
        let mut output = [0u8; 32];

        // Baseline: normal update + finalize
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("baseline", name), &input, |b, input| {
            b.iter(|| {
                let mut shake = Shake256::new();
                shake.update(black_box(input));
                shake.finalize(black_box(&mut output));
                black_box(&output);
            });
        });

        // Fast path: finalize_small_message
        if size + 2 <= 136 {  // Only test fast path for messages that fit
            group.bench_with_input(BenchmarkId::new("fast_path", name), &input, |b, input| {
                b.iter(|| {
                    let mut shake = Shake256::new();
                    shake.finalize_small_message(black_box(input), black_box(&mut output));
                    black_box(&output);
                });
            });
        }
    }

    group.finish();
}

/// Benchmark different output sizes with fast path
fn bench_shake128_output_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_output_size_comparison");

    let input = vec![0xABu8; 32];  // Small 32-byte input

    // Test various output sizes
    let output_sizes = vec![
        ("16bytes", 16),
        ("32bytes", 32),
        ("64bytes", 64),
        ("128bytes", 128),
        ("256bytes", 256),  // Requires multiple squeezes
    ];

    for (name, size) in output_sizes {
        let mut output = vec![0u8; size];

        // Baseline
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("baseline", name), &size, |b, _| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.update(black_box(&input));
                shake.finalize(black_box(&mut output));
                black_box(&output);
            });
        });

        // Fast path
        group.bench_with_input(BenchmarkId::new("fast_path", name), &size, |b, _| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.finalize_small_message(black_box(&input), black_box(&mut output));
                black_box(&output);
            });
        });
    }

    group.finish();
}

/// Benchmark different input patterns
fn bench_shake128_input_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_input_pattern_comparison");

    let mut output = [0u8; 32];

    // Different input patterns
    let patterns = vec![
        ("zeros", vec![0u8; 64]),
        ("ones", vec![0xFFu8; 64]),
        ("alternating", {
            let mut v = vec![0u8; 64];
            for (i, byte) in v.iter_mut().enumerate() {
                *byte = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            v
        }),
        ("random_pattern", vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0].repeat(8)),
    ];

    for (name, input) in patterns {
        // Baseline
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::new("baseline", name), &input, |b, input| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.update(black_box(input));
                shake.finalize(black_box(&mut output));
                black_box(&output);
            });
        });

        // Fast path
        group.bench_with_input(BenchmarkId::new("fast_path", name), &input, |b, input| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.finalize_small_message(black_box(input), black_box(&mut output));
                black_box(&output);
            });
        });
    }

    group.finish();
}

/// Benchmark one-shot convenience API
fn bench_shake128_convenience_api(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake128_convenience_api");

    let sizes = vec![8, 16, 32, 64, 100];

    for size in sizes {
        let input = vec![0xABu8; size];
        let mut output = [0u8; 32];

        // Baseline
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("baseline", size), &input, |b, input| {
            b.iter(|| {
                let mut shake = Shake128::new();
                shake.update(black_box(input));
                shake.finalize(black_box(&mut output));
                black_box(&output);
            });
        });

        // Convenience API (auto-selects fast path)
        group.bench_with_input(BenchmarkId::new("hash_small", size), &input, |b, input| {
            b.iter(|| {
                Shake128::hash_small(black_box(input), black_box(&mut output));
                black_box(&output);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_shake128_small_messages,
    bench_shake256_small_messages,
    bench_shake128_output_sizes,
    bench_shake128_input_patterns,
    bench_shake128_convenience_api,
);
criterion_main!(benches);
