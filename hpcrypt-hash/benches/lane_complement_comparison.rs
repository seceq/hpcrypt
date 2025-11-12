use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_hash::sha3::{Sha3_256, Sha3_512};

/// Benchmark SHA3-256 with different message sizes
fn bench_sha3_256_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_256");

    let sizes = [16, 64, 256, 1024, 4096];

    for size in sizes.iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::new("standard", size), &message, |b, msg| {
            b.iter(|| {
                let mut hasher = Sha3_256::new();
                hasher.update(black_box(msg));
                black_box(hasher.finalize())
            });
        });
    }

    group.finish();
}

/// Benchmark SHA3-512 with different message sizes
fn bench_sha3_512_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_512");

    let sizes = [16, 64, 256, 1024, 4096];

    for size in sizes.iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::new("standard", size), &message, |b, msg| {
            b.iter(|| {
                let mut hasher = Sha3_512::new();
                hasher.update(black_box(msg));
                black_box(hasher.finalize())
            });
        });
    }

    group.finish();
}

/// Benchmark incremental hashing
fn bench_sha3_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_incremental");

    // Test incremental updates with 64-byte chunks
    let total_size = 1024;
    let chunk_size = 64;
    let message = vec![0x42u8; total_size];

    group.bench_function("sha3_256_incremental", |b| {
        b.iter(|| {
            let mut hasher = Sha3_256::new();
            for chunk in message.chunks(chunk_size) {
                hasher.update(black_box(chunk));
            }
            black_box(hasher.finalize())
        });
    });

    group.bench_function("sha3_512_incremental", |b| {
        b.iter(|| {
            let mut hasher = Sha3_512::new();
            for chunk in message.chunks(chunk_size) {
                hasher.update(black_box(chunk));
            }
            black_box(hasher.finalize())
        });
    });

    group.finish();
}

/// Benchmark small messages (where initialization overhead matters)
fn bench_sha3_small_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_small_messages");

    let sizes = [1, 4, 8, 16, 32];

    for size in sizes.iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::new("sha3_256", size), &message, |b, msg| {
            b.iter(|| {
                let mut hasher = Sha3_256::new();
                hasher.update(black_box(msg));
                black_box(hasher.finalize())
            });
        });

        group.bench_with_input(BenchmarkId::new("sha3_512", size), &message, |b, msg| {
            b.iter(|| {
                let mut hasher = Sha3_512::new();
                hasher.update(black_box(msg));
                black_box(hasher.finalize())
            });
        });
    }

    group.finish();
}

/// Benchmark empty hash (pure initialization + finalization)
fn bench_sha3_empty(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_empty");

    group.bench_function("sha3_256_empty", |b| {
        b.iter(|| {
            let hasher = Sha3_256::new();
            black_box(hasher.finalize())
        });
    });

    group.bench_function("sha3_512_empty", |b| {
        b.iter(|| {
            let hasher = Sha3_512::new();
            black_box(hasher.finalize())
        });
    });

    group.finish();
}

/// Benchmark Keccak-f permutation directly (if accessible)
/// This isolates the permutation performance from absorption/squeezing overhead
fn bench_keccak_permutation_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_permutation_patterns");

    // Test with different state patterns
    group.bench_function("all_zeros", |b| {
        b.iter(|| {
            let message = [0u8; 136]; // SHA3-256 rate
            let mut hasher = Sha3_256::new();
            hasher.update(black_box(&message));
            black_box(hasher.finalize())
        });
    });

    group.bench_function("all_ones", |b| {
        b.iter(|| {
            let message = [0xFFu8; 136];
            let mut hasher = Sha3_256::new();
            hasher.update(black_box(&message));
            black_box(hasher.finalize())
        });
    });

    group.bench_function("alternating", |b| {
        b.iter(|| {
            let message = [0xAAu8; 136];
            let mut hasher = Sha3_256::new();
            hasher.update(black_box(&message));
            black_box(hasher.finalize())
        });
    });

    group.bench_function("sequential", |b| {
        b.iter(|| {
            let message: Vec<u8> = (0..136).map(|i| i as u8).collect();
            let mut hasher = Sha3_256::new();
            hasher.update(black_box(&message));
            black_box(hasher.finalize())
        });
    });

    group.finish();
}

/// Benchmark multiple block processing
fn bench_sha3_multi_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3_multi_block");

    // SHA3-256 has 136-byte rate, SHA3-512 has 72-byte rate
    // Test messages that trigger multiple permutations

    let blocks = [1, 2, 4, 8, 16];

    for num_blocks in blocks.iter() {
        let size = num_blocks * 136; // SHA3-256 rate
        let message = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("sha3_256", format!("{}blocks", num_blocks)),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mut hasher = Sha3_256::new();
                    hasher.update(black_box(msg));
                    black_box(hasher.finalize())
                });
            },
        );
    }

    for num_blocks in blocks.iter() {
        let size = num_blocks * 72; // SHA3-512 rate
        let message = vec![0x42u8; size];

        group.bench_with_input(
            BenchmarkId::new("sha3_512", format!("{}blocks", num_blocks)),
            &message,
            |b, msg| {
                b.iter(|| {
                    let mut hasher = Sha3_512::new();
                    hasher.update(black_box(msg));
                    black_box(hasher.finalize())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sha3_256_comparison,
    bench_sha3_512_comparison,
    bench_sha3_incremental,
    bench_sha3_small_messages,
    bench_sha3_empty,
    bench_keccak_permutation_patterns,
    bench_sha3_multi_block
);
criterion_main!(benches);
