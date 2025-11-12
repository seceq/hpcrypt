//! GHASH Optimization Benchmarks
//!
//! This benchmark suite validates performance improvements from each optimization technique:
//! 1. Baseline: Current bit-by-bit implementation
//! 2. BearSSL ctmul: Constant-time multiplication with masking
//! 3. Karatsuba: 3-multiplication algorithm
//! 4. Powers of H: Precomputation for parallelism
//! 5. Barrett reduction: Optimized reduction algorithm
//! 6. Aggregated reduction: Deferred reduction for multiple blocks

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use hpcrypt_aead::ghash::{GHash, ghash};
use hpcrypt_aead::ghash_optimized::{GHashOptimized, GHashAggregated, ghash_optimized};
use hpcrypt_aead::ghash_fast::{GHashFast, ghash_fast};
use std::time::Duration;

fn benchmark_ghash_single_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghash_single_block");
    group.measurement_time(Duration::from_secs(10));

    let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
             0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
    let block = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];

    group.throughput(Throughput::Bytes(16));

    // Baseline: Current bit-by-bit implementation
    group.bench_function("01_baseline", |b| {
        let mut hasher = GHash::new(&h);
        b.iter(|| {
            hasher.update(black_box(&block));
        });
    });

    // Optimized: Karatsuba + Barrett + Powers of H
    group.bench_function("02_optimized_degree4", |b| {
        let mut hasher = GHashOptimized::new(&h, 4);
        b.iter(|| {
            hasher.update(black_box(&block));
        });
    });

    // Aggregated reduction
    group.bench_function("03_aggregated", |b| {
        let mut hasher = GHashAggregated::new(&h, 4, 8);
        b.iter(|| {
            hasher.update(black_box(&block));
        });
    });

    // Fast: BearSSL ctmul + Powers of H
    group.bench_function("04_fast_ctmul", |b| {
        let mut hasher = GHashFast::new_default(&h);
        b.iter(|| {
            hasher.update(black_box(&block));
        });
    });

    group.finish();
}

fn benchmark_ghash_multiple_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghash_multiple_blocks");
    group.measurement_time(Duration::from_secs(10));

    let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
             0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Baseline
        group.bench_with_input(
            BenchmarkId::new("01_baseline", size),
            size,
            |b, _| {
                b.iter(|| {
                    let tag = ghash(black_box(&h), black_box(&data));
                    black_box(tag);
                });
            },
        );

        // Optimized - degree 4
        group.bench_with_input(
            BenchmarkId::new("02_optimized_deg4", size),
            size,
            |b, _| {
                b.iter(|| {
                    let mut hasher = GHashOptimized::new(&h, 4);
                    hasher.update_padded(black_box(&data));
                    let tag = hasher.finalize();
                    black_box(tag);
                });
            },
        );

        // Optimized - degree 8
        group.bench_with_input(
            BenchmarkId::new("03_optimized_deg8", size),
            size,
            |b, _| {
                b.iter(|| {
                    let mut hasher = GHashOptimized::new(&h, 8);
                    hasher.update_padded(black_box(&data));
                    let tag = hasher.finalize();
                    black_box(tag);
                });
            },
        );

        // Optimized - batch processing
        if *size >= 64 {
            group.bench_with_input(
                BenchmarkId::new("04_optimized_batch", size),
                size,
                |b, _| {
                    b.iter(|| {
                        let mut hasher = GHashOptimized::new(&h, 8);
                        let blocks: Vec<[u8; 16]> = data
                            .chunks_exact(16)
                            .map(|chunk| {
                                let mut block = [0u8; 16];
                                block.copy_from_slice(chunk);
                                block
                            })
                            .collect();
                        hasher.update_batch(black_box(&blocks));
                        let tag = hasher.finalize();
                        black_box(tag);
                    });
                },
            );
        }

        // Fast ctmul - degree 4
        group.bench_with_input(
            BenchmarkId::new("05_fast_ctmul", size),
            size,
            |b, _| {
                b.iter(|| {
                    let tag = ghash_fast(black_box(&h), black_box(&data));
                    black_box(tag);
                });
            },
        );
    }

    group.finish();
}

fn benchmark_ghash_parallel_degrees(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghash_parallel_degrees");
    group.measurement_time(Duration::from_secs(10));

    let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
             0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];

    let data = vec![0x42u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // Test different parallelism degrees
    for degree in [1, 2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("degree", degree),
            degree,
            |b, &deg| {
                b.iter(|| {
                    let mut hasher = GHashOptimized::new(&h, deg);
                    hasher.update_padded(black_box(&data));
                    let tag = hasher.finalize();
                    black_box(tag);
                });
            },
        );
    }

    group.finish();
}

fn benchmark_ghash_convenience_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghash_convenience");
    group.measurement_time(Duration::from_secs(10));

    let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
             0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
    let data = vec![0x42u8; 1024];

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("baseline_convenience", |b| {
        b.iter(|| {
            let tag = ghash(black_box(&h), black_box(&data));
            black_box(tag);
        });
    });

    group.bench_function("optimized_convenience", |b| {
        b.iter(|| {
            let tag = ghash_optimized(black_box(&h), black_box(&data));
            black_box(tag);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_ghash_single_block,
    benchmark_ghash_multiple_blocks,
    benchmark_ghash_parallel_degrees,
    benchmark_ghash_convenience_functions
);
criterion_main!(benches);
