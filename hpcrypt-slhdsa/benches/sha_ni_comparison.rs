//! SHA-NI comparison benchmark.
//!
//! Compares hardware-accelerated SHA-256 (with SHA-NI) vs software implementation.
//! This benchmark demonstrates the benefit of SHA hardware instructions.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use sha2::{Sha256, Digest};

/// Benchmark SHA-256 hashing with different input sizes
fn bench_sha256_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_throughput");

    for &size in &[32, 64, 128, 256, 512, 1024, 4096, 8192] {
        let data = vec![0x42u8; size];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(&data));
                    let result = hasher.finalize();
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark multiple independent SHA-256 operations (common in SLH-DSA)
fn bench_sha256_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_batch");

    for &count in &[10, 50, 100, 500, 1000] {
        let data = vec![0x42u8; 32];

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(count),
            &count,
            |b, _| {
                b.iter(|| {
                    for _ in 0..count {
                        let mut hasher = Sha256::new();
                        hasher.update(black_box(&data));
                        let result = hasher.finalize();
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark SHA-256 chains (simulates WOTS chains)
fn bench_sha256_chains(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_chains");

    for &chain_len in &[10, 50, 100, 200] {
        let mut current = [0x42u8; 32];

        group.throughput(Throughput::Elements(chain_len as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(chain_len),
            &chain_len,
            |b, _| {
                b.iter(|| {
                    let mut state = current;
                    for i in 0..chain_len {
                        let mut hasher = Sha256::new();
                        hasher.update(black_box(&state));
                        hasher.update(&(i as u32).to_be_bytes());
                        state = hasher.finalize().into();
                    }
                    black_box(state);
                });
            },
        );
    }

    group.finish();
}

/// Realistic WOTS scenario: Multiple parallel chains
fn bench_wots_scenario(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_scenario");

    const NUM_CHAINS: usize = 67;
    const CHAIN_LENGTH: usize = 67;

    let seed = [0x42u8; 32];

    group.throughput(Throughput::Elements((NUM_CHAINS * CHAIN_LENGTH) as u64));
    group.bench_function("full_wots", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(NUM_CHAINS);

            for chain_idx in 0..NUM_CHAINS {
                let mut current = seed;

                for step in 0..CHAIN_LENGTH {
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(&current));
                    hasher.update(&(chain_idx as u32).to_be_bytes());
                    hasher.update(&(step as u32).to_be_bytes());
                    current = hasher.finalize().into();
                }

                results.push(current);
            }

            black_box(results);
        });
    });

    group.finish();
}

/// Realistic FORS scenario: Tree leaf generation
fn bench_fors_scenario(c: &mut Criterion) {
    let mut group = c.benchmark_group("fors_scenario");

    for &num_leaves in &[16, 64, 256, 1024] {
        let seed = [0x42u8; 32];

        group.throughput(Throughput::Elements(num_leaves as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(num_leaves),
            &num_leaves,
            |b, _| {
                b.iter(|| {
                    let mut leaves = Vec::with_capacity(num_leaves);

                    for i in 0..num_leaves {
                        let mut hasher = Sha256::new();
                        hasher.update(black_box(&seed));
                        hasher.update(&(i as u32).to_be_bytes());
                        let leaf = hasher.finalize();
                        leaves.push(leaf);
                    }

                    black_box(leaves);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256_throughput,
    bench_sha256_batch,
    bench_sha256_chains,
    bench_wots_scenario,
    bench_fors_scenario,
);
criterion_main!(benches);
