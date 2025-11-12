//! Benchmarks for Merkle tree caching performance.
//!
//! Compares signing performance with and without Merkle cache at different depths.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_slhdsa::{
    address::Address,
    hash::sha2::Sha2HashFunction,
    hypertree::{ht_sign, ht_sign_cached},
    merkle_cache::MerkleCache,
    params::Sha2_128s,
};

/// Benchmark hypertree signing without cache (baseline).
fn bench_no_cache(c: &mut Criterion) {
    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];
    let message = [0x56u8; 16];

    c.bench_function("hypertree_sign_no_cache", |b| {
        b.iter(|| {
            let mut addr = Address::new();
            ht_sign::<Sha2_128s, _>(
                black_box(&message),
                black_box(&sk_seed),
                black_box(&pk_seed),
                black_box(0),
                &mut addr,
                &hash,
            )
        });
    });
}

/// Benchmark hypertree signing with different cache depths.
fn bench_with_cache(c: &mut Criterion) {
    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];
    let message = [0x56u8; 16];

    let mut group = c.benchmark_group("hypertree_sign_cached");

    // Test cache depths 1-3 (4+ has diminishing returns)
    for cache_depth in 1..=3 {
        // Build cache once
        let cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, cache_depth, &hash);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("depth_{}", cache_depth)),
            &cache_depth,
            |b, _| {
                b.iter(|| {
                    let mut addr = Address::new();
                    ht_sign_cached::<Sha2_128s, _>(
                        black_box(&message),
                        black_box(&sk_seed),
                        black_box(&pk_seed),
                        black_box(0),
                        &mut addr,
                        &hash,
                        Some(&cache),
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache build time for different depths.
fn bench_cache_build(c: &mut Criterion) {
    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];

    let mut group = c.benchmark_group("cache_build");

    for cache_depth in 1..=3 {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("depth_{}", cache_depth)),
            &cache_depth,
            |b, &depth| {
                b.iter(|| {
                    MerkleCache::<Sha2_128s>::build(
                        black_box(&sk_seed),
                        black_box(&pk_seed),
                        black_box(depth),
                        &hash,
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache lookup performance.
fn bench_cache_lookup(c: &mut Criterion) {
    let hash = Sha2HashFunction::<16>::new();
    let sk_seed = [0x12u8; 16];
    let pk_seed = [0x34u8; 16];

    // Build cache with depth 3
    let cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 3, &hash);

    c.bench_function("cache_lookup", |b| {
        b.iter(|| {
            // Lookup cached layer (top layer = 6)
            cache.get_auth_path(black_box(6), black_box(0))
        });
    });
}

criterion_group!(
    benches,
    bench_no_cache,
    bench_with_cache,
    bench_cache_build,
    bench_cache_lookup
);
criterion_main!(benches);
