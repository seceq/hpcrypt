//! Benchmark for inline optimization of critical hash functions
//!
//! This benchmark measures the impact of adding #[inline(always)] to hot
//! hash functions (t_node, t_leaf, prf_msg, h_msg) in SHA2 and SHAKE implementations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::hash::sha2::Sha2HashFunction;
use hpcrypt_slhdsa::hash::shake::ShakeHashFunction;
use hpcrypt_slhdsa::hash::traits::HashFunction;

fn bench_hash_function_calls(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_function_inline");

    // SHA2-128s (N=16)
    {
        let hash_fn = Sha2HashFunction::<16>::new();
        let pk_seed = [0x42u8; 16];
        let addr = [0u8; 32];
        let leaf = [0x11u8; 16];
        let left = [0x11u8; 16];
        let right = [0x22u8; 16];
        let mut out = [0u8; 16];

        // Benchmark t_leaf (called ~70,000 times per signature)
        group.bench_function("sha2_128s_t_leaf", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_leaf(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&leaf),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });

        // Benchmark t_node (called ~70,000 times per signature)
        group.bench_function("sha2_128s_t_node", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_node(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&left),
                    black_box(&right),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });

        // Benchmark prf_msg (called once per signature)
        let sk_prf = [0xAAu8; 16];
        let opt_rand = [0xBBu8; 16];
        let msg = b"test message for benchmarking";
        group.bench_function("sha2_128s_prf_msg", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.prf_msg(
                    black_box(&sk_prf),
                    black_box(&opt_rand),
                    black_box(msg),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });
    }

    // SHA2-256s (N=32)
    {
        let hash_fn = Sha2HashFunction::<32>::new();
        let pk_seed = [0x42u8; 32];
        let addr = [0u8; 32];
        let leaf = [0x11u8; 32];
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let mut out = [0u8; 32];

        group.bench_function("sha2_256s_t_leaf", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_leaf(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&leaf),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });

        group.bench_function("sha2_256s_t_node", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_node(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&left),
                    black_box(&right),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });
    }

    // SHAKE-128s (N=16)
    {
        let hash_fn = ShakeHashFunction::<16>::new();
        let pk_seed = [0x42u8; 16];
        let addr = [0u8; 32];
        let leaf = [0x11u8; 16];
        let left = [0x11u8; 16];
        let right = [0x22u8; 16];
        let mut out = [0u8; 16];

        group.bench_function("shake_128s_t_leaf", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_leaf(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&leaf),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });

        group.bench_function("shake_128s_t_node", |b| {
            b.iter(|| {
                let mut out_local = out;
                hash_fn.t_node(
                    black_box(&pk_seed),
                    black_box(&addr),
                    black_box(&left),
                    black_box(&right),
                    &mut out_local,
                );
                black_box(out_local)
            })
        });
    }

    group.finish();
}

fn bench_hot_loop_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_function_hot_loop");

    // SHA2-128s: Simulate 1000 t_node calls (typical for one tree level)
    {
        let hash_fn = Sha2HashFunction::<16>::new();
        let pk_seed = [0x42u8; 16];
        let mut addr = [0u8; 32];
        let left = [0x11u8; 16];
        let right = [0x22u8; 16];
        let mut out = [0u8; 16];

        group.bench_function("sha2_128s_1000_t_node_calls", |b| {
            b.iter(|| {
                let mut out_local = out;
                for i in 0..1000 {
                    addr[28] = (i & 0xFF) as u8;
                    hash_fn.t_node(
                        black_box(&pk_seed),
                        black_box(&addr),
                        black_box(&left),
                        black_box(&right),
                        &mut out_local,
                    );
                    black_box(out_local);
                }
            })
        });
    }

    // SHA2-256s: Simulate 1000 t_node calls
    {
        let hash_fn = Sha2HashFunction::<32>::new();
        let pk_seed = [0x42u8; 32];
        let mut addr = [0u8; 32];
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let mut out = [0u8; 32];

        group.bench_function("sha2_256s_1000_t_node_calls", |b| {
            b.iter(|| {
                let mut out_local = out;
                for i in 0..1000 {
                    addr[28] = (i & 0xFF) as u8;
                    hash_fn.t_node(
                        black_box(&pk_seed),
                        black_box(&addr),
                        black_box(&left),
                        black_box(&right),
                        &mut out_local,
                    );
                    black_box(out_local);
                }
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_function_calls,
    bench_hot_loop_simulation
);
criterion_main!(benches);
