//! Benchmark for hypertree node.clone() elimination optimization
//!
//! This benchmark measures the impact of eliminating Vec cloning in the
//! hypertree signing hot path (called 7 times per signature for D=7).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{Sha2_128s, KeyPair};
use rand::rngs::OsRng;

fn bench_hypertree_signing_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("hypertree_clone_optimization");

    // Generate keypair once
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    // Benchmark full signing (includes all 7 clone operations)
    group.bench_function("baseline_with_clones", |b| {
        b.iter(|| {
            let message = b"Test message for benchmarking clone elimination in hypertree";
            let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
            black_box(sig)
        })
    });

    // Benchmark multiple signatures to see cumulative effect
    group.bench_function("baseline_10_signatures", |b| {
        b.iter(|| {
            for i in 0..10 {
                let message = format!("Test message {}", i);
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message.as_bytes()));
                black_box(sig);
            }
        })
    });

    group.finish();
}

fn bench_memory_allocation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone_overhead");

    // Measure clone overhead for different sizes (N=16 for SHA2-128s)
    group.bench_function("vec_clone_16bytes", |b| {
        let vec = vec![0u8; 16];
        b.iter(|| {
            let cloned = black_box(&vec).clone();
            black_box(cloned)
        })
    });

    // Measure 7 clones (one per layer)
    group.bench_function("vec_clone_16bytes_x7", |b| {
        let vec = vec![0u8; 16];
        b.iter(|| {
            for _ in 0..7 {
                let cloned = black_box(&vec).clone();
                black_box(cloned);
            }
        })
    });

    // Measure buffer swap (zero-cost alternative)
    group.bench_function("buffer_swap_16bytes", |b| {
        let mut buf1 = vec![0u8; 16];
        let mut buf2 = vec![0u8; 16];
        b.iter(|| {
            core::mem::swap(black_box(&mut buf1), black_box(&mut buf2));
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hypertree_signing_baseline,
    bench_memory_allocation_overhead
);
criterion_main!(benches);
