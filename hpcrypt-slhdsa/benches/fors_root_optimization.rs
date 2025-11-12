//! Benchmark for FORS root buffer stack allocation optimization
//!
//! This benchmark measures the impact of eliminating to_vec() calls when storing
//! FORS tree roots. Current implementation clones K roots (14-33 depending on parameter set).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{Sha2_128s, Sha2_128f, Sha2_192s, KeyPair};
use rand::rngs::OsRng;

fn bench_fors_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("fors_root_optimization");

    // SHA2-128s (K=14, 14 root clones per signature)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for FORS root buffer optimization";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f (K=33, 33 root clones per signature - worst case)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
        let message = b"Test message for FORS root buffer optimization";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (K=17)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for FORS root buffer optimization";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    group.finish();
}

fn bench_vec_clone_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_clone_overhead");

    // Measure clone overhead for different K values
    // SHA2-128s: K=14
    group.bench_function("clone_14_roots_16bytes", |b| {
        let roots: Vec<Vec<u8>> = (0..14).map(|_| vec![0u8; 16]).collect();
        b.iter(|| {
            let cloned: Vec<Vec<u8>> = roots.iter().map(|r| r.clone()).collect();
            black_box(cloned)
        })
    });

    // SHA2-128f: K=33 (worst case)
    group.bench_function("clone_33_roots_16bytes", |b| {
        let roots: Vec<Vec<u8>> = (0..33).map(|_| vec![0u8; 16]).collect();
        b.iter(|| {
            let cloned: Vec<Vec<u8>> = roots.iter().map(|r| r.clone()).collect();
            black_box(cloned)
        })
    });

    // Measure single to_vec() call (per-tree overhead)
    group.bench_function("single_to_vec_16bytes", |b| {
        let node = [0u8; 16];
        b.iter(|| {
            let vec = black_box(&node).to_vec();
            black_box(vec)
        })
    });

    // Measure 14 to_vec() calls (SHA2-128s)
    group.bench_function("14_to_vec_16bytes", |b| {
        let node = [0u8; 16];
        b.iter(|| {
            let mut roots = Vec::with_capacity(14);
            for _ in 0..14 {
                roots.push(black_box(&node).to_vec());
            }
            black_box(roots)
        })
    });

    // Stack-based alternative (zero clone)
    group.bench_function("stack_14_roots_16bytes", |b| {
        b.iter(|| {
            let mut roots_buf = [[0u8; 16]; 14];
            let node = [0u8; 16];
            for root in roots_buf.iter_mut() {
                root.copy_from_slice(&node);
            }
            black_box(roots_buf)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_fors_signing,
    bench_vec_clone_overhead
);
criterion_main!(benches);
