//! Benchmark for Merkle auth path to_vec() call reduction
//!
//! This benchmark measures the impact of eliminating to_vec() calls in
//! compute_auth_path() by using a stack-allocated buffer instead.
//!
//! Current: tree_height × to_vec() calls (9-15 allocations per auth path)
//! Target: Single pre-allocated buffer reused across iterations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{KeyPair, Sha2_128f, Sha2_128s, Sha2_192s, Sha2_256s};
use rand::rngs::OsRng;

fn bench_allocation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_to_vec_overhead");

    // Measure single to_vec() cost for different sizes
    group.bench_function("to_vec_16_bytes", |b| {
        let data = [0u8; 16];
        b.iter(|| {
            let vec = black_box(data.to_vec());
            black_box(vec)
        })
    });

    group.bench_function("to_vec_24_bytes", |b| {
        let data = [0u8; 24];
        b.iter(|| {
            let vec = black_box(data.to_vec());
            black_box(vec)
        })
    });

    group.bench_function("to_vec_32_bytes", |b| {
        let data = [0u8; 32];
        b.iter(|| {
            let vec = black_box(data.to_vec());
            black_box(vec)
        })
    });

    // Measure 9 to_vec() calls (SHA2-128s tree height)
    group.bench_function("to_vec_9x16_bytes", |b| {
        let data = [0u8; 16];
        b.iter(|| {
            let mut auth_path = Vec::with_capacity(9);
            for _ in 0..9 {
                auth_path.push(black_box(data.to_vec()));
            }
            black_box(auth_path)
        })
    });

    // Measure 15 to_vec() calls (SHA2-256s tree height)
    group.bench_function("to_vec_15x32_bytes", |b| {
        let data = [0u8; 32];
        b.iter(|| {
            let mut auth_path = Vec::with_capacity(15);
            for _ in 0..15 {
                auth_path.push(black_box(data.to_vec()));
            }
            black_box(auth_path)
        })
    });

    // Stack allocation alternative (9 iterations)
    group.bench_function("stack_9x16_bytes", |b| {
        b.iter(|| {
            let mut auth_path_buf = [[0u8; 16]; 15]; // MAX_TREE_HEIGHT = 15
            for i in 0..9 {
                auth_path_buf[i] = black_box([0u8; 16]);
            }
            // Convert to Vec at end
            let mut auth_path = Vec::with_capacity(9);
            for i in 0..9 {
                auth_path.push(auth_path_buf[i].to_vec());
            }
            black_box(auth_path)
        })
    });

    group.finish();
}

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_to_vec_sign");

    // SHA2-128s (tree_height = 9)
    {
        let keypair = KeyPair::<Sha2_128s>::generate();
        let message = b"Test message for Merkle to_vec() optimization";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f (tree_height = 9, more signatures)
    {
        let keypair = KeyPair::<Sha2_128f>::generate();
        let message = b"Test message for Merkle to_vec() optimization";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (tree_height = 11)
    {
        let keypair = KeyPair::<Sha2_192s>::generate();
        let message = b"Test message for Merkle to_vec() optimization";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-256s (tree_height = 15)
    {
        let keypair = KeyPair::<Sha2_256s>::generate();
        let message = b"Test message for Merkle to_vec() optimization";

        group.bench_function("sha2_256s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    group.finish();
}

fn bench_verify_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_to_vec_verify");

    // SHA2-128s
    {
        let keypair = KeyPair::<Sha2_128s>::generate();
        let message = b"Test message for Merkle to_vec() optimization";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(
                    &keypair.public_key,
                    black_box(message),
                    black_box(&signature),
                );
                black_box(valid)
            })
        });
    }

    // SHA2-192s
    {
        let keypair = KeyPair::<Sha2_192s>::generate();
        let message = b"Test message for Merkle to_vec() optimization";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(
                    &keypair.public_key,
                    black_box(message),
                    black_box(&signature),
                );
                black_box(valid)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_allocation_overhead,
    bench_sign_baseline,
    bench_verify_baseline
);
criterion_main!(benches);
