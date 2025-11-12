//! Benchmark for WOTS chain buffer reuse optimization
//!
//! This benchmark measures the impact of stack-allocating msg_base_w buffers
//! to eliminate heap allocations in WOTS signing and verification.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{Sha2_128s, Sha2_128f, Sha2_192s, Sha2_256s, KeyPair};
use rand::rngs::OsRng;

fn bench_wots_allocation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_buffer_allocation");

    // Measure heap allocation cost for msg_base_w buffer
    // SHA2-128s: WOTS_LEN = 35
    group.bench_function("heap_alloc_35_usize", |b| {
        b.iter(|| {
            let buf: Vec<usize> = vec![0; 35];
            black_box(buf)
        })
    });

    // SHA2-128f: WOTS_LEN = 35
    group.bench_function("heap_alloc_35_usize_128f", |b| {
        b.iter(|| {
            let buf: Vec<usize> = vec![0; 35];
            black_box(buf)
        })
    });

    // SHA2-192s: WOTS_LEN = 51
    group.bench_function("heap_alloc_51_usize", |b| {
        b.iter(|| {
            let buf: Vec<usize> = vec![0; 51];
            black_box(buf)
        })
    });

    // SHA2-256s: WOTS_LEN = 67
    group.bench_function("heap_alloc_67_usize", |b| {
        b.iter(|| {
            let buf: Vec<usize> = vec![0; 67];
            black_box(buf)
        })
    });

    // Stack allocation (should be nearly free)
    group.bench_function("stack_alloc_67_usize", |b| {
        b.iter(|| {
            let buf = [0usize; 67];
            black_box(buf)
        })
    });

    // Measure 2 allocations per signature (sign + pk_from_sig in verification)
    group.bench_function("heap_alloc_2x35_usize", |b| {
        b.iter(|| {
            let buf1: Vec<usize> = vec![0; 35];
            let buf2: Vec<usize> = vec![0; 35];
            black_box((buf1, buf2))
        })
    });

    // Stack version
    group.bench_function("stack_alloc_2x35_usize", |b| {
        b.iter(|| {
            let buf1 = [0usize; 35];
            let buf2 = [0usize; 35];
            black_box((buf1, buf2))
        })
    });

    group.finish();
}

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("wots_buffer_sign");

    // SHA2-128s (WOTS_LEN=35)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f (WOTS_LEN=35)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (WOTS_LEN=51)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-256s (WOTS_LEN=67)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";

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
    let mut group = c.benchmark_group("wots_buffer_verify");

    // SHA2-128s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(&keypair.public_key, black_box(message), black_box(&signature));
                black_box(valid)
            })
        });
    }

    // SHA2-192s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for WOTS buffer optimization";
        let signature = hpcrypt_slhdsa::sign(&keypair.secret_key, message);

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let valid = hpcrypt_slhdsa::verify(&keypair.public_key, black_box(message), black_box(&signature));
                black_box(valid)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_wots_allocation_overhead,
    bench_sign_baseline,
    bench_verify_baseline
);
criterion_main!(benches);
