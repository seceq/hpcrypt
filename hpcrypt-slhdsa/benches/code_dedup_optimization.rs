//! Benchmark for code deduplication optimization
//!
//! This benchmark measures the impact of reducing code duplication in merkle.rs
//! by using macros instead of repeated match arms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{KeyPair, Sha2_128f, Sha2_128s, Sha2_192s, Sha2_256s};
use rand::rngs::OsRng;

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("code_dedup_sign");

    // SHA2-128s (N=16)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (N=24)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-256s (N=32)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";

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
    let mut group = c.benchmark_group("code_dedup_verify");

    // SHA2-128s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";
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
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for code deduplication optimization";
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

criterion_group!(benches, bench_sign_baseline, bench_verify_baseline);
criterion_main!(benches);
