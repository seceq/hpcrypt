//! Benchmark for const generics loop unrolling optimization
//!
//! This benchmark measures the impact of using const generics to enable
//! explicit loop unrolling for compile-time known loop bounds.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{KeyPair, Sha2_128f, Sha2_128s, Sha2_192s, Sha2_256s};
use hpcrypt_rng::OsRng;

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("const_generic_sign");

    // SHA2-128s (N=16, WOTS_LEN=35)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for const generic optimization";

        group.bench_function("sha2_128s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-128f (N=16, WOTS_LEN=35)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
        let message = b"Test message for const generic optimization";

        group.bench_function("sha2_128f_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-192s (N=24, WOTS_LEN=51)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
        let message = b"Test message for const generic optimization";

        group.bench_function("sha2_192s_baseline", |b| {
            b.iter(|| {
                let sig = hpcrypt_slhdsa::sign(&keypair.secret_key, black_box(message));
                black_box(sig)
            })
        });
    }

    // SHA2-256s (N=32, WOTS_LEN=67)
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
        let message = b"Test message for const generic optimization";

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
    let mut group = c.benchmark_group("const_generic_verify");

    // SHA2-128s
    {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
        let message = b"Test message for const generic optimization";
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
        let message = b"Test message for const generic optimization";
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
