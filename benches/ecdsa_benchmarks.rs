use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_signatures::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use hpcrypt_signatures::ecdsa_p384::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use hpcrypt_signatures::ecdsa_secp256k1::{SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey};

// P-256 ECDSA Benchmarks
fn bench_p256_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-256 Key Generation");

    let secret_key = [1u8; 32];

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let signing_key = black_box(P256SigningKey::from_bytes(&secret_key).unwrap());
            let verifying_key = black_box(signing_key.verifying_key());
            black_box((signing_key, verifying_key))
        });
    });

    group.finish();
}

fn bench_p256_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-256 ECDSA Sign");

    let secret_key = [1u8; 32];
    let signing_key = P256SigningKey::from_bytes(&secret_key).unwrap();
    let message = b"Hello, world!";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = black_box(signing_key.sign(message));
            black_box(signature)
        });
    });

    group.finish();
}

fn bench_p256_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-256 ECDSA Verify");

    let secret_key = [1u8; 32];
    let signing_key = P256SigningKey::from_bytes(&secret_key).unwrap();
    let verifying_key = signing_key.verifying_key();
    let message = b"Hello, world!";
    let signature = signing_key.sign(message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = black_box(verifying_key.verify(message, &signature));
            black_box(valid)
        });
    });

    group.finish();
}

fn bench_p256_sign_verify_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-256 ECDSA End-to-End");

    let secret_key = [1u8; 32];
    let signing_key = P256SigningKey::from_bytes(&secret_key).unwrap();
    let verifying_key = signing_key.verifying_key();
    let message = b"Hello, world!";

    group.bench_function("sign_and_verify", |b| {
        b.iter(|| {
            let signature = black_box(signing_key.sign(message));
            let valid = black_box(verifying_key.verify(message, &signature));
            black_box(valid)
        });
    });

    group.finish();
}

// P-384 ECDSA Benchmarks
fn bench_p384_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-384 Key Generation");

    let secret_key = [1u8; 48];

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let signing_key = black_box(P384SigningKey::from_bytes(&secret_key).unwrap());
            let verifying_key = black_box(signing_key.verifying_key());
            black_box((signing_key, verifying_key))
        });
    });

    group.finish();
}

fn bench_p384_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-384 ECDSA Sign");

    let secret_key = [1u8; 48];
    let signing_key = P384SigningKey::from_bytes(&secret_key).unwrap();
    let message = b"Hello, world!";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = black_box(signing_key.sign(message));
            black_box(signature)
        });
    });

    group.finish();
}

fn bench_p384_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-384 ECDSA Verify");

    let secret_key = [1u8; 48];
    let signing_key = P384SigningKey::from_bytes(&secret_key).unwrap();
    let verifying_key = signing_key.verifying_key();
    let message = b"Hello, world!";
    let signature = signing_key.sign(message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = black_box(verifying_key.verify(message, &signature));
            black_box(valid)
        });
    });

    group.finish();
}

// secp256k1 ECDSA Benchmarks
fn bench_secp256k1_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 Key Generation");

    let secret_key = [1u8; 32];

    group.bench_function("generate_keypair", |b| {
        b.iter(|| {
            let signing_key = black_box(Secp256k1SigningKey::from_bytes(&secret_key).unwrap());
            let verifying_key = black_box(signing_key.verifying_key());
            black_box((signing_key, verifying_key))
        });
    });

    group.finish();
}

fn bench_secp256k1_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 ECDSA Sign");

    let secret_key = [1u8; 32];
    let signing_key = Secp256k1SigningKey::from_bytes(&secret_key).unwrap();
    let message = b"Hello, world!";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = black_box(signing_key.sign(message));
            black_box(signature)
        });
    });

    group.finish();
}

fn bench_secp256k1_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1 ECDSA Verify");

    let secret_key = [1u8; 32];
    let signing_key = Secp256k1SigningKey::from_bytes(&secret_key).unwrap();
    let verifying_key = signing_key.verifying_key();
    let message = b"Hello, world!";
    let signature = signing_key.sign(message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let valid = black_box(verifying_key.verify(message, &signature));
            black_box(valid)
        });
    });

    group.finish();
}

// Comparison benchmarks across curves
fn bench_sign_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA Sign Comparison");

    // P-256
    let p256_key = P256SigningKey::from_bytes(&[1u8; 32]).unwrap();
    let message = b"Hello, world!";

    group.bench_with_input(BenchmarkId::new("curve", "P-256"), &(), |b, _| {
        b.iter(|| {
            black_box(p256_key.sign(message))
        });
    });

    // P-384
    let p384_key = P384SigningKey::from_bytes(&[1u8; 48]).unwrap();

    group.bench_with_input(BenchmarkId::new("curve", "P-384"), &(), |b, _| {
        b.iter(|| {
            black_box(p384_key.sign(message))
        });
    });

    // secp256k1
    let secp_key = Secp256k1SigningKey::from_bytes(&[1u8; 32]).unwrap();

    group.bench_with_input(BenchmarkId::new("curve", "secp256k1"), &(), |b, _| {
        b.iter(|| {
            black_box(secp_key.sign(message))
        });
    });

    group.finish();
}

fn bench_verify_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDSA Verify Comparison");

    let message = b"Hello, world!";

    // P-256
    let p256_signing = P256SigningKey::from_bytes(&[1u8; 32]).unwrap();
    let p256_verifying = p256_signing.verifying_key();
    let p256_sig = p256_signing.sign(message);

    group.bench_with_input(BenchmarkId::new("curve", "P-256"), &(), |b, _| {
        b.iter(|| {
            black_box(p256_verifying.verify(message, &p256_sig))
        });
    });

    // P-384
    let p384_signing = P384SigningKey::from_bytes(&[1u8; 48]).unwrap();
    let p384_verifying = p384_signing.verifying_key();
    let p384_sig = p384_signing.sign(message);

    group.bench_with_input(BenchmarkId::new("curve", "P-384"), &(), |b, _| {
        b.iter(|| {
            black_box(p384_verifying.verify(message, &p384_sig))
        });
    });

    // secp256k1
    let secp_signing = Secp256k1SigningKey::from_bytes(&[1u8; 32]).unwrap();
    let secp_verifying = secp_signing.verifying_key();
    let secp_sig = secp_signing.sign(message);

    group.bench_with_input(BenchmarkId::new("curve", "secp256k1"), &(), |b, _| {
        b.iter(|| {
            black_box(secp_verifying.verify(message, &secp_sig))
        });
    });

    group.finish();
}

// Benchmark message sizes
fn bench_p256_varying_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("P-256 Sign - Message Sizes");

    let signing_key = P256SigningKey::from_bytes(&[1u8; 32]).unwrap();

    for size in [16, 64, 256, 1024, 4096] {
        let message = vec![0u8; size];

        group.bench_with_input(
            BenchmarkId::new("size", format!("{}_bytes", size)),
            &message,
            |b, msg| {
                b.iter(|| {
                    black_box(signing_key.sign(msg))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    p256_benches,
    bench_p256_key_generation,
    bench_p256_sign,
    bench_p256_verify,
    bench_p256_sign_verify_e2e,
    bench_p256_varying_message_sizes,
);

criterion_group!(
    p384_benches,
    bench_p384_key_generation,
    bench_p384_sign,
    bench_p384_verify,
);

criterion_group!(
    secp256k1_benches,
    bench_secp256k1_key_generation,
    bench_secp256k1_sign,
    bench_secp256k1_verify,
);

criterion_group!(
    comparison_benches,
    bench_sign_comparison,
    bench_verify_comparison,
);

criterion_main!(
    p256_benches,
    p384_benches,
    secp256k1_benches,
    comparison_benches,
);
