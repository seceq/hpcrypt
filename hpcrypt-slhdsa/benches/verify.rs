//! Verification benchmarks for SLH-DSA.
//!
//! Measures the performance of signature verification across all parameter sets.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_slhdsa::{
    sign, verify, KeyPair, Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s,
};
use hpcrypt_rng::OsRng;

fn bench_verify_sha2_128s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_128s", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_sha2_128f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_128f", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_sha2_192s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_192s", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_sha2_192f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_192f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_192f", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_sha2_256s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_256s", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_sha2_256f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_256f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let signature = sign(&keypair.secret_key, message);

    c.bench_function("verify_sha2_256f", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

fn bench_verify_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_all");
    let mut rng = OsRng;
    let message = b"Benchmark message for SLH-DSA verification performance test";

    let keypair_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    let sig_128s = sign(&keypair_128s.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128s"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_128s.public_key),
                black_box(message),
                black_box(&sig_128s),
            );
            black_box(valid);
        });
    });

    let keypair_128f = KeyPair::<Sha2_128f>::generate(&mut rng);
    let sig_128f = sign(&keypair_128f.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128f"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_128f.public_key),
                black_box(message),
                black_box(&sig_128f),
            );
            black_box(valid);
        });
    });

    let keypair_192s = KeyPair::<Sha2_192s>::generate(&mut rng);
    let sig_192s = sign(&keypair_192s.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192s"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_192s.public_key),
                black_box(message),
                black_box(&sig_192s),
            );
            black_box(valid);
        });
    });

    let keypair_192f = KeyPair::<Sha2_192f>::generate(&mut rng);
    let sig_192f = sign(&keypair_192f.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192f"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_192f.public_key),
                black_box(message),
                black_box(&sig_192f),
            );
            black_box(valid);
        });
    });

    let keypair_256s = KeyPair::<Sha2_256s>::generate(&mut rng);
    let sig_256s = sign(&keypair_256s.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256s"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_256s.public_key),
                black_box(message),
                black_box(&sig_256s),
            );
            black_box(valid);
        });
    });

    let keypair_256f = KeyPair::<Sha2_256f>::generate(&mut rng);
    let sig_256f = sign(&keypair_256f.secret_key, message);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256f"), |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair_256f.public_key),
                black_box(message),
                black_box(&sig_256f),
            );
            black_box(valid);
        });
    });

    group.finish();
}

fn bench_verify_invalid_signature(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA verification performance test";
    let mut signature = sign(&keypair.secret_key, message);

    // Corrupt the signature
    signature[0] ^= 0xFF;

    c.bench_function("verify_invalid_signature", |b| {
        b.iter(|| {
            let valid = verify(
                black_box(&keypair.public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(valid);
        });
    });
}

criterion_group!(
    benches,
    bench_verify_sha2_128s,
    bench_verify_sha2_128f,
    bench_verify_sha2_192s,
    bench_verify_sha2_192f,
    bench_verify_sha2_256s,
    bench_verify_sha2_256f,
    bench_verify_comparison,
    bench_verify_invalid_signature
);
criterion_main!(benches);
