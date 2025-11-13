//! Signing benchmarks for SLH-DSA.
//!
//! Measures the performance of signature generation across all parameter sets.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_slhdsa::{
    sign, KeyPair, Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s,
};
use rand::rngs::OsRng;

fn bench_sign_sha2_128s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_128s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_sha2_128f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_128f", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_sha2_192s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_192s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_192s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_sha2_192f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_192f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_192f", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_sha2_256s(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_256s>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_256s", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_sha2_256f(c: &mut Criterion) {
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_256f>::generate(&mut rng);
    let message = b"Benchmark message for SLH-DSA signing performance test";

    c.bench_function("sign_sha2_256f", |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair.secret_key), black_box(message));
            black_box(sig);
        });
    });
}

fn bench_sign_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_all");
    let mut rng = OsRng;
    let message = b"Benchmark message for SLH-DSA signing performance test";

    let keypair_128s = KeyPair::<Sha2_128s>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128s"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_128f = KeyPair::<Sha2_128f>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128f"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_128f.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_192s = KeyPair::<Sha2_192s>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192s"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_192s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_192f = KeyPair::<Sha2_192f>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192f"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_192f.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_256s = KeyPair::<Sha2_256s>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256s"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_256s.secret_key), black_box(message));
            black_box(sig);
        });
    });

    let keypair_256f = KeyPair::<Sha2_256f>::generate(&mut rng);
    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256f"), |b| {
        b.iter(|| {
            let sig = sign(black_box(&keypair_256f.secret_key), black_box(message));
            black_box(sig);
        });
    });

    group.finish();
}

fn bench_sign_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_message_sizes");
    let mut rng = OsRng;
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let sig = sign(black_box(&keypair.secret_key), black_box(&message));
                black_box(sig);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sign_sha2_128s,
    bench_sign_sha2_128f,
    bench_sign_sha2_192s,
    bench_sign_sha2_192f,
    bench_sign_sha2_256s,
    bench_sign_sha2_256f,
    bench_sign_comparison,
    bench_sign_message_sizes
);
criterion_main!(benches);
