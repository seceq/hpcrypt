//! Key generation benchmarks for SLH-DSA.
//!
//! Measures the performance of key generation across all parameter sets.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_slhdsa::{KeyPair, Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s};
use rand::rngs::OsRng;

fn bench_keygen_sha2_128s(c: &mut Criterion) {
    c.bench_function("keygen_sha2_128s", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_sha2_128f(c: &mut Criterion) {
    c.bench_function("keygen_sha2_128f", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_sha2_192s(c: &mut Criterion) {
    c.bench_function("keygen_sha2_192s", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_192s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_sha2_192f(c: &mut Criterion) {
    c.bench_function("keygen_sha2_192f", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_192f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_sha2_256s(c: &mut Criterion) {
    c.bench_function("keygen_sha2_256s", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_256s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_sha2_256f(c: &mut Criterion) {
    c.bench_function("keygen_sha2_256f", |b| {
        let mut rng = OsRng;
        b.iter(|| {
            let keypair = KeyPair::<Sha2_256f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });
}

fn bench_keygen_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen_all");
    let mut rng = OsRng;

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128s"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_128f"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_128f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192s"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_192s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_192f"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_192f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256s"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_256s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.bench_function(BenchmarkId::new("parameter_set", "sha2_256f"), |b| {
        b.iter(|| {
            let keypair = KeyPair::<Sha2_256f>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen_sha2_128s,
    bench_keygen_sha2_128f,
    bench_keygen_sha2_192s,
    bench_keygen_sha2_192f,
    bench_keygen_sha2_256s,
    bench_keygen_sha2_256f,
    bench_keygen_comparison
);
criterion_main!(benches);
