//! PGO baseline benchmark - measures current performance before PGO optimization

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_slhdsa::{sign, verify, KeyPair, Sha2_128s};

fn bench_sign_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgo_baseline");

    // Generate keypair once
    let mut rng = rand::thread_rng();
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for PGO testing";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = sign(&keypair.secret_key, black_box(message));
            black_box(signature);
        });
    });

    group.finish();
}

fn bench_verify_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgo_baseline");

    let mut rng = rand::thread_rng();
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Benchmark message for PGO testing";
    let signature = sign(&keypair.secret_key, message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = verify(
                &keypair.public_key,
                black_box(message),
                black_box(&signature),
            );
            black_box(result);
        });
    });

    group.finish();
}

fn bench_keygen_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgo_baseline");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let mut rng = rand::thread_rng();
            let keypair = KeyPair::<Sha2_128s>::generate(black_box(&mut rng));
            black_box(keypair);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sign_baseline,
    bench_verify_baseline,
    bench_keygen_baseline,
);
criterion_main!(benches);
