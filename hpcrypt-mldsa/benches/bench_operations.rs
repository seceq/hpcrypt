use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_mldsa::params::MlDsa65;
use hpcrypt_mldsa::keygen::keygen_from_seed;
use hpcrypt_mldsa::sign::sign_deterministic;
use hpcrypt_mldsa::verify::verify;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    let seed = [42u8; 32];

    group.bench_function("keygen_mldsa65", |b| {
        b.iter(|| {
            keygen_from_seed::<MlDsa65>(black_box(&seed))
        });
    });

    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");

    let seed = [42u8; 32];
    let (_, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"benchmark message";
    let rnd = [0u8; 32];

    group.bench_function("sign_mldsa65", |b| {
        b.iter(|| {
            sign_deterministic::<MlDsa65>(black_box(&sk), black_box(message), black_box(&rnd))
        });
    });

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    let seed = [42u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"benchmark message";
    let rnd = [0u8; 32];
    let sig = sign_deterministic::<MlDsa65>(&sk, message, &rnd).unwrap();

    group.bench_function("verify_mldsa65", |b| {
        b.iter(|| {
            verify::<MlDsa65>(black_box(&pk), black_box(message), black_box(&sig))
        });
    });

    group.finish();
}

fn bench_sign_verify_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    let seed = [42u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"benchmark message";
    let rnd = [0u8; 32];

    group.bench_function("sign_verify_roundtrip", |b| {
        b.iter(|| {
            let sig = sign_deterministic::<MlDsa65>(black_box(&sk), black_box(message), black_box(&rnd)).unwrap();
            verify::<MlDsa65>(black_box(&pk), black_box(message), black_box(&sig))
        });
    });

    group.finish();
}

fn bench_message_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_sizes");

    let seed = [42u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let rnd = [0u8; 32];

    for size in [32, 256, 1024, 4096, 16384].iter() {
        let message = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("sign", size), size, |b, _| {
            b.iter(|| {
                sign_deterministic::<MlDsa65>(black_box(&sk), black_box(&message), black_box(&rnd))
            });
        });

        let sig = sign_deterministic::<MlDsa65>(&sk, &message, &rnd).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                verify::<MlDsa65>(black_box(&pk), black_box(&message), black_box(&sig))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_sign_verify_roundtrip,
    bench_message_sizes
);
criterion_main!(benches);
