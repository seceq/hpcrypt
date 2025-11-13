use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hpcrypt_mlkem::{KeyPair, MlKem1024, MlKem512, MlKem768};

fn bench_decaps_512(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem512>();
    let (ciphertext, _) = keypair.encapsulate::<MlKem512>();

    c.bench_function("ML-KEM-512 Decaps", |b| {
        b.iter(|| {
            let ss = keypair.decapsulate::<MlKem512>(&ciphertext);
            black_box(ss);
        });
    });
}

fn bench_decaps_768(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem768>();
    let (ciphertext, _) = keypair.encapsulate::<MlKem768>();

    c.bench_function("ML-KEM-768 Decaps", |b| {
        b.iter(|| {
            let ss = keypair.decapsulate::<MlKem768>(&ciphertext);
            black_box(ss);
        });
    });
}

fn bench_decaps_1024(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem1024>();
    let (ciphertext, _) = keypair.encapsulate::<MlKem1024>();

    c.bench_function("ML-KEM-1024 Decaps", |b| {
        b.iter(|| {
            let ss = keypair.decapsulate::<MlKem1024>(&ciphertext);
            black_box(ss);
        });
    });
}

fn bench_decaps_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Decaps");

    let kp512 = KeyPair::generate::<MlKem512>();
    let (ct512, _) = kp512.encapsulate::<MlKem512>();
    group.bench_function(BenchmarkId::new("ML-KEM", 512), |b| {
        b.iter(|| kp512.decapsulate::<MlKem512>(&ct512));
    });

    let kp768 = KeyPair::generate::<MlKem768>();
    let (ct768, _) = kp768.encapsulate::<MlKem768>();
    group.bench_function(BenchmarkId::new("ML-KEM", 768), |b| {
        b.iter(|| kp768.decapsulate::<MlKem768>(&ct768));
    });

    let kp1024 = KeyPair::generate::<MlKem1024>();
    let (ct1024, _) = kp1024.encapsulate::<MlKem1024>();
    group.bench_function(BenchmarkId::new("ML-KEM", 1024), |b| {
        b.iter(|| kp1024.decapsulate::<MlKem1024>(&ct1024));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decaps_512,
    bench_decaps_768,
    bench_decaps_1024,
    bench_decaps_all
);
criterion_main!(benches);
