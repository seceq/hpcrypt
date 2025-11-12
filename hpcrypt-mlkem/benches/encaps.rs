use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_mlkem::{KeyPair, MlKem512, MlKem768, MlKem1024};

fn bench_encaps_512(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem512>();

    c.bench_function("ML-KEM-512 Encaps", |b| {
        b.iter(|| {
            let result = keypair.encapsulate::<MlKem512>();
            black_box(result);
        });
    });
}

fn bench_encaps_768(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem768>();

    c.bench_function("ML-KEM-768 Encaps", |b| {
        b.iter(|| {
            let result = keypair.encapsulate::<MlKem768>();
            black_box(result);
        });
    });
}

fn bench_encaps_1024(c: &mut Criterion) {
    let keypair = KeyPair::generate::<MlKem1024>();

    c.bench_function("ML-KEM-1024 Encaps", |b| {
        b.iter(|| {
            let result = keypair.encapsulate::<MlKem1024>();
            black_box(result);
        });
    });
}

fn bench_encaps_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Encaps");

    let kp512 = KeyPair::generate::<MlKem512>();
    group.bench_function(BenchmarkId::new("ML-KEM", 512), |b| {
        b.iter(|| kp512.encapsulate::<MlKem512>());
    });

    let kp768 = KeyPair::generate::<MlKem768>();
    group.bench_function(BenchmarkId::new("ML-KEM", 768), |b| {
        b.iter(|| kp768.encapsulate::<MlKem768>());
    });

    let kp1024 = KeyPair::generate::<MlKem1024>();
    group.bench_function(BenchmarkId::new("ML-KEM", 1024), |b| {
        b.iter(|| kp1024.encapsulate::<MlKem1024>());
    });

    group.finish();
}

criterion_group!(benches, bench_encaps_512, bench_encaps_768, bench_encaps_1024, bench_encaps_all);
criterion_main!(benches);
