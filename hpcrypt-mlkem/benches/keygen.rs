use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hpcrypt_mlkem::{KeyPair, MlKem512, MlKem768, MlKem1024};

fn bench_keygen_512(c: &mut Criterion) {
    c.bench_function("ML-KEM-512 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate::<MlKem512>();
            black_box(keypair);
        });
    });
}

fn bench_keygen_768(c: &mut Criterion) {
    c.bench_function("ML-KEM-768 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate::<MlKem768>();
            black_box(keypair);
        });
    });
}

fn bench_keygen_1024(c: &mut Criterion) {
    c.bench_function("ML-KEM-1024 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate::<MlKem1024>();
            black_box(keypair);
        });
    });
}

fn bench_keygen_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM KeyGen");

    group.bench_function(BenchmarkId::new("ML-KEM", 512), |b| {
        b.iter(KeyPair::generate::<MlKem512>);
    });

    group.bench_function(BenchmarkId::new("ML-KEM", 768), |b| {
        b.iter(KeyPair::generate::<MlKem768>);
    });

    group.bench_function(BenchmarkId::new("ML-KEM", 1024), |b| {
        b.iter(KeyPair::generate::<MlKem1024>);
    });

    group.finish();
}

criterion_group!(benches, bench_keygen_512, bench_keygen_768, bench_keygen_1024, bench_keygen_all);
criterion_main!(benches);
