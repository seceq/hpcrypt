use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_curves::X448;

fn bench_x448_shared_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("X448 Key Exchange");

    let alice_private = [1u8; 56];
    let bob_private = [2u8; 56];
    let bob_public = X448::public_key(&bob_private);

    group.bench_function("shared_secret", |b| {
        b.iter(|| {
            let shared = black_box(X448::shared_secret(&alice_private, &bob_public).unwrap());
            black_box(shared)
        });
    });

    group.finish();
}

criterion_group!(x448_benches, bench_x448_shared_secret);
criterion_main!(x448_benches);
