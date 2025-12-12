use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcrypt_mldsa::ntt::{inv_ntt, inv_ntt_merged, ntt_merged, ntt_scalar};
use hpcrypt_mldsa::poly::Poly;

const N: usize = 256;

fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    for i in 0..N {
        poly.coeffs[i] = (seed.wrapping_mul((i as i32) + 1)) % 8380417;
    }
    poly
}

fn bench_ntt_comparison(c: &mut Criterion) {
    let poly = create_test_poly(42);

    let mut group = c.benchmark_group("ntt_comparison");

    group.bench_function("ntt_scalar", |b| {
        b.iter(|| black_box(ntt_scalar(black_box(&poly))))
    });

    group.bench_function("ntt_merged_with_rolling_macros", |b| {
        b.iter(|| black_box(ntt_merged(black_box(&poly))))
    });

    group.finish();
}

fn bench_inv_ntt_comparison(c: &mut Criterion) {
    let poly = create_test_poly(42);
    let ntt_poly = ntt_scalar(&poly);

    let mut group = c.benchmark_group("inv_ntt_comparison");

    group.bench_function("inv_ntt", |b| {
        b.iter(|| black_box(inv_ntt(black_box(&ntt_poly))))
    });

    group.bench_function("inv_ntt_merged_with_rolling_macros", |b| {
        b.iter(|| black_box(inv_ntt_merged(black_box(&ntt_poly))))
    });

    group.finish();
}

fn bench_ntt_roundtrip_comparison(c: &mut Criterion) {
    let poly = create_test_poly(42);

    let mut group = c.benchmark_group("ntt_roundtrip_comparison");

    group.bench_function("standard", |b| {
        b.iter(|| {
            let ntt_poly = ntt_scalar(black_box(&poly));
            black_box(inv_ntt(&ntt_poly))
        })
    });

    group.bench_function("merged_with_rolling_macros", |b| {
        b.iter(|| {
            let ntt_poly = ntt_merged(black_box(&poly));
            black_box(inv_ntt_merged(&ntt_poly))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ntt_comparison,
    bench_inv_ntt_comparison,
    bench_ntt_roundtrip_comparison
);
criterion_main!(benches);
