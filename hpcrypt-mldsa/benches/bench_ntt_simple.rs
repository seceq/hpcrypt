//! Simple benchmark test for NTT scalar

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mldsa::poly::Poly;
use mldsa::ntt::ntt_scalar;
use mldsa::params::N;

fn bench_ntt_scalar_simple(c: &mut Criterion) {
    // Create a simple test polynomial
    let mut poly = Poly::new();
    for i in 0..N {
        poly.coeffs[i] = i as i32;
    }

    c.bench_function("ntt_scalar_simple", |b| {
        b.iter(|| {
            let result = ntt_scalar(black_box(&poly));
            black_box(result);
        });
    });
}

criterion_group!(benches, bench_ntt_scalar_simple);
criterion_main!(benches);
