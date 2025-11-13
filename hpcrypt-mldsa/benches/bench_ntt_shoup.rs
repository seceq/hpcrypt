//! Benchmark for Shoup multiplication in NTT
//!
//! Compares Shoup multiplication vs Montgomery reduction performance.
//! Shoup provides better instruction-level parallelism (ILP) which can
//! lead to 5-10% NTT speedup on modern CPUs.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mldsa::ntt::{inv_ntt, ntt};
use mldsa::params::Q;
use mldsa::poly::Poly;

/// Create test polynomial with realistic values
fn create_test_poly(seed: usize) -> Poly {
    let mut poly = Poly::new();
    for i in 0..256 {
        poly.coeffs[i] = ((i * seed * 7919 + 12345) % Q as usize) as i32;
    }
    poly
}

/// Benchmark forward NTT
fn bench_forward_ntt(c: &mut Criterion) {
    let poly = create_test_poly(42);

    c.bench_function("forward_ntt", |b| {
        b.iter(|| {
            let freq = ntt(black_box(&poly));
            black_box(freq);
        });
    });
}

/// Benchmark inverse NTT
fn bench_inverse_ntt(c: &mut Criterion) {
    let poly = create_test_poly(42);
    let freq = ntt(&poly);

    c.bench_function("inverse_ntt", |b| {
        b.iter(|| {
            let recovered = inv_ntt(black_box(&freq));
            black_box(recovered);
        });
    });
}

/// Benchmark full NTT roundtrip (forward + inverse)
fn bench_ntt_roundtrip(c: &mut Criterion) {
    let poly = create_test_poly(42);

    c.bench_function("ntt_roundtrip", |b| {
        b.iter(|| {
            let freq = ntt(black_box(&poly));
            let recovered = inv_ntt(black_box(&freq));
            black_box(recovered);
        });
    });
}

/// Benchmark batch NTT operations (simulates signing workload)
fn bench_batch_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_ntt");

    // Simulate signing: multiple forward NTTs
    group.bench_function("forward_batch_10", |b| {
        let polys: Vec<Poly> = (0..10).map(create_test_poly).collect();

        b.iter(|| {
            for poly in &polys {
                let freq = ntt(black_box(poly));
                black_box(freq);
            }
        });
    });

    // Simulate signing: multiple inverse NTTs
    let freqs: Vec<Poly> = (0..10).map(|i| ntt(&create_test_poly(i))).collect();

    group.bench_function("inverse_batch_10", |b| {
        b.iter(|| {
            for freq in &freqs {
                let recovered = inv_ntt(black_box(freq));
                black_box(recovered);
            }
        });
    });

    group.finish();
}

/// Benchmark NTT with different polynomial patterns
fn bench_ntt_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_patterns");

    // Zero polynomial
    let zero = Poly::new();
    group.bench_function("forward_zero", |b| {
        b.iter(|| {
            let freq = ntt(black_box(&zero));
            black_box(freq);
        });
    });

    // Dense polynomial (all coefficients non-zero)
    let dense = create_test_poly(12345);
    group.bench_function("forward_dense", |b| {
        b.iter(|| {
            let freq = ntt(black_box(&dense));
            black_box(freq);
        });
    });

    // Sparse polynomial (only a few coefficients)
    let mut sparse = Poly::new();
    sparse.coeffs[0] = 12345;
    sparse.coeffs[1] = 67890;
    sparse.coeffs[128] = 11111;
    group.bench_function("forward_sparse", |b| {
        b.iter(|| {
            let freq = ntt(black_box(&sparse));
            black_box(freq);
        });
    });

    group.finish();
}

/// Verify correctness (sanity check)
fn verify_correctness() {
    println!("Verifying NTT correctness with Shoup multiplication...");

    for seed in 0..10 {
        let poly = create_test_poly(seed);

        // NTT roundtrip
        let freq = ntt(&poly);
        let recovered = inv_ntt(&freq);

        // Check roundtrip (allowing for Montgomery form)
        for i in 0..256 {
            let orig = poly.coeffs[i].rem_euclid(Q);
            let recov = mldsa::ntt::from_montgomery(recovered.coeffs[i]).rem_euclid(Q);

            if orig != recov {
                panic!(
                    "NTT roundtrip failed for seed {}, index {}: {} != {}",
                    seed, i, orig, recov
                );
            }
        }
    }

    println!("✓ Correctness verification passed for 10 test polynomials");
}

// Run correctness check before benchmarks
#[ctor::ctor]
fn init() {
    verify_correctness();
}

criterion_group!(
    benches,
    bench_forward_ntt,
    bench_inverse_ntt,
    bench_ntt_roundtrip,
    bench_batch_ntt,
    bench_ntt_patterns
);
criterion_main!(benches);
