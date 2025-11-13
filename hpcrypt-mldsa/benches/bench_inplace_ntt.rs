//! Benchmark for In-Place NTT optimization
//!
//! This benchmark compares standard NTT (with clone) vs in-place NTT (without clone).
//! The in-place version eliminates the allocation overhead of cloning the polynomial.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use mldsa::ntt::{inv_ntt, inv_ntt_inplace, ntt, ntt_inplace};
use mldsa::poly::Poly;

/// Helper: Create a test polynomial with pseudo-random coefficients
fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    let q = 8380417i32;
    for i in 0..256 {
        // Simple pseudo-random formula
        let val = (((seed as i64) + (i as i64)) * 1103515245 + 12345) % (q as i64);
        poly.coeffs[i] = if val > (q as i64) / 2 {
            (val - (q as i64)) as i32
        } else {
            val as i32
        };
    }
    poly
}

/// Benchmark: Forward NTT (clone vs in-place)
fn bench_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt");

    let poly = create_test_poly(1000);

    // Current implementation: clone inside ntt()
    group.bench_function("ntt_clone", |b| {
        b.iter(|| {
            let result = ntt(black_box(&poly));
            black_box(&result);
        });
    });

    // In-place version: no clone, modifies input
    group.bench_function("ntt_inplace", |b| {
        b.iter_batched(
            || poly.clone(), // Setup: clone for each iteration (to measure just NTT)
            |mut poly| {
                ntt_inplace(&mut poly);
                black_box(&poly);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark: Inverse NTT (clone vs in-place)
fn bench_inv_ntt_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("inv_ntt");

    let poly = create_test_poly(1000);
    let poly_ntt = ntt(&poly); // Pre-transform to NTT domain

    // Current implementation: clone inside inv_ntt()
    group.bench_function("inv_ntt_clone", |b| {
        b.iter(|| {
            let result = inv_ntt(black_box(&poly_ntt));
            black_box(&result);
        });
    });

    // In-place version: no clone, modifies input
    group.bench_function("inv_ntt_inplace", |b| {
        b.iter_batched(
            || poly_ntt.clone(), // Setup: clone for each iteration
            |mut poly| {
                inv_ntt_inplace(&mut poly);
                black_box(&poly);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark: Full NTT roundtrip (forward + inverse)
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_roundtrip");

    let poly = create_test_poly(1000);

    // Current: clone twice (inside ntt and inv_ntt)
    group.bench_function("clone_version", |b| {
        b.iter(|| {
            let ntt_poly = ntt(black_box(&poly));
            let result = inv_ntt(&ntt_poly);
            black_box(&result);
        });
    });

    // In-place: no clones (transforms in-place)
    group.bench_function("inplace_version", |b| {
        b.iter_batched(
            || poly.clone(), // Setup: start with clean poly
            |mut poly| {
                ntt_inplace(&mut poly);
                inv_ntt_inplace(&mut poly);
                black_box(&poly);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark: Matrix-vector multiply pattern (realistic workload)
///
/// Simulates the pattern in ML-DSA signing where we transform each row of matrix A
/// and then multiply with vector y.
fn bench_matrix_vector_pattern(c: &mut Criterion) {
    let l = 5; // ML-DSA-65

    let mut group = c.benchmark_group("matrix_vector_transform");

    let matrix_row: Vec<Poly> = (0..l)
        .map(|i| create_test_poly((i as i32) * 1000))
        .collect();

    // Current pattern: clone inside ntt() for each matrix element
    group.bench_function("current_pattern", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(l);
            for poly in &matrix_row {
                let poly_ntt = ntt(black_box(poly));
                results.push(poly_ntt);
            }
            black_box(&results);
        });
    });

    // In-place pattern: explicit clone, then in-place transform
    // Note: This doesn't save allocations (still need to clone for results vector)
    // but makes the allocation explicit
    group.bench_function("inplace_explicit_clone", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(l);
            for poly in &matrix_row {
                let mut poly_ntt = poly.clone();
                ntt_inplace(&mut poly_ntt);
                results.push(poly_ntt);
            }
            black_box(&results);
        });
    });

    // Better pattern: pre-allocate and transform in-place
    group.bench_function("inplace_preallocated", |b| {
        b.iter(|| {
            let mut results: Vec<Poly> = matrix_row.clone();
            for poly in &mut results {
                ntt_inplace(poly);
            }
            black_box(&results);
        });
    });

    group.finish();
}

/// Benchmark: Rejection loop pattern (most realistic for signing)
///
/// In ML-DSA signing, we often transform vectors in a rejection loop.
/// The polynomial is sampled, transformed, used, and discarded if rejected.
fn bench_rejection_loop_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("rejection_loop");

    let num_iterations: usize = 10; // Simulate 10 rejection iterations
    let polys: Vec<Poly> = (0..num_iterations)
        .map(|i| create_test_poly((i as i32) * 100))
        .collect();

    // Current pattern: ntt() clones each time
    group.bench_function("current_clone", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_iterations);
            for poly in &polys {
                let poly_ntt = ntt(black_box(poly));
                // In real code: use poly_ntt, then might reject
                results.push(poly_ntt);
            }
            black_box(&results);
        });
    });

    // In-place pattern: transform sampled polynomial directly
    // This is realistic: we sample y, transform it, use it, then reject or accept
    group.bench_function("inplace_no_clone", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_iterations);
            for poly in &polys {
                let mut poly_ntt = poly.clone(); // Represents sampling
                ntt_inplace(&mut poly_ntt);
                // In real code: use poly_ntt, then might reject
                results.push(poly_ntt);
            }
            black_box(&results);
        });
    });

    group.finish();
}

/// Benchmark: Clone overhead measurement (baseline)
///
/// Measures pure clone cost to quantify the expected savings
fn bench_clone_overhead(c: &mut Criterion) {
    let poly = create_test_poly(1000);

    c.bench_function("poly_clone", |b| {
        b.iter(|| {
            let copy = poly.clone();
            black_box(&copy);
        });
    });
}

criterion_group!(
    benches,
    bench_clone_overhead,
    bench_ntt_comparison,
    bench_inv_ntt_comparison,
    bench_roundtrip,
    bench_matrix_vector_pattern,
    bench_rejection_loop_pattern
);
criterion_main!(benches);
