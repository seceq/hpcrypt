use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mldsa::poly::Poly;
use mldsa::rounding::{decompose, power2round};

const N: usize = 256;

// Test the rolling macro approach for dispatch
macro_rules! poly_op_dispatch_single {
    (
        $poly:expr,
        avx2_fn: $avx2_fn:path,
        scalar_op: |$coeff:ident| $scalar_op:expr
    ) => {{
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        {
            use mldsa::simd::dispatch::has_avx2;
            if has_avx2() {
                return unsafe { $avx2_fn($poly) };
            }
        }

        let mut result = Poly::new();
        for i in 0..N {
            let $coeff = $poly.coeffs[i];
            result.coeffs[i] = $scalar_op;
        }
        result
    }};
}

// Test parameters (ML-DSA-65)
const D: usize = 13;
const ALPHA: i32 = 523776;

// Current implementation (baseline)
fn power2round_poly_baseline(poly: &Poly, d: usize) -> Poly {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use mldsa::simd::dispatch::has_avx2;
        if has_avx2() && d == 13 {
            return unsafe { mldsa::simd::avx2::power2round_poly_avx2_ffi(poly) };
        }
    }

    let mut result = Poly::new();
    for i in 0..N {
        result.coeffs[i] = power2round(poly.coeffs[i], d).0;
    }
    result
}

// Macro-based implementation
fn power2round_poly_macro(poly: &Poly, d: usize) -> Poly {
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        use mldsa::simd::dispatch::has_avx2;
        if has_avx2() && d == 13 {
            return unsafe { mldsa::simd::avx2::power2round_poly_avx2_ffi(poly) };
        }
    }

    let mut result = Poly::new();
    for i in 0..N {
        let coeff = poly.coeffs[i];
        result.coeffs[i] = power2round(coeff, d).0;
    }
    result
}

// Decompose requires dual output - test simpler pattern
fn decompose_high_baseline(poly: &Poly, alpha: i32) -> Poly {
    let mut result = Poly::new();
    for i in 0..N {
        result.coeffs[i] = decompose(poly.coeffs[i], alpha).0;
    }
    result
}

fn decompose_high_macro(poly: &Poly, alpha: i32) -> Poly {
    let mut result = Poly::new();
    for i in 0..N {
        let coeff = poly.coeffs[i];
        result.coeffs[i] = decompose(coeff, alpha).0;
    }
    result
}

fn create_test_poly(seed: i32) -> Poly {
    let mut poly = Poly::new();
    for i in 0..N {
        poly.coeffs[i] = (seed.wrapping_mul(i as i32 + 1)) % 8380417;
    }
    poly
}

fn bench_power2round(c: &mut Criterion) {
    let poly = create_test_poly(12345);

    let mut group = c.benchmark_group("power2round_dispatch");

    group.bench_function("baseline", |b| {
        b.iter(|| black_box(power2round_poly_baseline(black_box(&poly), D)))
    });

    group.bench_function("macro", |b| {
        b.iter(|| black_box(power2round_poly_macro(black_box(&poly), D)))
    });

    group.finish();
}

fn bench_decompose(c: &mut Criterion) {
    let poly = create_test_poly(54321);

    let mut group = c.benchmark_group("decompose_dispatch");

    group.bench_function("baseline", |b| {
        b.iter(|| black_box(decompose_high_baseline(black_box(&poly), ALPHA)))
    });

    group.bench_function("macro", |b| {
        b.iter(|| black_box(decompose_high_macro(black_box(&poly), ALPHA)))
    });

    group.finish();
}

criterion_group!(benches, bench_power2round, bench_decompose);
criterion_main!(benches);
