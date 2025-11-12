//! Benchmark for rejection sampling optimization with lookup tables
//!
//! This benchmark compares the baseline rejection sampling with lookup table optimization
//! for both eta=2 and eta=4 cases.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mldsa::symmetric::Shake256Xof;
use mldsa::sampling::{sample_poly_eta, sample_poly_eta_baseline};

fn bench_sampling_eta2_optimized(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling_eta2_optimized");

    group.bench_function("sample_poly_eta2_lut", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let poly = sample_poly_eta(black_box(&mut xof), black_box(2));
            black_box(poly);
        });
    });

    group.finish();
}

fn bench_sampling_eta4_optimized(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling_eta4_optimized");

    group.bench_function("sample_poly_eta4_lut", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let poly = sample_poly_eta(black_box(&mut xof), black_box(4));
            black_box(poly);
        });
    });

    group.finish();
}

fn bench_sampling_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling_comparison");

    for eta in [2, 4].iter() {
        group.bench_with_input(BenchmarkId::new("baseline_modulo", eta), eta, |b, &eta| {
            let seed = [0x42u8; 66];

            b.iter(|| {
                let mut xof = Shake256Xof::new(&seed);
                let poly = sample_poly_eta_baseline(black_box(&mut xof), black_box(eta));
                black_box(poly);
            });
        });

        group.bench_with_input(BenchmarkId::new("optimized_lut", eta), eta, |b, &eta| {
            let seed = [0x42u8; 66];

            b.iter(|| {
                let mut xof = Shake256Xof::new(&seed);
                let poly = sample_poly_eta(black_box(&mut xof), black_box(eta));
                black_box(poly);
            });
        });
    }

    group.finish();
}

fn bench_modulo_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("modulo_operations");

    // Benchmark the modulo operation itself
    group.bench_function("mod5_baseline", |b| {
        b.iter(|| {
            let mut sum = 0u32;
            for i in 0u8..15 {
                sum += (i % 5) as u32;
            }
            black_box(sum);
        });
    });

    // Benchmark lookup table version
    group.bench_function("mod5_lut", |b| {
        // Access the lookup table from mldsa crate
        const MOD5_TABLE: [u8; 16] = {
            let mut table = [0u8; 16];
            let mut i = 0;
            while i < 16 {
                table[i] = (i % 5) as u8;
                i += 1;
            }
            table
        };

        b.iter(|| {
            let mut sum = 0u32;
            for i in 0u8..15 {
                sum += MOD5_TABLE[i as usize] as u32;
            }
            black_box(sum);
        });
    });

    group.bench_function("mod9_baseline", |b| {
        b.iter(|| {
            let mut sum = 0u32;
            for i in 0u8..9 {
                sum += (i % 9) as u32;
            }
            black_box(sum);
        });
    });

    // Benchmark lookup table version
    group.bench_function("mod9_lut", |b| {
        const MOD9_TABLE: [u8; 16] = {
            let mut table = [0u8; 16];
            let mut i = 0;
            while i < 16 {
                table[i] = (i % 9) as u8;
                i += 1;
            }
            table
        };

        b.iter(|| {
            let mut sum = 0u32;
            for i in 0u8..9 {
                sum += MOD9_TABLE[i as usize] as u32;
            }
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sampling_eta2_optimized,
    bench_sampling_eta4_optimized,
    bench_sampling_comparison,
    bench_modulo_operations
);
criterion_main!(benches);
