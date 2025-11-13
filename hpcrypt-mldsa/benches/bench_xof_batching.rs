//! Benchmark for XOF batching optimization
//!
//! This benchmark compares different XOF read strategies:
//! - Current: Multiple small reads (136 bytes for eta=2, 272+136 for eta=4)
//! - Batched: Single large read (200 bytes for eta=2, 350 bytes for eta=4)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mldsa::sampling::sample_poly_eta;
use mldsa::symmetric::Shake256Xof;

fn bench_sampling_with_batching(c: &mut Criterion) {
    let mut group = c.benchmark_group("sampling_with_batching");

    group.bench_function("eta2_batched_200", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let poly = sample_poly_eta(black_box(&mut xof), black_box(2));
            black_box(poly);
        });
    });

    group.bench_function("eta4_batched_350", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let poly = sample_poly_eta(black_box(&mut xof), black_box(4));
            black_box(poly);
        });
    });

    group.finish();
}

fn bench_xof_read_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("xof_read_overhead");

    // Benchmark different read sizes to measure overhead
    for &size in &[136, 200, 272, 350, 400] {
        group.bench_with_input(BenchmarkId::new("read_bytes", size), &size, |b, &size| {
            let seed = [0x42u8; 66];

            b.iter(|| {
                let mut xof = Shake256Xof::new(&seed);
                let mut buf = vec![0u8; size];
                xof.read(black_box(&mut buf));
                black_box(&buf);
            });
        });
    }

    group.finish();
}

fn bench_multiple_vs_single_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_strategies");

    // Simulate current eta=2 pattern: 2 reads of 136 bytes
    group.bench_function("eta2_two_reads_136", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let mut buf1 = [0u8; 136];
            let mut buf2 = [0u8; 136];
            xof.read(black_box(&mut buf1));
            xof.read(black_box(&mut buf2));
            black_box((&buf1, &buf2));
        });
    });

    // Proposed: single read of 200 bytes
    group.bench_function("eta2_one_read_200", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let mut buf = [0u8; 200];
            xof.read(black_box(&mut buf));
            black_box(&buf);
        });
    });

    // Simulate current eta=4 pattern: 272 + 136 bytes
    group.bench_function("eta4_two_reads_272_136", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let mut buf1 = [0u8; 272];
            let mut buf2 = [0u8; 136];
            xof.read(black_box(&mut buf1));
            xof.read(black_box(&mut buf2));
            black_box((&buf1, &buf2));
        });
    });

    // Proposed: single read of 350 bytes
    group.bench_function("eta4_one_read_350", |b| {
        let seed = [0x42u8; 66];

        b.iter(|| {
            let mut xof = Shake256Xof::new(&seed);
            let mut buf = [0u8; 350];
            xof.read(black_box(&mut buf));
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sampling_with_batching,
    bench_xof_read_sizes,
    bench_multiple_vs_single_read
);
criterion_main!(benches);
