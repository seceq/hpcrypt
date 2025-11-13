// Performance benchmarks for SHAKE256 AVX2 implementation
//
// This benchmark compares:
// 1. AVX2 4-way parallel SHAKE256 (fips202x4)
// 2. Reference scalar SHAKE256 (sha3 crate)
//
// Target: 2-3X speedup for SHAKE256 operations

#![cfg(all(feature = "avx2", feature = "std", feature = "simd"))]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
use mldsa::simd::keccak::{shake256x4_batch, Shake256X4, SHAKE256_RATE};

/// Reference SHAKE256 using sha3 crate (scalar)
fn shake256_scalar(input: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; outlen];
    reader.read(&mut output);
    output
}

fn bench_shake256_single_vs_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_single");

    for input_len in [32, 64, 136, 256, 512] {
        let input = vec![0x42u8; input_len];

        group.throughput(Throughput::Bytes(input_len as u64));

        // Scalar (sha3 crate) - single computation
        group.bench_with_input(BenchmarkId::new("scalar", input_len), &input, |b, input| {
            b.iter(|| {
                black_box(shake256_scalar(black_box(input), 256));
            });
        });

        // AVX2 - compute 4 in parallel (amortized cost per stream)
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        group.bench_with_input(
            BenchmarkId::new("avx2_batch4_amortized", input_len),
            &input,
            |b, input| {
                b.iter(|| {
                    let inputs = [&input[..]; 4];
                    let _outputs = black_box(shake256x4_batch(black_box(inputs), 256));
                });
            },
        );
    }

    group.finish();
}

fn bench_shake256_output_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake256_output_length");

    let input = vec![0x5Au8; 64];

    for outlen in [64, 128, 256, 512, 1024] {
        group.throughput(Throughput::Bytes(outlen as u64));

        // Scalar
        group.bench_with_input(BenchmarkId::new("scalar", outlen), &outlen, |b, &outlen| {
            b.iter(|| {
                black_box(shake256_scalar(black_box(&input), outlen));
            });
        });

        // AVX2 batch (amortized)
        #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
        group.bench_with_input(
            BenchmarkId::new("avx2_batch4_amortized", outlen),
            &outlen,
            |b, &outlen| {
                b.iter(|| {
                    let inputs = [&input[..]; 4];
                    let _outputs = black_box(shake256x4_batch(black_box(inputs), outlen));
                });
            },
        );
    }

    group.finish();
}

fn bench_shake256_ml_dsa_expand_s(c: &mut Criterion) {
    // Simulate ML-DSA ExpandS operation
    // ML-DSA-65: Need to expand s1 (5 polynomials) and s2 (6 polynomials)
    // Each polynomial needs ~256 bytes from SHAKE256

    let mut group = c.benchmark_group("ml_dsa_expand_s");

    let seed = [0x42u8; 32];
    let outlen = 256; // bytes per polynomial (for eta=4 sampling)

    // Scalar: expand 4 polynomials sequentially
    group.bench_function("scalar_4poly", |b| {
        b.iter(|| {
            for nonce in 0..4u16 {
                let input = [&seed[..], &nonce.to_le_bytes()[..]].concat();
                let _out = black_box(shake256_scalar(black_box(&input), outlen));
            }
        });
    });

    // AVX2: expand 4 polynomials in parallel
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    group.bench_function("avx2_4poly_parallel", |b| {
        b.iter(|| {
            let in0 = [&seed[..], &0u16.to_le_bytes()[..]].concat();
            let in1 = [&seed[..], &1u16.to_le_bytes()[..]].concat();
            let in2 = [&seed[..], &2u16.to_le_bytes()[..]].concat();
            let in3 = [&seed[..], &3u16.to_le_bytes()[..]].concat();

            let _outputs = black_box(shake256x4_batch(
                [&in0[..], &in1[..], &in2[..], &in3[..]],
                outlen,
            ));
        });
    });

    group.finish();
}

fn bench_shake256_ml_dsa_expand_mask(c: &mut Criterion) {
    // Simulate ML-DSA ExpandMask operation during signing
    // ML-DSA-65: Need to expand y vector (L=5 polynomials)
    // Each polynomial needs more bytes (for larger range)

    let mut group = c.benchmark_group("ml_dsa_expand_mask");

    let seed = [0x7Fu8; 64]; // rho_prime concatenated with counter
    let outlen = 640; // bytes per polynomial for mask expansion

    // Scalar: expand 4 polynomials sequentially
    group.bench_function("scalar_4poly", |b| {
        b.iter(|| {
            for i in 0..4 {
                let mut input = seed.to_vec();
                input.push(i as u8);
                let _out = black_box(shake256_scalar(black_box(&input), outlen));
            }
        });
    });

    // AVX2: expand 4 polynomials in parallel
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    group.bench_function("avx2_4poly_parallel", |b| {
        b.iter(|| {
            let mut in0 = seed.to_vec();
            in0.push(0);
            let mut in1 = seed.to_vec();
            in1.push(1);
            let mut in2 = seed.to_vec();
            in2.push(2);
            let mut in3 = seed.to_vec();
            in3.push(3);

            let _outputs = black_box(shake256x4_batch(
                [&in0[..], &in1[..], &in2[..], &in3[..]],
                outlen,
            ));
        });
    });

    group.finish();
}

fn bench_shake256_incremental(c: &mut Criterion) {
    // Test incremental squeezing performance
    let mut group = c.benchmark_group("shake256_incremental");

    let input = vec![0xABu8; 128];

    // Scalar: squeeze 8 blocks (1088 bytes)
    group.bench_function("scalar_8blocks", |b| {
        b.iter(|| {
            let mut hasher = Shake256::default();
            hasher.update(black_box(&input));
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; 8 * SHAKE256_RATE];
            reader.read(&mut output);
            black_box(output);
        });
    });

    // AVX2: squeeze 8 blocks from 4 streams
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    group.bench_function("avx2_batch4_8blocks", |b| {
        b.iter(|| {
            let inputs = [&input[..]; 4];
            let mut xof = Shake256X4::absorb_once(black_box(inputs));
            let _outputs = black_box(xof.squeeze_blocks(8));
        });
    });

    group.finish();
}

fn bench_shake256_throughput(c: &mut Criterion) {
    // Measure overall throughput (bytes/sec) for different scenarios
    let mut group = c.benchmark_group("shake256_throughput");
    group.throughput(Throughput::Bytes(4 * 256)); // 4 streams × 256 bytes each

    let inputs_data = vec![0x55u8; 64];

    // Scalar: 4 sequential computations
    group.bench_function("scalar_4sequential", |b| {
        b.iter(|| {
            for _ in 0..4 {
                let _out = black_box(shake256_scalar(black_box(&inputs_data), 256));
            }
        });
    });

    // AVX2: 4 parallel computations
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    group.bench_function("avx2_4parallel", |b| {
        b.iter(|| {
            let inputs = [&inputs_data[..]; 4];
            let _outputs = black_box(shake256x4_batch(black_box(inputs), 256));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_shake256_single_vs_batch,
    bench_shake256_output_length,
    bench_shake256_ml_dsa_expand_s,
    bench_shake256_ml_dsa_expand_mask,
    bench_shake256_incremental,
    bench_shake256_throughput,
);

criterion_main!(benches);
