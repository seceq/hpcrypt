// Simple profiling example for SHAKE256 AVX2 vs scalar performance
//
// This measures the time taken for SHAKE256 operations and calculates speedup

#![cfg(all(feature = "avx2", feature = "std", feature = "simd"))]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::time::Instant;

#[cfg(all(feature = "avx2", target_arch = "x86_64"))]
use mldsa::simd::keccak::shake256x4_batch;

/// Reference SHAKE256 using sha3 crate (scalar)
fn shake256_scalar(input: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; outlen];
    reader.read(&mut output);
    output
}

fn main() {
    println!("SHAKE256 AVX2 Performance Analysis");
    println!("===================================\n");

    // Test parameters
    let iterations = 10000;
    let input = vec![0x42u8; 64];
    let outlen = 256;

    // Benchmark scalar (4 sequential)
    println!("Running scalar baseline (4 sequential SHAKE256)...");
    let start = Instant::now();
    for _ in 0..iterations {
        for _ in 0..4 {
            let _out = shake256_scalar(&input, outlen);
        }
    }
    let scalar_time = start.elapsed();
    let scalar_ns_per_op = scalar_time.as_nanos() / (iterations * 4);
    println!(
        "  Time: {:?} ({} ns per operation)",
        scalar_time, scalar_ns_per_op
    );

    // Benchmark AVX2 (4 parallel)
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        println!("\nRunning AVX2 (4 parallel SHAKE256)...");
        let start = Instant::now();
        for _ in 0..iterations {
            let inputs = [&input[..]; 4];
            let _outputs = shake256x4_batch(inputs, outlen);
        }
        let avx2_time = start.elapsed();
        let avx2_ns_per_op = avx2_time.as_nanos() / (iterations * 4);
        println!(
            "  Time: {:?} ({} ns per operation)",
            avx2_time, avx2_ns_per_op
        );

        // Calculate speedup
        let speedup = scalar_time.as_secs_f64() / avx2_time.as_secs_f64();
        println!("\n=== Results ===");
        println!("Speedup: {:.2}X", speedup);
        println!("Scalar:  {} ns/op", scalar_ns_per_op);
        println!("AVX2:    {} ns/op", avx2_ns_per_op);
        println!("Improvement: {:.1}%", (speedup - 1.0) * 100.0);

        if speedup >= 2.0 {
            println!("\n Target achieved! (2X+ speedup)");
        } else if speedup >= 1.5 {
            println!("\n🟡 Good speedup, but below 2X target");
        } else {
            println!("\n🔴 Speedup lower than expected");
        }
    }

    // ML-DSA workload simulation
    println!("\n\n=== ML-DSA Workload Simulation ===");
    println!("Simulating ExpandS (4 polynomials)...\n");

    let seed = [0x42u8; 32];
    let poly_iterations = 1000;

    // Scalar: expand 4 polynomials sequentially
    println!("Running scalar ExpandS...");
    let start = Instant::now();
    for _ in 0..poly_iterations {
        for nonce in 0..4u16 {
            let input = [&seed[..], &nonce.to_le_bytes()[..]].concat();
            let _out = shake256_scalar(&input, 256);
        }
    }
    let scalar_expand = start.elapsed();
    println!(
        "  Time: {:?} ({} µs per 4-poly expansion)",
        scalar_expand,
        scalar_expand.as_micros() / poly_iterations
    );

    // AVX2: expand 4 polynomials in parallel
    #[cfg(all(feature = "avx2", target_arch = "x86_64"))]
    {
        println!("\nRunning AVX2 ExpandS...");
        let start = Instant::now();
        for _ in 0..poly_iterations {
            let in0 = [&seed[..], &0u16.to_le_bytes()[..]].concat();
            let in1 = [&seed[..], &1u16.to_le_bytes()[..]].concat();
            let in2 = [&seed[..], &2u16.to_le_bytes()[..]].concat();
            let in3 = [&seed[..], &3u16.to_le_bytes()[..]].concat();

            let _outputs = shake256x4_batch([&in0[..], &in1[..], &in2[..], &in3[..]], 256);
        }
        let avx2_expand = start.elapsed();
        println!(
            "  Time: {:?} ({} µs per 4-poly expansion)",
            avx2_expand,
            avx2_expand.as_micros() / poly_iterations
        );

        let expand_speedup = scalar_expand.as_secs_f64() / avx2_expand.as_secs_f64();
        println!("\nExpandS Speedup: {:.2}X", expand_speedup);

        // Estimate ML-DSA overall impact
        // Assuming SHAKE256 is 25% of ML-DSA runtime
        let shake_fraction = 0.25;
        let overall_improvement = 1.0 / ((1.0 - shake_fraction) + shake_fraction / expand_speedup);
        println!(
            "Estimated ML-DSA overall speedup: {:.2}X ({:.1}% faster)",
            overall_improvement,
            (overall_improvement - 1.0) * 100.0
        );
    }

    println!("\n=== Analysis Complete ===");
}
