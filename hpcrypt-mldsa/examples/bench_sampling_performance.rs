//! Performance benchmark for sampling vectorization
//!
//! Measures signing performance before and after AVX2 sampling optimization

use mldsa::MlDsa65;
use mldsa::keygen::keygen;
use mldsa::sign;
use std::time::Instant;

fn main() {
    println!("========================================");
    println!("ML-DSA-65 Sampling Performance Test");
    println!("========================================\n");

    // Generate keypair once
    let (pk, sk) = keygen::<MlDsa65>();
    let message = b"Test message for sampling performance benchmark";

    // Warm up
    println!("Warming up...");
    for _ in 0..100 {
        let _ = sign::sign::<MlDsa65>(&sk, message);
    }

    // Benchmark signing (multiple runs for accuracy)
    const ITERATIONS: usize = 1000;
    println!("\nRunning {} signing operations...\n", ITERATIONS);

    let start = Instant::now();
    let mut successful_signs = 0;
    for _ in 0..ITERATIONS {
        if sign::sign::<MlDsa65>(&sk, message).is_some() {
            successful_signs += 1;
        }
    }
    let elapsed = start.elapsed();

    let total_micros = elapsed.as_micros();
    let avg_micros = total_micros / ITERATIONS as u128;

    println!("Results:");
    println!("  Total time:       {:?}", elapsed);
    println!("  Successful signs: {}/{}", successful_signs, ITERATIONS);
    println!("  Average per sign: {} µs", avg_micros);
    println!("  Throughput:       {:.1} signs/sec", 1_000_000.0 / avg_micros as f64);
    println!("\n========================================\n");

    // Verification benchmark
    let sig = sign::sign::<MlDsa65>(&sk, message).expect("Failed to generate signature");

    println!("Running {} verification operations...\n", ITERATIONS);

    let start = Instant::now();
    let mut successful_verifies = 0;
    for _ in 0..ITERATIONS {
        if mldsa::verify::verify::<MlDsa65>(&pk, message, &sig) {
            successful_verifies += 1;
        }
    }
    let elapsed = start.elapsed();

    let total_micros = elapsed.as_micros();
    let avg_micros = total_micros / ITERATIONS as u128;

    println!("Results:");
    println!("  Total time:          {:?}", elapsed);
    println!("  Successful verifies: {}/{}", successful_verifies, ITERATIONS);
    println!("  Average per verify:  {} µs", avg_micros);
    println!("  Throughput:          {:.1} verifies/sec", 1_000_000.0 / avg_micros as f64);
    println!("\n========================================\n");

    println!("Performance Summary:");
    println!("  Sign:   {} µs", total_micros / ITERATIONS as u128);
    println!("  Verify: {} µs", avg_micros);
}
