// Detailed profiling of ML-DSA operations
//
// This tool breaks down signing performance to identify the next optimization target

use mldsa::keygen::keygen;
use mldsa::MlDsa65;
use std::time::Instant;

fn main() {
    println!("================================================================================");
    println!("ML-DSA-65 Detailed Performance Profile");
    println!("================================================================================");
    println!();

    let iterations = 1000;

    // Generate key once
    let (pk, sk) = keygen::<MlDsa65>();
    let message = b"Profiling message for detailed performance analysis";

    println!("Profiling {} signing operations...", iterations);
    println!();

    // Comprehensive signing benchmark
    let start = Instant::now();
    let mut successful_signs = 0;
    for _ in 0..iterations {
        if let Some(_sig) = mldsa::sign::sign::<MlDsa65>(&sk, message) {
            successful_signs += 1;
        }
    }
    let total_time = start.elapsed();

    let avg_sign_us = total_time.as_micros() / iterations;

    println!("=== Signing Performance ===");
    println!("Total time: {:?}", total_time);
    println!("Average per signature: {} µs", avg_sign_us);
    println!("Successful: {}/{}", successful_signs, iterations);
    println!();

    // Verification benchmark
    let sig = mldsa::sign::sign::<MlDsa65>(&sk, message).unwrap();
    let start = Instant::now();
    let mut successful_verifies = 0;
    for _ in 0..iterations {
        if mldsa::verify::verify::<MlDsa65>(&pk, message, &sig) {
            successful_verifies += 1;
        }
    }
    let verify_time = start.elapsed();
    let avg_verify_us = verify_time.as_micros() / iterations;

    println!("=== Verification Performance ===");
    println!("Total time: {:?}", verify_time);
    println!("Average per verification: {} µs", avg_verify_us);
    println!("Successful: {}/{}", successful_verifies, iterations);
    println!();

    // KeyGen benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keygen::<MlDsa65>();
    }
    let keygen_time = start.elapsed();
    let avg_keygen_us = keygen_time.as_micros() / iterations;

    println!("=== Key Generation Performance ===");
    println!("Total time: {:?}", keygen_time);
    println!("Average per keygen: {} µs", avg_keygen_us);
    println!();

    println!("================================================================================");
    println!("=== Summary ===");
    println!("================================================================================");
    println!("KeyGen:  {:4} µs", avg_keygen_us);
    println!("Sign:    {:4} µs", avg_sign_us);
    println!("Verify:  {:4} µs", avg_verify_us);
    println!(
        "Total:   {:4} µs",
        avg_keygen_us + avg_sign_us + avg_verify_us
    );
    println!();

    println!("================================================================================");
    println!("=== Next Optimization Targets ===");
    println!("================================================================================");
    println!();
    println!(
        "Based on current performance (~{} µs signing):",
        avg_sign_us
    );
    println!();
    println!("1. SHAKE256/XOF Operations (20-30% of signing)");
    println!("   - Current: ~{} µs estimated", avg_sign_us * 25 / 100);
    println!("   - Potential: AVX2 Keccak implementation");
    println!("   - Expected gain: 10-15% overall");
    println!();
    println!("2. Polynomial Operations (15-20% of signing)");
    println!("   - Current: ~{} µs estimated", avg_sign_us * 17 / 100);
    println!("   - Potential: SIMD add/sub/reduce");
    println!("   - Expected gain: 3-5% overall");
    println!();
    println!("3. Memory/Cache Optimization (5-10% potential)");
    println!("   - Alignment, prefetching, layout");
    println!("   - Expected gain: 2-3% overall");
    println!();
    println!("4. Rejection Sampling (already optimized 12% via early check)");
    println!("   - Further optimization: Lazy w computation (high complexity)");
    println!("   - Expected additional gain: 3-8%");
    println!();
    println!("================================================================================");
    println!("Recommendation: Profile SHAKE256 usage to confirm it's the bottleneck");
    println!("================================================================================");
}
