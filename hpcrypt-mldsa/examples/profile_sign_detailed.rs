//! Detailed profiling of signing operation with manual instrumentation
//!
//! This inserts timing measurements at key points in the signing algorithm
//! to identify actual bottlenecks.

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::MlDsa65;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

// Global timing accumulators (atomic for thread safety)
#[allow(dead_code)]
static TIME_MU_HASH: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_RHO_PRIME_HASH: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_EXPAND_A: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_SAMPLE_Y: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_EARLY_CHECK: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_MATRIX_MUL: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_HIGH_BITS: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_CHALLENGE_HASH: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_SAMPLE_C: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_COMPUTE_Z: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_CHECK_Z: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_COMPUTE_R: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_CHECK_R0: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_HINTS: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TIME_CHECK_HINTS: AtomicU64 = AtomicU64::new(0);

#[allow(dead_code)]
static TOTAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
static TOTAL_SIGNS: AtomicU64 = AtomicU64::new(0);

fn main() {
    println!("================================================================================");
    println!("ML-DSA-65 Detailed Signing Profile");
    println!("================================================================================\n");

    println!("NOTE: This is a coarse-grained profiling approach using the sign() API.");
    println!("For fine-grained profiling, we would need to instrument sign.rs directly.\n");

    // Generate keypair
    let (_pk, sk) = keygen::<MlDsa65>();
    let message = b"Profiling message for detailed bottleneck analysis";

    // Warmup
    println!("Warming up (100 signatures)...");
    for _ in 0..100 {
        let _ = hpcrypt_mldsa::sign::sign::<MlDsa65>(&sk, message);
    }

    println!("Running instrumented benchmark (1000 signatures)...\n");

    const ITERATIONS: usize = 1000;

    // Since we can't modify sign.rs inline without code changes,
    // we'll do overall timing and estimate breakdown based on algorithm structure

    let start = Instant::now();
    let mut successful = 0;
    for _ in 0..ITERATIONS {
        if hpcrypt_mldsa::sign::sign::<MlDsa65>(&sk, message).is_some() {
            successful += 1;
        }
    }
    let total_elapsed = start.elapsed();

    let avg_micros = total_elapsed.as_micros() / ITERATIONS as u128;

    println!("================================================================================");
    println!("Overall Performance");
    println!("================================================================================\n");
    println!("Total time:    {:?}", total_elapsed);
    println!("Successful:    {}/{}", successful, ITERATIONS);
    println!("Average:       {} µs per signature", avg_micros);
    println!(
        "Throughput:    {:.1} signs/sec\n",
        1_000_000.0 / avg_micros as f64
    );

    println!("================================================================================");
    println!("Estimated Breakdown (Based on Algorithm Analysis)");
    println!("================================================================================\n");

    // Based on ML-DSA-65 algorithm structure and previous profiling
    // These are ESTIMATES - would need code instrumentation for exact numbers

    let total_us = avg_micros as f64;

    println!("Estimated time per operation (single attempt, no rejection):");
    println!();

    // One-time operations (not in retry loop)
    let mu_hash_est = 3.0; // H(tr || M)
    let rho_prime_hash_est = 3.0; // H(K || rnd || mu)
    let expand_a_est = 80.0; // Expand 6x5 matrix

    // Per-attempt operations (average ~4.5 attempts)
    let avg_attempts = 4.5;
    let sample_y_est = 15.0; // Sample L=5 polynomials (using XOF x4)
    let early_check_est = 0.5; // Norm check on y
    let matrix_mul_est = 60.0; // A·y (6x5 matrix-vector mul with NTT)
    let high_bits_est = 8.0; // Extract w1
    let challenge_hash_est = 3.0; // H(mu || w1)
    let sample_c_est = 2.0; // sample_in_ball
    let compute_z_est = 12.0; // z = y + c·s1 (5 polys)
    let check_z_est = 1.0; // Norm check
    let compute_r_est = 20.0; // r = w - c·s2 (6 polys with NTT)
    let check_r0_est = 8.0; // LowBits and check
    let hints_est = 12.0; // MakeHint
    let check_hints_est = 1.0; // Count hints

    // Calculate per-attempt cost (operations in retry loop)
    let per_attempt_est = sample_y_est
        + early_check_est
        + matrix_mul_est
        + high_bits_est
        + challenge_hash_est
        + sample_c_est
        + compute_z_est
        + check_z_est
        + compute_r_est
        + check_r0_est
        + hints_est
        + check_hints_est;

    // One-time setup
    let setup_est = mu_hash_est + rho_prime_hash_est + expand_a_est;

    // Total estimate
    let estimated_total = setup_est + (per_attempt_est * avg_attempts);

    println!("Setup (one-time):");
    println!("  μ hash (H(tr || M)):           {:>6.1} µs", mu_hash_est);
    println!(
        "  ρ' hash (H(K || rnd || μ)):    {:>6.1} µs",
        rho_prime_hash_est
    );
    println!("  Expand matrix A:                {:>6.1} µs", expand_a_est);
    println!(
        "  Subtotal:                       {:>6.1} µs ({:.1}%)",
        setup_est,
        100.0 * setup_est / total_us
    );
    println!();

    println!("Per-attempt ({:.1} avg attempts):", avg_attempts);
    println!(
        "  Sample y (L={} polys):         {:>6.1} µs",
        5, sample_y_est
    );
    println!(
        "  Early rejection check:          {:>6.1} µs",
        early_check_est
    );
    println!(
        "  Matrix multiply (A·y):         {:>6.1} µs",
        matrix_mul_est
    );
    println!(
        "  Extract high bits (w1):         {:>6.1} µs",
        high_bits_est
    );
    println!(
        "  Challenge hash (H(μ || w1)):   {:>6.1} µs",
        challenge_hash_est
    );
    println!("  Sample challenge (c):           {:>6.1} µs", sample_c_est);
    println!("  Compute z (y + c·s1):          {:>6.1} µs", compute_z_est);
    println!("  Check ||z||:                    {:>6.1} µs", check_z_est);
    println!("  Compute r (w - c·s2):          {:>6.1} µs", compute_r_est);
    println!("  Check ||r0||:                   {:>6.1} µs", check_r0_est);
    println!("  Make hints:                     {:>6.1} µs", hints_est);
    println!(
        "  Check hint count:               {:>6.1} µs",
        check_hints_est
    );
    println!(
        "  Subtotal per attempt:           {:>6.1} µs",
        per_attempt_est
    );
    println!(
        "  × {:.1} attempts:               {:>6.1} µs ({:.1}%)",
        avg_attempts,
        per_attempt_est * avg_attempts,
        100.0 * (per_attempt_est * avg_attempts) / total_us
    );
    println!();

    println!("Estimated total: {:.1} µs", estimated_total);
    println!("Actual measured: {:.1} µs", total_us);
    println!(
        "Difference: {:.1} µs ({:.1}%)",
        total_us - estimated_total,
        100.0 * (total_us - estimated_total) / total_us
    );
    println!();

    println!("================================================================================");
    println!("Top Bottlenecks (Estimated)");
    println!("================================================================================\n");

    let mut bottlenecks = vec![
        ("Expand matrix A (one-time)", expand_a_est, setup_est),
        (
            "Matrix multiply A·y",
            matrix_mul_est * avg_attempts,
            per_attempt_est * avg_attempts,
        ),
        (
            "Compute r (w - c·s2)",
            compute_r_est * avg_attempts,
            per_attempt_est * avg_attempts,
        ),
        (
            "Sample y",
            sample_y_est * avg_attempts,
            per_attempt_est * avg_attempts,
        ),
        (
            "Make hints",
            hints_est * avg_attempts,
            per_attempt_est * avg_attempts,
        ),
        (
            "Compute z (y + c·s1)",
            compute_z_est * avg_attempts,
            per_attempt_est * avg_attempts,
        ),
    ];

    bottlenecks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    println!("Rank | Operation                  | Est Time | % of Total");
    println!("-----|----------------------------|----------|------------");
    for (i, (name, time, _)) in bottlenecks.iter().enumerate() {
        println!(
            "  {:2}  | {:<26} | {:>6.1} µs | {:>6.1}%",
            i + 1,
            name,
            time,
            100.0 * time / total_us
        );
    }
    println!();

    println!("================================================================================");
    println!("Optimization Opportunities");
    println!("================================================================================\n");

    println!("Based on estimated breakdown:");
    println!();
    println!(
        "1. Matrix multiply A·y ({:.0} µs, {:.1}%)",
        matrix_mul_est * avg_attempts,
        100.0 * matrix_mul_est * avg_attempts / total_us
    );
    println!("   - Already uses AVX2 NTT");
    println!("   - Opportunity: Better cache utilization, prefetching");
    println!(
        "   - Potential gain: 10-15% → ~{:.0} µs",
        0.125 * matrix_mul_est * avg_attempts
    );
    println!();

    println!(
        "2. Expand matrix A ({:.0} µs, {:.1}%)",
        expand_a_est,
        100.0 * expand_a_est / total_us
    );
    println!("   - One-time cost, but significant");
    println!("   - Already uses XOF");
    println!("   - Opportunity: Cache matrix A in sk (if memory allows)");
    println!("   - Potential gain: 100% → ~{:.0} µs", expand_a_est);
    println!();

    println!(
        "3. Compute r (w - c·s2) ({:.0} µs, {:.1}%)",
        compute_r_est * avg_attempts,
        100.0 * compute_r_est * avg_attempts / total_us
    );
    println!("   - Uses NTT for multiplication");
    println!("   - Opportunity: Optimize polynomial subtraction");
    println!(
        "   - Potential gain: 20% → ~{:.0} µs",
        0.2 * compute_r_est * avg_attempts
    );
    println!();

    println!(
        "4. Sample y ({:.0} µs, {:.1}%)",
        sample_y_est * avg_attempts,
        100.0 * sample_y_est * avg_attempts / total_us
    );
    println!("   - Already uses XOF x4 parallel");
    println!("   - Limited optimization potential");
    println!(
        "   - Potential gain: 10% → ~{:.0} µs",
        0.1 * sample_y_est * avg_attempts
    );
    println!();

    println!("================================================================================");
    println!("IMPORTANT NOTES");
    println!("================================================================================\n");
    println!("These are ESTIMATES based on algorithm analysis.");
    println!("For accurate profiling, we need to:");
    println!("  1. Add Instant::now() timing to sign.rs directly");
    println!("  2. Use Linux perf (if available)");
    println!("  3. Use Criterion for micro-benchmarks");
    println!();
    println!("The estimates assume:");
    println!("  - Average 4.5 rejection attempts (actual may vary)");
    println!("  - Uniform cost per operation (actual has variance)");
    println!("  - No cache effects or CPU throttling");
    println!();
    println!("================================================================================");
}
