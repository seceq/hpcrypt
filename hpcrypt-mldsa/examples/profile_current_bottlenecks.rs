//! Current Bottleneck Analysis
//!
//! Re-profile ML-DSA after all optimizations (Phases 1-4 + Quick Wins + Sampling)
//! to identify actual current bottlenecks.

use mldsa::MlDsa65;
use mldsa::keygen::keygen;
use mldsa::sign;
use mldsa::verify;
use std::time::Instant;

fn main() {
    println!("================================================================================");
    println!("ML-DSA-65 Current Bottleneck Analysis (After All Optimizations)");
    println!("================================================================================\n");

    const ITERATIONS: usize = 1000;

    // Generate keypair
    let (pk, sk) = keygen::<MlDsa65>();
    let message = b"Profiling message for bottleneck analysis";

    // Warm up
    println!("Warming up...\n");
    for _ in 0..100 {
        let _ = sign::sign::<MlDsa65>(&sk, message);
    }

    // ========================================
    // SIGNING BREAKDOWN
    // ========================================
    println!("=== SIGNING PERFORMANCE ===\n");

    // Overall signing
    let start = Instant::now();
    let mut successful_signs = 0;
    for _ in 0..ITERATIONS {
        if sign::sign::<MlDsa65>(&sk, message).is_some() {
            successful_signs += 1;
        }
    }
    let total_sign_time = start.elapsed();
    let avg_sign_us = total_sign_time.as_micros() / ITERATIONS as u128;

    println!("Overall Signing:");
    println!("  Average: {} µs", avg_sign_us);
    println!("  Throughput: {:.1} signs/sec", 1_000_000.0 / avg_sign_us as f64);
    println!("  Total time: {:?}\n", total_sign_time);

    // ========================================
    // VERIFICATION BREAKDOWN
    // ========================================
    println!("=== VERIFICATION PERFORMANCE ===\n");

    let sig = sign::sign::<MlDsa65>(&sk, message).expect("Failed to sign");

    let start = Instant::now();
    let mut successful_verifies = 0;
    for _ in 0..ITERATIONS {
        if verify::verify::<MlDsa65>(&pk, message, &sig) {
            successful_verifies += 1;
        }
    }
    let total_verify_time = start.elapsed();
    let avg_verify_us = total_verify_time.as_micros() / ITERATIONS as u128;

    println!("Overall Verification:");
    println!("  Average: {} µs", avg_verify_us);
    println!("  Throughput: {:.1} verifies/sec", 1_000_000.0 / avg_verify_us as f64);
    println!("  Total time: {:?}\n", total_verify_time);

    // ========================================
    // KEY GENERATION BREAKDOWN
    // ========================================
    println!("=== KEY GENERATION PERFORMANCE ===\n");

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = keygen::<MlDsa65>();
    }
    let total_keygen_time = start.elapsed();
    let avg_keygen_us = total_keygen_time.as_micros() / ITERATIONS as u128;

    println!("Overall KeyGen:");
    println!("  Average: {} µs", avg_keygen_us);
    println!("  Throughput: {:.1} keygens/sec", 1_000_000.0 / avg_keygen_us as f64);
    println!("  Total time: {:?}\n", total_keygen_time);

    // ========================================
    // SUMMARY TABLE
    // ========================================
    println!("================================================================================");
    println!("=== PERFORMANCE SUMMARY ===");
    println!("================================================================================\n");

    println!("┌─────────────┬─────────────┬──────────────────┬─────────────────┐");
    println!("│ Operation   │ Time (µs)   │ Throughput/sec   │ % of Total      │");
    println!("├─────────────┼─────────────┼──────────────────┼─────────────────┤");
    println!("│ KeyGen      │ {:>11} │ {:>16.1} │ {:>15.1}% │",
        avg_keygen_us,
        1_000_000.0 / avg_keygen_us as f64,
        100.0 * avg_keygen_us as f64 / (avg_keygen_us + avg_sign_us + avg_verify_us) as f64
    );
    println!("│ Sign        │ {:>11} │ {:>16.1} │ {:>15.1}% │",
        avg_sign_us,
        1_000_000.0 / avg_sign_us as f64,
        100.0 * avg_sign_us as f64 / (avg_keygen_us + avg_sign_us + avg_verify_us) as f64
    );
    println!("│ Verify      │ {:>11} │ {:>16.1} │ {:>15.1}% │",
        avg_verify_us,
        1_000_000.0 / avg_verify_us as f64,
        100.0 * avg_verify_us as f64 / (avg_keygen_us + avg_sign_us + avg_verify_us) as f64
    );
    println!("├─────────────┼─────────────┼──────────────────┼─────────────────┤");
    println!("│ TOTAL       │ {:>11} │                  │ {:>15}  │",
        avg_keygen_us + avg_sign_us + avg_verify_us,
        "100.0%"
    );
    println!("└─────────────┴─────────────┴──────────────────┴─────────────────┘\n");

    // ========================================
    // HISTORICAL COMPARISON
    // ========================================
    println!("================================================================================");
    println!("=== OPTIMIZATION PROGRESS ===");
    println!("================================================================================\n");

    let baseline_us = 938;
    let improvement_pct = 100.0 * (baseline_us as f64 - avg_sign_us as f64) / baseline_us as f64;

    println!("Baseline (unoptimized):     {} µs", baseline_us);
    println!("After Phase 1 (NTT):        ~700 µs  (-25%)");
    println!("After Phase 2 (NTT full):   ~600 µs  (-36%)");
    println!("After Phase 3 (PGO):        ~580 µs  (-38%)");
    println!("After Phase 4 (XOF x4):     ~440 µs  (-53%)");
    println!("After Quick Wins:           ~440 µs  (-53%)");
    println!("After Sampling AVX2:        {} µs  ({:.1}%)", avg_sign_us, -improvement_pct);
    println!();
    println!("Total improvement: {:.1}% ({} → {} µs)", improvement_pct, baseline_us, avg_sign_us);
    println!();

    // ========================================
    // COMPARISON TO REFERENCE
    // ========================================
    println!("================================================================================");
    println!("=== COMPARISON TO REFERENCE IMPLEMENTATIONS ===");
    println!("================================================================================\n");

    let reference_c_us = 2100;
    let optimized_ref_us = 420;
    let hand_asm_us = 380;

    println!("Reference C implementation:       ~{} µs", reference_c_us);
    println!("Optimized C reference:            ~{} µs", optimized_ref_us);
    println!("Hand-optimized assembly:          ~{} µs", hand_asm_us);
    println!("Our Rust implementation:          {} µs", avg_sign_us);
    println!();

    let gap_to_optimized = ((avg_sign_us as f64 / optimized_ref_us as f64) - 1.0) * 100.0;
    let gap_to_asm = ((avg_sign_us as f64 / hand_asm_us as f64) - 1.0) * 100.0;

    println!("Gap to optimized C:    {:.1}% slower", gap_to_optimized);
    println!("Gap to hand-opt ASM:   {:.1}% slower", gap_to_asm);
    println!();

    // ========================================
    // NEXT OPTIMIZATION TARGETS
    // ========================================
    println!("================================================================================");
    println!("=== RECOMMENDED NEXT STEPS ===");
    println!("================================================================================\n");

    println!("To close the {:.1}% gap to hand-optimized assembly ({} µs):", gap_to_asm, hand_asm_us);
    println!();
    println!("Need to save: {} µs", avg_sign_us - hand_asm_us as u128);
    println!();
    println!("RECOMMENDATION: Re-profile with Linux perf to identify current bottlenecks.");
    println!();
    println!("Suggested profiling commands:");
    println!("  1. perf record --call-graph dwarf cargo run --release --example bench_sampling_performance");
    println!("  2. perf report --no-children");
    println!("  3. flamegraph generation for visualization");
    println!();
    println!("Expected current bottlenecks (need profiling to confirm):");
    println!("  1. Remaining polynomial operations (add/sub/norms) - 10-15%");
    println!("  2. Hint generation/checking - 8-10%");
    println!("  3. Memory/cache inefficiencies - 5-10%");
    println!("  4. Rejection sampling retry overhead - 5-8%");
    println!();
    println!("DO NOT optimize without fresh profiling data!");
    println!();

    println!("================================================================================");
}
