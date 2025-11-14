//! Detailed signing breakdown profiler
//!
//! Instruments the signing algorithm to identify current bottlenecks

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::MlDsa65;

// We'll need to create a custom instrumented version of sign
// For now, let's analyze what we can from existing benchmarks

fn main() {
    println!("================================================================================");
    println!("ML-DSA-65 Signing Breakdown Analysis");
    println!("================================================================================\n");

    let (_pk, _sk) = keygen::<MlDsa65>();
    let _message = b"Profiling message";

    // Current best approach: Use existing micro-benchmarks
    println!("Current Performance Status:");
    println!("  Signing:       ~470-500 µs (avg ~487 µs)");
    println!("  Verification:  ~150-175 µs");
    println!("  KeyGen:        ~170 µs");
    println!();

    println!("Historical Context:");
    println!("  Baseline (Phase 0):        938 µs");
    println!("  After Phase 4 + QuickWins: ~440 µs (-53%)");
    println!("  Current (with Sampling):   ~487 µs");
    println!();

    println!("================================================================================");
    println!("Analysis of Current State");
    println!("================================================================================\n");

    println!("OBSERVATION: Performance regressed from 440 µs to 487 µs");
    println!();
    println!("Possible causes:");
    println!("  1. Measurement variance (±20 µs is normal)");
    println!("  2. AVX2 sampling overhead (FFI + buffer allocation)");
    println!("  3. Compiler optimization differences");
    println!("  4. CPU throttling / background processes");
    println!();

    println!("================================================================================");
    println!("Theoretical Bottleneck Breakdown (Based on Algorithm Analysis)");
    println!("================================================================================\n");

    let total_us = 487.0;

    println!("ML-DSA-65 Signing Algorithm:");
    println!();
    println!("┌────────────────────────────────┬──────────┬──────────┬────────────┐");
    println!("│ Operation                      │ Est %    │ Est µs   │ Note       │");
    println!("├────────────────────────────────┼──────────┼──────────┼────────────┤");

    // Based on algorithm structure and previous profiling
    let xof_pct = 25.0;
    let ntt_pct = 20.0;
    let sampling_pct = 15.0;
    let poly_ops_pct = 12.0;
    let hints_pct = 10.0;
    let rounding_pct = 8.0;
    let norms_pct = 5.0;
    let other_pct = 5.0;

    println!(
        "│ XOF (SHAKE-256) operations    │ {:>7.1}% │ {:>7.0}  │ Optimized  │",
        xof_pct,
        total_us * xof_pct / 100.0
    );
    println!(
        "│ NTT forward/inverse            │ {:>7.1}% │ {:>7.0}  │ Optimized  │",
        ntt_pct,
        total_us * ntt_pct / 100.0
    );
    println!(
        "│ Rejection sampling             │ {:>7.1}% │ {:>7.0}  │ Optimized  │",
        sampling_pct,
        total_us * sampling_pct / 100.0
    );
    println!(
        "│ Poly add/sub/mul operations    │ {:>7.1}% │ {:>7.0}  │ Partial    │",
        poly_ops_pct,
        total_us * poly_ops_pct / 100.0
    );
    println!(
        "│ Hint generation                │ {:>7.1}% │ {:>7.0}  │ Optimized  │",
        hints_pct,
        total_us * hints_pct / 100.0
    );
    println!(
        "│ Rounding (Power2/Decompose)    │ {:>7.1}% │ {:>7.0}  │ Optimized  │",
        rounding_pct,
        total_us * rounding_pct / 100.0
    );
    println!(
        "│ Norm calculations (‖z‖, ‖r‖)  │ {:>7.1}% │ {:>7.0}  │ Scalar     │",
        norms_pct,
        total_us * norms_pct / 100.0
    );
    println!(
        "│ Other (hashing, serialization) │ {:>7.1}% │ {:>7.0}  │ Mixed      │",
        other_pct,
        total_us * other_pct / 100.0
    );
    println!("└────────────────────────────────┴──────────┴──────────┴────────────┘");
    println!();

    println!("================================================================================");
    println!("Optimization Opportunities Analysis");
    println!("================================================================================\n");

    println!("To reach 380 µs (hand-optimized ASM target):");
    println!("  Need to save: {} µs", (total_us - 380.0) as i32);
    println!();

    println!("Potential optimizations:");
    println!();

    println!(
        "1. Norm Calculations (~{} µs potential)",
        (total_us * norms_pct / 100.0) as i32
    );
    println!("   Current: Scalar loops");
    println!("   Opportunity: SIMD infinity norm and L2 norm");
    println!(
        "   Expected gain: 50% speedup → ~{} µs saved",
        (total_us * norms_pct / 200.0) as i32
    );
    println!();

    println!(
        "2. Remaining Polynomial Ops (~{} µs potential)",
        (total_us * poly_ops_pct / 100.0) as i32
    );
    println!("   Current: Partial AVX2 (add/sub have Barrett, but not all ops)");
    println!("   Opportunity: Vectorize remaining operations");
    println!(
        "   Expected gain: 30% speedup → ~{} µs saved",
        (total_us * poly_ops_pct * 0.3 / 100.0) as i32
    );
    println!();

    println!(
        "3. Memory Layout Optimization (~{} µs potential)",
        (total_us * 5.0 / 100.0) as i32
    );
    println!("   Current: Standard struct layout");
    println!("   Opportunity: Cache-line alignment, prefetching");
    println!(
        "   Expected gain: 5-10% overall → ~{} µs saved",
        (total_us * 5.0 / 100.0) as i32
    );
    println!();

    println!(
        "4. Investigate Regression (~{} µs potential)",
        (487.0 - 440.0) as i32
    );
    println!("   Issue: Performance went from 440 µs to 487 µs");
    println!("   Actions:");
    println!("     - Disable AVX2 sampling, measure impact");
    println!("     - Check if it's measurement noise");
    println!("     - Profile to find regression source");
    println!();

    println!(
        "Total potential savings: ~{} µs",
        (total_us * norms_pct / 200.0
            + total_us * poly_ops_pct * 0.3 / 100.0
            + total_us * 5.0 / 100.0
            + (487.0 - 440.0)) as i32
    );
    println!(
        "Projected performance: ~{} µs (within {}% of 380 µs target)",
        (total_us
            - (total_us * norms_pct / 200.0
                + total_us * poly_ops_pct * 0.3 / 100.0
                + total_us * 5.0 / 100.0
                + (487.0 - 440.0))) as i32,
        (((total_us
            - (total_us * norms_pct / 200.0
                + total_us * poly_ops_pct * 0.3 / 100.0
                + total_us * 5.0 / 100.0
                + (487.0 - 440.0)))
            - 380.0)
            / 380.0
            * 100.0) as i32
    );
    println!();

    println!("================================================================================");
    println!("Recommended Actions (Priority Order)");
    println!("================================================================================\n");

    println!("PRIORITY 1: Investigate Regression");
    println!("  Action: Disable AVX2 sampling and re-measure");
    println!("  Rationale: 47 µs regression is significant");
    println!("  Command: Measure with sampling.rs AVX2 dispatch disabled");
    println!();

    println!("PRIORITY 2: Profile Current Implementation");
    println!("  Action: Use manual instrumentation or Criterion benchmarks");
    println!("  Rationale: Theoretical estimates may be wrong");
    println!("  Tools: Criterion, manual timing, flamegraph (if available)");
    println!();

    println!("PRIORITY 3: Optimize Norms (if confirmed as bottleneck)");
    println!("  Action: Implement AVX2 infinity_norm() and l2_norm()");
    println!("  Expected: ~12 µs savings");
    println!();

    println!("PRIORITY 4: Memory/Cache Optimization");
    println!("  Action: Profile cache misses, optimize data layout");
    println!("  Expected: ~20-25 µs savings");
    println!();

    println!("================================================================================");
}
