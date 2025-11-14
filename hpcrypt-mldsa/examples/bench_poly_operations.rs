//! Benchmark: Polynomial Operations with Barrett Reduction
//!
//! Measures the cost of Barrett reduction in typical ML-DSA poly operations:
//! - poly.add() - used in signing
//! - poly.sub() - used in signing
//! - poly.mul_scalar() - less frequent
//!
//! Goal: Determine if Barrett+Shoup would provide meaningful speedup

use hpcrypt_mldsa::params::{MlDsa65, N};
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::DsaParams;
use std::time::Instant;

const Q: i32 = 8380417;

fn benchmark_poly_add(iterations: usize) -> f64 {
    // Create test polynomials
    let mut p1 = Poly::new();
    let mut p2 = Poly::new();

    for i in 0..N {
        p1.coeffs[i] = (i as i32 * 12345) % Q;
        p2.coeffs[i] = (i as i32 * 67890) % Q;
    }

    // Warmup
    for _ in 0..100 {
        let _ = p1.add(&p2);
    }

    // Accumulator to prevent optimization
    let mut acc: i64 = 0;

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let result = p1.add(&p2);
        acc = acc.wrapping_add(result.coeffs[0] as i64);
    }
    let elapsed = start.elapsed();

    // Use accumulator
    if acc == 0x1234567890ABCDEF_i64 {
        println!("Impossible: {}", acc);
    }

    elapsed.as_nanos() as f64 / iterations as f64
}

fn benchmark_poly_sub(iterations: usize) -> f64 {
    let mut p1 = Poly::new();
    let mut p2 = Poly::new();

    for i in 0..N {
        p1.coeffs[i] = (i as i32 * 12345) % Q;
        p2.coeffs[i] = (i as i32 * 67890) % Q;
    }

    let mut acc: i64 = 0;

    let start = Instant::now();
    for _ in 0..iterations {
        let result = p1.sub(&p2);
        acc = acc.wrapping_add(result.coeffs[0] as i64);
    }
    let elapsed = start.elapsed();

    if acc == 0x1234567890ABCDEF_i64 {
        println!("Impossible: {}", acc);
    }

    elapsed.as_nanos() as f64 / iterations as f64
}

fn benchmark_poly_reduce(iterations: usize) -> f64 {
    let mut p = Poly::new();

    for i in 0..N {
        p.coeffs[i] = (i as i32 * 12345) % Q;
    }

    let start = Instant::now();
    for _ in 0..iterations {
        p.reduce();
        // p is modified in-place, preventing optimization
    }
    let elapsed = start.elapsed();

    // Use p to prevent dead code elimination
    if p.coeffs[0] == -999 {
        println!("Impossible");
    }

    elapsed.as_nanos() as f64 / iterations as f64
}

fn count_operations_in_signing() {
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("Operations Count in ML-DSA-65 Signing");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    let k = MlDsa65::K;
    let l = MlDsa65::L;

    println!("Per signing attempt:");
    println!("  1. Compute w = A·y:");
    println!(
        "     - Matrix-vector multiply: {} × {} polynomial multiplications",
        k, l
    );
    println!("     - Accumulation: {} poly.add() calls", k * (l - 1));
    println!();
    println!("  2. Compute z = y + c·s1:");
    println!("     - {} poly.add() calls", l);
    println!();
    println!("  3. Compute w - c·s2:");
    println!("     - {} poly.sub() calls", k);
    println!();

    let adds_per_attempt = k * (l - 1) + l;
    let subs_per_attempt = k;

    println!("Total per attempt:");
    println!("  - poly.add(): {} calls", adds_per_attempt);
    println!("  - poly.sub(): {} calls", subs_per_attempt);
    println!(
        "  - Total Barrett reductions: {} × 256 = {} reductions",
        adds_per_attempt + subs_per_attempt,
        (adds_per_attempt + subs_per_attempt) * 256
    );
    println!();

    // Average attempts needed (rejection sampling)
    let avg_attempts = 4.5; // Approximate for ML-DSA-65

    println!("Expected per signature (avg {} attempts):", avg_attempts);
    println!(
        "  - poly.add(): {:.0} calls",
        adds_per_attempt as f64 * avg_attempts
    );
    println!(
        "  - poly.sub(): {:.0} calls",
        subs_per_attempt as f64 * avg_attempts
    );
    println!(
        "  - Total Barrett reductions: {:.0}",
        (adds_per_attempt + subs_per_attempt) as f64 * 256.0 * avg_attempts
    );
    println!();
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║         Polynomial Operations Benchmark - Barrett Reduction Impact          ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();

    count_operations_in_signing();

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("Performance Benchmarks (100,000 iterations)");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    let iterations = 100_000;

    let add_time = benchmark_poly_add(iterations);
    println!(
        "poly.add():    {:.2} ns/op  ({} barrett_reduce calls)",
        add_time, N
    );

    let sub_time = benchmark_poly_sub(iterations);
    println!(
        "poly.sub():    {:.2} ns/op  ({} barrett_reduce calls)",
        sub_time, N
    );

    let reduce_time = benchmark_poly_reduce(iterations);
    println!(
        "poly.reduce(): {:.2} ns/op  ({} barrett_reduce calls)",
        reduce_time, N
    );
    println!();

    let barrett_time_per_coeff = add_time / N as f64;
    println!(
        "Per-coefficient Barrett reduction: {:.3} ns",
        barrett_time_per_coeff
    );
    println!();

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("Impact Analysis");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    // ML-DSA-65 parameters
    let k = 6;
    let l = 5;
    let adds_per_attempt = k * (l - 1) + l;
    let subs_per_attempt = k;
    let total_ops_per_attempt = adds_per_attempt + subs_per_attempt;
    let avg_attempts = 4.5;

    // Calculate time spent in Barrett reductions during signing
    let barrett_ops_per_sig = total_ops_per_attempt as f64 * N as f64 * avg_attempts;
    let barrett_time_per_sig_ns = barrett_ops_per_sig * barrett_time_per_coeff;
    let barrett_time_per_sig_us = barrett_time_per_sig_ns / 1000.0;

    println!(
        "Barrett reductions per signature: {:.0}",
        barrett_ops_per_sig
    );
    println!(
        "Time in Barrett per signature: {:.2} µs",
        barrett_time_per_sig_us
    );
    println!();

    // Current signing performance (from our benchmarks)
    let current_sign_time_us = 550.0; // From Phase 4 + Shoup
    let barrett_percentage = (barrett_time_per_sig_us / current_sign_time_us) * 100.0;

    println!("Current signing time: {:.0} µs", current_sign_time_us);
    println!("Barrett percentage: {:.2}%", barrett_percentage);
    println!();

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("What if we applied Barrett+Shoup?");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    // From our earlier benchmark: Barrett+Shoup is 11.7% faster than standard Barrett
    let shoup_improvement = 0.117;
    let new_barrett_time = barrett_time_per_sig_us * (1.0 - shoup_improvement);
    let time_saved = barrett_time_per_sig_us - new_barrett_time;
    let overall_improvement = (time_saved / current_sign_time_us) * 100.0;

    println!(
        "Barrett+Shoup improvement: {:.1}% faster",
        shoup_improvement * 100.0
    );
    println!(
        "New Barrett time: {:.2} µs (was {:.2} µs)",
        new_barrett_time, barrett_time_per_sig_us
    );
    println!("Time saved: {:.2} µs", time_saved);
    println!("Overall ML-DSA improvement: {:.2}%", overall_improvement);
    println!();

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("Conclusion");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    if overall_improvement < 1.0 {
        println!(" NOT WORTH IT - Barrett+Shoup would improve overall performance by < 1%");
        println!();
        println!("Reasons:");
        println!(
            "  1. Barrett operations are only {:.1}% of signing time",
            barrett_percentage
        );
        println!(
            "  2. Even with 11.7% Barrett speedup → only {:.2}% overall gain",
            overall_improvement
        );
        println!("  3. Implementation complexity not justified");
        println!("  4. Memory overhead (3× larger tables) for minimal gain");
        println!();
        println!("Recommendation: Keep current Barrett implementation OK");
    } else if overall_improvement < 3.0 {
        println!(
            "  MARGINAL - Barrett+Shoup would provide {:.2}% overall improvement",
            overall_improvement
        );
        println!();
        println!("Consider trade-offs:");
        println!("  Pros: {:.2}% faster signing", overall_improvement);
        println!("  Cons: Implementation complexity, memory overhead, maintenance burden");
    } else {
        println!(
            " WORTH IT - Barrett+Shoup would provide {:.2}% overall improvement",
            overall_improvement
        );
        println!();
        println!("Implementation recommended if:");
        println!("  - Code complexity is acceptable");
        println!("  - Memory overhead is acceptable");
        println!("  - Maintenance burden is acceptable");
    }

    println!();
}
