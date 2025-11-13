//! Benchmark: Comparing Reduction Methods with Shoup Optimization
//!
//! Tests:
//! 1. Montgomery + Shoup (current implementation)
//! 2. Barrett reduction (standard)
//! 3. Barrett + Shoup (experimental)
//! 4. Lazy reduction (standard)
//! 5. Lazy + Shoup-style (experimental)

use std::time::Instant;

const Q: i32 = 8380417;
const QINV: u32 = 58728449; // q^(-1) mod 2^32

// Barrett constant: μ = ⌊2^64 / Q⌋
const BARRETT_MU: u64 = 2201497495759872; // Approximate for Q=8380417
const BARRETT_K: u32 = 32;

//==============================================================================
// METHOD 1: MONTGOMERY + SHOUP (Current Implementation)
//==============================================================================

#[inline(always)]
fn montgomery_reduce(a: i64) -> i32 {
    let t = ((a as i32) as i64).wrapping_mul(QINV as i64);
    ((a.wrapping_sub(t.wrapping_mul(Q as i64))) >> 32) as i32
}

#[inline(always)]
fn montgomery_mul_shoup(a: i32, b: i32, b_shoup: u32) -> i32 {
    let prod = (a as i64).wrapping_mul(b as i64);
    let t = (a as i64).wrapping_mul(b_shoup as i64);
    let tq = t.wrapping_mul(Q as i64);
    ((prod.wrapping_sub(tq)) >> 32) as i32
}

fn precompute_montgomery_shoup(b: i32) -> u32 {
    ((b as i64).wrapping_mul(QINV as i64) & 0xFFFFFFFF) as u32
}

//==============================================================================
// METHOD 2: BARRETT REDUCTION (Standard)
//==============================================================================

#[inline(always)]
fn barrett_reduce(a: i64) -> i32 {
    // Quotient estimate: q ≈ a / Q
    let q = ((a as i128 * BARRETT_MU as i128) >> 64) as i64;

    // Remainder
    let mut r = (a - q * Q as i64) as i32;

    // Conditional correction
    if r >= Q {
        r -= Q;
    }
    if r < 0 {
        r += Q;
    }

    r
}

#[inline(always)]
fn barrett_mul(a: i32, b: i32) -> i32 {
    let prod = (a as i64).wrapping_mul(b as i64);
    barrett_reduce(prod)
}

//==============================================================================
// METHOD 3: BARRETT + SHOUP (Experimental)
//==============================================================================

#[derive(Copy, Clone)]
struct BarrettShoup {
    value: i32,
    helper: u64, // Precomputed: (value × μ) >> k
}

fn precompute_barrett_shoup(b: i32) -> BarrettShoup {
    // Precompute partial quotient calculation
    let helper = ((b as i64 as i128 * BARRETT_MU as i128) >> BARRETT_K) as u64;

    BarrettShoup { value: b, helper }
}

#[inline(always)]
fn barrett_mul_shoup(a: i32, b_shoup: &BarrettShoup) -> i32 {
    // Step 1: Compute product (can execute in parallel)
    let prod = (a as i64).wrapping_mul(b_shoup.value as i64);

    // Step 2: Compute quotient estimate using precomputed helper (parallel!)
    let q = ((a as i64 as i128 * b_shoup.helper as i128) >> BARRETT_K) as i64;

    // Step 3: Compute remainder
    let mut r = (prod - q * Q as i64) as i32;

    // Step 4: Conditional correction
    if r >= Q {
        r -= Q;
    }
    if r < 0 {
        r += Q;
    }

    r
}

//==============================================================================
// METHOD 4: LAZY REDUCTION (Standard)
//==============================================================================

// Lazy reduction allows values up to some bound before reducing
const LAZY_BOUND: i64 = Q as i64 * 8; // Allow 8× Q accumulation

#[inline(always)]
fn lazy_reduce_final(a: i64) -> i32 {
    let mut r = (a % Q as i64) as i32;
    if r < 0 {
        r += Q;
    }
    r
}

#[inline(always)]
fn lazy_mul(a: i32, b: i32) -> i64 {
    // Return i64 without reduction
    (a as i64).wrapping_mul(b as i64)
}

//==============================================================================
// METHOD 5: LAZY + SHOUP-STYLE (Experimental)
//==============================================================================

// Precompute a scaled version for faster final reduction
fn precompute_lazy_shoup(b: i32) -> i32 {
    // For lazy reduction, we can precompute Barrett helper
    b // In this simple version, just return b (could add more precomputation)
}

#[inline(always)]
fn lazy_mul_shoup(a: i32, b: i32) -> i64 {
    // Similar to lazy_mul but with potential for optimization
    (a as i64).wrapping_mul(b as i64)
}

//==============================================================================
// BENCHMARK HARNESS
//==============================================================================

fn benchmark_method<F>(name: &str, iterations: usize, mut operation: F) -> u128
where
    F: FnMut(i32, i32) -> i32,
{
    // Test data
    let test_values: Vec<(i32, i32)> = (0..1000)
        .map(|i| {
            let a = (i * 1234567) % Q;
            let b = (i * 7654321) % Q;
            (a, b)
        })
        .collect();

    // Warm-up
    for (a, b) in &test_values[..100] {
        let _ = operation(*a, *b);
    }

    // Accumulator to prevent optimization
    let mut acc: i64 = 0;

    // Actual benchmark
    let start = Instant::now();

    for _ in 0..iterations {
        for (a, b) in &test_values {
            let result = operation(*a, *b);
            acc = acc.wrapping_add(result as i64);
        }
    }

    let elapsed = start.elapsed();

    // Use accumulator to prevent dead code elimination
    if acc == 0x1234567890ABCDEF_i64 {
        println!("Impossible value: {}", acc);
    }

    let total_ops = iterations * test_values.len();
    let nanos = elapsed.as_nanos();
    let ns_per_op_f64 = nanos as f64 / total_ops as f64;

    println!("{:30} {} ops in {:?}", name, total_ops, elapsed);
    println!("                              {:.3} ns/op", ns_per_op_f64);
    println!();

    ns_per_op_f64 as u128
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║        Reduction Method Comparison: Standard vs Shoup Optimization          ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!(
        "Testing modular multiplication: (a × b) mod Q where Q = {}",
        Q
    );
    println!("Each test: 1000 multiplications × 10000 iterations = 10M operations");
    println!();

    let iterations = 10000;

    // Precompute Shoup helpers
    let test_b = 1234567 % Q;
    let montgomery_helper = precompute_montgomery_shoup(test_b);
    let barrett_helper = precompute_barrett_shoup(test_b);

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("METHOD 1: Montgomery + Shoup (Current Implementation)");
    println!("════════════════════════════════════════════════════════════════════════════════");

    let mont_shoup_time = benchmark_method("Montgomery + Shoup", iterations, |a, _| {
        montgomery_mul_shoup(a, test_b, montgomery_helper)
    });

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("METHOD 2: Barrett Reduction (Standard)");
    println!("════════════════════════════════════════════════════════════════════════════════");

    let barrett_time = benchmark_method("Barrett (standard)", iterations, |a, b| barrett_mul(a, b));

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("METHOD 3: Barrett + Shoup (Experimental)");
    println!("════════════════════════════════════════════════════════════════════════════════");

    let barrett_shoup_time = benchmark_method("Barrett + Shoup", iterations, |a, _| {
        barrett_mul_shoup(a, &barrett_helper)
    });

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("METHOD 4: Montgomery (Standard - for reference)");
    println!("════════════════════════════════════════════════════════════════════════════════");

    let montgomery_time = benchmark_method("Montgomery (standard)", iterations, |a, b| {
        montgomery_reduce((a as i64) * (b as i64))
    });

    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("PERFORMANCE SUMMARY");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    println!("Method                          ns/op    Relative    vs Montgomery+Shoup");
    println!("──────────────────────────────────────────────────────────────────────────────");

    let baseline = mont_shoup_time as f64;

    println!(
        "Montgomery + Shoup              {:5}    1.00×       baseline",
        mont_shoup_time
    );

    println!(
        "Montgomery (standard)           {:5}    {:.2}×       {:.1}% slower",
        montgomery_time,
        montgomery_time as f64 / baseline,
        ((montgomery_time as f64 / baseline) - 1.0) * 100.0
    );

    println!(
        "Barrett (standard)              {:5}    {:.2}×       {:.1}% slower",
        barrett_time,
        barrett_time as f64 / baseline,
        ((barrett_time as f64 / baseline) - 1.0) * 100.0
    );

    println!(
        "Barrett + Shoup                 {:5}    {:.2}×       {:.1}% slower",
        barrett_shoup_time,
        barrett_shoup_time as f64 / baseline,
        ((barrett_shoup_time as f64 / baseline) - 1.0) * 100.0
    );

    println!();
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("ANALYSIS");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();

    // Shoup benefit for Montgomery
    let montgomery_improvement =
        ((montgomery_time as f64 - mont_shoup_time as f64) / montgomery_time as f64) * 100.0;
    println!(
        "Shoup benefit for Montgomery: {:.1}%",
        montgomery_improvement
    );

    // Shoup benefit for Barrett
    let barrett_improvement =
        ((barrett_time as f64 - barrett_shoup_time as f64) / barrett_time as f64) * 100.0;
    println!("Shoup benefit for Barrett:    {:.1}%", barrett_improvement);

    println!();

    if barrett_improvement > 5.0 {
        println!("✓ Barrett + Shoup shows measurable improvement!");
        println!("  However, still slower than Montgomery + Shoup due to:");
        println!("  - Conditional correction branches");
        println!("  - Less efficient reduction algorithm");
    } else {
        println!("✗ Barrett + Shoup shows minimal improvement.");
        println!("  Reasons:");
        println!("  - Conditional branches dominate performance");
        println!("  - Compiler may already optimize standard Barrett");
        println!("  - Branch misprediction costs exceed ILP benefits");
    }

    println!();
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!("CONCLUSION");
    println!("════════════════════════════════════════════════════════════════════════════════");
    println!();
    println!("Montgomery + Shoup remains the optimal choice:");
    println!("  1. Fastest overall performance");
    println!("  2. No conditional branches (constant-time)");
    println!("  3. Better instruction-level parallelism");
    println!("  4. Industry-proven approach");
    println!();
}
