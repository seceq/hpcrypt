//! Compare looped vs unrolled performance
//!
//! This benchmark measures the actual performance gain from loop unrolling
//! by comparing a looped implementation against the unrolled (macro-based) one.

use std::time::Instant;

const ITERATIONS: usize = 100_000_000;

// Looped version (what we would have without unrolling)
fn add_with_loop(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], bool) {
    let mut result = [0u64; 6];
    let mut carry = 0u64;

    for i in 0..6 {
        let (sum, c1) = a[i].overflowing_add(b[i]);
        let (sum, c2) = sum.overflowing_add(carry);
        result[i] = sum;
        carry = (c1 as u64) + (c2 as u64);
    }

    (result, carry != 0)
}

// Manually unrolled version (what we actually have)
fn add_unrolled(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], bool) {
    let mut limbs = [0u64; 6];

    // Limb 0
    let (sum0, c0_1) = a[0].overflowing_add(b[0]);
    limbs[0] = sum0;
    let carry0 = c0_1 as u64;

    // Limb 1
    let (sum1, c1_1) = a[1].overflowing_add(b[1]);
    let (sum1, c1_2) = sum1.overflowing_add(carry0);
    limbs[1] = sum1;
    let carry1 = (c1_1 as u64) + (c1_2 as u64);

    // Limb 2
    let (sum2, c2_1) = a[2].overflowing_add(b[2]);
    let (sum2, c2_2) = sum2.overflowing_add(carry1);
    limbs[2] = sum2;
    let carry2 = (c2_1 as u64) + (c2_2 as u64);

    // Limb 3
    let (sum3, c3_1) = a[3].overflowing_add(b[3]);
    let (sum3, c3_2) = sum3.overflowing_add(carry2);
    limbs[3] = sum3;
    let carry3 = (c3_1 as u64) + (c3_2 as u64);

    // Limb 4
    let (sum4, c4_1) = a[4].overflowing_add(b[4]);
    let (sum4, c4_2) = sum4.overflowing_add(carry3);
    limbs[4] = sum4;
    let carry4 = (c4_1 as u64) + (c4_2 as u64);

    // Limb 5
    let (sum5, c5_1) = a[5].overflowing_add(b[5]);
    let (sum5, c5_2) = sum5.overflowing_add(carry4);
    limbs[5] = sum5;
    let carry5 = (c5_1 as u64) + (c5_2 as u64);

    (limbs, carry5 != 0)
}

// Macro version (our new implementation)
macro_rules! unroll_add_local {
    ($result:expr, $a:expr, $b:expr, 6) => {{
        // Limb 0
        let (sum0, c0) = $a[0].overflowing_add($b[0]);
        $result[0] = sum0;
        let carry0 = c0 as u64;

        // Limb 1
        let (sum1, c1_1) = $a[1].overflowing_add($b[1]);
        let (sum1, c1_2) = sum1.overflowing_add(carry0);
        $result[1] = sum1;
        let carry1 = (c1_1 as u64) + (c1_2 as u64);

        // Limb 2
        let (sum2, c2_1) = $a[2].overflowing_add($b[2]);
        let (sum2, c2_2) = sum2.overflowing_add(carry1);
        $result[2] = sum2;
        let carry2 = (c2_1 as u64) + (c2_2 as u64);

        // Limb 3
        let (sum3, c3_1) = $a[3].overflowing_add($b[3]);
        let (sum3, c3_2) = sum3.overflowing_add(carry2);
        $result[3] = sum3;
        let carry3 = (c3_1 as u64) + (c3_2 as u64);

        // Limb 4
        let (sum4, c4_1) = $a[4].overflowing_add($b[4]);
        let (sum4, c4_2) = sum4.overflowing_add(carry3);
        $result[4] = sum4;
        let carry4 = (c4_1 as u64) + (c4_2 as u64);

        // Limb 5
        let (sum5, c5_1) = $a[5].overflowing_add($b[5]);
        let (sum5, c5_2) = sum5.overflowing_add(carry4);
        $result[5] = sum5;
        let final_carry = (c5_1 as u64) + (c5_2 as u64);

        final_carry != 0
    }};
}

fn add_macro(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], bool) {
    let mut result = [0u64; 6];
    let overflow = unroll_add_local!(result, a, b, 6);
    (result, overflow)
}

fn main() {
    println!("Loop Unrolling Performance Comparison");
    println!("Comparing: Looped vs Manually Unrolled vs Macro Unrolled");
    println!("Operations: {} iterations", ITERATIONS);
    println!("{}", "=".repeat(70));
    println!();

    let a = [1u64, 2, 3, 4, 5, 6];
    let b = [7u64, 8, 9, 10, 11, 12];

    // Warm up
    for _ in 0..10000 {
        let _ = add_with_loop(&a, &b);
        let _ = add_unrolled(&a, &b);
        let _ = add_macro(&a, &b);
    }

    // Benchmark looped version
    let start = Instant::now();
    let mut result_loop = ([0u64; 6], false);
    for _ in 0..ITERATIONS {
        result_loop = add_with_loop(&a, &b);
    }
    let duration_loop = start.elapsed();
    let ns_per_op_loop = duration_loop.as_nanos() as f64 / ITERATIONS as f64;

    // Benchmark manually unrolled version
    let start = Instant::now();
    let mut result_unrolled = ([0u64; 6], false);
    for _ in 0..ITERATIONS {
        result_unrolled = add_unrolled(&a, &b);
    }
    let duration_unrolled = start.elapsed();
    let ns_per_op_unrolled = duration_unrolled.as_nanos() as f64 / ITERATIONS as f64;

    // Benchmark macro version
    let start = Instant::now();
    let mut result_macro = ([0u64; 6], false);
    for _ in 0..ITERATIONS {
        result_macro = add_macro(&a, &b);
    }
    let duration_macro = start.elapsed();
    let ns_per_op_macro = duration_macro.as_nanos() as f64 / ITERATIONS as f64;

    // Verify all produce same results
    assert_eq!(
        result_loop.0, result_unrolled.0,
        "Loop and unrolled should match"
    );
    assert_eq!(result_loop.0, result_macro.0, "Loop and macro should match");
    assert_eq!(
        result_loop.1, result_unrolled.1,
        "Overflow flags should match"
    );
    assert_eq!(result_loop.1, result_macro.1, "Overflow flags should match");

    // Display results
    println!("Results (P-384 style 6-limb addition):");
    println!("{}", "-".repeat(70));
    println!();
    println!(
        "  Looped version:          {:.2} ns/op  ({:.2} M ops/sec)",
        ns_per_op_loop,
        1000.0 / ns_per_op_loop
    );
    println!(
        "  Manually unrolled:       {:.2} ns/op  ({:.2} M ops/sec)",
        ns_per_op_unrolled,
        1000.0 / ns_per_op_unrolled
    );
    println!(
        "  Macro unrolled:          {:.2} ns/op  ({:.2} M ops/sec)",
        ns_per_op_macro,
        1000.0 / ns_per_op_macro
    );
    println!();
    println!("{}", "-".repeat(70));

    // Calculate speedups
    let speedup_manual = ((ns_per_op_loop - ns_per_op_unrolled) / ns_per_op_loop) * 100.0;
    let speedup_macro = ((ns_per_op_loop - ns_per_op_macro) / ns_per_op_loop) * 100.0;
    let macro_vs_manual = ((ns_per_op_macro - ns_per_op_unrolled) / ns_per_op_unrolled) * 100.0;

    println!("Performance Analysis:");
    println!();
    println!(
        "  Manual unrolling vs Loop:     {:+.1}% faster",
        speedup_manual
    );
    println!(
        "  Macro unrolling vs Loop:      {:+.1}% faster",
        speedup_macro
    );
    println!(
        "  Macro vs Manual unrolling:    {:+.1}% difference",
        macro_vs_manual
    );
    println!();

    if speedup_manual > 5.0 {
        println!(
            " Loop unrolling provides significant benefit ({:.1}% speedup)",
            speedup_manual
        );
    } else if speedup_manual > 0.0 {
        println!(
            "  Loop unrolling provides modest benefit ({:.1}% speedup)",
            speedup_manual
        );
    } else {
        println!(" Loop unrolling provides no benefit (compiler optimized loop)");
    }

    if macro_vs_manual.abs() < 2.0 {
        println!(" Macro and manual unrolling have identical performance");
    } else {
        println!("  Macro differs from manual by {:.1}%", macro_vs_manual);
    }

    // Prevent optimizing away
    std::hint::black_box(result_loop);
    std::hint::black_box(result_unrolled);
    std::hint::black_box(result_macro);
}
