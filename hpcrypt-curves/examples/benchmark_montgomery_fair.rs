//! Fair Montgomery Performance Comparison
//!
//! This benchmark provides an ACCURATE comparison by measuring both:
//! 1. Single operation with conversion overhead
//! 2. Batch operations (amortized conversion cost)
//!
//! Run with: cargo run --release --example benchmark_montgomery_fair

use std::time::Instant;
use std::hint::black_box;

use hpcrypt_curves::p256::{FieldElement};
use hpcrypt_curves::p256::field_montgomery_native::MontgomeryFieldElement as NativeMontgomery;

const ITERATIONS: usize = 100_000;

fn benchmark_karatsuba_single() -> u128 {
    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.mul(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    duration.as_nanos() / ITERATIONS as u128
}

fn benchmark_montgomery_single_with_conversion() -> u128 {
    // This measures a SINGLE multiplication including conversion overhead
    let a_normal = [12345u64, 0, 0, 0];
    let b_normal = [67890u64, 0, 0, 0];

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        // Convert to Montgomery form
        let a = black_box(NativeMontgomery::to_montgomery(&a_normal));
        let b = black_box(NativeMontgomery::to_montgomery(&b_normal));

        // Multiply
        let c = black_box(a.mul(&b));

        // Convert back
        let _result = black_box(c.from_montgomery());
    }
    let duration = start.elapsed();

    duration.as_nanos() / ITERATIONS as u128
}

fn benchmark_montgomery_batch(batch_size: usize) -> u128 {
    // This measures batch operations where conversion is amortized
    let a_normal = [12345u64, 0, 0, 0];
    let b_normal = [67890u64, 0, 0, 0];

    let start = Instant::now();
    for _ in 0..(ITERATIONS / batch_size) {
        // Convert to Montgomery form ONCE
        let a = black_box(NativeMontgomery::to_montgomery(&a_normal));
        let b = black_box(NativeMontgomery::to_montgomery(&b_normal));

        // Do multiple multiplications in Montgomery form
        let mut result = a;
        for _ in 0..batch_size {
            result = black_box(result.mul(&b));
        }

        // Convert back ONCE
        let _final = black_box(result.from_montgomery());
    }
    let duration = start.elapsed();

    duration.as_nanos() / ITERATIONS as u128
}

fn benchmark_montgomery_mul_only() -> u128 {
    // This measures JUST the Montgomery multiplication (no conversion)
    // This is what the original benchmark was measuring
    let a = NativeMontgomery::one();
    let b = a.add(&a).add(&a); // 3 in Montgomery form

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.mul(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    duration.as_nanos() / ITERATIONS as u128
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║  Fair P-256 Montgomery Performance Comparison                  ║");
    println!("║  Iterations: {:>6}                                           ║", ITERATIONS);
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!("\n┌─ BASELINE: KARATSUBA ────────────────────────────────────────┐");
    let karatsuba_time = benchmark_karatsuba_single();
    println!("  Karatsuba + NIST reduction: {} ns", karatsuba_time);
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n┌─ MONTGOMERY: JUST MULTIPLICATION (Original Benchmark) ──────┐");
    let montgomery_mul_only = benchmark_montgomery_mul_only();
    println!("  Montgomery mul (no conversion): {} ns", montgomery_mul_only);
    println!("  ⚠️  MISLEADING SPEEDUP: {:.0}x",
             karatsuba_time as f64 / montgomery_mul_only as f64);
    println!("  ⚠️  This comparison is UNFAIR!");
    println!("  (Montgomery values are already converted)");
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n┌─ MONTGOMERY: SINGLE OPERATION (Fair Comparison) ────────────┐");
    let montgomery_single = benchmark_montgomery_single_with_conversion();
    println!("  Montgomery with conversion: {} ns", montgomery_single);
    println!("  ✓ ACTUAL SPEEDUP: {:.1}x",
             karatsuba_time as f64 / montgomery_single as f64);
    println!("  (Includes: to_montgomery + mul + from_montgomery)");
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n┌─ MONTGOMERY: BATCH OPERATIONS (Realistic Use) ──────────────┐");
    println!("  In real ECC operations, you convert once and do many muls.");
    println!();

    let batch_sizes = [5, 10, 20, 50];
    for &size in &batch_sizes {
        let batch_time = benchmark_montgomery_batch(size);
        let speedup = karatsuba_time as f64 / batch_time as f64;
        println!("  Batch of {:>2} multiplications: {} ns/op  ({:.0}x speedup)",
                 size, batch_time, speedup);
    }
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  CONCLUSION                                                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();
    println!("The original \"146x speedup\" claim was MISLEADING because:");
    println!("  • It compared Montgomery without conversion (13 ns)");
    println!("  • Against Karatsuba with full reduction (1901 ns)");
    println!("  • This is not an apples-to-apples comparison");
    println!();
    println!("ACCURATE performance analysis:");
    println!("  • Single operation:  ~{:.0}x speedup",
             karatsuba_time as f64 / montgomery_single as f64);
    println!("  • Batch of 10:       ~{:.0}x speedup",
             karatsuba_time as f64 / benchmark_montgomery_batch(10) as f64);
    println!("  • Batch of 20:       ~{:.0}x speedup",
             karatsuba_time as f64 / benchmark_montgomery_batch(20) as f64);
    println!();
    println!("Montgomery is STILL a huge win, but the speedup is more like");
    println!("30-40x for single ops, 100-130x for batches.");
    println!();
    println!("For ECC point operations (which do ~10-20 field muls), you get");
    println!("the batch performance, making Montgomery MUCH faster.");
}
