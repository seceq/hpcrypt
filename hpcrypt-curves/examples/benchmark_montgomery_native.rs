//! Comprehensive Montgomery Performance Comparison
//!
//! Compares three implementations:
//! 1. Current Karatsuba + NIST reduction (baseline)
//! 2. fiat-crypto Montgomery (formally verified)
//! 3. Native CIOS Montgomery (hand-optimized)
//!
//! Run with: cargo run --release --example benchmark_montgomery_native

use std::time::Instant;
use std::hint::black_box;

use hpcrypt_curves::p256::{FieldElement, MontgomeryFieldElement};
use hpcrypt_curves::p256::field_montgomery_native::MontgomeryFieldElement as NativeMontgomery;

const ITERATIONS: usize = 100_000;

fn benchmark_karatsuba_multiplication() {
    println!("\n=== Karatsuba + NIST Reduction (Current Baseline) ===");

    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.mul(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per multiplication: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_fiat_montgomery_multiplication() {
    println!("\n=== fiat-crypto Montgomery (Formally Verified) ===");

    let a = MontgomeryFieldElement::one();
    let two = a.add(&a);
    let b = two.add(&a); // 3

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.mul(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per multiplication: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_native_montgomery_multiplication() {
    println!("\n=== Native CIOS Montgomery (Hand-Optimized) ===");

    let a = NativeMontgomery::one();
    let two = a.add(&a);
    let b = two.add(&a); // 3

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.mul(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per multiplication: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_karatsuba_squaring() {
    println!("\n=== Karatsuba Squaring (Current Baseline) ===");

    let a = FieldElement::from_u64(12345);

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.square());
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per squaring: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_fiat_montgomery_squaring() {
    println!("\n=== fiat-crypto Montgomery Squaring ===");

    let a = MontgomeryFieldElement::one();
    let b = a.add(&a).add(&a); // 3

    let start = Instant::now();
    let mut result = b;
    for _ in 0..ITERATIONS {
        result = black_box(result.square());
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per squaring: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_native_montgomery_squaring() {
    println!("\n=== Native CIOS Montgomery Squaring ===");

    let a = NativeMontgomery::one();
    let b = a.add(&a).add(&a); // 3

    let start = Instant::now();
    let mut result = b;
    for _ in 0..ITERATIONS {
        result = black_box(result.square());
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    println!("Time per squaring: {} ns", ns_per_op);
    println!("Total time: {:?}", duration);
}

fn benchmark_addition() {
    println!("\n=== Addition Comparison ===");

    // Karatsuba
    let a = FieldElement::from_u64(12345);
    let b = FieldElement::from_u64(67890);

    let start = Instant::now();
    let mut result = a;
    for _ in 0..ITERATIONS {
        result = black_box(result.add(black_box(&b)));
    }
    let duration = start.elapsed();
    black_box(result);

    let ns_per_op_karatsuba = duration.as_nanos() / ITERATIONS as u128;
    println!("Karatsuba:           {} ns/op", ns_per_op_karatsuba);

    // fiat-crypto Montgomery
    let a_mont = MontgomeryFieldElement::one();
    let b_mont = a_mont.add(&a_mont);

    let start = Instant::now();
    let mut result_mont = a_mont;
    for _ in 0..ITERATIONS {
        result_mont = black_box(result_mont.add(black_box(&b_mont)));
    }
    let duration = start.elapsed();
    black_box(result_mont);

    let ns_per_op_fiat = duration.as_nanos() / ITERATIONS as u128;
    println!("fiat-crypto Montgomery: {} ns/op", ns_per_op_fiat);

    // Native Montgomery
    let a_native = NativeMontgomery::one();
    let b_native = a_native.add(&a_native);

    let start = Instant::now();
    let mut result_native = a_native;
    for _ in 0..ITERATIONS {
        result_native = black_box(result_native.add(black_box(&b_native)));
    }
    let duration = start.elapsed();
    black_box(result_native);

    let ns_per_op_native = duration.as_nanos() / ITERATIONS as u128;
    println!("Native Montgomery:    {} ns/op", ns_per_op_native);
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║  P-256 Montgomery Performance Comparison                       ║");
    println!("║  Iterations: {:>6}                                           ║", ITERATIONS);
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!("\n┌─ MULTIPLICATION ─────────────────────────────────────────────┐");
    benchmark_karatsuba_multiplication();
    benchmark_fiat_montgomery_multiplication();
    benchmark_native_montgomery_multiplication();
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n┌─ SQUARING ──────────────────────────────────────────────────┐");
    benchmark_karatsuba_squaring();
    benchmark_fiat_montgomery_squaring();
    benchmark_native_montgomery_squaring();
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n┌─ ADDITION ──────────────────────────────────────────────────┐");
    benchmark_addition();
    println!("└──────────────────────────────────────────────────────────────┘");

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║  Analysis                                                       ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!("\nExpected results:");
    println!("• Native Montgomery should be 15-25% faster than fiat-crypto");
    println!("• Native Montgomery should be competitive with or faster than Karatsuba");
    println!("• Addition should be similar across all (it's simpler)");
    println!("\nWhy Native Montgomery should be faster:");
    println!("• CIOS algorithm: interleaves multiply + reduce");
    println!("• Manual loop unrolling for 4-limb case");
    println!("• Optimized for P-256's specific modulus");
    println!("• No generic code paths like fiat-crypto");
}
