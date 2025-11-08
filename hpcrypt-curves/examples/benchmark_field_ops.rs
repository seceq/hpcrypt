//! Simple benchmark to measure field operation performance
//!
//! Run with: cargo run --release --example benchmark_field_ops

use std::time::Instant;
use hpcrypt_curves::p256::FieldElement as P256FieldElement;
use hpcrypt_curves::p384::FieldElement as P384FieldElement;
use hpcrypt_curves::p521::FieldElement as P521FieldElement;

const ITERATIONS: usize = 10_000_000;

fn main() {
    println!("Field Operations Performance Benchmark");
    println!("Iterations: {}", ITERATIONS);
    println!("{}", "=".repeat(60));
    println!();

    benchmark_p256();
    println!();
    benchmark_p384();
    println!();
    benchmark_p521();
}

fn benchmark_p256() {
    println!("P-256 Field Operations:");
    println!("{}", "-".repeat(60));

    let a = P256FieldElement::from_bytes(&[1u8; 32]).unwrap();
    let b = P256FieldElement::from_bytes(&[2u8; 32]).unwrap();

    // Warm up
    for _ in 0..1000 {
        let _ = a.add(&b);
    }

    // Addition benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.add(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Addition:     {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Subtraction benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.sub(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Subtraction:  {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Multiplication benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS / 10 {
        let _ = a.mul(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / (ITERATIONS / 10) as f64;
    println!("  Multiplication: {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);
}

fn benchmark_p384() {
    println!("P-384 Field Operations (with macros):");
    println!("{}", "-".repeat(60));

    let a = P384FieldElement::from_bytes(&[1u8; 48]).unwrap();
    let b = P384FieldElement::from_bytes(&[2u8; 48]).unwrap();

    // Warm up
    for _ in 0..1000 {
        let _ = a.add(&b);
    }

    // Addition benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.add(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Addition:     {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Subtraction benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.sub(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Subtraction:  {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Multiplication benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS / 10 {
        let _ = a.mul(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / (ITERATIONS / 10) as f64;
    println!("  Multiplication: {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);
}

fn benchmark_p521() {
    println!("P-521 Field Operations (with macros):");
    println!("{}", "-".repeat(60));

    let a = P521FieldElement::from_bytes(&[1u8; 66]).unwrap();
    let b = P521FieldElement::from_bytes(&[2u8; 66]).unwrap();

    // Warm up
    for _ in 0..1000 {
        let _ = a.add(&b);
    }

    // Addition benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.add(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Addition:     {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Subtraction benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = a.sub(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / ITERATIONS as f64;
    println!("  Subtraction:  {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);

    // Multiplication benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS / 10 {
        let _ = a.mul(&b);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / (ITERATIONS / 10) as f64;
    println!("  Multiplication: {:.2} ns/op ({:.2} M ops/sec)",
             ns_per_op, 1000.0 / ns_per_op);
}
