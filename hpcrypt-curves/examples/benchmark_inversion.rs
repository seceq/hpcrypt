//! Benchmark field inversion performance
//!
//! Measures current inversion performance to establish baseline
//! before implementing optimized addition chains.

use hpcrypt_curves::p256::FieldElement as P256FieldElement;
use hpcrypt_curves::p384::FieldElement as P384FieldElement;
use hpcrypt_curves::p521::FieldElement as P521FieldElement;
use std::time::Instant;

const ITERATIONS: usize = 10_000;

fn main() {
    println!("Field Inversion Performance Benchmark");
    println!("Iterations: {}", ITERATIONS);
    println!("{}", "=".repeat(70));
    println!();

    benchmark_p256();
    println!();
    benchmark_p384();
    println!();
    benchmark_p521();
}

fn benchmark_p256() {
    println!("P-256 Field Inversion (Current Binary Method):");
    println!("{}", "-".repeat(70));

    // Use various test values (small values that are definitely valid)
    let mut bytes1 = [0u8; 32];
    bytes1[0] = 5;
    let mut bytes2 = [0u8; 32];
    bytes2[0] = 7;
    let mut bytes3 = [0u8; 32];
    bytes3[0] = 11;

    let test_values = vec![
        P256FieldElement::from_bytes(&bytes1).unwrap(),
        P256FieldElement::from_bytes(&bytes2).unwrap(),
        P256FieldElement::from_bytes(&bytes3).unwrap(),
    ];

    // Warm up
    for val in &test_values {
        let _ = val.invert();
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for val in &test_values {
            let _ = val.invert();
        }
    }
    let duration = start.elapsed();

    let total_inversions = ITERATIONS * test_values.len();
    let ns_per_inv = duration.as_nanos() as f64 / total_inversions as f64;
    let us_per_inv = ns_per_inv / 1000.0;

    println!("  Total inversions: {}", total_inversions);
    println!(
        "  Time per inversion: {:.2} μs ({:.0} ns)",
        us_per_inv, ns_per_inv
    );
    println!(
        "  Throughput: {:.0} inversions/sec",
        1_000_000.0 / us_per_inv
    );

    // Verify correctness
    let test = P256FieldElement::from_bytes(&[5u8; 32]).unwrap();
    let inv = test.invert();
    let product = test.mul(&inv);
    let one = P256FieldElement::one();
    assert_eq!(product, one, "Sanity check: a * a^(-1) = 1");
    println!("  ✅ Correctness verified");
}

fn benchmark_p384() {
    println!("P-384 Field Inversion (Current Binary Method):");
    println!("{}", "-".repeat(70));

    let mut bytes1 = [0u8; 48];
    bytes1[0] = 5;
    let mut bytes2 = [0u8; 48];
    bytes2[0] = 7;
    let mut bytes3 = [0u8; 48];
    bytes3[0] = 11;

    let test_values = vec![
        P384FieldElement::from_bytes(&bytes1).unwrap(),
        P384FieldElement::from_bytes(&bytes2).unwrap(),
        P384FieldElement::from_bytes(&bytes3).unwrap(),
    ];

    // Warm up
    for val in &test_values {
        let _ = val.invert();
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for val in &test_values {
            let _ = val.invert();
        }
    }
    let duration = start.elapsed();

    let total_inversions = ITERATIONS * test_values.len();
    let ns_per_inv = duration.as_nanos() as f64 / total_inversions as f64;
    let us_per_inv = ns_per_inv / 1000.0;

    println!("  Total inversions: {}", total_inversions);
    println!(
        "  Time per inversion: {:.2} μs ({:.0} ns)",
        us_per_inv, ns_per_inv
    );
    println!(
        "  Throughput: {:.0} inversions/sec",
        1_000_000.0 / us_per_inv
    );

    // Verify correctness
    let test = P384FieldElement::from_bytes(&[5u8; 48]).unwrap();
    let inv = test.invert();
    let product = test.mul(&inv);
    let one = P384FieldElement::one();
    assert_eq!(product, one, "Sanity check: a * a^(-1) = 1");
    println!("  ✅ Correctness verified");
}

fn benchmark_p521() {
    println!("P-521 Field Inversion (Current Binary Method):");
    println!("{}", "-".repeat(70));

    let mut bytes1 = [0u8; 66];
    bytes1[0] = 5;
    let mut bytes2 = [0u8; 66];
    bytes2[0] = 7;
    let mut bytes3 = [0u8; 66];
    bytes3[0] = 11;

    let test_values = vec![
        P521FieldElement::from_bytes(&bytes1).unwrap(),
        P521FieldElement::from_bytes(&bytes2).unwrap(),
        P521FieldElement::from_bytes(&bytes3).unwrap(),
    ];

    // Warm up
    for val in &test_values {
        let _ = val.invert();
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for val in &test_values {
            let _ = val.invert();
        }
    }
    let duration = start.elapsed();

    let total_inversions = ITERATIONS * test_values.len();
    let ns_per_inv = duration.as_nanos() as f64 / total_inversions as f64;
    let us_per_inv = ns_per_inv / 1000.0;

    println!("  Total inversions: {}", total_inversions);
    println!(
        "  Time per inversion: {:.2} μs ({:.0} ns)",
        us_per_inv, ns_per_inv
    );
    println!(
        "  Throughput: {:.0} inversions/sec",
        1_000_000.0 / us_per_inv
    );

    // Verify correctness
    let test = P521FieldElement::from_bytes(&[5u8; 66]).unwrap();
    let inv = test.invert();
    let product = test.mul(&inv);
    let one = P521FieldElement::one();
    assert_eq!(product, one, "Sanity check: a * a^(-1) = 1");
    println!("  ✅ Correctness verified");
}
