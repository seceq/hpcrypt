//! Benchmark P-521 field inversion: SafeGCD vs Fermat
//!
//! Compares the performance of the new safegcd implementation
//! against the traditional Fermat's Little Theorem approach.

use hpcrypt_curves::p521::field::FieldElement;
use std::time::Instant;

const ITERATIONS: usize = 10_000;

fn main() {
    println!("P-521 Field Inversion Performance Comparison");
    println!("Iterations: {}", ITERATIONS);
    println!("{}", "=".repeat(70));
    println!();

    // Create test values
    let mut bytes1 = [0u8; 66];
    bytes1[0] = 5;
    let mut bytes2 = [0u8; 66];
    bytes2[0] = 7;
    let mut bytes3 = [0u8; 66];
    bytes3[0] = 11;
    let mut bytes4 = [0u8; 66];
    bytes4[31] = 0xFF;
    bytes4[32] = 0x12;

    let test_values = vec![
        FieldElement::from_bytes(&bytes1).unwrap(),
        FieldElement::from_bytes(&bytes2).unwrap(),
        FieldElement::from_bytes(&bytes3).unwrap(),
        FieldElement::from_bytes(&bytes4).unwrap(),
    ];

    // Benchmark SafeGCD
    println!("1. SafeGCD (Binary Extended GCD) - NEW:");
    println!("{}", "-".repeat(70));

    // Warm up
    for val in &test_values {
        let _ = val.invert_gcd();
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for val in &test_values {
            let _ = val.invert_gcd();
        }
    }
    let duration_gcd = start.elapsed();

    let total_inversions = ITERATIONS * test_values.len();
    let ns_per_inv_gcd = duration_gcd.as_nanos() as f64 / total_inversions as f64;
    let us_per_inv_gcd = ns_per_inv_gcd / 1000.0;

    println!("  Total inversions: {}", total_inversions);
    println!(
        "  Time per inversion: {:.2} μs ({:.0} ns)",
        us_per_inv_gcd, ns_per_inv_gcd
    );
    println!(
        "  Throughput: {:.0} inversions/sec",
        1_000_000.0 / us_per_inv_gcd
    );

    // Verify correctness
    let test = FieldElement::from_bytes(&bytes1).unwrap();
    let inv = test.invert_gcd();
    let product = test.mul(&inv);
    let one = FieldElement::one();
    assert_eq!(
        product.to_bytes(),
        one.to_bytes(),
        "SafeGCD: a * a^(-1) = 1"
    );
    println!("   Correctness verified");

    println!();

    // Benchmark Fermat
    println!("2. Fermat's Little Theorem - BASELINE:");
    println!("{}", "-".repeat(70));

    // Warm up
    for val in &test_values {
        let _ = val.invert_fermat();
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for val in &test_values {
            let _ = val.invert_fermat();
        }
    }
    let duration_fermat = start.elapsed();

    let ns_per_inv_fermat = duration_fermat.as_nanos() as f64 / total_inversions as f64;
    let us_per_inv_fermat = ns_per_inv_fermat / 1000.0;

    println!("  Total inversions: {}", total_inversions);
    println!(
        "  Time per inversion: {:.2} μs ({:.0} ns)",
        us_per_inv_fermat, ns_per_inv_fermat
    );
    println!(
        "  Throughput: {:.0} inversions/sec",
        1_000_000.0 / us_per_inv_fermat
    );

    // Verify correctness
    let inv = test.invert_fermat();
    let product = test.mul(&inv);
    assert_eq!(product.to_bytes(), one.to_bytes(), "Fermat: a * a^(-1) = 1");
    println!("   Correctness verified");

    println!();

    // Comparison
    println!("{}", "=".repeat(70));
    println!("PERFORMANCE COMPARISON:");
    println!("{}", "=".repeat(70));
    println!();
    println!("  SafeGCD:  {:.2} μs", us_per_inv_gcd);
    println!("  Fermat:   {:.2} μs", us_per_inv_fermat);
    println!();

    let speedup = us_per_inv_fermat / us_per_inv_gcd;
    let improvement = ((us_per_inv_fermat - us_per_inv_gcd) / us_per_inv_fermat) * 100.0;

    if speedup > 1.0 {
        println!(
            "   SafeGCD is {:.2}x faster ({:.1}% improvement)",
            speedup, improvement
        );
    } else {
        println!(
            "    Fermat is {:.2}x faster ({:.1}% slower)",
            1.0 / speedup,
            -improvement
        );
    }

    println!();
    println!(
        "  Time saved per inversion: {:.2} μs",
        us_per_inv_fermat - us_per_inv_gcd
    );
    println!(
        "  Time saved per 1000 inversions: {:.2} ms",
        (us_per_inv_fermat - us_per_inv_gcd) / 1000.0
    );

    println!();
    println!("{}", "=".repeat(70));

    // Verify both methods produce the same result
    println!("\nCROSS-VERIFICATION:");
    println!("{}", "-".repeat(70));
    for (i, val) in test_values.iter().enumerate() {
        let inv_gcd = val.invert_gcd();
        let inv_fermat = val.invert_fermat();
        assert_eq!(
            inv_gcd.to_bytes(),
            inv_fermat.to_bytes(),
            "Test value {} - SafeGCD and Fermat produce different results!",
            i
        );
        println!("  Test value {}:  Both methods agree", i + 1);
    }
}
