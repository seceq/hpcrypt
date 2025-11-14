// Benchmark different infinity_norm implementations

use hpcrypt_mldsa::params::N;
use hpcrypt_mldsa::poly::Poly;
use std::time::Instant;

fn main() {
    let sep = "=".to_string().repeat(80);
    println!("{}", sep);
    println!("Infinity Norm Implementation Benchmark");
    println!("{}", sep);
    println!();

    // Create test polynomials with different characteristics
    let mut polys = Vec::new();

    // Poly 1: Small values (typical case - won't exceed threshold)
    let mut poly1 = Poly::new();
    for i in 0..N {
        poly1.coeffs[i] = ((i * 1337) % 10000) as i32;
    }
    polys.push(("small values", poly1));

    // Poly 2: Large values (will exceed threshold early)
    let mut poly2 = Poly::new();
    for i in 0..N {
        poly2.coeffs[i] = 520000 + (i as i32 * 13) % 5000;
    }
    polys.push(("large values (early exit)", poly2));

    // Poly 3: Mixed (large value at end)
    let mut poly3 = Poly::new();
    for i in 0..N {
        poly3.coeffs[i] = ((i * 1337) % 10000) as i32;
    }
    poly3.coeffs[255] = 523000; // Large value at the end
    polys.push(("large at end", poly3));

    let iterations = 100_000;
    let threshold = 523896; // ML-DSA-65: γ₁ - 2β

    for (name, poly) in &polys {
        let dash = "-".to_string().repeat(80);
        println!("Testing: {}", name);
        println!("{}", dash);

        // Benchmark standard infinity_norm
        let start = Instant::now();
        let mut sum = 0i64;
        for _ in 0..iterations {
            let norm = poly.infinity_norm();
            sum += norm as i64;
        }
        let duration = start.elapsed();
        let ns_per_op = duration.as_nanos() / iterations;
        println!(
            "Standard infinity_norm:           {} ns/op (sum={})",
            ns_per_op, sum
        );

        // Benchmark threshold-based infinity_norm
        let start = Instant::now();
        let mut sum = 0i64;
        for _ in 0..iterations {
            let norm = poly.infinity_norm_with_threshold(threshold);
            sum += norm as i64;
        }
        let duration = start.elapsed();
        let ns_per_op = duration.as_nanos() / iterations;
        println!(
            "Threshold infinity_norm:          {} ns/op (sum={})",
            ns_per_op, sum
        );

        println!();
    }

    println!("{}", sep);
    println!("Analysis:");
    println!("- Standard: Full scan of all 256 coefficients");
    println!("- Threshold: Early exit when any value exceeds threshold");
    println!();
    println!("Expected:");
    println!("- Small values: Both should be similar (full scan needed)");
    println!("- Large early: Threshold should be MUCH faster (early exit)");
    println!("- Large at end: Threshold slightly slower (almost full scan + checks)");
    println!("{}", sep);
}
