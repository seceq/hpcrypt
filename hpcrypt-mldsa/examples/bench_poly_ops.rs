// Micro-benchmark for polynomial operations
// Tests if AVX2 SIMD would help poly.add/sub/reduce

use hpcrypt_mldsa::params::N;
use hpcrypt_mldsa::poly::Poly;
use std::time::Instant;

fn main() {
    println!("================================================================================");
    println!("Polynomial Operations Micro-Benchmark");
    println!("================================================================================");
    println!();

    let iterations = 1_000_000;

    // Create test polynomials
    let mut poly_a = Poly::new();
    let mut poly_b = Poly::new();
    for i in 0..N {
        poly_a.coeffs[i] = ((i * 12345) % 8380417) as i32;
        poly_b.coeffs[i] = ((i * 67890) % 8380417) as i32;
    }

    println!("Testing {} iterations per operation", iterations);
    println!();

    // Benchmark poly.add()
    let start = Instant::now();
    let mut sum_poly = Poly::new();
    for _ in 0..iterations {
        sum_poly = poly_a.add(&poly_b);
    }
    let add_time = start.elapsed();
    let add_ns = add_time.as_nanos() / iterations;
    println!("poly.add():    {:4} ns/op", add_ns);

    // Benchmark poly.sub()
    let start = Instant::now();
    let mut diff_poly = Poly::new();
    for _ in 0..iterations {
        diff_poly = poly_a.sub(&poly_b);
    }
    let sub_time = start.elapsed();
    let sub_ns = sub_time.as_nanos() / iterations;
    println!("poly.sub():    {:4} ns/op", sub_ns);

    // Benchmark poly.reduce()
    let mut test_poly = poly_a.clone();
    let start = Instant::now();
    for _ in 0..iterations {
        test_poly.reduce();
    }
    let reduce_time = start.elapsed();
    let reduce_ns = reduce_time.as_nanos() / iterations;
    println!("poly.reduce(): {:4} ns/op", reduce_ns);

    // Prevent optimization
    if sum_poly.coeffs[0] == diff_poly.coeffs[0] && test_poly.coeffs[0] == 0x12345678 {
        println!("Impossible");
    }

    println!();
    println!("================================================================================");
    println!("Analysis:");
    println!("================================================================================");
    println!();
    println!(
        "poly.add():    {} ns for 256 coefficients = {:.2} ns/coeff",
        add_ns,
        add_ns as f64 / 256.0
    );
    println!(
        "poly.sub():    {} ns for 256 coefficients = {:.2} ns/coeff",
        sub_ns,
        sub_ns as f64 / 256.0
    );
    println!(
        "poly.reduce(): {} ns for 256 coefficients = {:.2} ns/coeff",
        reduce_ns,
        reduce_ns as f64 / 256.0
    );
    println!();

    println!("Expected AVX2 improvement:");
    println!("- Theoretical maximum: 8× (process 8 coefficients at once)");
    println!("- Realistic with overhead: 2-3×");
    println!();

    println!("Potential overall impact:");
    println!("- If poly ops are 15% of signing (~90 µs)");
    println!("- 2× speedup → save 45 µs → 7.5% overall improvement");
    println!("- 3× speedup → save 60 µs → 10% overall improvement");
    println!();

    println!("Recommendation:");
    println!("- If poly ops take <100ns each: AVX2 overhead will dominate");
    println!("- If poly ops take >500ns each: AVX2 worth implementing");
    println!("================================================================================");
}
