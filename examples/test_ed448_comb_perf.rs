use std::time::Instant;
use hpcrypt_curves::ed448::{Point, Scalar, scalar_mul_base_comb};

fn main() {
    let scalar_bytes = [0x42u8; 57];
    let scalar = Scalar::from_bytes(&scalar_bytes);
    let base = Point::generator();

    println!("Warming up Comb table (first call)...");
    let _ = scalar_mul_base_comb(&scalar_bytes);
    println!("Table loaded.\n");

    // Measure variable-base scalar multiplication
    println!("Benchmarking variable-base scalar multiplication...");
    let start = Instant::now();
    let iters = 100;
    for _ in 0..iters {
        let _ = base.scalar_mul(&scalar);
    }
    let elapsed = start.elapsed();
    let per_op = elapsed.as_micros() / iters;
    println!("Variable-base: {} iterations in {:?}", iters, elapsed);
    println!("Per operation: {} µs\n", per_op);

    // Measure fixed-base Comb scalar multiplication
    println!("Benchmarking fixed-base Comb scalar multiplication...");
    let start = Instant::now();
    let iters = 100;
    for _ in 0..iters {
        let _ = scalar_mul_base_comb(&scalar_bytes);
    }
    let elapsed = start.elapsed();
    let per_op = elapsed.as_micros() / iters;
    println!("Fixed-base Comb: {} iterations in {:?}", iters, elapsed);
    println!("Per operation: {} µs\n", per_op);

    // Verify correctness
    let result_variable = base.scalar_mul(&scalar);
    let result_comb = scalar_mul_base_comb(&scalar_bytes);

    if result_variable == result_comb {
        println!("✅ Correctness verified: Both methods produce identical results");
    } else {
        println!("❌ ERROR: Methods produce different results!");
        println!("Variable-base: {:?}", result_variable);
        println!("Comb method:   {:?}", result_comb);
    }
}
