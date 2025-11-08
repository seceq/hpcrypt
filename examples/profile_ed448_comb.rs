use std::time::Instant;
use hpcrypt_curves::ed448::{Point, Scalar, scalar_mul_base_comb};

fn main() {
    let scalar_bytes = [0x42u8; 57];
    let scalar = Scalar::from_bytes(&scalar_bytes);

    println!("=== Ed448 Comb Method Performance Profiling ===\n");

    // Warm up the table
    println!("1. Warming up Comb table...");
    let start = Instant::now();
    let _ = scalar_mul_base_comb(&scalar_bytes);
    let warmup_time = start.elapsed();
    println!("   First call (includes table generation): {:?}\n", warmup_time);

    // Measure Comb method performance
    println!("2. Measuring Comb method (table already loaded)...");
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = scalar_mul_base_comb(&scalar_bytes);
    }
    let total_time = start.elapsed();
    let avg_time = total_time / iterations;
    println!("   {} iterations: {:?}", iterations, total_time);
    println!("   Average per operation: {:?}\n", avg_time);

    // Measure variable-base for comparison
    println!("3. Measuring variable-base scalar multiplication...");
    let base = Point::generator();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = base.scalar_mul(&scalar);
    }
    let total_time_var = start.elapsed();
    let avg_time_var = total_time_var / iterations;
    println!("   {} iterations: {:?}", iterations, total_time_var);
    println!("   Average per operation: {:?}\n", avg_time_var);

    // Compare
    println!("=== Comparison ===");
    println!("Variable-base: {:?}", avg_time_var);
    println!("Fixed-base:    {:?}", avg_time);

    if avg_time < avg_time_var {
        let speedup = avg_time_var.as_nanos() as f64 / avg_time.as_nanos() as f64;
        println!("Speedup:       {:.2}× faster ✅", speedup);
    } else {
        let slowdown = avg_time.as_nanos() as f64 / avg_time_var.as_nanos() as f64;
        println!("Slowdown:      {:.2}× SLOWER ❌", slowdown);
    }

    // Verify correctness
    println!("\n=== Correctness Check ===");
    let result_var = base.scalar_mul(&scalar);
    let result_comb = scalar_mul_base_comb(&scalar_bytes);

    if result_var == result_comb {
        println!("✅ Results match - implementation is correct");
    } else {
        println!("❌ Results differ - implementation has bug!");
    }
}
