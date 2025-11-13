use hpcrypt_curves::ed448::{scalar_mul_base_comb, Point, Scalar};
use std::time::Instant;

fn main() {
    println!("=== Simple Ed448 Comb Benchmark (No Criterion) ===\n");

    let scalar_bytes = [0x42u8; 57];
    let scalar = Scalar::from_bytes(&scalar_bytes);

    // First call - will initialize the Lazy static
    println!("1. First call to scalar_mul_base_comb (includes table generation):");
    let start = Instant::now();
    let result1 = scalar_mul_base_comb(&scalar_bytes);
    let first_call = start.elapsed();
    println!("   Time: {:?}\n", first_call);

    // Second call - should use cached table
    println!("2. Second call (table already cached):");
    let start = Instant::now();
    let result2 = scalar_mul_base_comb(&scalar_bytes);
    let second_call = start.elapsed();
    println!("   Time: {:?}\n", second_call);

    // Many subsequent calls
    println!("3. Average of 100 subsequent calls:");
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = scalar_mul_base_comb(&scalar_bytes);
    }
    let total = start.elapsed();
    println!("   Total: {:?}", total);
    println!("   Average: {:?}\n", total / iterations);

    // Compare with variable-base
    println!("4. Variable-base scalar multiplication (for comparison):");
    let base = Point::generator();
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = base.scalar_mul(&scalar);
    }
    let total_var = start.elapsed();
    println!("   Total: {:?}", total_var);
    println!("   Average: {:?}\n", total_var / iterations);

    // Verify correctness
    assert_eq!(result1, result2, "First and second calls should match");
    println!("✅ Correctness verified");
}
