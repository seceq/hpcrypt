//! Benchmark for poly_reduce() to measure AVX2 optimization impact

use hpcrypt_mldsa::poly::Poly;
use std::time::Instant;

fn main() {
    println!("Poly::reduce() Benchmark");
    println!("========================\n");

    // Create a test polynomial with random-ish values
    let mut poly = Poly::new();
    for i in 0..256 {
        poly.coeffs[i] = ((i * 12345 + 67890) % 16760834) as i32; // Values that need reduction
    }

    // Warmup
    for _ in 0..1000 {
        let mut p = poly;
        p.reduce();
    }

    // Benchmark reduce() operation
    const ITERATIONS: usize = 1_000_000;

    println!("Running {} reduce() operations...\n", ITERATIONS);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut p = poly;
        p.reduce();
    }
    let elapsed = start.elapsed();

    let total_micros = elapsed.as_micros();
    let per_op_nanos = (elapsed.as_nanos() as f64) / (ITERATIONS as f64);

    println!("Results:");
    println!("  Total time: {:.3} ms", total_micros as f64 / 1000.0);
    println!("  Per operation: {:.1} ns", per_op_nanos);
    println!("  Throughput: {:.2} M ops/sec", 1000.0 / per_op_nanos);

    // Also benchmark within signing context (with poly creation overhead)
    println!("\n\nRealistic signing benchmark (reduce called on w_i):");
    println!("Running 10,000 signing iterations with reduce...\n");

    let start = Instant::now();
    for _ in 0..10_000 {
        // Simulate what happens in signing: create w_i, then reduce
        let mut w_i = Poly::new();
        for i in 0..256 {
            w_i.coeffs[i] = ((i * 54321) % 16760834) as i32;
        }
        w_i.reduce();
    }
    let elapsed = start.elapsed();

    println!("Results:");
    println!(
        "  Total time: {:.3} ms",
        elapsed.as_micros() as f64 / 1000.0
    );
    println!(
        "  Per reduce: {:.1} µs",
        elapsed.as_micros() as f64 / 10_000.0
    );
}
