//! Benchmark comparing different scalar multiplication methods
//!
//! Compares:
//! 1. Current precomputed table (64 KB, 0 doublings + 64 additions)
//! 2. True comb method (1 KB, 64 doublings + 64 additions)
//! 3. wNAF (1 KB, 256 doublings + ~51 additions)
//! 4. Binary method (0 memory, 256 doublings + ~128 additions)
//!
//! Goal: Validate that current implementation is near-optimal

use hpcrypt_curves::p256::{AffinePoint, Point, Scalar};
use std::time::Instant;

const ITERATIONS: usize = 1_000;

fn main() {
    println!("Scalar Multiplication Method Comparison");
    println!("Iterations: {}", ITERATIONS);
    println!("{}", "=".repeat(80));
    println!();

    // Generate test scalars
    let test_scalars = generate_test_scalars();

    // Benchmark each method
    benchmark_current_precomputed(&test_scalars);
    println!();
    benchmark_true_comb(&test_scalars);
    println!();
    benchmark_wnaf(&test_scalars);
    println!();
    benchmark_binary(&test_scalars);
    println!();

    // Summary
    print_summary();
}

fn generate_test_scalars() -> Vec<Scalar> {
    vec![
        Scalar::from_u64(12345),
        Scalar::from_u64(67890),
        Scalar::from_u64(111213),
        Scalar::from_u64(141516),
        Scalar::from_u64(171819),
    ]
}

fn benchmark_current_precomputed(scalars: &[Scalar]) {
    println!("Method 1: Current Precomputed Table (Optimized Fixed-Base)");
    println!("{}", "-".repeat(80));

    use hpcrypt_curves::p256::precomputed::scalar_mul_generator_balanced;

    // Warm up
    for scalar in scalars {
        let _ = scalar_mul_generator_balanced(&scalar.to_bytes());
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for scalar in scalars {
            let _ = scalar_mul_generator_balanced(&scalar.to_bytes());
        }
    }
    let duration = start.elapsed();

    let total_ops = ITERATIONS * scalars.len();
    let us_per_op = duration.as_micros() as f64 / total_ops as f64;
    let ops_per_sec = 1_000_000.0 / us_per_op;

    println!("  Memory usage: ~64 KB (64 windows × 16 points)");
    println!("  Operations: 0 doublings + 64 additions");
    println!("  Time per scalar mult: {:.2} μs", us_per_op);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);

    // Verify correctness
    let g = Point::generator();
    let scalar = scalars[0].to_bytes();
    let result1 = scalar_mul_generator_balanced(&scalar);
    let result2 = g.scalar_mul(&scalar);
    let affine1 = result1.to_affine().unwrap();
    let affine2 = result2.to_affine().unwrap();
    assert_eq!(
        affine1.x, affine2.x,
        "Precomputed result should match standard"
    );
    println!("   Correctness verified");
}

fn benchmark_true_comb(scalars: &[Scalar]) {
    println!("Method 2: True Comb Method (Lim-Lee)");
    println!("{}", "-".repeat(80));

    // Build comb table
    let table = build_comb_table();

    // Warm up
    for scalar in scalars {
        let _ = comb_scalar_mul(&table, &scalar.to_bytes());
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for scalar in scalars {
            let _ = comb_scalar_mul(&table, &scalar.to_bytes());
        }
    }
    let duration = start.elapsed();

    let total_ops = ITERATIONS * scalars.len();
    let us_per_op = duration.as_micros() as f64 / total_ops as f64;
    let ops_per_sec = 1_000_000.0 / us_per_op;

    println!("  Memory usage: ~1 KB (16 points)");
    println!("  Operations: 64 doublings + 64 additions");
    println!("  Time per scalar mult: {:.2} μs", us_per_op);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);

    // Verify correctness
    let g = Point::generator();
    let scalar = scalars[0].to_bytes();
    let result1 = comb_scalar_mul(&table, &scalar);
    let result2 = g.scalar_mul(&scalar);
    let affine1 = result1.to_affine().unwrap();
    let affine2 = result2.to_affine().unwrap();
    assert_eq!(affine1.x, affine2.x, "Comb result should match standard");
    println!("   Correctness verified");
}

fn benchmark_wnaf(scalars: &[Scalar]) {
    println!("Method 3: wNAF (Window Non-Adjacent Form)");
    println!("{}", "-".repeat(80));

    use hpcrypt_curves::p256::wnaf::wnaf_scalar_mul;

    let g = Point::generator();

    // Warm up
    for scalar in scalars {
        let _ = wnaf_scalar_mul(&g, &scalar.to_bytes(), 4);
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for scalar in scalars {
            let _ = wnaf_scalar_mul(&g, &scalar.to_bytes(), 4);
        }
    }
    let duration = start.elapsed();

    let total_ops = ITERATIONS * scalars.len();
    let us_per_op = duration.as_micros() as f64 / total_ops as f64;
    let ops_per_sec = 1_000_000.0 / us_per_op;

    println!("  Memory usage: ~1 KB (8 odd multiples, computed on-the-fly)");
    println!("  Operations: 256 doublings + ~51 additions");
    println!("  Time per scalar mult: {:.2} μs", us_per_op);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);

    // Verify correctness
    let scalar = scalars[0].to_bytes();
    let result1 = wnaf_scalar_mul(&g, &scalar, 4);
    let result2 = g.scalar_mul(&scalar);
    let affine1 = result1.to_affine().unwrap();
    let affine2 = result2.to_affine().unwrap();
    assert_eq!(affine1.x, affine2.x, "wNAF result should match standard");
    println!("   Correctness verified");
}

fn benchmark_binary(scalars: &[Scalar]) {
    println!("Method 4: Binary Method (Double-and-Add)");
    println!("{}", "-".repeat(80));

    let g = Point::generator();

    // Warm up
    for scalar in scalars {
        let _ = g.scalar_mul(&scalar.to_bytes());
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for scalar in scalars {
            let _ = g.scalar_mul(&scalar.to_bytes());
        }
    }
    let duration = start.elapsed();

    let total_ops = ITERATIONS * scalars.len();
    let us_per_op = duration.as_micros() as f64 / total_ops as f64;
    let ops_per_sec = 1_000_000.0 / us_per_op;

    println!("  Memory usage: 0 bytes (no precomputation)");
    println!("  Operations: 256 doublings + ~128 additions");
    println!("  Time per scalar mult: {:.2} μs", us_per_op);
    println!("  Throughput: {:.0} ops/sec", ops_per_sec);
    println!("   Baseline method");
}

fn print_summary() {
    println!("{}", "=".repeat(80));
    println!("Summary:");
    println!("{}", "-".repeat(80));
    println!();
    println!("Expected ranking (fastest to slowest):");
    println!("  1. Current Precomputed (64 KB) - 0 doublings, fastest");
    println!("  2. wNAF (1 KB) - 256 doublings + 51 additions");
    println!("  3. True Comb (1 KB) - 64 doublings + 64 additions");
    println!("  4. Binary (0 KB) - 256 doublings + 128 additions, slowest");
    println!();
    println!("Key insight:");
    println!("  - Current precomputed table trades memory for speed (eliminates doublings)");
    println!("  - True comb saves memory but requires 64 doublings");
    println!("  - wNAF is good for unknown/variable base points");
    println!("  - Binary method is baseline (no precomputation)");
}

// ============================================================================
// True Comb Method Implementation
// ============================================================================

/// Comb table for d=64 teeth, w=4 bits per tooth
/// Stores 2^4 = 16 precomputed points
struct CombTable {
    /// table[c] = combination of basis points based on bits of c
    /// c = b₃b₂b₁b₀ (4 bits)
    /// table[c] = b₀×G + b₁×G×2^64 + b₂×G×2^128 + b₃×G×2^192
    table: [AffinePoint; 16],
}

/// Build comb table with d=64 teeth, w=4 bits
fn build_comb_table() -> CombTable {
    let g = Point::generator();

    // Compute basis points: G, G×2^64, G×2^128, G×2^192
    let mut basis = [Point::infinity(); 4];
    basis[0] = g;

    for i in 1..4 {
        // Double previous basis 64 times
        let mut point = basis[i - 1];
        for _ in 0..64 {
            point = point.double();
        }
        basis[i] = point;
    }

    // Precompute all 16 combinations
    let mut table = [AffinePoint {
        x: hpcrypt_curves::p256::FieldElement::zero(),
        y: hpcrypt_curves::p256::FieldElement::zero(),
    }; 16];

    for c in 0..16 {
        let mut point = Point::infinity();

        for bit in 0..4 {
            if (c & (1 << bit)) != 0 {
                point = point.add(&basis[bit]);
            }
        }

        table[c] = if c == 0 {
            // Sentinel for infinity
            AffinePoint {
                x: hpcrypt_curves::p256::FieldElement::zero(),
                y: hpcrypt_curves::p256::FieldElement::zero(),
            }
        } else {
            point.to_affine().expect("Should not be infinity")
        };
    }

    CombTable { table }
}

/// Perform scalar multiplication using comb method
fn comb_scalar_mul(comb: &CombTable, scalar: &[u8; 32]) -> Point {
    let mut result = Point::infinity();

    // Process 64 rows (from MSB row to LSB row)
    for row in (0..64).rev() {
        // Double once per row
        result = result.double();

        // Extract column value (4 bits at positions [row, row+64, row+128, row+192])
        let c = extract_column(scalar, row);

        // Add precomputed point for this column
        if c != 0 {
            result = result.add_affine(&comb.table[c]);
        }
    }

    result
}

/// Extract column value from scalar
/// Returns 4-bit value: bits at positions [row, row+64, row+128, row+192]
fn extract_column(scalar: &[u8; 32], row: usize) -> usize {
    let mut c = 0usize;

    for tooth in 0..4 {
        let bit_pos = row + tooth * 64;
        if bit_pos < 256 {
            let byte_idx = 31 - (bit_pos / 8); // Big-endian
            let bit_offset = bit_pos % 8;
            let bit = (scalar[byte_idx] >> bit_offset) & 1;
            c |= (bit as usize) << tooth;
        }
    }

    c
}
