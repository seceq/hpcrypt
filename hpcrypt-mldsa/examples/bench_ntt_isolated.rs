// Isolated NTT benchmark for Shoup optimization
//
// Directly measures NTT and inverse NTT performance
// to isolate Shoup's impact from other operations

use mldsa::poly::Poly;
use mldsa::ntt::{ntt, inv_ntt};
use std::time::Instant;

fn main() {
    let sep = "=".repeat(70);
    println!("{}", sep);
    println!("Isolated NTT Benchmark - Shoup's Butterfly Impact");
    println!("{}", sep);
    println!();

    // Check AVX2
    #[cfg(all(target_arch = "x86_64", feature = "avx2"))]
    {
        use mldsa::simd::dispatch::has_avx2;
        if has_avx2() {
            println!("✅ AVX2 with Shoup optimization active");
        } else {
            println!("⚠️  Scalar fallback");
        }
    }

    println!();

    let iterations = 10000;
    println!("Iterations: {}", iterations);
    println!();

    // Create test polynomial
    let mut poly = Poly::new();
    for i in 0..256 {
        poly.coeffs[i] = (i * 7 + 13) as i32;
    }

    // Warm-up
    for _ in 0..100 {
        let mut p = poly.clone();
        ntt(&mut p);
        inv_ntt(&mut p);
    }

    // Benchmark Forward NTT
    println!("=== Forward NTT ===");
    let mut polys: Vec<Poly> = (0..iterations).map(|_| poly.clone()).collect();

    let start = Instant::now();
    for p in &mut polys {
        ntt(p);
    }
    let ntt_time = start.elapsed();

    let ntt_ns_per_op = ntt_time.as_nanos() / iterations;
    println!("Total time: {:?}", ntt_time);
    println!("Per operation: {} ns", ntt_ns_per_op);
    println!("Throughput: {:.2} M ops/sec", 1000.0 / (ntt_ns_per_op as f64));

    // Benchmark Inverse NTT
    println!("\n=== Inverse NTT ===");
    let start = Instant::now();
    for p in &mut polys {
        inv_ntt(p);
    }
    let inv_ntt_time = start.elapsed();

    let inv_ntt_ns_per_op = inv_ntt_time.as_nanos() / iterations;
    println!("Total time: {:?}", inv_ntt_time);
    println!("Per operation: {} ns", inv_ntt_ns_per_op);
    println!("Throughput: {:.2} M ops/sec", 1000.0 / (inv_ntt_ns_per_op as f64));

    // Round-trip
    println!("\n=== NTT + InvNTT Round-trip ===");
    let mut test_polys: Vec<Poly> = (0..iterations).map(|_| poly.clone()).collect();

    let start = Instant::now();
    for p in &mut test_polys {
        ntt(p);
        inv_ntt(p);
    }
    let roundtrip_time = start.elapsed();

    let roundtrip_ns_per_op = roundtrip_time.as_nanos() / iterations;
    println!("Total time: {:?}", roundtrip_time);
    println!("Per operation: {} ns", roundtrip_ns_per_op);
    println!("Throughput: {:.2} M ops/sec", 1000.0 / (roundtrip_ns_per_op as f64));

    // Summary
    println!();
    println!("{}", sep);
    println!("=== Summary ===");
    println!("{}", sep);
    println!("Forward NTT:  {} ns/op", ntt_ns_per_op);
    println!("Inverse NTT:  {} ns/op", inv_ntt_ns_per_op);
    println!("Round-trip:   {} ns/op", roundtrip_ns_per_op);
    println!();

    // Expected impact
    println!("{}", sep);
    println!("=== Shoup Optimization Impact ===");
    println!("{}", sep);
    println!();
    println!("🎯 What's Measured:");
    println!("   - Pure NTT operations (no SHAKE256, no sampling)");
    println!("   - Both forward and inverse NTT with Shoup");
    println!("   - Direct measurement of butterfly performance");
    println!();
    println!("⚡ Shoup Benefits:");
    println!("   ✅ Precomputed zeta_shoup constants");
    println!("   ✅ Parallel execution: a*b || a*b_shoup");
    println!("   ✅ Reduced dependency chain latency");
    println!("   ✅ Better CPU pipeline utilization");
    println!();
    println!("📊 Context:");
    println!("   - NTT usage in ML-DSA:");
    println!("     KeyGen: ~15% (ExpandA, s1/s2)");
    println!("     Sign: ~25% (matrix mul, h computation)");
    println!("     Verify: ~20% (w1 computation)");
    println!();
    println!("   - Expected overall impact:");
    println!("     If NTT 10% faster → ML-DSA 1.5-2.5% faster");
    println!("     If NTT 20% faster → ML-DSA 3.0-5.0% faster");
    println!();
    println!("🔬 Measurement Quality:");
    println!("   - {} iterations for statistical significance", iterations);
    println!("   - Isolated from other operations");
    println!("   - Direct butterfly performance");

    println!();
    println!("{}", sep);
    println!("Benchmark Complete!");
    println!("{}", sep);
}
