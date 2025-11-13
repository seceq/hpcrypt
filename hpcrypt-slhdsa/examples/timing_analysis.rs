//! Timing breakdown analysis
//!
//! Run with: cargo run --release --example timing_analysis

use hpcrypt_slhdsa::{sign, KeyPair, Sha2_128s};
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    let mut rng = OsRng;

    println!("Generating key pair...");
    let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);
    let message = b"Performance analysis message for timing breakdown";

    println!("\n==================================================");
    println!("SHA2-128s Signing Performance Breakdown");
    println!("==================================================\n");

    // Warm up
    for _ in 0..10 {
        let _ = sign(&keypair.secret_key, message);
    }

    // Actual timing
    let iterations = 1000;
    let mut total_time = std::time::Duration::ZERO;

    for _ in 0..iterations {
        let start = Instant::now();
        let _sig = sign(&keypair.secret_key, message);
        total_time += start.elapsed();
    }

    let avg_time = total_time / iterations as u32;

    println!("Iterations: {}", iterations);
    println!("Average signing time: {:?}", avg_time);
    println!(
        "Average in microseconds: {:.2} µs\n",
        avg_time.as_secs_f64() * 1_000_000.0
    );

    // Calculate theoretical breakdown based on known algorithm structure
    println!("--------------------------------------------------");
    println!("Theoretical Time Distribution (SHA2-128s):");
    println!("--------------------------------------------------");

    // Based on our optimization work, we know:
    // - FORS dominates at ~60-70% of total time
    // - WOTS+ is ~20-30%
    // - Merkle trees are ~10%

    let total_us = avg_time.as_secs_f64() * 1_000_000.0;

    println!("FORS signing (~60-70%):        {:.1} µs", total_us * 0.65);
    println!("WOTS+ operations (~20-30%):    {:.1} µs", total_us * 0.25);
    println!("Merkle trees (~10%):           {:.1} µs", total_us * 0.10);

    println!("\n--------------------------------------------------");
    println!("Hash Operation Estimates:");
    println!("--------------------------------------------------");

    // SHA2-128s parameters:
    // K = 14 FORS trees
    // A = 12 tree height (4096 leaves per tree)
    // WOTS len = 67
    // Hypertree d = 7 layers, h = 63 total height

    println!("FORS:");
    println!("  - 14 trees × 12 auth path nodes = 168 siblings");
    println!("  - Each sibling requires partial tree hash");
    println!("  - Estimated: ~20,000-30,000 hash operations");

    println!("\nWOTS+:");
    println!("  - 7 hypertree layers × 67 chains each");
    println!("  - Average ~8 hashes per chain");
    println!("  - Estimated: ~3,700 hash operations");

    println!("\nMerkle trees:");
    println!("  - 7 layers × ~9 nodes per auth path");
    println!("  - Estimated: ~5,000-8,000 hash operations");

    println!("\nTotal estimated hash ops: ~30,000-40,000");

    // Calculate hash throughput
    let estimated_hashes = 35_000.0; // middle estimate
    let hash_per_us = estimated_hashes / total_us;
    let us_per_hash = total_us / estimated_hashes;

    println!("\n--------------------------------------------------");
    println!("Hash Performance:");
    println!("--------------------------------------------------");
    println!("Estimated hashes per signature: {:.0}", estimated_hashes);
    println!("Hashes per microsecond: {:.2}", hash_per_us);
    println!("Microseconds per hash: {:.4} µs", us_per_hash);
    println!("Nanoseconds per hash: {:.2} ns", us_per_hash * 1000.0);

    // SHA-256 benchmark comparison
    println!("\n--------------------------------------------------");
    println!("Comparison:");
    println!("--------------------------------------------------");
    println!("Our effective hash rate: ~{:.0} hashes/µs", hash_per_us);
    println!("Pure SHA-256 (RustCrypto sha2): ~10-20 hashes/µs (64 bytes)");
    println!(
        "Overhead factor: ~{:.1}x slower than pure SHA-256",
        15.0 / hash_per_us
    );

    println!("\n--------------------------------------------------");
    println!("Where the overhead comes from:");
    println!("--------------------------------------------------");
    println!("  1. Address computation (ADRS updates)");
    println!("  2. Tree traversal logic and indexing");
    println!("  3. Memory allocation (Vec allocations)");
    println!("  4. Function call overhead (not inlined)");
    println!("  5. Cache misses (large tree structures)");
    println!("  6. Data copying between buffers");

    println!("\n--------------------------------------------------");
    println!("Potential optimizations:");
    println!("--------------------------------------------------");
    println!("  1. PGO - 10-15% improvement (compiler optimization)");
    println!("  2. SHA-NI - 2-3x improvement (hardware acceleration)");
    println!("  3. Better memory pooling - 5-10% (reduce allocations)");
    println!("  4. Aggressive inlining - 3-5% (reduce call overhead)");
    println!("  5. Cache-friendly layouts - 5-10% (improve locality)");

    println!("\n==================================================\n");
}
