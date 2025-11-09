//! SHA-1 performance demonstration
//!
//! This example demonstrates the performance characteristics of different
//! SHA-1 usage patterns and optimizations.
//!
//! Run with: cargo run --example sha1_performance --release

use hpcrypt_hash::sha1::{sha1, Sha1};
use std::time::Instant;

fn main() {
    println!("=== SHA-1 Performance Examples ===\n");
    println!("Run with --release for accurate benchmarks!\n");

    // Example 1: Small message performance (fast path)
    println!("1. Small message performance (≤55 bytes):");
    let small_msg = b"Hello, World! This is a small message.";
    assert!(small_msg.len() <= 55);

    let iterations = 1_000_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha1(small_msg);
    }
    let duration = start.elapsed();
    println!("   {} iterations of {} bytes", iterations, small_msg.len());
    println!("   Time: {:?}", duration);
    println!(
        "   Rate: {:.2} million hashes/sec",
        iterations as f64 / duration.as_secs_f64() / 1_000_000.0
    );
    println!();

    // Example 2: Empty message performance (precomputed)
    println!("2. Empty message performance (precomputed):");
    let iterations = 10_000_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha1(b"");
    }
    let duration = start.elapsed();
    println!("   {} iterations", iterations);
    println!("   Time: {:?}", duration);
    println!(
        "   Rate: {:.2} million hashes/sec",
        iterations as f64 / duration.as_secs_f64() / 1_000_000.0
    );
    println!();

    // Example 3: Medium message (multi-block)
    println!("3. Medium message performance (1 KB):");
    let medium_msg = vec![b'A'; 1024];
    let iterations = 100_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha1(&medium_msg);
    }
    let duration = start.elapsed();
    let throughput = (iterations * medium_msg.len()) as f64 / duration.as_secs_f64() / 1_000_000.0;
    println!("   {} iterations of {} bytes", iterations, medium_msg.len());
    println!("   Time: {:?}", duration);
    println!("   Throughput: {:.2} MB/s", throughput);
    println!();

    // Example 4: Large message (many blocks)
    println!("4. Large message performance (1 MB):");
    let large_msg = vec![b'A'; 1_000_000];
    let iterations = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha1(&large_msg);
    }
    let duration = start.elapsed();
    let throughput = (iterations * large_msg.len()) as f64 / duration.as_secs_f64() / 1_000_000.0;
    println!(
        "   {} iterations of {} MB",
        iterations,
        large_msg.len() / 1_000_000
    );
    println!("   Time: {:?}", duration);
    println!("   Throughput: {:.2} MB/s", throughput);
    println!();

    // Example 5: Incremental vs one-shot
    println!("5. Incremental vs one-shot comparison:");
    let message = vec![b'A'; 10000];
    let iterations = 10_000;

    // One-shot
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha1(&message);
    }
    let oneshot_duration = start.elapsed();

    // Incremental (100-byte chunks)
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Sha1::new();
        for chunk in message.chunks(100) {
            hasher.update(chunk);
        }
        let _ = hasher.finalize();
    }
    let incremental_duration = start.elapsed();

    println!("   Message size: {} bytes", message.len());
    println!("   One-shot time:    {:?}", oneshot_duration);
    println!("   Incremental time: {:?}", incremental_duration);
    println!(
        "   Ratio: {:.2}x",
        incremental_duration.as_secs_f64() / oneshot_duration.as_secs_f64()
    );
    println!();

    // Example 6: Different message sizes
    println!("6. Throughput by message size:");
    for &size in &[64, 128, 256, 512, 1024, 4096, 16384, 65536] {
        let msg = vec![b'X'; size];
        let iterations = (10_000_000 / size).max(100);

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = sha1(&msg);
        }
        let duration = start.elapsed();
        let throughput = (iterations * size) as f64 / duration.as_secs_f64() / 1_000_000.0;

        println!("   {:6} bytes: {:7.2} MB/s", size, throughput);
    }
    println!();

    // Example 7: Boundary case performance
    println!("7. Boundary cases (55 vs 56 vs 64 bytes):");
    for &size in &[55, 56, 64] {
        let msg = vec![b'X'; size];
        let iterations = 1_000_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = sha1(&msg);
        }
        let duration = start.elapsed();

        println!(
            "   {} bytes: {:?} ({:.2} M hashes/s)",
            size,
            duration,
            iterations as f64 / duration.as_secs_f64() / 1_000_000.0
        );
    }
    println!();

    println!("=== Performance Notes ===");
    println!("- Messages ≤55 bytes use optimized single-block path");
    println!("- Empty messages use precomputed constant (fastest)");
    println!("- Incremental hashing has small overhead vs one-shot");
    println!("- Throughput peaks at ~1-4 KB message sizes");
    println!("- Cache line alignment helps with larger messages");
}
