//! Example demonstrating batch signing API
//!
//! This example shows how to use the batch signing functions for improved
//! throughput when processing multiple signature operations.
//!
//! Run with:
//! ```
//! cargo run --release --example batch_signing --features avx2,simd
//! ```

use mldsa::keygen::keygen;
use mldsa::params::MlDsa65;
use mldsa::{sign_batch, verify_batch};
use std::time::Instant;

fn main() {
    println!("ML-DSA Batch Signing Example");
    println!("==============================\n");

    // Generate keypair
    println!("Generating ML-DSA-65 keypair...");
    let (pk, sk) = keygen::<MlDsa65>();
    println!("✓ Keypair generated\n");

    // Create batch of messages
    let batch_sizes = [1, 4, 8, 16, 32];

    for &batch_size in &batch_sizes {
        println!("Batch size: {}", batch_size);

        // Prepare messages
        let messages: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| format!("Message number {}", i).into_bytes())
            .collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        // Time batch signing
        let start = Instant::now();
        let signatures = sign_batch(&sk, &msg_refs);
        let sign_time = start.elapsed();

        // Verify all signatures succeeded
        let success_count = signatures.iter().filter(|s| s.is_some()).count();
        println!("  Signing: {} signatures in {:?}", success_count, sign_time);
        println!(
            "  Throughput: {:.0} signs/sec",
            batch_size as f64 / sign_time.as_secs_f64()
        );

        // Time batch verification
        let sig_refs: Vec<_> = signatures.iter().map(|s| s.as_ref().unwrap()).collect();

        let start = Instant::now();
        let results = verify_batch(&pk, &msg_refs, &sig_refs);
        let verify_time = start.elapsed();

        let valid_count = results.iter().filter(|&&r| r).count();
        println!("  Verification: {} valid in {:?}", valid_count, verify_time);
        println!(
            "  Throughput: {:.0} verifications/sec",
            batch_size as f64 / verify_time.as_secs_f64()
        );
        println!();
    }

    println!("\nBatch API Notes:");
    println!("- Current implementation: Simple loop (baseline)");
    println!("- Future optimization: Vectorized batch operations");
    println!("- Expected future improvement: 15-30% for batches of 8-32");
    println!("- Best use case: Server workloads processing multiple requests");
}
