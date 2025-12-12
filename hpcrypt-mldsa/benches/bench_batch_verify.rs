//! Batch Verification Benchmark
//!
//! This benchmark compares individual verification vs batch verification
//! to establish baseline performance and measure optimization benefits.
//!
//! Research shows batch verification can provide ~28% improvement for
//! Dilithium/ML-DSA verification.
//!
//! Run with: cargo bench --bench bench_batch_verify

use hpcrypt_mldsa::batch::verify_batch;
use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::MlDsa65;
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::sign::Signature;
use hpcrypt_mldsa::verify::verify;
use std::time::Instant;

fn benchmark_individual_verify(num_signatures: usize) -> std::time::Duration {
    println!(
        "\n=== Individual Verification ({} signatures) ===",
        num_signatures
    );

    // Setup
    let (pk, sk) = keygen::<MlDsa65>();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for i in 0..num_signatures {
        let msg = format!("Test message {}", i);
        messages.push(msg);
    }

    // Sign all messages
    for msg in &messages {
        let sig = sign(&sk, msg.as_bytes()).expect("Signing failed");
        signatures.push(sig);
    }

    // Benchmark individual verification
    let start = Instant::now();
    for (msg, sig) in messages.iter().zip(signatures.iter()) {
        let valid = verify(&pk, msg.as_bytes(), sig);
        assert!(valid, "Signature verification failed");
    }
    let duration = start.elapsed();

    let avg_time = duration / num_signatures as u32;
    println!("Total time: {:.2?}", duration);
    println!("Average per signature: {:.2?}", avg_time);
    println!(
        "Throughput: {:.0} verifications/sec",
        num_signatures as f64 / duration.as_secs_f64()
    );

    duration
}

fn benchmark_batch_verify(num_signatures: usize) -> std::time::Duration {
    println!(
        "\n=== Batch Verification ({} signatures) ===",
        num_signatures
    );

    // Setup
    let (pk, sk) = keygen::<MlDsa65>();
    let mut messages = Vec::new();
    let mut signatures = Vec::new();

    for i in 0..num_signatures {
        let msg = format!("Test message {}", i);
        messages.push(msg);
    }

    // Sign all messages
    for msg in &messages {
        let sig = sign(&sk, msg.as_bytes()).expect("Signing failed");
        signatures.push(sig);
    }

    // Prepare references for batch verification
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_bytes()).collect();
    let sig_refs: Vec<&Signature<MlDsa65>> = signatures.iter().collect();

    // Benchmark batch verification
    let start = Instant::now();
    let results = verify_batch(&pk, &msg_refs, &sig_refs);
    let duration = start.elapsed();

    // Verify all passed
    assert!(
        results.iter().all(|&r| r),
        "Some signatures failed verification"
    );

    let avg_time = duration / num_signatures as u32;
    println!("Total time: {:.2?}", duration);
    println!("Average per signature: {:.2?}", avg_time);
    println!(
        "Throughput: {:.0} verifications/sec",
        num_signatures as f64 / duration.as_secs_f64()
    );

    duration
}

fn compare_verification_methods(batch_sizes: &[usize]) {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║         Batch Verification Performance Comparison             ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    println!(
        "\n{:>10} {:>15} {:>15} {:>12}",
        "Batch Size", "Individual", "Batch", "Speedup"
    );
    println!("{}", "─".repeat(70));

    for &size in batch_sizes {
        let individual_time = benchmark_individual_verify(size);
        let batch_time = benchmark_batch_verify(size);

        let speedup = individual_time.as_secs_f64() / batch_time.as_secs_f64();

        println!(
            "{:>10} {:>15.2?} {:>15.2?} {:>11.2}x",
            size, individual_time, batch_time, speedup
        );
    }
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║          ML-DSA Batch Verification Benchmark                  ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!("\nPurpose: Establish baseline and measure batch verification gains");
    println!("Research target: ~28% improvement for batch verification");
    println!("Parameter set: ML-DSA-65");

    // Test various batch sizes
    let batch_sizes = vec![2, 4, 8, 16, 32];

    compare_verification_methods(&batch_sizes);

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                    Benchmark Complete                         ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!("\nNote: Current batch implementation is a simple loop.");
    println!("If speedup ≈ 1.0x, optimization opportunity exists.");
    println!("Target: Implement optimized batch verification for ~28% gain.");
}
