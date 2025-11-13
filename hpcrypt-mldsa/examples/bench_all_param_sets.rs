//! Comprehensive benchmark for all ML-DSA parameter sets
//!
//! Measures signing and verification performance for ML-DSA-44, ML-DSA-65, and ML-DSA-87

use mldsa::keygen::keygen;
use mldsa::params::DsaParams;
use mldsa::sign;
use mldsa::verify::verify;
use mldsa::{MlDsa44, MlDsa65, MlDsa87};
use std::time::Instant;

fn benchmark_param_set<P: DsaParams>() -> (u128, u128) {
    // Generate keypair once
    let (pk, sk) = keygen::<P>();
    let message = b"Test message for ML-DSA parameter set benchmark";

    // Warm up
    for _ in 0..50 {
        let _ = sign::sign::<P>(&sk, message);
    }

    // Benchmark signing
    const ITERATIONS: usize = 1000;

    let start = Instant::now();
    let mut successful_signs = 0;
    for _ in 0..ITERATIONS {
        if sign::sign::<P>(&sk, message).is_some() {
            successful_signs += 1;
        }
    }
    let sign_elapsed = start.elapsed();
    let sign_avg_micros = sign_elapsed.as_micros() / ITERATIONS as u128;

    // Benchmark verification
    let sig = sign::sign::<P>(&sk, message).expect("Failed to generate signature");

    let start = Instant::now();
    let mut successful_verifies = 0;
    for _ in 0..ITERATIONS {
        if verify::<P>(&pk, message, &sig) {
            successful_verifies += 1;
        }
    }
    let verify_elapsed = start.elapsed();
    let verify_avg_micros = verify_elapsed.as_micros() / ITERATIONS as u128;

    assert_eq!(successful_signs, ITERATIONS, "Some signatures failed");
    assert_eq!(successful_verifies, ITERATIONS, "Some verifications failed");

    (sign_avg_micros, verify_avg_micros)
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║     ML-DSA Performance Benchmark - All Parameter Sets     ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ML-DSA-44
    println!("Benchmarking ML-DSA-44 (Security Level 2)...");
    let (sign_44, verify_44) = benchmark_param_set::<MlDsa44>();
    println!("  ✓ Complete\n");

    // ML-DSA-65
    println!("Benchmarking ML-DSA-65 (Security Level 3)...");
    let (sign_65, verify_65) = benchmark_param_set::<MlDsa65>();
    println!("  ✓ Complete\n");

    // ML-DSA-87
    println!("Benchmarking ML-DSA-87 (Security Level 5)...");
    let (sign_87, verify_87) = benchmark_param_set::<MlDsa87>();
    println!("  ✓ Complete\n");

    // Results table
    println!("════════════════════════════════════════════════════════════");
    println!("                    RESULTS SUMMARY                         ");
    println!("════════════════════════════════════════════════════════════\n");

    println!("┌────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│ Operation  │   ML-DSA-44  │   ML-DSA-65  │   ML-DSA-87  │");
    println!("├────────────┼──────────────┼──────────────┼──────────────┤");
    println!(
        "│ Sign (µs)  │  {:>10}  │  {:>10}  │  {:>10}  │",
        sign_44, sign_65, sign_87
    );
    println!(
        "│ Verify (µs)│  {:>10}  │  {:>10}  │  {:>10}  │",
        verify_44, verify_65, verify_87
    );
    println!("└────────────┴──────────────┴──────────────┴──────────────┘\n");

    println!("Throughput (operations/second):");
    println!("┌────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│ Operation  │   ML-DSA-44  │   ML-DSA-65  │   ML-DSA-87  │");
    println!("├────────────┼──────────────┼──────────────┼──────────────┤");
    println!(
        "│ Sign/s     │  {:>10.0}  │  {:>10.0}  │  {:>10.0}  │",
        1_000_000.0 / sign_44 as f64,
        1_000_000.0 / sign_65 as f64,
        1_000_000.0 / sign_87 as f64
    );
    println!(
        "│ Verify/s   │  {:>10.0}  │  {:>10.0}  │  {:>10.0}  │",
        1_000_000.0 / verify_44 as f64,
        1_000_000.0 / verify_65 as f64,
        1_000_000.0 / verify_87 as f64
    );
    println!("└────────────┴──────────────┴──────────────┴──────────────┘\n");

    // Relative performance
    println!("Relative Performance (vs ML-DSA-65):");
    println!("┌────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│ Operation  │   ML-DSA-44  │   ML-DSA-65  │   ML-DSA-87  │");
    println!("├────────────┼──────────────┼──────────────┼──────────────┤");
    println!(
        "│ Sign       │  {:>9.1}%  │     100.0%   │  {:>9.1}%  │",
        (sign_44 as f64 / sign_65 as f64) * 100.0,
        (sign_87 as f64 / sign_65 as f64) * 100.0
    );
    println!(
        "│ Verify     │  {:>9.1}%  │     100.0%   │  {:>9.1}%  │",
        (verify_44 as f64 / verify_65 as f64) * 100.0,
        (verify_87 as f64 / verify_65 as f64) * 100.0
    );
    println!("└────────────┴──────────────┴──────────────┴──────────────┘\n");

    println!("════════════════════════════════════════════════════════════");
    println!("Parameter Set Details:");
    println!("  ML-DSA-44: Security Level 2 (smallest, fastest)");
    println!("  ML-DSA-65: Security Level 3 (recommended)");
    println!("  ML-DSA-87: Security Level 5 (highest security)");
    println!("════════════════════════════════════════════════════════════");
}
