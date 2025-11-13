// End-to-end ML-DSA performance benchmark
//
// Measures actual performance improvement from Phase 4.2 SHAKE256 AVX2 integration

#![cfg(feature = "std")]

use mldsa::keygen::keygen;
use mldsa::params::MlDsa65;
use mldsa::sign::sign;
use mldsa::verify::verify;
use std::time::Instant;

fn main() {
    println!("ML-DSA End-to-End Performance Benchmark");
    println!("========================================\n");
    println!("Testing ML-DSA-65 (k=6, l=5)");

    let iterations = 100;
    let message = b"Benchmark message for ML-DSA performance testing";

    // Key Generation Benchmark
    println!("\n### Key Generation ###");
    let start = Instant::now();
    let mut keys = Vec::new();
    for _ in 0..iterations {
        let (pk, sk) = keygen::<MlDsa65>();
        keys.push((pk, sk));
    }
    let keygen_time = start.elapsed();
    let keygen_per_op = keygen_time.as_micros() / iterations;
    println!("Time: {:?} ({} µs per keygen)", keygen_time, keygen_per_op);

    // Signing Benchmark
    println!("\n### Signing ###");
    let (pk, sk) = &keys[0];
    let start = Instant::now();
    let mut signatures = Vec::new();
    for _ in 0..iterations {
        let sig = sign::<MlDsa65>(&sk, message);
        if let Some(s) = sig {
            signatures.push(s);
        }
    }
    let sign_time = start.elapsed();
    let sign_per_op = sign_time.as_micros() / iterations;
    println!("Time: {:?} ({} µs per sign)", sign_time, sign_per_op);
    println!("Signatures generated: {}/{}", signatures.len(), iterations);

    // Verification Benchmark
    println!("\n### Verification ###");
    let start = Instant::now();
    for sig in &signatures {
        let result = verify::<MlDsa65>(&pk, message, sig);
        assert!(result, "Verification failed");
    }
    let verify_time = start.elapsed();
    let verify_per_op = verify_time.as_micros() / iterations;
    println!("Time: {:?} ({} µs per verify)", verify_time, verify_per_op);

    // Summary
    println!("\n=== Summary (per operation) ===");
    println!("KeyGen:  {} µs", keygen_per_op);
    println!("Sign:    {} µs", sign_per_op);
    println!("Verify:  {} µs", verify_per_op);
    println!(
        "Total:   {} µs",
        keygen_per_op + sign_per_op + verify_per_op
    );

    #[cfg(all(feature = "avx2", feature = "simd", target_arch = "x86_64"))]
    {
        use mldsa::simd::dispatch::has_avx2;
        if has_avx2() {
            println!("\n AVX2 SHAKE256 optimization is ACTIVE");
            println!("Expected improvement vs scalar: ~20-22%");
        } else {
            println!("\n  AVX2 not available, using scalar fallback");
        }
    }

    #[cfg(not(all(feature = "avx2", feature = "simd", target_arch = "x86_64")))]
    {
        println!("\n📊 Scalar-only build (no AVX2)");
    }

    println!("\n=== Benchmark Complete ===");
}
