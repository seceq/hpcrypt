//! Performance benchmarks for ML-DSA operations
//!
//! Run with: cargo bench

use mldsa::keygen::keygen;
use mldsa::params::{MlDsa44, MlDsa65, MlDsa87};
use mldsa::sign::sign;
use mldsa::verify::verify;
use std::time::Instant;

fn benchmark_keygen<P: mldsa::params::DsaParams>(name: &str) {
    println!("\n=== {} KeyGen Benchmark ===", name);

    let start = Instant::now();
    let (_pk, _sk) = keygen::<P>();
    let duration = start.elapsed();

    println!("Time: {:.2?}", duration);
}

fn benchmark_sign<P: mldsa::params::DsaParams>(name: &str) {
    println!("\n=== {} Sign Benchmark ===", name);

    let (_pk, sk) = keygen::<P>();
    let message = b"Hello, ML-DSA!";

    let start = Instant::now();
    let _sig = sign(&sk, message).expect("Signing failed");
    let duration = start.elapsed();

    println!("Time: {:.2?}", duration);
}

fn benchmark_verify<P: mldsa::params::DsaParams>(name: &str) {
    println!("\n=== {} Verify Benchmark ===", name);

    let (pk, sk) = keygen::<P>();
    let message = b"Hello, ML-DSA!";
    let sig = sign(&sk, message).expect("Signing failed");

    let start = Instant::now();
    let valid = verify(&pk, message, &sig);
    let duration = start.elapsed();

    assert!(valid, "Signature verification failed");
    println!("Time: {:.2?}", duration);
}

fn main() {
    println!("ML-DSA Performance Benchmarks");
    println!("==============================");
    println!("Note: Using schoolbook O(n²) multiplication");
    println!("Expected speedup with NTT: 100-1000x");

    // ML-DSA-44
    benchmark_keygen::<MlDsa44>("ML-DSA-44");
    benchmark_sign::<MlDsa44>("ML-DSA-44");
    benchmark_verify::<MlDsa44>("ML-DSA-44");

    // ML-DSA-65
    benchmark_keygen::<MlDsa65>("ML-DSA-65");
    benchmark_sign::<MlDsa65>("ML-DSA-65");
    benchmark_verify::<MlDsa65>("ML-DSA-65");

    // ML-DSA-87 (commented out - very slow)
    // benchmark_keygen::<MlDsa87>("ML-DSA-87");
    // benchmark_sign::<MlDsa87>("ML-DSA-87");
    // benchmark_verify::<MlDsa87>("ML-DSA-87");

    println!("\n==============================");
    println!("Benchmarks complete!");
}
