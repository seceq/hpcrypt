//! Simple profiling of public API
//! Run with: cargo run --release --example simple_profiling --features std,simd,avx2

use hpcrypt_mldsa::keygen::keygen_from_seed;
use hpcrypt_mldsa::ntt::{inv_ntt, ntt, ntt_multiply};
use hpcrypt_mldsa::params::MlDsa65;
use hpcrypt_mldsa::params::N;
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::sign::sign_deterministic;
use hpcrypt_mldsa::verify::verify;
use std::time::Instant;

fn measure<F, R>(_name: &str, iterations: usize, mut f: F) -> (R, u128)
where
    F: FnMut() -> R,
{
    // Warmup
    for _ in 0..5 {
        let _ = std::hint::black_box(f());
    }

    let start = Instant::now();
    let mut result = None;
    for _ in 0..iterations {
        result = Some(std::hint::black_box(f()));
    }
    let elapsed = start.elapsed();

    let avg_nanos = elapsed.as_nanos() / iterations as u128;
    (result.unwrap(), avg_nanos)
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║       ML-DSA Performance Profiling Analysis          ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    // Prepare test data
    let seed = [42u8; 32];
    let message = b"Test message for profiling";
    let rnd = [0u8; 32];

    println!("═══ HIGH-LEVEL OPERATIONS ═══\n");

    // Profile KeyGen
    let ((pk, sk), keygen_ns) = measure("KeyGen", 500, || keygen_from_seed::<MlDsa65>(&seed));
    println!(
        "  KeyGen:  {:12} ns ({:8.2} µs)",
        keygen_ns,
        keygen_ns as f64 / 1000.0
    );

    // Profile Sign
    let (sig, sign_ns) = measure("Sign", 200, || {
        sign_deterministic::<MlDsa65>(&sk, message, &rnd).unwrap()
    });
    println!(
        "  Sign:    {:12} ns ({:8.2} µs)",
        sign_ns,
        sign_ns as f64 / 1000.0
    );

    // Profile Verify
    let (_, verify_ns) = measure("Verify", 500, || verify::<MlDsa65>(&pk, message, &sig));
    println!(
        "  Verify:  {:12} ns ({:8.2} µs)",
        verify_ns,
        verify_ns as f64 / 1000.0
    );

    println!("\n═══ NTT OPERATIONS ═══\n");

    // Create test polynomial
    let mut test_poly = Poly::new();
    for i in 0..N {
        test_poly.coeffs[i] = (i as i32) * 7919 % 1000;
    }

    // Profile NTT forward
    let (ntt_poly, ntt_fwd_ns) = measure("NTT forward", 10000, || ntt(&test_poly));
    println!(
        "  NTT forward:         {:8} ns ({:6.2} µs)",
        ntt_fwd_ns,
        ntt_fwd_ns as f64 / 1000.0
    );

    // Profile NTT inverse
    let (_, ntt_inv_ns) = measure("NTT inverse", 10000, || inv_ntt(&ntt_poly));
    println!(
        "  NTT inverse:         {:8} ns ({:6.2} µs)",
        ntt_inv_ns,
        ntt_inv_ns as f64 / 1000.0
    );

    // Profile pointwise multiply
    let ntt_poly2 = ntt(&test_poly);
    let (_, ntt_mul_ns) = measure("NTT multiply", 10000, || {
        ntt_multiply(&ntt_poly, &ntt_poly2)
    });
    println!(
        "  NTT pointwise_mul:   {:8} ns ({:6.2} µs)",
        ntt_mul_ns,
        ntt_mul_ns as f64 / 1000.0
    );

    println!("\n═══ ANALYSIS ═══\n");

    // Calculate NTT percentage of total time
    let ntt_total_per_op = ntt_fwd_ns + ntt_inv_ns + ntt_mul_ns;

    println!("Estimated NTT operations per high-level call:");
    println!("  (These are rough estimates based on algorithm structure)");
    println!();

    // KeyGen estimates (expanding matrix A, computing s1_hat, s2_hat, t)
    let estimated_ntts_keygen = 50; // Very rough estimate
    let ntt_time_in_keygen = ntt_total_per_op * estimated_ntts_keygen;
    let ntt_pct_keygen = (ntt_time_in_keygen as f64 / keygen_ns as f64) * 100.0;
    println!(
        "  KeyGen:  ~{} NTT ops → ~{:.1}% of time",
        estimated_ntts_keygen, ntt_pct_keygen
    );

    // Sign estimates (matrix-vector mult, NTT transforms)
    let estimated_ntts_sign = 100; // Very rough estimate
    let ntt_time_in_sign = ntt_total_per_op * estimated_ntts_sign;
    let ntt_pct_sign = (ntt_time_in_sign as f64 / sign_ns as f64) * 100.0;
    println!(
        "  Sign:    ~{} NTT ops → ~{:.1}% of time",
        estimated_ntts_sign, ntt_pct_sign
    );

    // Verify estimates (matrix-vector mult, hint checking)
    let estimated_ntts_verify = 60; // Very rough estimate
    let ntt_time_in_verify = ntt_total_per_op * estimated_ntts_verify;
    let ntt_pct_verify = (ntt_time_in_verify as f64 / verify_ns as f64) * 100.0;
    println!(
        "  Verify:  ~{} NTT ops → ~{:.1}% of time",
        estimated_ntts_verify, ntt_pct_verify
    );

    println!("\n  NOTE: NTT operation counts are estimates.");
    println!("    Actual bottlenecks likely include:");
    println!("    - Rejection sampling (random poly generation)");
    println!("    - SHAKE256 hashing");
    println!("    - Polynomial coefficient operations");
    println!("    - Hint generation/checking");

    println!("\nOK Profiling complete!");

    // Print AVX2 status
    #[allow(unexpected_cfgs)]
    {
        #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                println!("\nOK AVX2 SIMD is ENABLED and being used for NTT operations");
            } else {
                println!("\nFAIL AVX2 SIMD is NOT available (using scalar fallback)");
            }
        }
        #[cfg(not(all(feature = "avx2", feature = "std", target_arch = "x86_64")))]
        {
            println!("\nFAIL SIMD features not enabled");
        }
    }
}
