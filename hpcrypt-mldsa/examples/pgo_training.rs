// PGO Training Workload for ML-DSA
//
// This program exercises all major code paths to generate representative
// profiling data for Profile-Guided Optimization.
//
// Usage:
//   1. Build with instrumentation: RUSTFLAGS="-C profile-generate=/tmp/pgo-data" cargo run --release --example pgo_training
//   2. Run this program to collect profile data
//   3. Merge profiles: llvm-profdata merge -o /tmp/merged.profdata /tmp/pgo-data
//   4. Build with PGO: RUSTFLAGS="-C profile-use=/tmp/merged.profdata" cargo build --release

use mldsa::keygen::keygen;
use mldsa::params::{MlDsa44, MlDsa65, MlDsa87};
use mldsa::sign::sign;
use mldsa::verify::verify;

fn main() {
    println!("═══════════════════════════════════════════════════════");
    println!("    ML-DSA PGO Training Workload");
    println!("═══════════════════════════════════════════════════════");
    println!();

    // Train on all security levels to cover all code paths
    train_security_level::<MlDsa44>("ML-DSA-44");
    train_security_level::<MlDsa65>("ML-DSA-65");
    train_security_level::<MlDsa87>("ML-DSA-87");

    println!();
    println!("✓ PGO training workload complete!");
    println!();
    println!("Next steps:");
    println!("  1. Merge profiles: llvm-profdata merge -o /tmp/merged.profdata /tmp/pgo-data");
    println!("  2. Build with PGO: RUSTFLAGS=\"-C profile-use=/tmp/merged.profdata\" cargo build --release --features avx2");
}

/// Train on a specific security level
fn train_security_level<P: mldsa::params::DsaParams>(level_name: &str) {
    println!("Training on {}...", level_name);

    // Generate multiple keypairs to exercise keygen paths
    println!("  - KeyGen (100 iterations)...");
    let mut keypairs = Vec::new();
    for i in 0..100 {
        let (pk, sk) = keygen::<P>();
        if i < 5 {
            keypairs.push((pk, sk)); // Keep some for signing
        }
    }

    // Sign with various message sizes to exercise all signing paths
    println!("  - Sign (500 iterations, various message sizes)...");
    let messages = [
        vec![0u8; 0],       // Empty message
        vec![0u8; 1],       // Single byte
        vec![0u8; 32],      // Small message (hash size)
        vec![0x42u8; 64],   // Medium message
        vec![0xAAu8; 256],  // Large message
        vec![0x55u8; 1024], // Very large message
        vec![0xFFu8; 4096], // Extra large message
    ];

    let mut signatures = Vec::new();
    for (pk, sk) in &keypairs {
        for msg in &messages {
            for _ in 0..14 {
                // 5 keypairs × 7 messages × 14 = ~490 signatures
                let sig = sign(sk, msg).expect("Signing failed");
                signatures.push((pk.clone(), sig, msg.clone()));
            }
        }
    }

    // Verify signatures to exercise verification paths
    println!("  - Verify (500 iterations)...");
    for (pk, sig, msg) in signatures.iter() {
        // Verify correct signature
        let result = verify(pk, msg, sig);
        assert!(result, "Valid signature verification failed");
    }

    // Exercise edge cases
    println!("  - Edge cases...");

    // Boundary messages
    let boundary_sizes = [
        0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    ];
    let (test_pk, test_sk) = &keypairs[0];
    for size in boundary_sizes {
        let msg = vec![0xCCu8; size];
        let sig = sign(test_sk, &msg).expect("Signing failed");
        let result = verify(test_pk, &msg, &sig);
        assert!(result);
    }

    // Different byte patterns
    let patterns = [
        vec![0x00u8; 64], // All zeros
        vec![0xFFu8; 64], // All ones
        vec![0x55u8; 64], // Alternating 01010101
        vec![0xAAu8; 64], // Alternating 10101010
    ];
    for pattern in &patterns {
        let sig = sign(test_sk, pattern).expect("Signing failed");
        let result = verify(test_pk, pattern, &sig);
        assert!(result);
    }

    // Incremental byte patterns (exercises rejection sampling)
    for start_byte in 0..=255u8 {
        if start_byte % 16 == 0 {
            // Sample every 16th to keep workload reasonable
            let msg: Vec<u8> = (0..64).map(|i| start_byte.wrapping_add(i as u8)).collect();
            let _sig = sign(test_sk, &msg).expect("Signing failed");
            // Don't verify all to save time
        }
    }

    println!("  ✓ {} training complete", level_name);
    println!();
}
