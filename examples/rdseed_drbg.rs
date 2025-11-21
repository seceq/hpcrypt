//! RDSEED-DRBG Example
//!
//! This example demonstrates the use of the RDSEED-based DRBG,
//! which provides raw hardware entropy using Intel's RDSEED instruction.
//!
//! Run with:
//! ```bash
//! cargo run --example rdseed_drbg --features rdseed-drbg
//! ```

use hpcrypt_rng::drbg::{Drbg, RdseedDrbg};

fn main() {
    println!("=== RDSEED-DRBG Example ===\n");

    // Check if RDSEED is available
    if !RdseedDrbg::is_available() {
        println!("Warning: RDSEED instruction not supported on this CPU");
        println!("Required: Intel Broadwell (2014+) or AMD Zen (2017+)");
        return;
    }

    println!("- RDSEED instruction is available\n");

    // Create RDSEED-based DRBG
    let mut drbg = RdseedDrbg::new().expect("Failed to create RDSEED DRBG");

    println!("=== Basic Usage ===\n");

    // Generate master seed for other DRBGs
    let mut master_seed = [0u8; 32];
    drbg.generate(&mut master_seed)
        .expect("Generation failed");
    println!("Master seed (32 bytes): {}", hex_encode(&master_seed));

    // Generate long-term key
    let mut ltk = [0u8; 32];
    drbg.generate(&mut ltk).expect("Generation failed");
    println!("Long-term key (32 bytes): {}", hex_encode(&ltk));

    println!("\n=== DRBG Properties ===\n");

    println!("Security strength: {} bits", drbg.security_strength());
    println!("Needs reseed: {}", drbg.needs_reseed());
    println!("Entropy type: Raw hardware entropy (not conditioned)");

    println!("\n=== Performance Characteristics ===\n");

    println!("Warning: Much slower than RDRAND (100-1000x)");
    println!("Warning: Limited by entropy pool refill rate");
    println!("Warning: May block waiting for entropy");
    println!("- Best for infrequent, high-security uses");
    println!("- Ideal for seeding other DRBGs");

    println!("\n=== Security Considerations ===\n");

    println!("Strengths:");
    println!("  - Raw entropy from hardware source");
    println!("  - Not conditioned (full entropy)");
    println!("  - NIST SP 800-90B compliant");
    println!("  - Highest quality randomness available");
    println!("  - Each call gets fresh entropy");

    println!("\nWeaknesses:");
    println!("  Warning: Still requires trust in Intel hardware");
    println!("  Warning: Much slower than RDRAND");
    println!("  Warning: May fail under heavy load");

    println!("\nRecommendations:");
    println!("  Note: Use for long-term cryptographic keys");
    println!("  Note: Seed other DRBGs with RDSEED");
    println!("  Note: Mix with OS RNG for defense in depth");
    println!("  Note: Avoid for high-throughput applications");

    println!("\n=== Use Case: Seeding ChaCha20-DRBG ===\n");

    // Generate seed for ChaCha20-DRBG
    let mut chacha_seed = [0u8; 32];
    drbg.generate(&mut chacha_seed)
        .expect("Generation failed");
    println!("ChaCha20-DRBG seed: {}", hex_encode(&chacha_seed));
    println!("- This seed can be used to initialize a ChaCha20-DRBG");

    println!("\n=== Use Case: Master Key Generation ===\n");

    // Generate master keys for key hierarchy
    println!("Generating master keys for key derivation hierarchy...");

    for i in 1..=3 {
        let mut master_key = [0u8; 32];
        drbg.generate(&mut master_key)
            .expect("Generation failed");
        println!("Master Key {}: {}", i, hex_encode(&master_key[..16]));
    }

    println!("\n=== RDSEED vs RDRAND ===\n");

    println!("RDSEED:");
    println!("  • Raw entropy from hardware");
    println!("  • Not conditioned");
    println!("  • 256-bit security strength");
    println!("  • Slower (entropy pool limited)");
    println!("  • Best for seeds and long-term keys");

    println!("\nRDRAND:");
    println!("  • Conditioned output (AES-CTR-DRBG)");
    println!("  • 128-bit security strength");
    println!("  • Much faster (~3 billion samples/sec)");
    println!("  • Best for nonces, IVs, session keys");
    println!("  • Automatically seeded from RDSEED");

    println!("\n=== Best Practices ===\n");

    println!("1. Use RDSEED for:");
    println!("   • Seeding other DRBGs");
    println!("   • Master keys in key hierarchies");
    println!("   • Long-term cryptographic keys");
    println!("   • Critical secrets");

    println!("\n2. Use RDRAND for:");
    println!("   • Nonces and IVs");
    println!("   • Session keys");
    println!("   • High-throughput applications");
    println!("   • Temporary randomness");

    println!("\n3. Defense in depth:");
    println!("   • Mix RDSEED/RDRAND with OS RNG");
    println!("   • XOR different entropy sources");
    println!("   • Don't trust single entropy source");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
