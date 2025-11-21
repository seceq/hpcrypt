//! RDRAND-DRBG Example
//!
//! This example demonstrates the use of the RDRAND-based DRBG,
//! which provides hardware-accelerated random number generation using
//! Intel's RDRAND instruction.
//!
//! Run with:
//! ```bash
//! cargo run --example rdrand_drbg --features rdrand-drbg
//! ```

use hpcrypt_rng::drbg::{Drbg, RdrandDrbg};

fn main() {
    println!("=== RDRAND-DRBG Example ===\n");

    // Check if RDRAND is available
    if !RdrandDrbg::is_available() {
        println!("Warning: RDRAND instruction not supported on this CPU");
        println!("Required: Intel Ivy Bridge (2012+) or AMD Excavator (2015+)");
        return;
    }

    println!("- RDRAND instruction is available\n");

    // Create RDRAND-based DRBG
    let mut drbg = RdrandDrbg::new().expect("Failed to create RDRAND DRBG");

    println!("=== Basic Usage ===\n");

    // Generate random bytes
    let mut key = [0u8; 32];
    drbg.generate(&mut key).expect("Generation failed");
    println!("Generated key (32 bytes): {}", hex_encode(&key));

    // Generate nonce
    let mut nonce = [0u8; 12];
    drbg.generate(&mut nonce).expect("Generation failed");
    println!("Generated nonce (12 bytes): {}", hex_encode(&nonce));

    println!("\n=== DRBG Properties ===\n");

    println!("Security strength: {} bits", drbg.security_strength());
    println!("Needs reseed: {}", drbg.needs_reseed());
    println!(
        "Auto-reseeding: Hardware automatically reseeds from RDSEED"
    );

    println!("\n=== Performance Characteristics ===\n");

    println!("- Very fast (~3 billion samples/second)");
    println!("- ~0.1 ns per byte on modern CPUs");
    println!("- Much faster than OS RNG for small buffers");
    println!("- Suitable for high-throughput applications");

    println!("\n=== Security Considerations ===\n");

    println!("Strengths:");
    println!("  - Hardware-based (protected from software attacks)");
    println!("  - Constant-time operation");
    println!("  - NIST SP 800-90A compliant");
    println!("  - Validated by third-party audits");

    println!("\nWeaknesses:");
    println!("  Warning: Closed-source design (Intel proprietary)");
    println!("  Warning: Requires trust in Intel hardware");
    println!("  Warning: Single entropy source");

    println!("\nRecommendations:");
    println!("  Note: Use for nonces, IVs, session keys");
    println!("  Note: Mix with OS RNG for critical long-term keys");
    println!("  Note: Good for performance-critical paths");

    println!("\n=== Generating Multiple Values ===\n");

    for i in 1..=5 {
        let mut value = [0u8; 16];
        drbg.generate(&mut value).expect("Generation failed");
        println!("Value {}: {}", i, hex_encode(&value));
    }

    println!("\n=== Reseed Test ===\n");

    // Test reseeding (no-op for RDRAND, but demonstrates interface)
    println!("Calling reseed()...");
    drbg.reseed().expect("Reseed failed");
    println!("- Reseed completed (hardware manages entropy automatically)");

    // Generate after reseed
    let mut post_reseed = [0u8; 32];
    drbg.generate(&mut post_reseed).expect("Generation failed");
    println!(
        "Post-reseed generation: {}",
        hex_encode(&post_reseed[..16])
    );

    println!("\n=== Comparison with OS RNG ===\n");

    println!("RDRAND advantages:");
    println!("  • Much faster for small buffers");
    println!("  • No syscall overhead");
    println!("  • Hardware-protected state");

    println!("\nOS RNG advantages:");
    println!("  • Open-source entropy mixing");
    println!("  • Multiple entropy sources");
    println!("  • Better for defense in depth");

    println!("\nBest practice: Mix both sources for critical keys");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
