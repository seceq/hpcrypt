//! Example: ChaCha20-DRBG for Deterministic Random Generation
//!
//! This example demonstrates how to use the ChaCha20-based Deterministic
//! Random Bit Generator for reproducible randomness and testing.
//!
//! Run with:
//! ```bash
//! cargo run --example chacha20_drbg_example --features chacha20-drbg
//! ```

use hpcrypt_rng::{ChaCha20Drbg, Drbg};

fn main() {
    println!("=== ChaCha20-DRBG (Deterministic Random Bit Generator) ===\n");

    // Example 1: Reproducible randomness with seed
    println!("1. Deterministic Generation (Same Seed = Same Output):");
    reproducible_random();
    println!();

    // Example 2: Creating DRBG with OS entropy
    println!("2. DRBG with OS Entropy (Production Use):");
    os_entropy_drbg();
    println!();

    // Example 3: Reseeding for forward secrecy
    println!("3. Reseeding for Forward Secrecy:");
    reseeding_example();
    println!();

    // Example 4: Use case - Reproducible test fixtures
    println!("4. Use Case: Reproducible Test Fixtures:");
    test_fixture_example();
    println!();

    // Example 5: Use case - Hierarchical key derivation
    println!("5. Use Case: Hierarchical Key Derivation:");
    hierarchical_keys_example();
    println!();

    // Example 6: Security properties
    println!("6. Security Properties:");
    security_properties();
    println!();

    println!("=== Example Complete ===");
}

/// Example 1: Reproducible randomness
fn reproducible_random() {
    let seed = [42u8; 32];

    // First DRBG instance
    let mut drbg1 = ChaCha20Drbg::from_seed(&seed).expect("Failed to create DRBG");
    let mut output1 = [0u8; 16];
    drbg1.generate(&mut output1).expect("Generate failed");

    // Second DRBG instance with same seed
    let mut drbg2 = ChaCha20Drbg::from_seed(&seed).expect("Failed to create DRBG");
    let mut output2 = [0u8; 16];
    drbg2.generate(&mut output2).expect("Generate failed");

    println!("   Seed:     {:02x?}...", &seed[..4]);
    println!("   Output 1: {:02x?}", output1);
    println!("   Output 2: {:02x?}", output2);
    println!(
        "   Identical: {}",
        if output1 == output2 { "Yes" } else { "No" }
    );
}

/// Example 2: DRBG with OS entropy
fn os_entropy_drbg() {
    // Create with OS entropy (cryptographically secure)
    let mut drbg = ChaCha20Drbg::new().expect("Failed to create DRBG");

    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];

    drbg.generate(&mut key1).expect("Generate failed");
    drbg.generate(&mut key2).expect("Generate failed");

    println!("   Key 1: {:02x?}...", &key1[..8]);
    println!("   Key 2: {:02x?}...", &key2[..8]);
    println!(
        "   Different: {}",
        if key1 != key2 { "Yes" } else { "No" }
    );
    println!("   Security Strength: {} bits", drbg.security_strength());
}

/// Example 3: Reseeding
fn reseeding_example() {
    let seed = [1u8; 32];
    let mut drbg = ChaCha20Drbg::from_seed(&seed).expect("Failed to create DRBG");

    // Generate before reseed
    let mut before = [0u8; 16];
    drbg.generate(&mut before).expect("Generate failed");

    println!("   Before reseed: {:02x?}", before);
    println!("   Needs reseed:  {}", drbg.needs_reseed());

    // Reseed with new entropy
    let new_entropy = [99u8; 32];
    drbg.reseed_with(&new_entropy).expect("Reseed failed");

    // Generate after reseed
    let mut after = [0u8; 16];
    drbg.generate(&mut after).expect("Generate failed");

    println!("   After reseed:  {:02x?}", after);
    println!(
        "   Different:     {}",
        if before != after { "Yes" } else { "No" }
    );
}

/// Example 4: Reproducible test fixtures
fn test_fixture_example() {
    println!("   Generating test data for unit tests...");

    // Each test can have its own seed
    let test_seeds = [
        ("test_encryption", [1u8; 32]),
        ("test_signing", [2u8; 32]),
        ("test_key_exchange", [3u8; 32]),
    ];

    for (test_name, seed) in &test_seeds {
        let mut drbg = ChaCha20Drbg::from_seed(seed).expect("Failed to create DRBG");

        // Generate test key
        let mut test_key = [0u8; 32];
        drbg.generate(&mut test_key).expect("Generate failed");

        println!(
            "   {}: {:02x?}...",
            test_name,
            &test_key[..4]
        );
    }

    println!("   Note: Same seeds always produce same test data");
}

/// Example 5: Hierarchical key derivation
fn hierarchical_keys_example() {
    println!("   Master seed -> Multiple derived keys:");

    // Master seed (e.g., from password or root key)
    let master_seed = [42u8; 32]; // Fixed-size seed
    let mut master_drbg =
        ChaCha20Drbg::from_seed(&master_seed).expect("Failed to create DRBG");

    // Derive child keys for different purposes
    let purposes = ["encryption", "signing", "authentication"];

    for purpose in &purposes {
        // Create context-specific seed
        let mut context_seed = [0u8; 32];
        master_drbg.generate(&mut context_seed).expect("Generate failed");

        // Create child DRBG
        let mut child_drbg =
            ChaCha20Drbg::from_seed(&context_seed).expect("Failed to create DRBG");

        // Generate purpose-specific key
        let mut purpose_key = [0u8; 32];
        child_drbg
            .generate(&mut purpose_key)
            .expect("Generate failed");

        println!(
            "   {} key: {:02x?}...",
            purpose,
            &purpose_key[..4]
        );
    }

    println!("   Note: Hierarchical derivation from single master seed");
}

/// Example 6: Security properties
fn security_properties() {
    let seed = [42u8; 32];
    let mut drbg = ChaCha20Drbg::from_seed(&seed).expect("Failed to create DRBG");

    println!("   Security Strength:  {} bits", drbg.security_strength());
    println!("   Algorithm:          ChaCha20 stream cipher");
    println!("   State Size:         384 bits (256-bit key + 128-bit nonce)");
    println!("   Max Request Size:   4 GB");
    println!("   Reseed Interval:    281 TB");
    println!();
    println!("   Properties:");
    println!("   - Deterministic (same seed -> same output)");
    println!("   - Forward secrecy (state updated after each use)");
    println!("   - Backtracking resistance (can't recover past state)");
    println!("   - Constant-time operations");
    println!("   - No hardware dependencies");
    println!();

    // Demonstrate forward secrecy
    let mut out1 = [0u8; 16];
    let mut out2 = [0u8; 16];
    let mut out3 = [0u8; 16];

    drbg.generate(&mut out1).expect("Generate failed");
    drbg.generate(&mut out2).expect("Generate failed");
    drbg.generate(&mut out3).expect("Generate failed");

    println!("   Forward Secrecy Demonstration:");
    println!("   Output 1: {:02x?}", &out1[..8]);
    println!("   Output 2: {:02x?}", &out2[..8]);
    println!("   Output 3: {:02x?}", &out3[..8]);
    println!("   Note: All different (state updated after each generation)");
}
