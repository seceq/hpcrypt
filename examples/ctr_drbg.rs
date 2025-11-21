//! Example: CTR_DRBG for NIST SP 800-90A Compliance
//!
//! This example demonstrates the NIST-approved CTR_DRBG (Counter mode
//! Deterministic Random Bit Generator) using AES-256.
//!
//! Run with:
//! ```bash
//! cargo run --example ctr_drbg_example --features ctr-drbg
//! ```

use hpcrypt_rng::{CtrDrbg, Drbg};

fn main() {
    println!("=== CTR_DRBG (NIST SP 800-90A Compliant) ===\n");

    // Example 1: Deterministic generation
    println!("1. NIST-Compliant Deterministic Generation:");
    deterministic_generation();
    println!();

    // Example 2: Production use with OS entropy
    println!("2. Production Use (OS Entropy):");
    production_use();
    println!();

    // Example 3: Periodic reseeding
    println!("3. Periodic Reseeding for Forward Secrecy:");
    periodic_reseeding();
    println!();

    // Example 4: FIPS-compliant key generation
    println!("4. FIPS-Compliant Key Generation:");
    fips_key_generation();
    println!();

    // Example 5: Security properties
    println!("5. NIST SP 800-90A Properties:");
    security_properties();
    println!();

    println!("=== Example Complete ===");
}

/// Example 1: Deterministic generation
fn deterministic_generation() {
    // Seed must be 48 bytes (384 bits) for CTR_DRBG
    let seed = [42u8; 48];

    let mut drbg1 = CtrDrbg::from_seed(&seed).expect("Failed to create DRBG");
    let mut drbg2 = CtrDrbg::from_seed(&seed).expect("Failed to create DRBG");

    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    drbg1.generate(&mut output1).expect("Generate failed");
    drbg2.generate(&mut output2).expect("Generate failed");

    println!("   Seed length:  48 bytes (384 bits)");
    println!("   Output 1: {:02x?}...", &output1[..8]);
    println!("   Output 2: {:02x?}...", &output2[..8]);
    println!(
        "   Identical: {}",
        if output1 == output2 { "Yes" } else { "No" }
    );
    println!("   Note: Deterministic: same seed always produces same output");
}

/// Example 2: Production use
fn production_use() {
    // Create with OS entropy (cryptographically secure)
    let mut drbg = CtrDrbg::new().expect("Failed to create DRBG");

    // Generate multiple keys
    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 64];
    let mut nonce = [0u8; 12];

    drbg.generate(&mut aes_key).expect("Generate failed");
    drbg.generate(&mut hmac_key).expect("Generate failed");
    drbg.generate(&mut nonce).expect("Generate failed");

    println!("   AES-256 key:  {:02x?}...", &aes_key[..8]);
    println!("   HMAC key:     {:02x?}...", &hmac_key[..8]);
    println!("   Nonce:        {:02x?}", nonce);
    println!("   Security:     {} bits", drbg.security_strength());
}

/// Example 3: Periodic reseeding
fn periodic_reseeding() {
    let seed = [1u8; 48];
    let mut drbg = CtrDrbg::from_seed(&seed).expect("Failed to create DRBG");

    println!("   Initial state:");
    println!("   Needs reseed: {}", drbg.needs_reseed());

    // Generate some data
    let mut data = [0u8; 1024];
    drbg.generate(&mut data).expect("Generate failed");
    println!("   Generated:    1024 bytes");

    // Reseed with fresh entropy
    let new_entropy = [99u8; 48];
    drbg.reseed_with(&new_entropy).expect("Reseed failed");

    println!("   After reseed:");
    println!("   Needs reseed: {}", drbg.needs_reseed());
    println!("   Note: Forward secrecy maintained through periodic reseeding");
}

/// Example 4: FIPS-compliant key generation
fn fips_key_generation() {
    println!("   Generating FIPS-approved cryptographic keys...");

    let mut drbg = CtrDrbg::new().expect("Failed to create DRBG");

    // Generate keys for various algorithms
    let key_purposes = [
        ("AES-128", 16),
        ("AES-256", 32),
        ("HMAC-SHA256", 32),
        ("ECDSA P-256", 32),
    ];

    for (purpose, size) in &key_purposes {
        let mut key = vec![0u8; *size];
        drbg.generate(&mut key).expect("Generate failed");

        println!("   {}: {:02x?}...", purpose, &key[..4]);
    }

    println!("   Note: All keys generated using NIST SP 800-90A approved DRBG");
}

/// Example 5: Security properties
fn security_properties() {
    let seed = [42u8; 48];
    let drbg = CtrDrbg::from_seed(&seed).expect("Failed to create DRBG");

    println!("   Algorithm:        AES-256-CTR");
    println!("   Standard:         NIST SP 800-90A Rev. 1");
    println!("   Security:         {} bits", drbg.security_strength());
    println!("   FIPS 140-2/3:     Approved");
    println!("   Key size:         256 bits");
    println!("   Counter size:     128 bits");
    println!("   Seed size:        384 bits (48 bytes)");
    println!("   Max request:      64 KB");
    println!("   Reseed interval:  2^48 blocks");
    println!();
    println!("   Compliance:");
    println!("   - NIST SP 800-90A compliant");
    println!("   - FIPS 140-2/3 approved algorithm");
    println!("   - Suitable for government/enterprise use");
    println!("   - Deterministic (reproducible from seed)");
    println!("   - Forward secrecy (state updated after each use)");
    println!("   - Prediction resistance (with periodic reseeding)");
}
