//! HASH_DRBG (Hash-based Deterministic Random Bit Generator) Examples
//!
//! This demonstrates the NIST SP 800-90A compliant HASH_DRBG using SHA-256.
//!
//! Run with:
//! ```bash
//! cargo run --example hash_drbg_example --features hash-drbg
//! ```

use hpcrypt_rng::{Drbg, HashDrbg};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HASH_DRBG Examples ===\n");

    // Example 1: Create with OS entropy (recommended for production)
    println!("1. Creating HASH_DRBG with OS entropy:");
    let mut drbg = HashDrbg::new()?;
    let mut output = [0u8; 32];
    drbg.generate(&mut output)?;
    println!("   Generated 32 random bytes: {:02x?}...", &output[..8]);
    println!("   Security strength: {} bits\n", drbg.security_strength());

    // Example 2: Create from seed (deterministic, for testing)
    println!("2. Creating HASH_DRBG from seed (deterministic):");
    let seed = [42u8; 55]; // HASH_DRBG requires 55 bytes (440 bits)
    let mut drbg1 = HashDrbg::from_seed(&seed)?;
    let mut drbg2 = HashDrbg::from_seed(&seed)?;

    let mut output1 = [0u8; 64];
    let mut output2 = [0u8; 64];

    drbg1.generate(&mut output1)?;
    drbg2.generate(&mut output2)?;

    println!("   Same seed produces same output: {}", output1 == output2);
    println!("   Output: {:02x?}...\n", &output1[..8]);

    // Example 3: Generate various sizes
    println!("3. Generating different output sizes:");
    let seed = [99u8; 55];
    let mut drbg = HashDrbg::from_seed(&seed)?;

    let mut small = [0u8; 16];
    let mut medium = [0u8; 128];
    let mut large = [0u8; 1024];

    drbg.generate(&mut small)?;
    drbg.generate(&mut medium)?;
    drbg.generate(&mut large)?;

    println!("   Generated 16 bytes: {:02x?}...", &small[..8]);
    println!("   Generated 128 bytes: {:02x?}...", &medium[..8]);
    println!("   Generated 1024 bytes: {:02x?}...\n", &large[..8]);

    // Example 4: Reseeding with fresh entropy
    println!("4. Reseeding HASH_DRBG:");
    let seed = [1u8; 55];
    let mut drbg = HashDrbg::from_seed(&seed)?;

    let mut output_before = [0u8; 32];
    drbg.generate(&mut output_before)?;
    println!("   Before reseed: {:02x?}...", &output_before[..8]);

    // Reseed with new entropy
    let new_entropy = [2u8; 55];
    drbg.reseed_with(&new_entropy)?;

    let mut output_after = [0u8; 32];
    drbg.generate(&mut output_after)?;
    println!("   After reseed:  {:02x?}...", &output_after[..8]);
    println!("   Outputs differ: {}\n", output_before != output_after);

    // Example 5: Reseed status checking
    println!("5. Checking reseed status:");
    let seed = [123u8; 55];
    let mut drbg = HashDrbg::from_seed(&seed)?;

    println!("   Needs reseed initially: {}", drbg.needs_reseed());

    // Generate some data
    let mut output = [0u8; 256];
    drbg.generate(&mut output)?;

    println!("   Needs reseed after generation: {}", drbg.needs_reseed());
    println!("   (HASH_DRBG has very high reseed interval: 2^48 requests)\n");

    // Example 6: Use case - Deterministic session keys
    println!("6. Use case: Deterministic session key generation:");
    let master_seed = [77u8; 55]; // In production, this would be from secure storage
    let mut drbg = HashDrbg::from_seed(&master_seed)?;

    // Derive multiple session keys deterministically
    let mut session_key_1 = [0u8; 32];
    let mut session_key_2 = [0u8; 32];
    let mut session_key_3 = [0u8; 32];

    drbg.generate(&mut session_key_1)?;
    drbg.generate(&mut session_key_2)?;
    drbg.generate(&mut session_key_3)?;

    println!("   Session key 1: {:02x?}...", &session_key_1[..8]);
    println!("   Session key 2: {:02x?}...", &session_key_2[..8]);
    println!("   Session key 3: {:02x?}...", &session_key_3[..8]);
    println!("   All derived deterministically from master seed!\n");

    // Example 7: Comparing with other DRBGs
    println!("7. HASH_DRBG characteristics:");
    println!("   Seed length: 55 bytes (440 bits)");
    println!("   State size: 110 bytes (V + C)");
    println!("   Algorithm: SHA-256 hash function");
    println!("   Performance: Good (hash-based, no block cipher)");
    println!("   Dependencies: Only hash function (simplest)\n");

    println!("=== HASH_DRBG Advantages ===");
    println!("- NIST SP 800-90A Rev. 1 compliant");
    println!("- FIPS 140-2/3 approved algorithm");
    println!("- Simplest NIST DRBG (only requires hash function)");
    println!("- Based on widely-trusted SHA-256");
    println!("- No block cipher or MAC required");
    println!("- 256-bit security strength");
    println!("- Production-ready for cryptographic applications");
    println!("- Efficient for environments with hash acceleration");

    Ok(())
}
