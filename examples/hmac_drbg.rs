//! HMAC_DRBG (HMAC-based Deterministic Random Bit Generator) Examples
//!
//! This demonstrates the NIST SP 800-90A compliant HMAC_DRBG using HMAC-SHA256.
//!
//! Run with:
//! ```bash
//! cargo run --example hmac_drbg_example --features hmac-drbg
//! ```

use hpcrypt_rng::{Drbg, HmacDrbg};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HMAC_DRBG Examples ===\n");

    // Example 1: Create with OS entropy (recommended for production)
    println!("1. Creating HMAC_DRBG with OS entropy:");
    let mut drbg = HmacDrbg::new()?;
    let mut output = [0u8; 32];
    drbg.generate(&mut output)?;
    println!("   Generated 32 random bytes: {:02x?}...", &output[..8]);
    println!("   Security strength: {} bits\n", drbg.security_strength());

    // Example 2: Create from seed (deterministic, for testing)
    println!("2. Creating HMAC_DRBG from seed (deterministic):");
    let seed = [42u8; 32];
    let mut drbg1 = HmacDrbg::from_seed(&seed)?;
    let mut drbg2 = HmacDrbg::from_seed(&seed)?;

    let mut output1 = [0u8; 64];
    let mut output2 = [0u8; 64];

    drbg1.generate(&mut output1)?;
    drbg2.generate(&mut output2)?;

    println!("   Same seed produces same output: {}", output1 == output2);
    println!("   Output: {:02x?}...\n", &output1[..8]);

    // Example 3: Generate various sizes
    println!("3. Generating different output sizes:");
    let seed = [99u8; 32];
    let mut drbg = HmacDrbg::from_seed(&seed)?;

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
    println!("4. Reseeding HMAC_DRBG:");
    let seed = [1u8; 32];
    let mut drbg = HmacDrbg::from_seed(&seed)?;

    let mut output_before = [0u8; 32];
    drbg.generate(&mut output_before)?;
    println!("   Before reseed: {:02x?}...", &output_before[..8]);

    // Reseed with new entropy
    let new_entropy = [2u8; 32];
    drbg.reseed_with(&new_entropy)?;

    let mut output_after = [0u8; 32];
    drbg.generate(&mut output_after)?;
    println!("   After reseed:  {:02x?}...", &output_after[..8]);
    println!("   Outputs differ: {}\n", output_before != output_after);

    // Example 5: Reseed status checking
    println!("5. Checking reseed status:");
    let seed = [123u8; 32];
    let mut drbg = HmacDrbg::from_seed(&seed)?;

    println!("   Needs reseed initially: {}", drbg.needs_reseed());

    // Generate some data
    let mut output = [0u8; 256];
    drbg.generate(&mut output)?;

    println!("   Needs reseed after generation: {}", drbg.needs_reseed());
    println!("   (HMAC_DRBG has very high reseed interval: 2^48 requests)\n");

    // Example 6: Use case - Deterministic key derivation
    println!("6. Use case: Deterministic key derivation from master seed:");
    let master_seed = [77u8; 32]; // In production, this would be from secure storage
    let mut drbg = HmacDrbg::from_seed(&master_seed)?;

    // Derive multiple keys deterministically
    let mut encryption_key = [0u8; 32];
    let mut authentication_key = [0u8; 32];
    let mut iv = [0u8; 16];

    drbg.generate(&mut encryption_key)?;
    drbg.generate(&mut authentication_key)?;
    drbg.generate(&mut iv)?;

    println!("   Encryption key:     {:02x?}...", &encryption_key[..8]);
    println!("   Authentication key: {:02x?}...", &authentication_key[..8]);
    println!("   IV:                 {:02x?}...", &iv[..8]);
    println!("   All derived deterministically from master seed!\n");

    println!("=== HMAC_DRBG Advantages ===");
    println!("- NIST SP 800-90A Rev. 1 compliant");
    println!("- FIPS 140-2/3 approved algorithm");
    println!("- Simpler than CTR_DRBG (no block cipher needed)");
    println!("- Based on widely-trusted HMAC-SHA256");
    println!("- Used in OpenSSL, BoringSSL, TLS, and more");
    println!("- 256-bit security strength");
    println!("- Production-ready for cryptographic applications");

    Ok(())
}
