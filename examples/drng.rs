//! Intel DRNG (Digital Random Number Generator) Example
//!
//! This example demonstrates the use of Intel's hardware random number generator
//! using RDRAND and RDSEED through the DRBG interface.
//!
//! Run with:
//! ```bash
//! cargo run --example drng --features rdrand-drbg,rdseed-drbg
//! ```

use hpcrypt_rng::drbg::{Drbg, RdrandDrbg, RdseedDrbg};

fn main() {
    println!("=== Intel DRNG Hardware Support ===\n");

    // Check hardware support
    let rdrand_available = RdrandDrbg::is_available();
    let rdseed_available = RdseedDrbg::is_available();

    println!("RDRAND support: {}", if rdrand_available { "-" } else { "-" });
    println!("RDSEED support: {}", if rdseed_available { "-" } else { "-" });
    println!();

    if !rdrand_available && !rdseed_available {
        println!("Warning: No hardware RNG support detected on this CPU");
        println!("RDRAND requires: Intel Ivy Bridge (2012+) or AMD Excavator (2015+)");
        println!("RDSEED requires: Intel Broadwell (2014+) or AMD Zen (2017+)");
        return;
    }

    // Demonstrate RDRAND
    if rdrand_available {
        println!("=== RDRAND Examples ===\n");
        demonstrate_rdrand();
        println!();
    }

    // Demonstrate RDSEED
    if rdseed_available {
        println!("=== RDSEED Examples ===\n");
        demonstrate_rdseed();
        println!();
    }

    // Demonstrate mixed mode
    if rdrand_available {
        println!("=== Defense in Depth ===\n");
        demonstrate_defense_in_depth();
        println!();
    }

    // Recommendations
    println!("=== Security Recommendations ===\n");
    print_recommendations();
}

fn demonstrate_rdrand() {
    println!("1. Quick generation using static method:");
    let mut nonce = [0u8; 12];
    RdrandDrbg::fill(&mut nonce).expect("RDRAND failed");
    println!("   Nonce (12 bytes): {}", hex_encode(&nonce));

    println!("\n2. Type-safe key generation:");
    let key: [u8; 32] = RdrandDrbg::key().expect("RDRAND failed");
    println!("   AES-256 key: {}", hex_encode(&key));

    println!("\n3. Persistent DRBG for multiple generations:");
    let mut drbg = RdrandDrbg::new().expect("RDRAND failed");
    println!("   Security strength: {} bits", drbg.security_strength());
    println!("   Needs reseed: {}", drbg.needs_reseed());

    let mut output1 = [0u8; 16];
    let mut output2 = [0u8; 16];
    drbg.generate(&mut output1).expect("Generation failed");
    drbg.generate(&mut output2).expect("Generation failed");
    println!("   Output 1: {}", hex_encode(&output1));
    println!("   Output 2: {}", hex_encode(&output2));

    println!("\n4. Performance characteristics:");
    println!("   - Very fast (~3 billion samples/second)");
    println!("   - Conditioned output (AES-CTR-DRBG internally)");
    println!("   - Suitable for high-throughput applications");
    println!("   - Automatically reseeded from RDSEED");
}

fn demonstrate_rdseed() {
    println!("1. Quick generation using static method:");
    let mut seed = [0u8; 32];
    RdseedDrbg::fill(&mut seed).expect("RDSEED failed");
    println!("   Seed (32 bytes): {}", hex_encode(&seed));

    println!("\n2. Type-safe master key generation:");
    let master_key: [u8; 32] = RdseedDrbg::key().expect("RDSEED failed");
    println!("   Master key: {}", hex_encode(&master_key));

    println!("\n3. Using DRBG trait interface:");
    let mut drbg = RdseedDrbg::new().expect("RDSEED failed");
    println!("   Security strength: {} bits", drbg.security_strength());
    println!("   Needs reseed: {}", drbg.needs_reseed());

    let mut entropy = [0u8; 32];
    drbg.generate(&mut entropy).expect("Generation failed");
    println!("   Raw entropy: {}", hex_encode(&entropy[..16]));

    println!("\n4. Performance characteristics:");
    println!("   - Slower than RDRAND (100-1000x)");
    println!("   - Raw entropy directly from hardware");
    println!("   - Best for seeding DRBGs and long-term keys");
    println!("   - May block briefly waiting for entropy");
}

fn demonstrate_defense_in_depth() {
    println!("1. Mixing RDRAND with OS RNG:");

    let mut hw_key = [0u8; 32];
    RdrandDrbg::fill(&mut hw_key).expect("RDRAND failed");

    let mut os_key = [0u8; 32];
    hpcrypt_rng::generate_random_bytes(&mut os_key).expect("OS RNG failed");

    // XOR mix both sources
    for i in 0..32 {
        hw_key[i] ^= os_key[i];
    }
    println!("   Mixed key: {}", hex_encode(&hw_key));

    println!("\n2. Benefits of mixed mode:");
    println!("   - Protection against Intel hardware backdoors");
    println!("   - Protection against OS vulnerabilities");
    println!("   - No trust required in any single source");
    println!("   - Secure if either source is secure");

    println!("\n3. Polymorphic DRBG usage:");
    fn generate_with_drbg<D: Drbg>(mut drbg: D) -> Vec<[u8; 16]> {
        let mut keys = Vec::new();
        for _ in 0..3 {
            let mut key = [0u8; 16];
            drbg.generate(&mut key).expect("Generation failed");
            keys.push(key);
        }
        keys
    }

    let rdrand_keys = generate_with_drbg(RdrandDrbg::new().expect("RDRAND failed"));
    println!("   RDRAND keys generated: {}", rdrand_keys.len());
}

fn print_recommendations() {
    println!("1. Quick one-off generation:");
    println!("   RdrandDrbg::fill(&mut buffer)?");
    println!("   RdseedDrbg::key::<32>()?");
    println!();

    println!("2. Repeated generation:");
    println!("   let mut drbg = RdrandDrbg::new()?;");
    println!("   drbg.generate(&mut buffer)?");
    println!();

    println!("3. Use RDRAND for:");
    println!("   • Nonces and IVs");
    println!("   • Session keys");
    println!("   • High-throughput applications");
    println!();

    println!("4. Use RDSEED for:");
    println!("   • Seeding other DRBGs");
    println!("   • Master keys in key hierarchies");
    println!("   • Long-term cryptographic keys");
    println!();

    println!("5. Defense in depth:");
    println!("   • Mix hardware RNG with OS RNG (XOR)");
    println!("   • Don't trust single entropy source");
    println!("   • Consider your threat model");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
