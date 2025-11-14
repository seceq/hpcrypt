//! KMAC (Keccak Message Authentication Code) examples
//!
//! Demonstrates various use cases for KMAC128 and KMAC256

use hpcrypt_mac::{kmac128, kmac256, Kmac128};

fn main() {
    println!("=== KMAC Examples ===\n");

    basic_mac_generation();
    println!();

    variable_length_output();
    println!();

    customization_string_usage();
    println!();

    mac_verification();
    println!();

    key_derivation_example();
    println!();

    domain_separation_example();
}

fn basic_mac_generation() {
    println!("1. Basic MAC Generation");
    println!("   --------------------");

    let key = b"secret-key-2024";
    let message = b"Important message requiring authentication";

    // KMAC128 - 32-byte MAC
    let mac128 = kmac128(key, message, b"", 32);
    println!("   KMAC128 (32 bytes):");
    println!("     {}", hex::encode(&mac128));

    // KMAC256 - 64-byte MAC
    let mac256 = kmac256(key, message, b"", 64);
    println!("   KMAC256 (64 bytes):");
    println!("     {}", hex::encode(&mac256));
}

fn variable_length_output() {
    println!("2. Variable-Length Output");
    println!("   ----------------------");

    let key = b"my-secret-key";
    let message = b"Some data";

    println!("   KMAC128 with different output lengths:");

    // 16-byte MAC (128 bits)
    let mac_16 = kmac128(key, message, b"", 16);
    println!("     16 bytes: {}", hex::encode(&mac_16));

    // 32-byte MAC (256 bits)
    let mac_32 = kmac128(key, message, b"", 32);
    println!("     32 bytes: {}", hex::encode(&mac_32));

    // 48-byte MAC (384 bits)
    let mac_48 = kmac128(key, message, b"", 48);
    println!("     48 bytes: {}", hex::encode(&mac_48));
}

fn customization_string_usage() {
    println!("3. Customization String Usage");
    println!("   --------------------------");

    let key = b"shared-key";
    let message = b"Transaction data";

    // Different customization strings produce different MACs
    let custom1 = b"email-signature";
    let custom2 = b"api-authentication";
    let custom3 = b"file-integrity";

    let mac1 = kmac128(key, message, custom1, 32);
    let mac2 = kmac128(key, message, custom2, 32);
    let mac3 = kmac128(key, message, custom3, 32);

    println!("   Same key and message, different customization:");
    println!(
        "     '{}': {}",
        std::str::from_utf8(custom1).unwrap(),
        hex::encode(&mac1[..8])
    );
    println!(
        "     '{}': {}",
        std::str::from_utf8(custom2).unwrap(),
        hex::encode(&mac2[..8])
    );
    println!(
        "     '{}': {}",
        std::str::from_utf8(custom3).unwrap(),
        hex::encode(&mac3[..8])
    );
    println!(
        "     All different: {}",
        mac1 != mac2 && mac2 != mac3 && mac1 != mac3
    );
}

fn mac_verification() {
    println!("4. MAC Verification");
    println!("   ----------------");

    let key = b"verification-key";
    let message = b"Authentic message";

    // Generate MAC
    let mac = kmac128(key, message, b"", 32);
    println!("   Original MAC: {}", hex::encode(&mac[..8]));

    // Verify correct MAC
    let valid = Kmac128::verify(key, message, b"", &mac);
    println!("   Correct MAC verified: {}", valid);

    // Verify tampered MAC
    let mut tampered_mac = mac.clone();
    tampered_mac[0] ^= 0x01;
    let valid = Kmac128::verify(key, message, b"", &tampered_mac);
    println!("   Tampered MAC verified: {}", valid);

    // Verify with wrong message
    let valid = Kmac128::verify(key, b"Wrong message", b"", &mac);
    println!("   Wrong message verified: {}", valid);
}

fn key_derivation_example() {
    println!("5. Key Derivation with KMAC");
    println!("   ------------------------");

    let master_key = b"master-key-2024";
    let context = b"encryption-key-derivation";

    // Derive 256-bit encryption key
    let enc_key = kmac256(master_key, b"encryption", context, 32);
    println!("   Encryption key: {}", hex::encode(&enc_key));

    // Derive 256-bit MAC key
    let mac_key = kmac256(master_key, b"authentication", context, 32);
    println!("   MAC key:        {}", hex::encode(&mac_key));

    // Derive 128-bit IV
    let iv = kmac256(master_key, b"iv", context, 16);
    println!("   IV:             {}", hex::encode(&iv));

    println!("   All keys are cryptographically independent");
}

fn domain_separation_example() {
    println!("6. Domain Separation");
    println!("   -----------------");

    let key = b"shared-application-key";
    let user_id = b"user123";

    // Use customization strings for domain separation
    let session_token = kmac128(key, user_id, b"session-token", 32);
    let api_token = kmac128(key, user_id, b"api-token", 32);
    let refresh_token = kmac128(key, user_id, b"refresh-token", 32);

    println!("   Session token:  {}", hex::encode(&session_token[..8]));
    println!("   API token:      {}", hex::encode(&api_token[..8]));
    println!("   Refresh token:  {}", hex::encode(&refresh_token[..8]));
    println!(
        "   All unique: {}",
        session_token != api_token && api_token != refresh_token && session_token != refresh_token
    );
}
