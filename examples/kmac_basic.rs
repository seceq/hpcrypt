//! Basic KMAC128 and KMAC256 usage examples
//!
//! Demonstrates MAC generation and verification with KMAC

use hpcrypt_hash::kmac::{Kmac128, Kmac256};

fn main() {
    println!("=== KMAC Basic Usage Examples ===\n");

    // Example 1: KMAC128 - Basic MAC generation
    println!("1. KMAC128 - Basic MAC Generation");
    let key = b"my secret key";
    let message = b"Hello, World!";

    let mut kmac = Kmac128::new(key, b"");
    kmac.update(message);
    let mac = kmac.finalize(32);

    println!("   Key: {:?}", std::str::from_utf8(key).unwrap());
    println!("   Message: {:?}", std::str::from_utf8(message).unwrap());
    println!("   MAC (32 bytes): {}", hex::encode(&mac));
    println!();

    // Example 2: KMAC256 - Basic MAC generation
    println!("2. KMAC256 - Basic MAC Generation");
    let mut kmac = Kmac256::new(key, b"");
    kmac.update(message);
    let mac = kmac.finalize(32);

    println!("   Key: {:?}", std::str::from_utf8(key).unwrap());
    println!("   Message: {:?}", std::str::from_utf8(message).unwrap());
    println!("   MAC (64 bytes): {}", hex::encode(&mac));
    println!();

    // Example 3: KMAC with customization string
    println!("3. KMAC with Customization String");
    let customization = b"email-signature";

    let mut kmac = Kmac128::new(key, customization);
    kmac.update(message);
    let mac = kmac.finalize(32);

    println!("   Customization: {:?}", std::str::from_utf8(customization).unwrap());
    println!("   MAC: {}", hex::encode(&mac));
    println!();

    // Example 4: Variable-length output
    println!("4. KMAC with Variable-Length Output");

    let output_16 = kmac128(key, message, b"", 16);
    println!("   16-byte output: {}", hex::encode(&output_16));

    let output_64 = kmac128(key, message, b"", 64);
    println!("   64-byte output: {}", hex::encode(&output_64));
    println!();

    // Example 5: MAC verification
    println!("5. MAC Verification");
    let mac = kmac128(key, message, b"", 32);

    // Verify with correct MAC
    let is_valid = Kmac128::verify(key, message, b"", &mac);
    println!("   Correct MAC verification: {}", is_valid);

    // Verify with incorrect MAC
    let mut wrong_mac = mac.clone();
    wrong_mac[0] ^= 0xFF;
    let is_valid = Kmac128::verify(key, message, b"", &wrong_mac);
    println!("   Wrong MAC verification: {}", is_valid);
    println!();

    // Example 6: Incremental updates
    println!("6. Incremental Message Processing");
    let mut kmac = Kmac256::new(key, b"");
    kmac.update(b"Part 1: ");
    kmac.update(b"Hello, ");
    kmac.update(b"World!");
    let mac1 = kmac.finalize(32);

    let mut kmac = Kmac256::new(key, b"");
    kmac.update(b"Part 1: Hello, World!");
    let mac2 = kmac.finalize(32);

    println!("   Incremental MAC: {}", hex::encode(&mac1));
    println!("   Single MAC:      {}", hex::encode(&mac2));
    println!("   Match: {}", mac1 == mac2);
    println!();

    // Example 7: Convenience functions
    println!("7. Convenience Functions");
    let mac = hpcrypt_hash::kmac::kmac128(key, message, b"", 32);
    println!("   kmac128() result: {}", hex::encode(&mac));

    let mac = hpcrypt_hash::kmac::kmac256(key, message, b"", 64);
    println!("   kmac256() result: {}", hex::encode(&mac));
    println!();

    println!("=== Examples Complete ===");
}
