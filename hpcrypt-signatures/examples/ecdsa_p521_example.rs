//! ECDSA P-521 Example
//!
//! Demonstrates key generation, signing, and verification using ECDSA with P-521 curve.
//!
//! Run with: cargo run --example ecdsa_p521_example

use hpcrypt_signatures::ecdsa_p521::{SigningKey, VerifyingKey, Signature};

fn main() {
    println!("=== ECDSA P-521 Example ===\n");

    // 1. Generate a new key pair
    println!("1. Generating key pair...");
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    println!("   Key pair generated\n");

    // 2. Sign a message
    let message = b"Hello, ECDSA P-521!";
    println!("2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = signing_key.sign(message);
    println!("   Signature created\n");

    // 3. Verify the signature
    println!("3. Verifying signature...");
    let is_valid = verifying_key.verify(message, &signature);
    println!("   Signature valid: {}\n", is_valid);
    assert!(is_valid, "Signature verification failed!");

    // 4. Try to verify with wrong message (should fail)
    let wrong_message = b"Wrong message";
    println!("4. Verifying with wrong message: {:?}", String::from_utf8_lossy(wrong_message));
    let is_valid = verifying_key.verify(wrong_message, &signature);
    println!("   Signature valid: {} (expected: false)\n", is_valid);
    assert!(!is_valid, "Signature should not verify with wrong message!");

    // 5. Demonstrate deterministic signatures (RFC 6979)
    println!("5. Demonstrating deterministic signatures (RFC 6979)...");
    let sig1 = signing_key.sign(message);
    let sig2 = signing_key.sign(message);
    let deterministic = sig1.r == sig2.r && sig1.s == sig2.s;
    println!("   Same message produces same signature: {}\n", deterministic);
    assert!(deterministic, "RFC 6979 should produce deterministic signatures!");

    // 6. Encoding/Decoding examples
    println!("6. Testing signature encoding formats...");

    // DER encoding
    let (der, len) = signature.to_der();
    let _sig_from_der = Signature::from_der(&der[..len]).expect("Failed to parse DER");
    println!("   DER encoding: {} bytes", len);

    // Raw bytes (r || s)
    let bytes = signature.to_bytes();
    let _sig_from_bytes = Signature::from_bytes(&bytes);
    println!("   Raw bytes encoding: {} bytes\n", bytes.len());

    // 7. Public key encoding
    println!("7. Testing public key encoding...");

    // Uncompressed SEC1 format
    let sec1_uncompressed = verifying_key.to_sec1_uncompressed();
    let vk_from_sec1 = VerifyingKey::from_sec1_uncompressed(&sec1_uncompressed)
        .expect("Failed to parse SEC1");
    println!("   SEC1 uncompressed: {} bytes", sec1_uncompressed.len());

    // Verify that decoded key can still verify the signature
    let still_valid = vk_from_sec1.verify(message, &signature);
    println!("   Decoded key verifies signature: {}\n", still_valid);
    assert!(still_valid, "Decoded key should verify signature!");

    // 8. Security information
    println!("8. Security Information:");
    println!("   • Curve: P-521 (NIST, secp521r1)");
    println!("   • Security level: ~260 bits");
    println!("   • Hash function: SHA-512");
    println!("   • Nonce generation: RFC 6979 (deterministic)");
    println!("   • Signature size: 132 bytes (raw), ~141 bytes max (DER)");
    println!("   • Public key size: 133 bytes (uncompressed SEC1)");
    println!("\nAll examples completed successfully!");
}
