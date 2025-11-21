//! Example: Ed25519 Digital Signatures
//!
//! This example demonstrates how to use Ed25519 for digital signatures:
//! - Generate keypairs
//! - Sign messages
//! - Verify signatures
//! - Handle verification failures

use hpcrypt_curves::Ed25519;

fn main() {
    println!("=== Ed25519 Digital Signatures Example ===\n");

    // Example 1: Basic signing and verification
    println!("1. Basic Signing and Verification:");

    // Generate a signing key (in production, use cryptographically secure random bytes)
    let private_key = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    // Derive the public key
    let public_key = Ed25519::public_key(&private_key);

    println!(
        "   Private key: {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        private_key[0],
        private_key[1],
        private_key[2],
        private_key[3],
        private_key[28],
        private_key[29],
        private_key[30],
        private_key[31]
    );
    println!(
        "   Public key:  {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        public_key[0],
        public_key[1],
        public_key[2],
        public_key[3],
        public_key[28],
        public_key[29],
        public_key[30],
        public_key[31]
    );

    // Sign a message
    let message = b"Hello, Ed25519!";
    let signature = Ed25519::sign(&private_key, message);

    println!(
        "   Message:     {:?}",
        std::str::from_utf8(message).unwrap()
    );
    println!(
        "   Signature:   {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x} ({} bytes)",
        signature[0],
        signature[1],
        signature[2],
        signature[3],
        signature[60],
        signature[61],
        signature[62],
        signature[63],
        signature.len()
    );

    // Verify the signature
    let is_valid = Ed25519::verify(&public_key, message, &signature);
    println!(
        "   Verification: {}",
        if is_valid { "- Valid" } else { "- Invalid" }
    );
    println!();

    // Example 2: Detecting tampered messages
    println!("2. Tamper Detection:");

    let original_message = b"Transfer $100 to Alice";
    let original_signature = Ed25519::sign(&private_key, original_message);

    println!(
        "   Original message: {:?}",
        std::str::from_utf8(original_message).unwrap()
    );
    println!(
        "   Signature valid:  {}",
        if Ed25519::verify(&public_key, original_message, &original_signature) {
            "Yes"
        } else {
            "No"
        }
    );

    // Try to verify with a tampered message
    let tampered_message = b"Transfer $999 to Alice";
    println!(
        "   Tampered message: {:?}",
        std::str::from_utf8(tampered_message).unwrap()
    );
    println!(
        "   Signature valid:  {}",
        if Ed25519::verify(&public_key, tampered_message, &original_signature) {
            "Yes"
        } else {
            "No (correctly rejected)"
        }
    );
    println!();

    // Example 3: Wrong public key
    println!("3. Wrong Public Key Detection:");

    let message3 = b"Confidential document";
    let signature3 = Ed25519::sign(&private_key, message3);

    // Generate a different keypair
    let wrong_private_key = [0x42; 32];
    let wrong_public_key = Ed25519::public_key(&wrong_private_key);

    println!(
        "   Message:           {:?}",
        std::str::from_utf8(message3).unwrap()
    );
    println!(
        "   Correct key verification: {}",
        if Ed25519::verify(&public_key, message3, &signature3) {
            "- Valid"
        } else {
            "- Invalid"
        }
    );
    println!(
        "   Wrong key verification:   {}",
        if Ed25519::verify(&wrong_public_key, message3, &signature3) {
            "- Valid"
        } else {
            "- Invalid (correctly rejected)"
        }
    );
    println!();

    // Example 4: Empty message signing
    println!("4. Empty Message:");
    let empty_message = b"";
    let empty_signature = Ed25519::sign(&private_key, empty_message);
    let empty_valid = Ed25519::verify(&public_key, empty_message, &empty_signature);

    println!("   Message:      (empty)");
    println!("   Can sign:     Yes");
    println!(
        "   Can verify:   {}",
        if empty_valid { "Yes" } else { "No" }
    );
    println!();

    // Example 5: Large message
    println!("5. Large Message:");
    let large_message = vec![0x42u8; 1_000_000]; // 1 MB message
    let large_signature = Ed25519::sign(&private_key, &large_message);
    let large_valid = Ed25519::verify(&public_key, &large_message, &large_signature);

    println!("   Message size: {} bytes (1 MB)", large_message.len());
    println!(
        "   Signature:    {} bytes (always 64)",
        large_signature.len()
    );
    println!(
        "   Verified:     {}",
        if large_valid { "Yes" } else { "No" }
    );
    println!();

    // Example 6: RFC 8032 Test Vector
    println!("6. RFC 8032 Compliance (Test Vector 2):");
    let rfc_sk = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    let rfc_pk = Ed25519::public_key(&rfc_sk);
    let rfc_message = [0x72u8];
    let rfc_signature = Ed25519::sign(&rfc_sk, &rfc_message);
    let rfc_valid = Ed25519::verify(&rfc_pk, &rfc_message, &rfc_signature);

    println!("   Test vector:  RFC 8032 Test Vector 2");
    println!("   Message:      {:02x}", rfc_message[0]);
    println!(
        "   Signature:    {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        rfc_signature[0],
        rfc_signature[1],
        rfc_signature[2],
        rfc_signature[3],
        rfc_signature[60],
        rfc_signature[61],
        rfc_signature[62],
        rfc_signature[63]
    );
    println!(
        "   RFC Compliant: {}",
        if rfc_valid { "Yes" } else { "No" }
    );

    println!("\n=== Example Complete ===");
}
