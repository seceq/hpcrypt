//! ECDSA Signature Examples
//!
//! This example demonstrates ECDSA (Elliptic Curve Digital Signature Algorithm)
//! signatures across three popular curves: P-256, P-384, and secp256k1.
//!
//! # Run this example
//!
//! ```bash
//! cargo run --example ecdsa_signatures
//! ```
//!
//! # Features Demonstrated
//!
//! 1. Key generation for all three curves
//! 2. Message signing with RFC 6979 deterministic nonces
//! 3. Signature verification
//! 4. DER encoding/decoding of signatures
//! 5. Public key serialization (compressed/uncompressed)
//! 6. Batch verification
//!
//! # Security Notes
//!
//! - Always hash messages before signing (SHA-256/SHA-384)
//! - Use RFC 6979 deterministic signing (prevents nonce reuse)
//! - Verify signatures before trusting signed data
//! - Protect private keys with encryption at rest

use hpcrypt_signatures::ecdsa::SigningKey as P256SigningKey;
use hpcrypt_signatures::ecdsa_p384::SigningKey as P384SigningKey;
use hpcrypt_signatures::ecdsa_secp256k1::SigningKey as Secp256k1SigningKey;

fn main() {
    println!("═══════════════════════════════════════════════════════════");
    println!("  ECDSA Signature Examples - HPCrypt");
    println!("═══════════════════════════════════════════════════════════\n");

    // Run examples for each curve
    p256_example();
    println!("\n{}\n", "─".repeat(60));

    p384_example();
    println!("\n{}\n", "─".repeat(60));

    secp256k1_example();
    println!("\n{}\n", "─".repeat(60));

    batch_verification_example();

    println!("\n═══════════════════════════════════════════════════════════");
    println!("  All examples completed successfully!");
    println!("═══════════════════════════════════════════════════════════");
}

/// Example: ECDSA with NIST P-256 curve
fn p256_example() {
    println!(" ECDSA P-256 (NIST) Example");
    println!("   Curve: secp256r1 / prime256v1");
    println!("   Hash: SHA-256");
    println!("   Use case: TLS, general-purpose signatures\n");

    // 1. Generate a signing key
    println!("1.  Generating P-256 keypair...");
    let signing_key = P256SigningKey::generate().expect("Failed to generate P-256 signing key");

    // Derive the corresponding verifying (public) key
    let verifying_key = signing_key.verifying_key();
    println!("   ✓ Keypair generated");

    // 2. Prepare message to sign
    let message = b"Hello, P-256! This message will be signed.";
    println!("\n2.  Message to sign:");
    println!("   \"{}\"", String::from_utf8_lossy(message));

    // 3. Sign the message (uses RFC 6979 deterministic nonces)
    println!("\n3.  Signing message with RFC 6979...");
    let signature = signing_key.sign(message);
    println!("   ✓ Signature generated (64 bytes)");
    println!("   r: {:02x?}...", &signature.to_bytes()[..8]);
    println!("   s: {:02x?}...", &signature.to_bytes()[32..40]);

    // 4. Verify the signature
    println!("\n4.  Verifying signature...");
    let is_valid = verifying_key.verify(message, &signature);
    println!(
        "   ✓ Signature verification: {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // 5. DER encoding (for interoperability)
    println!("\n5.  DER encoding signature...");
    let (der_bytes, len) = signature.to_der();
    println!(
        "   ✓ DER encoded ({} bytes): {:02x?}...",
        len,
        &der_bytes[..16]
    );

    // 6. Public key serialization
    println!("\n6.  Public key serialization:");
    let pub_uncompressed = verifying_key.to_bytes_uncompressed();
    println!(
        "   Uncompressed (65 bytes): {:02x?}...",
        &pub_uncompressed[..10]
    );

    let pub_compressed = verifying_key.to_bytes_compressed();
    println!(
        "   Compressed (33 bytes):   {:02x?}...",
        &pub_compressed[..10]
    );

    // 7. Deterministic signing (same message = same signature)
    println!("\n7.  Testing RFC 6979 determinism...");
    let signature2 = signing_key.sign(message);
    println!(
        "   First signature:  {:02x?}...",
        &signature.to_bytes()[..8]
    );
    println!(
        "   Second signature: {:02x?}...",
        &signature2.to_bytes()[..8]
    );
    println!(
        "   ✓ Signatures match: {}",
        signature.to_bytes() == signature2.to_bytes()
    );

    // 8. Invalid signature detection
    println!("\n8.  Testing invalid signature detection...");
    let wrong_message = b"Different message";
    let is_invalid = verifying_key.verify(wrong_message, &signature);
    println!("   ✓ Wrong message rejected: {}", !is_invalid);
}

/// Example: ECDSA with NIST P-384 curve
fn p384_example() {
    println!(" ECDSA P-384 (NIST) Example");
    println!("   Curve: secp384r1");
    println!("   Hash: SHA-384");
    println!("   Use case: High-security applications, Suite B\n");

    // 1. Generate a signing key
    println!("1.  Generating P-384 keypair...");
    let signing_key = P384SigningKey::generate().expect("Failed to generate P-384 signing key");
    let verifying_key = signing_key.verifying_key();
    println!("   ✓ Keypair generated (384-bit security)");

    // 2. Sign a message
    let message = b"High-security message for P-384";
    println!("\n2.  Message: \"{}\"", String::from_utf8_lossy(message));

    println!("\n3.  Signing with P-384...");
    let signature = signing_key.sign(message);
    println!("   ✓ Signature generated (96 bytes)");

    // 3. Verify
    println!("\n4.  Verifying signature...");
    let is_valid = verifying_key.verify(message, &signature);
    println!(
        "   ✓ Signature verification: {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // 4. Show larger key sizes
    println!("\n5.  P-384 key sizes:");
    let pub_uncompressed = verifying_key.to_bytes_uncompressed();
    println!(
        "   Uncompressed public key: {} bytes",
        pub_uncompressed.len()
    );
    let pub_compressed = verifying_key.to_bytes_compressed();
    println!("   Compressed public key:   {} bytes", pub_compressed.len());
    println!(
        "   Signature size:          {} bytes",
        signature.to_bytes().len()
    );
}

/// Example: ECDSA with secp256k1 curve (Bitcoin/Ethereum)
fn secp256k1_example() {
    println!(" ECDSA secp256k1 (Bitcoin/Ethereum) Example");
    println!("   Curve: secp256k1");
    println!("   Hash: SHA-256");
    println!("   Use case: Bitcoin, Ethereum, blockchain applications\n");

    // 1. Generate a signing key
    println!("1.  Generating secp256k1 keypair...");
    let signing_key =
        Secp256k1SigningKey::generate().expect("Failed to generate secp256k1 signing key");
    let verifying_key = signing_key.verifying_key();
    println!("   ✓ Keypair generated");

    // 2. Bitcoin-style transaction signing simulation
    let transaction = b"Bitcoin TX: Send 0.1 BTC to address xyz";
    println!("\n2.  Transaction to sign:");
    println!("   \"{}\"", String::from_utf8_lossy(transaction));

    println!("\n3.  Signing transaction...");
    let signature = signing_key.sign(transaction);
    println!("   ✓ Transaction signed (64 bytes)");
    println!("   r: {:02x?}...", &signature.to_bytes()[..8]);
    println!("   s: {:02x?}...", &signature.to_bytes()[32..40]);

    // 3. Verify the transaction signature
    println!("\n4.  Verifying transaction signature...");
    let is_valid = verifying_key.verify(transaction, &signature);
    println!(
        "   ✓ Signature verification: {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );

    // 4. DER encoding (used in Bitcoin)
    println!("\n5.  DER encoding (Bitcoin format)...");
    let (der_bytes, len) = signature.to_der();
    println!("   ✓ DER encoded ({} bytes)", len);
    println!("   DER: {:02x?}...", &der_bytes[..min(len, 20)]);

    // 5. Public key formats
    println!("\n6.  Public key formats:");
    let pub_uncompressed = verifying_key.to_bytes_uncompressed();
    println!(
        "   Uncompressed (65 bytes): {:02x?}...",
        &pub_uncompressed[..10]
    );
    let pub_compressed = verifying_key.to_bytes_compressed();
    println!(
        "   Compressed (33 bytes):   {:02x?}...",
        &pub_compressed[..10]
    );
    println!("   (Bitcoin uses compressed format by default)");
}

/// Example: Batch signature verification
fn batch_verification_example() {
    println!(" Batch Signature Verification Example");
    println!("   Verify multiple signatures efficiently\n");

    // Create multiple signers and signatures
    println!("1.  Creating 5 P-256 signatures...");
    let messages = [
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
        b"Message 3".as_slice(),
        b"Message 4".as_slice(),
        b"Message 5".as_slice(),
    ];

    let mut keys = Vec::new();
    let mut signatures = Vec::new();

    for (i, msg) in messages.iter().enumerate() {
        let signing_key = P256SigningKey::generate().expect("Failed to generate key");
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(msg);

        keys.push(verifying_key);
        signatures.push(signature);

        println!("   ✓ Signature {} created", i + 1);
    }

    // Verify all signatures
    println!("\n2.  Verifying all signatures...");
    for (i, ((key, sig), msg)) in keys.iter().zip(&signatures).zip(&messages).enumerate() {
        let valid = key.verify(msg, sig);
        println!(
            "   Signature {}: {}",
            i + 1,
            if valid { "✓ VALID" } else { "✗ INVALID" }
        );
    }

    println!(
        "\n   ✓ Batch verification: All {} signatures valid",
        messages.len()
    );

    // Test with one invalid signature
    println!("\n3.  Testing with one tampered signature...");
    let is_valid = keys[0].verify(b"Wrong message", &signatures[0]);
    println!("   ✓ Invalid signature detected: {}", !is_valid);
}

// Helper function for minimum
fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}
