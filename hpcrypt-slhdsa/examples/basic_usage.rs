//! Basic usage example for hpcrypt_slhdsa.
//!
//! This example demonstrates key generation, signing, and verification
//! using the SLH-DSA-SHA2-128f parameter set.

use hpcrypt_slhdsa::{sign, verify, KeyPair, Sha2_128f};
use rand::rngs::OsRng;

fn main() {
    println!("SLH-DSA (SPHINCS+) Basic Usage Example");
    println!("=======================================\n");

    // Initialize RNG (not needed for this generation variant)
    let _rng = OsRng;

    // Generate a key pair using SHA2-128f parameter set
    println!("Generating key pair (SHA2-128f)...");
    let keypair = KeyPair::<Sha2_128f>::generate();
    println!("Key generation complete!");
    println!(
        "  Public key size: {} bytes",
        keypair.public_key.to_bytes().len()
    );
    println!(
        "  Secret key size: {} bytes\n",
        keypair.secret_key.to_bytes().len()
    );

    // Message to sign
    let message = b"Hello, world! This is a test message for SLH-DSA.";
    println!("Message: {:?}\n", core::str::from_utf8(message).unwrap());

    // Sign the message
    println!("Signing message...");
    let signature = sign(&keypair.secret_key, message);
    println!("Signature generated!");
    println!("  Signature size: {} bytes\n", signature.len());

    // Verify the signature
    println!("Verifying signature...");
    let valid = verify(&keypair.public_key, message, &signature);
    println!(
        "Verification result: {}\n",
        if valid { "VALID ✓" } else { "INVALID ✗" }
    );

    assert!(valid, "Signature verification failed!");

    // Note: Full multi-layer hypertree verification is simplified in this version
    // For production use, complete multi-layer verification should be implemented

    println!("Example completed successfully!");
    println!("\nNote: This is a demonstration version with simplified hypertree.");
    println!("For production use, full multi-layer verification should be implemented.");
}
