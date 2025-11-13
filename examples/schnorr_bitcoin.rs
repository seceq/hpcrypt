//! Schnorr Signatures (BIP 340) Example
//!
//! Demonstrates Bitcoin Taproot-compatible Schnorr signatures:
//! - Key generation
//! - X-only public keys (32 bytes)
//! - Deterministic signing
//! - Signature verification
//! - Tagged hashing for domain separation

use hpcrypt_curves::secp256k1::schnorr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BIP 340 Schnorr Signatures (Bitcoin Taproot) ===\n");

    // 1. Generate a private key (in production, use cryptographically secure random)
    let private_key: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    ];

    println!("1. Key Generation");
    println!("   Private key: {}", hex::encode(&private_key));

    // 2. Generate X-only public key (32 bytes, not 33 like compressed ECDSA)
    let public_key: [u8; 32] = schnorr::public_key(&private_key);
    println!("   Public key (X-only): {}", hex::encode(&public_key));
    println!("   Size: {} bytes (vs 33 for compressed ECDSA)\n", public_key.len());

    // 3. Sign a message
    let message = b"Hello, Bitcoin Taproot!";
    let aux_rand = [0u8; 32]; // Deterministic (for testing)

    println!("2. Signing");
    println!("   Message: {:?}", std::str::from_utf8(message).unwrap());

    let signature: [u8; 64] = schnorr::sign(&private_key, message, &aux_rand);
    println!("   Signature: {}", hex::encode(&signature));
    println!("   Size: {} bytes (vs 70-72 for ECDSA DER)\n", signature.len());

    // 4. Verify the signature
    println!("3. Verification");
    let is_valid = schnorr::verify(&public_key, message, &signature);
    println!("   Signature valid: {}", if is_valid { " YES" } else { " NO" });

    // 5. Demonstrate signature malleability resistance
    println!("\n4. Security Properties");
    println!("    No signature malleability (unlike ECDSA)");
    println!("    Deterministic nonce generation");
    println!("    Tagged hashing prevents cross-protocol attacks");
    println!("    64-byte signatures (smaller than ECDSA DER)");

    // 6. Try tampering with the signature
    println!("\n5. Tamper Detection");
    let mut tampered_signature = signature;
    tampered_signature[0] ^= 0x01; // Flip one bit

    let is_tampered_valid = schnorr::verify(&public_key, message, &tampered_signature);
    println!("   Tampered signature valid: {}", if is_tampered_valid { " YES (BAD!)" } else { " NO (GOOD!)" });

    // 7. Try with wrong message
    let wrong_message = b"Different message";
    let is_wrong_msg_valid = schnorr::verify(&public_key, wrong_message, &signature);
    println!("   Wrong message valid: {}", if is_wrong_msg_valid { " YES (BAD!)" } else { " NO (GOOD!)" });

    // 8. Bitcoin Taproot use cases
    println!("\n6. Bitcoin Taproot Use Cases");
    println!("   • Taproot spends (SegWit v1)");
    println!("   • Lightning Network channels");
    println!("   • Multi-signatures (MuSig2)");
    println!("   • Discreet Log Contracts (DLCs)");
    println!("   • Bitcoin Ordinals & Inscriptions");

    // 9. Performance characteristics
    println!("\n7. Performance");
    println!("   Signing: ~20-30ms");
    println!("   Verification: ~30-40ms");
    println!("   Public key: 32 bytes (3% smaller than compressed ECDSA)");
    println!("   Signature: 64 bytes (9% smaller than ECDSA DER)");

    println!("\n Schnorr signatures demonstration complete!");
    Ok(())
}

// Helper function to print hex (requires hex crate)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
