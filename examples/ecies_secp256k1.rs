//! ECIES secp256k1 Encryption Example
//!
//! Demonstrates hybrid public-key encryption for Bitcoin/Ethereum:
//! - Key generation
//! - Public-key encryption with AES-128-GCM
//! - Authenticated decryption
//! - Forward secrecy via ephemeral keys
//! - Domain separation with shared info

use hpcrypt_ecies::EciesSecp256k1;
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ECIES secp256k1 Hybrid Encryption ===\n");

    let mut rng = thread_rng();

    // 1. Generate recipient's keypair
    println!("1. Key Generation");
    let (recipient_secret, recipient_public) = EciesSecp256k1::generate_keypair(&mut rng)?;

    println!("   Recipient private key: {} bytes", recipient_secret.len());
    println!(
        "   Recipient public key: {} bytes (0x04 || X || Y)",
        recipient_public.len()
    );
    println!(
        "   Public key prefix: 0x{:02x} (uncompressed)",
        recipient_public[0]
    );

    // 2. Encrypt a message
    println!("\n2. Encryption");
    let message = b"Hello, Bitcoin! This is a private message.";
    println!("   Plaintext: {:?}", std::str::from_utf8(message).unwrap());
    println!("   Plaintext size: {} bytes", message.len());

    let ciphertext = EciesSecp256k1::encrypt(&recipient_public, message, &[], &mut rng)?;

    println!("   Ciphertext size: {} bytes", ciphertext.len());
    println!(
        "   Overhead: {} bytes (ephemeral key + nonce + tag)",
        ciphertext.len() - message.len()
    );
    println!("   Breakdown:");
    println!("     - Ephemeral public key: 65 bytes");
    println!("     - AES-GCM nonce: 12 bytes");
    println!("     - Encrypted data: {} bytes", message.len());
    println!("     - Authentication tag: 16 bytes");

    // 3. Decrypt the message
    println!("\n3. Decryption");
    let plaintext = EciesSecp256k1::decrypt(&recipient_secret, &ciphertext, &[])?;

    println!(
        "   Decrypted: {:?}",
        std::str::from_utf8(&plaintext).unwrap()
    );
    println!(
        "   Match original: {}",
        if plaintext == message { " YES" } else { " NO" }
    );

    // 4. Demonstrate forward secrecy
    println!("\n4. Forward Secrecy");
    let message2 = b"Another message";
    let ciphertext2 = EciesSecp256k1::encrypt(&recipient_public, message2, &[], &mut rng)?;

    println!("   Same recipient, different message");
    println!(
        "   Ciphertext 1 != Ciphertext 2: {}",
        if ciphertext != ciphertext2 {
            " YES"
        } else {
            " NO"
        }
    );
    println!("   Reason: Fresh ephemeral key for each encryption");

    // 5. Domain separation with shared info
    println!("\n5. Domain Separation");
    let context1 = b"email-encryption-v1";
    let context2 = b"chat-encryption-v1";

    let ct_email = EciesSecp256k1::encrypt(&recipient_public, message, context1, &mut rng)?;
    let ct_chat = EciesSecp256k1::encrypt(&recipient_public, message, context2, &mut rng)?;

    println!("   Same message, different contexts");
    println!(
        "   Email context: {:?}",
        std::str::from_utf8(context1).unwrap()
    );
    println!(
        "   Chat context: {:?}",
        std::str::from_utf8(context2).unwrap()
    );

    // Decrypting with wrong context fails
    let wrong_context_result = EciesSecp256k1::decrypt(&recipient_secret, &ct_email, context2);
    println!(
        "   Decrypt email with chat context: {}",
        if wrong_context_result.is_err() {
            " FAILS (GOOD!)"
        } else {
            " WORKS (BAD!)"
        }
    );

    // Decrypting with correct context works
    let correct_result = EciesSecp256k1::decrypt(&recipient_secret, &ct_email, context1)?;
    println!("   Decrypt email with email context:  WORKS");

    // 6. Demonstrate tampering detection
    println!("\n6. Tampering Detection");
    let mut tampered_ciphertext = ciphertext.clone();
    let len = tampered_ciphertext.len();
    tampered_ciphertext[len - 1] ^= 0x01; // Flip one bit in the tag

    let tamper_result = EciesSecp256k1::decrypt(&recipient_secret, &tampered_ciphertext, &[]);
    println!(
        "   Tampered ciphertext decryption: {}",
        if tamper_result.is_err() {
            " FAILS (GOOD!)"
        } else {
            " WORKS (BAD!)"
        }
    );

    // 7. Empty message support
    println!("\n7. Edge Cases");
    let empty_message = b"";
    let empty_ct = EciesSecp256k1::encrypt(&recipient_public, empty_message, &[], &mut rng)?;
    let empty_pt = EciesSecp256k1::decrypt(&recipient_secret, &empty_ct, &[])?;

    println!("   Empty message: {:?}", empty_message);
    println!(
        "   Ciphertext size: {} bytes (just overhead)",
        empty_ct.len()
    );
    println!(
        "   Decryption works: {}",
        if empty_pt == empty_message {
            " YES"
        } else {
            " NO"
        }
    );

    // 8. Use cases
    println!("\n8. Use Cases");
    println!("   • Encrypted messaging to Bitcoin/Ethereum addresses");
    println!("   • Privacy-preserving DApps");
    println!("   • Secure wallet-to-wallet communication");
    println!("   • Lightning Network encrypted channels");
    println!("   • Web3 encrypted data storage");
    println!("   • Bitcoin/Ethereum private notes");

    // 9. Security properties
    println!("\n9. Security Properties");
    println!("    IND-CCA2 secure (indistinguishable under chosen-ciphertext)");
    println!("    Forward secrecy (ephemeral keys)");
    println!("    Authenticated encryption (AES-GCM)");
    println!("    Domain separation (shared info parameter)");
    println!("    Tampering detection (authentication tag)");

    // 10. Algorithm details
    println!("\n10. Algorithm Details");
    println!("   Curve: secp256k1 (Bitcoin/Ethereum)");
    println!("   KDF: ANSI X9.63 with SHA-256");
    println!("   AEAD: AES-128-GCM");
    println!("   Standard: SEC 1 v2.0");

    println!("\n ECIES secp256k1 encryption demonstration complete!");
    Ok(())
}
