//! Example demonstrating HPKE with X25519
//!
//! This example shows how to use HPKE (Hybrid Public Key Encryption)
//! with the X25519 curve for all four modes.

use hpcrypt_hpke::{HpkeX25519, Result};
use rand::thread_rng;

fn main() -> Result<()> {
    let mut rng = thread_rng();

    println!("=== HPKE with X25519 Example ===\n");

    // Generate recipient keypair
    let (sk_recipient, pk_recipient) = HpkeX25519::generate_keypair(&mut rng)?;
    println!("Generated recipient keypair");
    println!("  Secret key length: {} bytes", sk_recipient.len());
    println!("  Public key length: {} bytes\n", pk_recipient.len());

    // ========== BASE MODE ==========
    println!("--- Base Mode ---");

    let hpke = HpkeX25519::new();
    let info = b"application context";
    let aad = b"associated data";
    let plaintext = b"Hello, X25519 HPKE!";

    // Sender: setup and encrypt
    let (enc, mut sender_ctx) = hpke.setup_base_sender(&pk_recipient, info, &mut rng)?;
    let ciphertext = sender_ctx.seal(aad, plaintext)?;

    println!("Sender:");
    println!("  Encapsulated key: {} bytes", enc.len());
    println!("  Ciphertext: {} bytes", ciphertext.len());

    // Recipient: setup and decrypt
    let mut recipient_ctx = hpke.setup_base_recipient(&enc, &sk_recipient, info)?;
    let decrypted = recipient_ctx.open(aad, &ciphertext)?;

    println!("Recipient:");
    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted, plaintext);
    println!("  Decryption successful!\n");

    // ========== AUTH MODE ==========
    println!("--- Auth Mode ---");

    // Generate sender keypair for authentication
    let (sk_sender, pk_sender) = HpkeX25519::generate_keypair(&mut rng)?;

    // Sender: authenticated encryption
    let (enc, mut sender_ctx) = hpke.setup_auth_sender(&pk_recipient, info, &sk_sender, &mut rng)?;
    let ciphertext = sender_ctx.seal(aad, plaintext)?;

    println!("Sender (authenticated):");
    println!("  Used sender's private key for authentication");
    println!("  Ciphertext: {} bytes", ciphertext.len());

    // Recipient: verify and decrypt
    let mut recipient_ctx = hpke.setup_auth_recipient(&enc, &sk_recipient, info, &pk_sender)?;
    let decrypted = recipient_ctx.open(aad, &ciphertext)?;

    println!("Recipient:");
    println!("  Verified sender's identity using public key");
    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted, plaintext);
    println!("  Authenticated decryption successful!\n");

    // ========== SINGLE-SHOT API ==========
    println!("--- Single-Shot API ---");

    // Single-shot encryption (enc || ciphertext)
    let sealed = hpke.seal_base(&pk_recipient, info, aad, plaintext, &mut rng)?;
    println!("Single-shot seal: {} bytes total", sealed.len());

    // Single-shot decryption
    let opened = hpke.open_base(&sealed, &sk_recipient, info, aad)?;
    println!("Single-shot open: {}", String::from_utf8_lossy(&opened));
    assert_eq!(opened, plaintext);
    println!("  Single-shot operation successful!\n");

    // ========== MULTIPLE CIPHER SUITES ==========
    println!("--- Different Cipher Suites ---");

    let hpke_aes256 = HpkeX25519::with_aes256();
    println!("Using X25519 + HKDF-SHA256 + AES-256-GCM");
    let (enc, mut ctx) = hpke_aes256.setup_base_sender(&pk_recipient, info, &mut rng)?;
    let ct = ctx.seal(aad, plaintext)?;
    let mut ctx_r = hpke_aes256.setup_base_recipient(&enc, &sk_recipient, info)?;
    let pt = ctx_r.open(aad, &ct)?;
    assert_eq!(pt, plaintext);
    println!("  AES-256-GCM works!\n");

    let hpke_chacha = HpkeX25519::with_chacha();
    println!("Using X25519 + HKDF-SHA256 + ChaCha20-Poly1305");
    let (enc, mut ctx) = hpke_chacha.setup_base_sender(&pk_recipient, info, &mut rng)?;
    let ct = ctx.seal(aad, plaintext)?;
    let mut ctx_r = hpke_chacha.setup_base_recipient(&enc, &sk_recipient, info)?;
    let pt = ctx_r.open(aad, &ct)?;
    assert_eq!(pt, plaintext);
    println!("  ChaCha20-Poly1305 works!\n");

    println!("=== All examples completed successfully! ===");

    Ok(())
}
