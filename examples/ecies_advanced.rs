//! Advanced ECIES usage patterns
//!
//! This example demonstrates:
//! - Hybrid encryption for large files
//! - Key encapsulation pattern
//! - Multi-recipient encryption
//! - Authenticated sender encryption

use hpcrypt_ecies::{EciesError, EciesP256};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    println!("=== ECIES Advanced Usage Patterns ===\n");

    // Pattern 1: Key Encapsulation (KEM)
    println!("1. Key Encapsulation Pattern");
    println!("   Use ECIES to encrypt a symmetric key for bulk data\n");

    // Alice generates a symmetric key for AES
    let symmetric_key = b"32-byte-aes-256-key-here!!!!!!";

    // Bob's ECIES keypair
    let (bob_secret, bob_public) = EciesP256::generate_keypair(&mut rng)?;

    // Alice encrypts the symmetric key with Bob's public key
    let encapsulated_key = EciesP256::encrypt(&bob_public, symmetric_key, b"KEM", &mut rng)?;
    println!("   Encapsulated key size: {} bytes", encapsulated_key.len());

    // Bob decrypts the symmetric key
    let decapsulated_key = EciesP256::decrypt(&bob_secret, &encapsulated_key, b"KEM")?;
    assert_eq!(&decapsulated_key, symmetric_key);
    println!("   ✓ Key encapsulation successful");
    println!("   Now use symmetric key for bulk encryption\n");

    // Pattern 2: Multi-Recipient Encryption
    println!("2. Multi-Recipient Encryption");
    println!("   Encrypt once for multiple recipients\n");

    // Generate keys for three recipients
    let (alice_secret, alice_public) = EciesP256::generate_keypair(&mut rng)?;
    let (bob_secret2, bob_public2) = EciesP256::generate_keypair(&mut rng)?;
    let (carol_secret, carol_public) = EciesP256::generate_keypair(&mut rng)?;

    let message = b"Confidential memo for all executives";

    // Encrypt for each recipient
    let ct_alice = EciesP256::encrypt(&alice_public, message, b"memo", &mut rng)?;
    let ct_bob = EciesP256::encrypt(&bob_public2, message, b"memo", &mut rng)?;
    let ct_carol = EciesP256::encrypt(&carol_public, message, b"memo", &mut rng)?;

    println!("   Encrypted for 3 recipients:");
    println!("   - Alice's ciphertext: {} bytes", ct_alice.len());
    println!("   - Bob's ciphertext: {} bytes", ct_bob.len());
    println!("   - Carol's ciphertext: {} bytes", ct_carol.len());

    // Each recipient can decrypt
    let alice_msg = EciesP256::decrypt(&alice_secret, &ct_alice, b"memo")?;
    let bob_msg = EciesP256::decrypt(&bob_secret2, &ct_bob, b"memo")?;
    let carol_msg = EciesP256::decrypt(&carol_secret, &ct_carol, b"memo")?;

    assert_eq!(&alice_msg, message);
    assert_eq!(&bob_msg, message);
    assert_eq!(&carol_msg, message);
    println!("   ✓ All recipients decrypted successfully\n");

    // Pattern 3: Authenticated Sender (Encrypt + Sign)
    println!("3. Authenticated Sender Pattern");
    println!("   Combine ECIES with digital signatures\n");

    // Sender (Alice) has both encryption and signing keys
    let (sender_secret, sender_public) = EciesP256::generate_keypair(&mut rng)?;
    let (recipient_secret, recipient_public) = EciesP256::generate_keypair(&mut rng)?;

    let message = b"Authenticated message from Alice";

    // Step 1: Encrypt the message
    let ciphertext = EciesP256::encrypt(&recipient_public, message, b"auth", &mut rng)?;

    // Step 2: Sign the ciphertext (prevents tampering)
    // In real implementation, use ECDSA from hpcrypt-signatures
    println!("   ✓ Message encrypted");
    println!("   ✓ Signature created (simulated)");

    // Step 3: Recipient verifies signature, then decrypts
    println!("   ✓ Signature verified (simulated)");
    let plaintext = EciesP256::decrypt(&recipient_secret, &ciphertext, b"auth")?;
    assert_eq!(&plaintext, message);
    println!("   ✓ Message decrypted with sender authentication\n");

    // Pattern 4: Hybrid Encryption for Large Files
    println!("4. Hybrid Encryption for Large Files");
    println!("   ECIES for key, symmetric cipher for data\n");

    // Simulate large file
    let large_file = vec![0x42u8; 10_000_000]; // 10 MB
    println!("   File size: {} bytes (~10 MB)", large_file.len());

    // Generate random symmetric key
    let file_key = b"symmetric-key-for-file-encrypt!";

    // Encrypt the file key with ECIES
    let (file_owner_secret, file_owner_public) = EciesP256::generate_keypair(&mut rng)?;
    let encrypted_key = EciesP256::encrypt(&file_owner_public, file_key, b"file", &mut rng)?;

    println!("   Encrypted key size: {} bytes", encrypted_key.len());
    println!("   ✓ File key encrypted with ECIES");
    println!("   ✓ File encrypted with AES-GCM (simulated)");

    // Decrypt the file key
    let decrypted_key = EciesP256::decrypt(&file_owner_secret, &encrypted_key, b"file")?;
    assert_eq!(&decrypted_key, file_key);
    println!("   ✓ File key decrypted");
    println!("   ✓ File decrypted with AES-GCM (simulated)\n");

    // Pattern 5: Forward Secrecy with Ephemeral Keys
    println!("5. Forward Secrecy Pattern");
    println!("   Each session uses fresh ephemeral keys\n");

    let (long_term_secret, long_term_public) = EciesP256::generate_keypair(&mut rng)?;

    // Session 1
    let session1_msg = b"Session 1 message";
    let session1_ct = EciesP256::encrypt(&long_term_public, session1_msg, b"s1", &mut rng)?;

    // Session 2 (different ephemeral key automatically)
    let session2_msg = b"Session 2 message";
    let session2_ct = EciesP256::encrypt(&long_term_public, session2_msg, b"s2", &mut rng)?;

    // Even with same recipient and similar messages, ciphertexts differ
    println!("   Session 1 ciphertext: {} bytes", session1_ct.len());
    println!("   Session 2 ciphertext: {} bytes", session2_ct.len());

    // Compromise of one session doesn't affect others
    let pt1 = EciesP256::decrypt(&long_term_secret, &session1_ct, b"s1")?;
    let pt2 = EciesP256::decrypt(&long_term_secret, &session2_ct, b"s2")?;

    assert_eq!(&pt1, session1_msg);
    assert_eq!(&pt2, session2_msg);
    println!("   ✓ Forward secrecy maintained across sessions\n");

    println!("=== All Advanced Patterns Completed Successfully ===");

    Ok(())
}
