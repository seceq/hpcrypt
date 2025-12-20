//! Tests for deterministic encryption property
//! AES-SIV's core feature: same inputs always produce same outputs

use hpcrypt_aead::Aes128Siv;

#[test]
fn test_deterministic_same_input_same_output() {
    // Core SIV property: encrypting the same message multiple times
    // produces identical ciphertext (when not using nonce)

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad = b"additional data";
    let msg = b"deterministic test message";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Deterministic Encryption Test ===");
    println!("Encrypting same message 1000 times...");

    // Encrypt the same message 1000 times
    let first = Aes128Siv::encrypt(&key_array, b"", msg, aad);

    for i in 1..1000 {
        let result = Aes128Siv::encrypt(&key_array, b"", msg, aad);
        assert_eq!(result, first, "Encryption {} produced different output", i);
    }

    println!("All 1000 encryptions produced identical output");
    println!("  Ciphertext: {}", hex::encode(&first));
}

#[test]
fn test_deterministic_with_nonce_changes() {
    // When using nonce, different nonces produce different outputs
    // This is key for nonce-based mode

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = b"test message";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Nonce-Based Non-Determinism ===");

    // Same message with different nonces should produce different ciphertexts
    let nonce1 = b"nonce1";
    let nonce2 = b"nonce2";
    let nonce3 = b"nonce1"; // Same as nonce1

    let ct1 = Aes128Siv::encrypt(&key_array, nonce1, msg, b"");
    let ct2 = Aes128Siv::encrypt(&key_array, nonce2, msg, b"");
    let ct3 = Aes128Siv::encrypt(&key_array, nonce3, msg, b"");

    let len = ct1.len().min(32);
    println!("Nonce 1: {}", hex::encode(&ct1[..len]));
    println!("Nonce 2: {}", hex::encode(&ct2[..len]));
    println!("Nonce 3: {}", hex::encode(&ct3[..len]));

    // Different nonces produce different ciphertexts
    assert_ne!(ct1, ct2, "Different nonces should produce different ciphertexts");

    // Same nonce produces same ciphertext (deterministic)
    assert_eq!(ct1, ct3, "Same nonce should produce same ciphertext");

    println!("Different nonces produce different ciphertexts");
    println!("Same nonce produces same ciphertext (deterministic)");
}

#[test]
fn test_deterministic_message_changes() {
    // Different messages always produce different ciphertexts

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad = b"aad";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Message Uniqueness ===");

    let mut ciphertexts = std::collections::HashSet::new();

    // Encrypt 100 different messages
    for i in 0..100 {
        let msg = format!("message {}", i);
        let ct = Aes128Siv::encrypt(&key_array, b"", msg.as_bytes(), aad);

        // Check that this ciphertext is unique
        let ct_hex = hex::encode(&ct);
        assert!(!ciphertexts.contains(&ct_hex), "Duplicate ciphertext for message {}", i);
        ciphertexts.insert(ct_hex);
    }

    println!("All 100 different messages produced unique ciphertexts");
}

#[test]
fn test_deterministic_bit_sensitivity() {
    // Single bit change in message should produce completely different ciphertext

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = b"test message for bit sensitivity";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Bit Sensitivity Test ===");

    // Original message
    let ct_original = Aes128Siv::encrypt(&key_array, b"", msg, b"");
    let len = ct_original.len().min(32);
    println!("Original: {}", hex::encode(&ct_original[..len]));

    // Flip single bit in message
    let mut msg_modified = msg.to_vec();
    msg_modified[0] ^= 0x01;

    let ct_modified = Aes128Siv::encrypt(&key_array, b"", &msg_modified, b"");
    println!("Modified: {}", hex::encode(&ct_modified[..len]));

    // Should be completely different
    assert_ne!(ct_original, ct_modified, "Single bit flip should change ciphertext");

    // Count how many bytes differ
    let mut diff_count = 0;
    for i in 0..ct_original.len().min(ct_modified.len()) {
        if ct_original[i] != ct_modified[i] {
            diff_count += 1;
        }
    }

    println!("Single bit flip changed {} out of {} bytes", diff_count, ct_original.len());

    // Should have avalanche effect - at least half the bytes should differ
    let half_len = ct_original.len() / 2;
    assert!(diff_count >= half_len, "Insufficient avalanche effect");

    println!("Avalanche effect verified (>50% bytes changed)");
}

#[test]
fn test_deterministic_key_separation() {
    // Different keys produce different ciphertexts for same message

    let msg = b"test message";
    let aad = b"aad";

    println!("\n=== Key Separation Test ===");

    let key1_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let key2_hex = "101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f";

    let key1 = hex::decode(key1_hex).unwrap();
    let key1_array: [u8; 32] = key1.try_into().unwrap();

    let key2 = hex::decode(key2_hex).unwrap();
    let key2_array: [u8; 32] = key2.try_into().unwrap();

    let ct1 = Aes128Siv::encrypt(&key1_array, b"", msg, aad);
    let ct2 = Aes128Siv::encrypt(&key2_array, b"", msg, aad);

    let len = ct1.len().min(32);
    println!("Key 1: {}", hex::encode(&ct1[..len]));
    println!("Key 2: {}", hex::encode(&ct2[..len]));

    assert_ne!(ct1, ct2, "Different keys should produce different ciphertexts");

    println!("Different keys produce different ciphertexts");
}

#[test]
fn test_deterministic_aad_sensitivity() {
    // AAD changes should produce different ciphertexts

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = b"plaintext";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== AAD Sensitivity Test ===");

    let ct1 = Aes128Siv::encrypt(&key_array, b"", msg, b"aad1");
    let ct2 = Aes128Siv::encrypt(&key_array, b"", msg, b"aad2");
    let ct3 = Aes128Siv::encrypt(&key_array, b"", msg, b"aad1");

    let len = ct1.len().min(32);
    println!("AAD 'aad1': {}", hex::encode(&ct1[..len]));
    println!("AAD 'aad2': {}", hex::encode(&ct2[..len]));
    println!("AAD 'aad1': {}", hex::encode(&ct3[..len]));

    // Different AAD produces different ciphertext
    assert_ne!(ct1, ct2, "Different AAD should produce different ciphertext");

    // Same AAD produces same ciphertext (deterministic)
    assert_eq!(ct1, ct3, "Same AAD should produce same ciphertext");

    println!("AAD changes produce different ciphertexts");
    println!("Same AAD produces same ciphertext (deterministic)");
}

#[test]
fn test_misuse_resistance() {
    // SIV Mode's key property: nonce reuse doesn't break security
    // (though it does reveal when the same message is encrypted)

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce = b"reused nonce";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Nonce Reuse Resistance (Misuse Resistance) ===");

    // Reuse same nonce with different messages
    let msg1 = b"first message";
    let msg2 = b"second message";
    let msg3 = b"first message"; // Same as msg1

    let ct1 = Aes128Siv::encrypt(&key_array, nonce, msg1, b"");
    let ct2 = Aes128Siv::encrypt(&key_array, nonce, msg2, b"");
    let ct3 = Aes128Siv::encrypt(&key_array, nonce, msg3, b"");

    let len = ct1.len().min(32);
    println!("Message 1 (reused nonce): {}", hex::encode(&ct1[..len]));
    println!("Message 2 (reused nonce): {}", hex::encode(&ct2[..len]));
    println!("Message 3 (same as 1):    {}", hex::encode(&ct3[..len]));

    // Different messages produce different ciphertexts even with reused nonce
    assert_ne!(ct1, ct2, "Different messages should produce different ciphertexts");

    // Same message with same nonce produces same ciphertext
    // This is the "deterministic" part - reveals message equality
    assert_eq!(ct1, ct3, "Same message should produce same ciphertext");

    println!("Nonce reuse with different messages is safe");
    println!("But reveals when same message is encrypted (deterministic)");

    // All ciphertexts should decrypt correctly
    let dec1 = Aes128Siv::decrypt(&key_array, nonce, &ct1, b"").unwrap();
    let dec2 = Aes128Siv::decrypt(&key_array, nonce, &ct2, b"").unwrap();
    let dec3 = Aes128Siv::decrypt(&key_array, nonce, &ct3, b"").unwrap();

    assert_eq!(dec1, msg1);
    assert_eq!(dec2, msg2);
    assert_eq!(dec3, msg3);

    println!("All messages decrypt correctly despite nonce reuse");
}
