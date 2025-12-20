//! Tests for empty plaintext encryption
//! These cases are particularly important as they were failing in Wycheproof

use hpcrypt_aead::Aes128Siv;

#[test]
fn test_empty_plaintext_empty_aad() {
    // Wycheproof test 2: Both plaintext and AAD empty
    // This is the minimal input case - tests S2V with just empty strings

    let key_hex = "2b27e429fb6c02678e589ccc4437c5adfb44b331ab6d21ea321727e6ec03d354";
    let expected_siv_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let expected_siv = hex::decode(expected_siv_hex).unwrap();

    println!("\n=== Empty Plaintext + Empty AAD ===");
    println!("Key: {}", key_hex);
    println!("Expected SIV: {}", expected_siv_hex);

    // Encrypt empty message with empty AAD
    let result = Aes128Siv::encrypt(&key_array, b"", b"", b"");
    println!("Got SIV:      {}", hex::encode(&result[..16]));

    // Should produce only the SIV (no ciphertext for empty plaintext)
    assert_eq!(result.len(), 16, "Empty plaintext should produce only SIV");

    // Check SIV matches
    assert_eq!(&result[..16], expected_siv.as_slice(), "SIV mismatch for empty message");

    println!("Empty message encryption successful");

    // Test roundtrip
    let decrypted = Aes128Siv::decrypt(&key_array, b"", &result, b"").unwrap();
    assert_eq!(decrypted.len(), 0, "Should decrypt to empty plaintext");

    println!("Empty message roundtrip successful");
}

#[test]
fn test_empty_plaintext_with_aad() {
    // Empty plaintext but with AAD - validates AAD-only authentication

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad_hex = "101112131415161718191a1b1c1d1e1f";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap();

    println!("\n=== Empty Plaintext + Non-Empty AAD ===");
    println!("Key: {}", key_hex);
    println!("AAD: {}", aad_hex);

    // Encrypt empty message with AAD
    let result = Aes128Siv::encrypt(&key_array, b"", b"", &aad);
    println!("SIV: {}", hex::encode(&result[..16]));

    assert_eq!(result.len(), 16, "Empty plaintext should produce only SIV");

    // Test roundtrip
    let decrypted = Aes128Siv::decrypt(&key_array, b"", &result, &aad).unwrap();
    assert_eq!(decrypted.len(), 0, "Should decrypt to empty plaintext");

    // Verify authentication: wrong AAD should fail
    let wrong_aad = hex::decode("202122232425262728292a2b2c2d2e2f").unwrap();
    let decrypt_result = Aes128Siv::decrypt(&key_array, b"", &result, &wrong_aad);
    assert!(decrypt_result.is_err(), "Wrong AAD should fail authentication");

    println!("Empty plaintext with AAD successful");
    println!("AAD authentication verified");
}

#[test]
fn test_empty_plaintext_with_nonce() {
    // Empty plaintext with nonce - validates nonce handling

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce_hex = "09f911029d74e35bd84156c5635688c0";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();

    println!("\n=== Empty Plaintext + Nonce ===");
    println!("Key:   {}", key_hex);
    println!("Nonce: {}", nonce_hex);

    // Encrypt empty message with nonce
    let result = Aes128Siv::encrypt(&key_array, &nonce, b"", b"");
    println!("SIV: {}", hex::encode(&result[..16]));

    assert_eq!(result.len(), 16, "Empty plaintext should produce only SIV");

    // Test roundtrip
    let decrypted = Aes128Siv::decrypt(&key_array, &nonce, &result, b"").unwrap();
    assert_eq!(decrypted.len(), 0, "Should decrypt to empty plaintext");

    // Verify nonce matters: different nonce should produce different SIV
    let nonce2_hex = "19f911029d74e35bd84156c5635688c0";
    let nonce2 = hex::decode(nonce2_hex).unwrap();
    let result2 = Aes128Siv::encrypt(&key_array, &nonce2, b"", b"");

    assert_ne!(result, result2, "Different nonces should produce different SIVs");

    println!("Empty plaintext with nonce successful");
    println!("Nonce uniqueness verified");
}

#[test]
fn test_empty_plaintext_aes256() {
    // Test empty plaintext with AES-256-SIV (64-byte key)

    let key_hex = "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980401a981030254a54b1756a8c96e600b7252fd0aab12f39d115d256b3f3e7c2c41a7fece72ba7c3c4";
    let expected_siv_hex = "44b1c6fe8a8c07dee5377b161f283c31";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 64] = key.try_into().unwrap();
    let expected_siv = hex::decode(expected_siv_hex).unwrap();

    println!("\n=== Empty Plaintext AES-256-SIV ===");
    println!("Key (256-bit): {}...", &key_hex[..32]);
    println!("Expected SIV:  {}", expected_siv_hex);

    // Encrypt empty message
    let result = hpcrypt_aead::Aes256Siv::encrypt(&key_array, b"", b"", b"");
    println!("Got SIV:       {}", hex::encode(&result[..16]));

    assert_eq!(result.len(), 16, "Empty plaintext should produce only SIV");
    assert_eq!(&result[..16], expected_siv.as_slice(), "SIV mismatch for AES-256");

    println!("AES-256-SIV empty message successful");
}
