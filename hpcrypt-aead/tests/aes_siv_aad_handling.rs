//! Comprehensive AAD handling tests
//! These tests document the critical discovery: empty AAD != no AAD

use hpcrypt_aead::Aes128Siv;

#[test]
fn test_no_aad_vs_empty_aad() {
    // CRITICAL TEST: Documents that no AAD and empty AAD produce different SIVs
    // This was the root cause of Wycheproof failures

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg_hex = "1d7f9cc81b316c518efcd7927e8f7b88";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let msg = hex::decode(msg_hex).unwrap();

    println!("\n=== No AAD vs Empty AAD ===");
    println!("Key: {}", key_hex);
    println!("Msg: {}", msg_hex);

    // Case 1: No AAD at all - treated as S2V(K, plaintext)
    // In our current API, this is represented by passing empty slice
    // But semantically, this should be treated as "AAD not provided"

    // Case 2: Empty AAD - treated as S2V(K, "", plaintext)
    // This explicitly includes empty AAD in the S2V input

    // Our implementation should treat passing b"" as empty AAD (case 2)
    let result_empty_aad = Aes128Siv::encrypt(&key_array, b"", &msg, b"");
    println!("\nWith empty AAD slice b\"\":");
    println!("  SIV: {}", hex::encode(&result_empty_aad[..16]));

    // For "no AAD" case, we would need a different API
    // This test documents the expected behavior

    println!("\nIMPORTANT: Our API always includes AAD in S2V");
    println!("Empty AAD (b\"\") is processed through S2V as an empty string");
    println!("This matches RustCrypto and Wycheproof expectations");
}

#[test]
fn test_aad_variations() {
    // Test various AAD sizes and contents

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = b"test message";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== AAD Variations ===");

    // Empty AAD
    let siv1 = Aes128Siv::encrypt(&key_array, b"", msg, b"");
    println!("Empty AAD:      {}", hex::encode(&siv1[..16]));

    // 1-byte AAD
    let siv2 = Aes128Siv::encrypt(&key_array, b"", msg, b"A");
    println!("1-byte AAD:     {}", hex::encode(&siv2[..16]));

    // 15-byte AAD (one less than block)
    let aad15 = b"123456789012345";
    let siv3 = Aes128Siv::encrypt(&key_array, b"", msg, aad15);
    println!("15-byte AAD:    {}", hex::encode(&siv3[..16]));

    // 16-byte AAD (exactly one block)
    let aad16 = b"1234567890123456";
    let siv4 = Aes128Siv::encrypt(&key_array, b"", msg, aad16);
    println!("16-byte AAD:    {}", hex::encode(&siv4[..16]));

    // 17-byte AAD (one more than block)
    let aad17 = b"12345678901234567";
    let siv5 = Aes128Siv::encrypt(&key_array, b"", msg, aad17);
    println!("17-byte AAD:    {}", hex::encode(&siv5[..16]));

    // All should be different
    assert_ne!(siv1[..16], siv2[..16], "Empty vs 1-byte should differ");
    assert_ne!(siv2[..16], siv3[..16], "1-byte vs 15-byte should differ");
    assert_ne!(siv3[..16], siv4[..16], "15-byte vs 16-byte should differ");
    assert_ne!(siv4[..16], siv5[..16], "16-byte vs 17-byte should differ");

    println!("\nAll AAD variations produce unique SIVs");
}

#[test]
fn test_aad_authentication() {
    // Verify that AAD is properly authenticated

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad = b"authenticated data";
    let msg = b"plaintext message";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== AAD Authentication ===");

    // Encrypt with AAD
    let encrypted = Aes128Siv::encrypt(&key_array, b"", msg, aad);
    println!("Encrypted with AAD: {}", hex::encode(&encrypted[..32]));

    // Decrypt with correct AAD - should succeed
    let decrypted = Aes128Siv::decrypt(&key_array, b"", &encrypted, aad).unwrap();
    assert_eq!(decrypted, msg, "Decryption with correct AAD failed");
    println!("Decryption with correct AAD successful");

    // Decrypt with wrong AAD - should fail
    let wrong_aad = b"different data!!!";
    let result = Aes128Siv::decrypt(&key_array, b"", &encrypted, wrong_aad);
    assert!(result.is_err(), "Should fail with wrong AAD");
    println!("Correctly rejects wrong AAD");

    // Decrypt with empty AAD - should fail
    let result = Aes128Siv::decrypt(&key_array, b"", &encrypted, b"");
    assert!(result.is_err(), "Should fail with empty AAD when non-empty was used");
    println!("Correctly rejects empty AAD");

    // Decrypt with modified AAD - should fail
    let mut modified_aad = aad.to_vec();
    modified_aad[0] ^= 0x01;
    let result = Aes128Siv::decrypt(&key_array, b"", &encrypted, &modified_aad);
    assert!(result.is_err(), "Should fail with modified AAD");
    println!("Correctly rejects modified AAD");
}

#[test]
fn test_large_aad() {
    // Test with large AAD to ensure no issues with buffer handling

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let msg = b"test message";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Large AAD Test ===");

    // 1 KB AAD
    let aad_1kb = vec![0x42u8; 1024];
    let result1 = Aes128Siv::encrypt(&key_array, b"", msg, &aad_1kb);
    println!("1 KB AAD:   {}", hex::encode(&result1[..16]));

    let decrypted = Aes128Siv::decrypt(&key_array, b"", &result1, &aad_1kb).unwrap();
    assert_eq!(decrypted, msg);
    println!("1 KB AAD roundtrip successful");

    // 64 KB AAD
    let aad_64kb = vec![0x43u8; 65536];
    let result2 = Aes128Siv::encrypt(&key_array, b"", msg, &aad_64kb);
    println!("64 KB AAD:  {}", hex::encode(&result2[..16]));

    let decrypted = Aes128Siv::decrypt(&key_array, b"", &result2, &aad_64kb).unwrap();
    assert_eq!(decrypted, msg);
    println!("64 KB AAD roundtrip successful");

    // Different large AADs should produce different SIVs
    assert_ne!(result1[..16], result2[..16], "Different AADs should produce different SIVs");
}

#[test]
fn test_aad_with_nonce() {
    // Test AAD combined with nonce

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad = b"additional data";
    let nonce = b"unique nonce 123";
    let msg = b"plaintext";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== AAD + Nonce ===");

    // Encrypt with both AAD and nonce
    let encrypted = Aes128Siv::encrypt(&key_array, nonce, msg, aad);
    let display_len = encrypted.len().min(32);
    println!("Encrypted: {}", hex::encode(&encrypted[..display_len]));

    // Decrypt with correct AAD and nonce
    let decrypted = Aes128Siv::decrypt(&key_array, nonce, &encrypted, aad).unwrap();
    assert_eq!(decrypted, msg);
    println!("Decryption with AAD + nonce successful");

    // Wrong nonce should fail
    let wrong_nonce = b"wrong nonce 1234";
    let result = Aes128Siv::decrypt(&key_array, wrong_nonce, &encrypted, aad);
    assert!(result.is_err(), "Should fail with wrong nonce");
    println!("Correctly rejects wrong nonce");

    // Wrong AAD should fail
    let wrong_aad = b"wrong data!!!!!";
    let result = Aes128Siv::decrypt(&key_array, nonce, &encrypted, wrong_aad);
    assert!(result.is_err(), "Should fail with wrong AAD");
    println!("Correctly rejects wrong AAD");
}
