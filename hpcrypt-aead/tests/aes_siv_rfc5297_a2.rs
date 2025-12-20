//! RFC 5297 Appendix A.2 test vector
//! Nonce-Based Authenticated Encryption Using AES-SIV

use hpcrypt_aead::Aes128Siv;

#[test]
fn test_rfc5297_a2() {
    // RFC 5297 Appendix A.2: Nonce-Based Authenticated Encryption
    // This tests S2V with multiple AAD inputs + nonce + plaintext

    let key_hex = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f";
    let ad1_hex = "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100";
    let ad2_hex = "102030405060708090a0";
    let nonce_hex = "09f911029d74e35bd84156c5635688c0";
    let plaintext_hex = "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553";
    let expected_ct_hex = "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let ad1 = hex::decode(ad1_hex).unwrap();
    let ad2 = hex::decode(ad2_hex).unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("\n=== RFC 5297 Appendix A.2 ===" );
    println!("Key:        {}", key_hex);
    println!("AD1:        {}...", &ad1_hex[..40]);
    println!("AD2:        {}", ad2_hex);
    println!("Nonce:      {}", nonce_hex);
    println!("Plaintext:  {}...", &plaintext_hex[..40]);
    println!("Expected:   {}...", &expected_ct_hex[..40]);

    // RFC A.2 uses S2V(K, AD1, AD2, nonce, plaintext) - 4 inputs to S2V
    // Use the multi-AAD API to properly test this
    let aad_components: [&[u8]; 2] = [&ad1, &ad2];
    let result = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_components, &nonce, &plaintext);

    println!("\nResult:     {}", hex::encode(&result));
    println!("Result SIV: {}", hex::encode(&result[..16]));
    let ct_preview_len = result[16..].len().min(20);
    println!("Result CT:  {}...", hex::encode(&result[16..16 + ct_preview_len]));
    println!("Expected:   {}", hex::encode(&expected_ct));

    // Verify match
    assert_eq!(result, expected_ct, "RFC 5297 A.2 test failed");
    println!("\nPASSED: RFC 5297 Appendix A.2 test");

    // Test roundtrip
    let decrypted = Aes128Siv::decrypt_with_aad_components(&key_array, &aad_components, &nonce, &result).unwrap();
    assert_eq!(decrypted, plaintext, "Roundtrip failed");
    println!("Roundtrip successful")
}

#[test]
fn test_rfc5297_a2_simplified() {
    // Simplified version with single AAD + nonce
    let key_hex = "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f";
    let nonce_hex = "09f911029d74e35bd84156c5635688c0";
    let plaintext_hex = "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let nonce = hex::decode(nonce_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();

    println!("\n=== RFC 5297 A.2 Simplified (Nonce Only) ===");

    // Encrypt with nonce, no AAD
    let encrypted = Aes128Siv::encrypt(&key_array, &nonce, &plaintext, b"");
    println!("Encrypted with nonce: {}", hex::encode(&encrypted[..32]));

    // Decrypt and verify
    let decrypted = Aes128Siv::decrypt(&key_array, &nonce, &encrypted, b"").unwrap();
    assert_eq!(decrypted, plaintext, "Roundtrip with nonce failed");

    println!("Nonce-based encryption roundtrip successful");
}

#[test]
fn test_multi_aad_components() {
    // Test the multi-AAD API with various AAD component configurations

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let plaintext = b"test message with multiple AAD components";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    println!("\n=== Multi-AAD Components Test ===");

    // Test 1: Single AAD component
    let aad1 = b"component1";
    let aad_single: [&[u8]; 1] = [aad1];
    let ct1 = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_single, b"", plaintext);
    println!("Single AAD:   {}", hex::encode(&ct1[..16]));

    // Test 2: Two AAD components
    let aad2 = b"component2";
    let aad_double: [&[u8]; 2] = [aad1, aad2];
    let ct2 = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_double, b"", plaintext);
    println!("Two AADs:     {}", hex::encode(&ct2[..16]));

    // Test 3: Three AAD components
    let aad3 = b"component3";
    let aad_triple: [&[u8]; 3] = [aad1, aad2, aad3];
    let ct3 = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_triple, b"", plaintext);
    println!("Three AADs:   {}", hex::encode(&ct3[..16]));

    // Different AAD configurations should produce different SIVs
    assert_ne!(ct1[..16], ct2[..16], "Different AAD counts should produce different SIVs");
    assert_ne!(ct2[..16], ct3[..16], "Different AAD counts should produce different SIVs");

    // Verify roundtrips
    let dec1 = Aes128Siv::decrypt_with_aad_components(&key_array, &aad_single, b"", &ct1).unwrap();
    let dec2 = Aes128Siv::decrypt_with_aad_components(&key_array, &aad_double, b"", &ct2).unwrap();
    let dec3 = Aes128Siv::decrypt_with_aad_components(&key_array, &aad_triple, b"", &ct3).unwrap();

    assert_eq!(dec1, plaintext);
    assert_eq!(dec2, plaintext);
    assert_eq!(dec3, plaintext);

    println!("All multi-AAD configurations work correctly");

    // Test 4: AAD order matters
    let aad_reversed: [&[u8]; 2] = [aad2, aad1];
    let ct_reversed = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_reversed, b"", plaintext);
    assert_ne!(ct2[..16], ct_reversed[..16], "AAD order should affect SIV");
    println!("AAD order is respected (different order = different SIV)");

    // Test 5: With nonce
    let nonce = b"test-nonce-123";
    let ct_with_nonce = Aes128Siv::encrypt_with_aad_components(&key_array, &aad_double, nonce, plaintext);
    assert_ne!(ct2[..16], ct_with_nonce[..16], "Nonce should affect SIV");
    let dec_nonce = Aes128Siv::decrypt_with_aad_components(&key_array, &aad_double, nonce, &ct_with_nonce).unwrap();
    assert_eq!(dec_nonce, plaintext);
    println!("Multi-AAD with nonce works correctly");
}
