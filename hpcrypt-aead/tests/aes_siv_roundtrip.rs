//! Test that edge case SIV values work in roundtrip
use hpcrypt_aead::Aes128Siv;

#[test]
fn test_edge_case_roundtrip() {
    // Even though we can't produce the specific edge case SIVs,
    // we should be able to decrypt messages that were encrypted
    // with those edge case SIVs (if the CTR and verification work correctly)

    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();

    // Test our implementation's roundtrip with same inputs
    let test_cases = vec![
        ("1d7f9cc81b316c518efcd7927e8f7b88", "test plaintext 1"),
        ("110d3aa6f558c30977870672804064e0", "test plaintext 2"),
        ("c83e256ba8baec09f5f1f8a55e7eac96", "test plaintext 3"),
    ];

    println!("\n=== Edge Case Roundtrip Tests ===");

    for (msg_hex, name) in test_cases {
        let msg = hex::decode(msg_hex).unwrap();

        println!("\nTest: {}", name);
        println!("Plaintext: {}", msg_hex);

        // Encrypt
        let encrypted = Aes128Siv::encrypt(&key_array, b"", &msg, b"");
        println!("Encrypted (SIV+CT): {}", hex::encode(&encrypted));
        println!("SIV: {}", hex::encode(&encrypted[..16]));

        // Decrypt
        let decrypted = Aes128Siv::decrypt(&key_array, b"", &encrypted, b"").unwrap();
        println!("Decrypted: {}", hex::encode(&decrypted));

        assert_eq!(decrypted, msg, "Roundtrip failed for {}", name);
        println!("Roundtrip OK");
    }
}
