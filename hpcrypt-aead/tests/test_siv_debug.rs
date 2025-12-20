// Debug AES-SIV test case
use hpcrypt_aead::Aes128Siv;

#[test]
fn test_siv_rfc5297_test1() {
    // Test 1 from Wycheproof / RFC 5297
    let key_hex = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let aad_hex = "101112131415161718191a1b1c1d1e1f2021222324252627";
    let msg_hex = "112233445566778899aabbccddee";
    let expected_ct_hex = "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let msg = hex::decode(msg_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("Key:      {}", key_hex);
    println!("AAD:      {}", aad_hex);
    println!("MSG:      {}", msg_hex);
    println!("Expected: {}", expected_ct_hex);

    // Encrypt with empty nonce (DAEAD mode)
    let encrypted = Aes128Siv::encrypt(&key_array, b"", &msg, &aad);
    println!("Got:      {}", hex::encode(&encrypted));

    // Check if they match
    if encrypted == expected_ct {
        println!("PASS");
    } else {
        println!("FAIL");
        println!("  IV (first 16 bytes):");
        println!("    Expected: {}", hex::encode(&expected_ct[..16]));
        println!("    Got:      {}", hex::encode(&encrypted[..16]));
    }

    assert_eq!(encrypted, expected_ct);
}
