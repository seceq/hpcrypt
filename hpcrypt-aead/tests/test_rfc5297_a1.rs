//! RFC 5297 Appendix A.1 test vector
use hpcrypt_aead::Aes128Siv;

#[test]
fn test_rfc5297_a1() {
    // RFC 5297 Appendix A.1: Deterministic Authenticated Encryption
    let key_hex = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let aad_hex = "101112131415161718191a1b1c1d1e1f2021222324252627";
    let plaintext_hex = "112233445566778899aabbccddee";
    let expected_siv_hex = "85632d07c6e8f37f950acd320a2ecc93";
    let expected_ct_hex = "40c02b9690c4dc04daef7f6afe5c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();
    let expected_siv = hex::decode(expected_siv_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("\n=== RFC 5297 Appendix A.1 ===");
    println!("Key:              {}", key_hex);
    println!("AAD:              {}", aad_hex);
    println!("Plaintext:        {}", plaintext_hex);
    println!("Expected SIV:     {}", expected_siv_hex);
    println!("Expected CT:      {}", expected_ct_hex);

    // AES-SIV with no nonce (deterministic mode)
    let result = Aes128Siv::encrypt(&key_array, b"", &plaintext, &aad);

    println!("\nResult:           {}", hex::encode(&result));
    println!("Result SIV:       {}", hex::encode(&result[..16]));
    println!("Result CT:        {}", hex::encode(&result[16..]));

    // Check SIV
    let got_siv = &result[..16];
    let got_ct = &result[16..];

    println!("\nSIV match: {}", got_siv == expected_siv.as_slice());
    println!("CT match:  {}", got_ct == expected_ct.as_slice());

    // Full comparison
    let mut expected_full = Vec::new();
    expected_full.extend_from_slice(&expected_siv);
    expected_full.extend_from_slice(&expected_ct);

    assert_eq!(result, expected_full, "RFC 5297 A.1 test failed");
}
