// Test case 296: AES-256-SIV with empty everything
use hpcrypt_aead::Aes256Siv;

#[test]
fn test_siv_test296() {
    let key_hex = "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980401a981030254a54b1756a8c96e600b7252fd0aab12f39d115d256b3f3e7c2c41a7fece72ba7c3c4";
    let aad = b"";
    let msg = b"";
    let expected_ct_hex = "44b1c6fe8a8c07dee5377b161f283c31";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 64] = key.try_into().unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("Test 296: AES-256-SIV, empty AAD, empty MSG");
    println!("Expected: {}", expected_ct_hex);

    let encrypted = Aes256Siv::encrypt(&key_array, b"", msg, aad);
    println!("Got:      {}", hex::encode(&encrypted));

    assert_eq!(encrypted, expected_ct, "Test 296 failed");
}
