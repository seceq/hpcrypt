// Test case 2: AES-128-SIV with empty everything
use hpcrypt_aead::Aes128Siv;

#[test]
fn test_siv_test2() {
    let key_hex = "2b27e429fb6c02678e589ccc4437c5adfb44b331ab6d21ea321727e6ec03d354";
    let aad = b"";
    let msg = b"";
    let expected_ct_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("Test 2: AES-128-SIV, empty AAD, empty MSG");
    println!("Key: {}", key_hex);
    println!("Expected: {}", expected_ct_hex);

    let encrypted = Aes128Siv::encrypt(&key_array, b"", msg, aad);
    println!("Got:      {}", hex::encode(&encrypted));

    assert_eq!(encrypted, expected_ct, "Test 2 failed");
}
