//! Test edge case SIV from Wycheproof
use hpcrypt_aead::Aes128Siv;

#[test]
fn test_edge_case_siv_31() {
    // Test 31: edge case SIV with all-zero SIV
    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad_hex = "";
    let msg_hex = "1d7f9cc81b316c518efcd7927e8f7b88";
    let expected_ct_hex = "00000000000000000000000000000000f0dcac3115ddbd3d8ec28822e54088d0";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap_or_default();
    let msg = hex::decode(msg_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("\n=== Test 31: Edge Case SIV (all zeros) ===");
    println!("Key:         {}", key_hex);
    println!("AAD:         {} (empty)", aad_hex);
    println!("Msg:         {}", msg_hex);
    println!("Expected CT: {}", expected_ct_hex);
    println!("Expected SIV: {}", &expected_ct_hex[..32]);

    let result = Aes128Siv::encrypt(&key_array, b"", &msg, &aad);
    println!("Got CT:      {}", hex::encode(&result));
    println!("Got SIV:     {}", hex::encode(&result[..16]));

    if result == expected_ct {
        println!("PASS");
    } else {
        println!("FAIL");
        println!("SIV match: {}", &result[..16] == &expected_ct[..16]);
        println!("CT match:  {}", &result[16..] == &expected_ct[16..]);
    }

    assert_eq!(result, expected_ct, "Edge case SIV test 31 failed");
}

#[test]
fn test_edge_case_siv_33() {
    // Test 33: edge case SIV with all-ones SIV
    let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let aad_hex = "";
    let msg_hex = "110d3aa6f558c30977870672804064e0";
    let expected_ct_hex = "ffffffffffffffffffffffffffffffff01f74b8e43a262001d8357f95489432e";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 32] = key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap_or_default();
    let msg = hex::decode(msg_hex).unwrap();
    let expected_ct = hex::decode(expected_ct_hex).unwrap();

    println!("\n=== Test 33: Edge Case SIV (all ones) ===");
    println!("Key:         {}", key_hex);
    println!("AAD:         {} (empty)", aad_hex);
    println!("Msg:         {}", msg_hex);
    println!("Expected CT: {}", expected_ct_hex);
    println!("Expected SIV: {}", &expected_ct_hex[..32]);

    let result = Aes128Siv::encrypt(&key_array, b"", &msg, &aad);
    println!("Got CT:      {}", hex::encode(&result));
    println!("Got SIV:     {}", hex::encode(&result[..16]));

    if result == expected_ct {
        println!("PASS");
    } else {
        println!("FAIL");
        println!("SIV match: {}", &result[..16] == &expected_ct[..16]);
        println!("CT match:  {}", &result[16..] == &expected_ct[16..]);
    }

    assert_eq!(result, expected_ct, "Edge case SIV test 33 failed");
}
