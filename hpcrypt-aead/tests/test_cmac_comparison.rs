//! Compare our CMAC with hpcrypt-mac CMAC
use hpcrypt_mac::AesCmac128;

#[test]
fn test_cmac_empty() {
    let key_hex = "2b27e429fb6c02678e589ccc4437c5ad";
    let expected_iv_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let expected = hex::decode(expected_iv_hex).unwrap();

    println!("\n=== CMAC of empty message ===");
    println!("Key:      {}", key_hex);
    println!("Expected: {}", expected_iv_hex);

    let cmac = AesCmac128::new(&key_array);
    let result = cmac.compute(b"");
    println!("Got:      {}", hex::encode(&result));
    println!("Match:    {}", result.to_vec() == expected);

    assert_eq!(result.to_vec(), expected, "CMAC of empty should match expected IV");
}
