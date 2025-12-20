//! Trace S2V computation step by step
use hpcrypt_mac::AesCmac128;

#[test]
fn test_s2v_empty_trace() {
    let key_hex = "2b27e429fb6c02678e589ccc4437c5ad";
    let expected_iv_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let expected = hex::decode(expected_iv_hex).unwrap();

    let cmac = AesCmac128::new(&key_array);

    println!("\n=== S2V for empty plaintext ===");
    println!("Inputs: just empty plaintext [b\"\"]");
    println!("According to RFC, n=1, so: V = AES-CMAC(K, pad(S[1]))");
    println!("pad(\"\") = 0x80 followed by zeros");

    let mut padded = [0u8; 16];
    padded[0] = 0x80;
    
    let result = cmac.compute(&padded);
    println!("\nCMAC(K, pad(empty)): {}", hex::encode(&result));
    println!("Expected IV:         {}", expected_iv_hex);
    println!("Match: {}", result.to_vec() == expected);

    assert_eq!(result.to_vec(), expected);
}

#[test]
fn test_s2v_n_equals_zero() {
    let key_hex = "2b27e429fb6c02678e589ccc4437c5ad";
    let expected_iv_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();
    let expected = hex::decode(expected_iv_hex).unwrap();

    let cmac = AesCmac128::new(&key_array);

    println!("\n=== S2V n=0 case ===");
    println!("RFC 5297: if n=0 then return V = AES-CMAC(K, <one>)");
    
    let one = [0x01u8; 16];
    let result = cmac.compute(&one);
    println!("CMAC(<one>): {}", hex::encode(&result));
    println!("Expected:    {}", expected_iv_hex);
    println!("Match: {}", result.to_vec() == expected);

    assert_eq!(result.to_vec(), expected, "n=0 case should match");
}
