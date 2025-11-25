use hpcrypt_aead::ascon::{Ascon128, Ascon128Nist};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[test]
fn test_kat_vector_1() {
    // Official KAT vector from ascon-c repo
    let key = hex_decode("000102030405060708090A0B0C0D0E0F");
    let nonce = hex_decode("101112131415161718191A1B1C1D1E1F");
    let pt: Vec<u8> = vec![];  // empty
    let ad: Vec<u8> = vec![];  // empty
    
    // Expected CT includes tag (for empty PT, CT is just the tag)
    let expected_ct_with_tag = hex_decode("4F9C278211BEC9316BF68F46EE8B2EC6");
    
    let key_arr: [u8; 16] = key.clone().try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.clone().try_into().unwrap();
    
    let result = Ascon128Nist::encrypt(&key_arr, &nonce_arr, &pt, &ad);
    
    println!();
    println!("KAT Vector 1 (empty PT, empty AD):");
    println!("Key:      {}", hex::encode(&key));
    println!("Nonce:    {}", hex::encode(&nonce));
    println!();
    println!("Got:      {}", hex::encode(&result));
    println!("Expected: {}", hex::encode(&expected_ct_with_tag));
    println!("Match: {}", result == expected_ct_with_tag);
    
    assert_eq!(result, expected_ct_with_tag, "KAT vector 1 mismatch");
}

#[test]
fn test_kat_vector_2() {
    // Official KAT vector from ascon-c repo - with AD
    let key = hex_decode("000102030405060708090A0B0C0D0E0F");
    let nonce = hex_decode("101112131415161718191A1B1C1D1E1F");
    let pt: Vec<u8> = vec![];  // empty
    let ad = hex_decode("30");  // single byte
    
    // Expected CT includes tag
    let expected_ct_with_tag = hex_decode("CCCB674FE18A09A285D6AB11B35675C0");
    
    let key_arr: [u8; 16] = key.clone().try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.clone().try_into().unwrap();
    
    let result = Ascon128Nist::encrypt(&key_arr, &nonce_arr, &pt, &ad);
    
    println!();
    println!("KAT Vector 2 (empty PT, 1 byte AD):");
    println!("Key:      {}", hex::encode(&key));
    println!("Nonce:    {}", hex::encode(&nonce));
    println!("AD:       {}", hex::encode(&ad));
    println!();
    println!("Got:      {}", hex::encode(&result));
    println!("Expected: {}", hex::encode(&expected_ct_with_tag));
    println!("Match: {}", result == expected_ct_with_tag);
    
    assert_eq!(result, expected_ct_with_tag, "KAT vector 2 mismatch");
}
