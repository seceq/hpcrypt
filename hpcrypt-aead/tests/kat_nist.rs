// Official KAT test vectors from ascon-c for Ascon-AEAD128 (NIST SP 800-232)

use hpcrypt_aead::ascon::Ascon128Nist;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[test]
fn test_kat1_empty_pt_empty_ad() {
    // From LWC_AEAD_KAT_128_128.txt
    let key = hex_decode("000102030405060708090A0B0C0D0E0F");
    let nonce = hex_decode("101112131415161718191A1B1C1D1E1F");
    let pt: Vec<u8> = vec![];
    let ad: Vec<u8> = vec![];
    let expected_ct_tag = hex_decode("4F9C278211BEC9316BF68F46EE8B2EC6");

    let key_arr: [u8; 16] = key.try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

    let result = Ascon128Nist::encrypt(&key_arr, &nonce_arr, &pt, &ad);

    println!("\n=== KAT Test 1: Empty PT, Empty AD ===");
    println!("Key:      {}", hex::encode(&key_arr));
    println!("Nonce:    {}", hex::encode(&nonce_arr));
    println!("PT:       (empty)");
    println!("AD:       (empty)");
    println!();
    println!("Got:      {}", hex::encode(&result));
    println!("Expected: {}", hex::encode(&expected_ct_tag));
    println!("Match:    {}", result == expected_ct_tag);

    assert_eq!(result, expected_ct_tag, "KAT test 1 failed");
}

#[test]
fn test_kat2_empty_pt_1byte_ad() {
    let key = hex_decode("000102030405060708090A0B0C0D0E0F");
    let nonce = hex_decode("101112131415161718191A1B1C1D1E1F");
    let pt: Vec<u8> = vec![];
    let ad = hex_decode("30");
    let expected_ct_tag = hex_decode("CCCB674FE18A09A285D6AB11B35675C0");

    let key_arr: [u8; 16] = key.try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

    let result = Ascon128Nist::encrypt(&key_arr, &nonce_arr, &pt, &ad);

    println!("\n=== KAT Test 2: Empty PT, 1-byte AD ===");
    println!("Key:      {}", hex::encode(&key_arr));
    println!("Nonce:    {}", hex::encode(&nonce_arr));
    println!("PT:       (empty)");
    println!("AD:       {}", hex::encode(&ad));
    println!();
    println!("Got:      {}", hex::encode(&result));
    println!("Expected: {}", hex::encode(&expected_ct_tag));
    println!("Match:    {}", result == expected_ct_tag);

    assert_eq!(result, expected_ct_tag, "KAT test 2 failed");
}

#[test]
fn test_kat34_1byte_pt_empty_ad() {
    // First test case with plaintext
    let key = hex_decode("000102030405060708090A0B0C0D0E0F");
    let nonce = hex_decode("101112131415161718191A1B1C1D1E1F");
    let pt = hex_decode("20");
    let ad: Vec<u8> = vec![];
    // CT (1 byte) + Tag (16 bytes) = 17 bytes
    let expected_ct_tag = hex_decode("E8DD576ABA1CD3E6FC704DE02AEDB79588");

    let key_arr: [u8; 16] = key.try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.try_into().unwrap();

    let result = Ascon128Nist::encrypt(&key_arr, &nonce_arr, &pt, &ad);

    println!("\n=== KAT Test 34: 1-byte PT, Empty AD ===");
    println!("Key:      {}", hex::encode(&key_arr));
    println!("Nonce:    {}", hex::encode(&nonce_arr));
    println!("PT:       {}", hex::encode(&pt));
    println!("AD:       (empty)");
    println!();
    println!("Got:      {}", hex::encode(&result));
    println!("Expected: {}", hex::encode(&expected_ct_tag));
    println!("Match:    {}", result == expected_ct_tag);

    let (ct, tag) = result.split_at(result.len() - 16);
    let (exp_ct, exp_tag) = expected_ct_tag.split_at(expected_ct_tag.len() - 16);
    println!();
    println!("CT:       {} (expected: {})", hex::encode(ct), hex::encode(exp_ct));
    println!("Tag:      {} (expected: {})", hex::encode(tag), hex::encode(exp_tag));

    assert_eq!(result, expected_ct_tag, "KAT test 34 failed");
}
