//! Debug test for Ascon (original big-endian implementation)

fn main() {
    // Wycheproof test case 1 (Ascon v1.2 big-endian)
    let key = hex::decode("b67b1a6efdd40d37080fbe8f8047aeb9").unwrap();
    let nonce = hex::decode("fa294b129972f7fc5bbd5b96bba837c9").unwrap();
    let ad: Vec<u8> = vec![];
    let pt: Vec<u8> = vec![];
    let expected_tag = hex::decode("47648fcad24982437276b8d5901f812b").unwrap();

    println!("=== Wycheproof Test Case 1 (Ascon v1.2 big-endian) ===");
    println!("Key: {}", hex::encode(&key));
    println!("Nonce: {}", hex::encode(&nonce));
    println!("AD: {}", hex::encode(&ad));
    println!("PT: {}", hex::encode(&pt));
    println!("Expected Tag: {}", hex::encode(&expected_tag));
    println!();

    use hpcrypt_aead::ascon::Ascon128;
    
    let key_arr: [u8; 16] = key.try_into().unwrap();
    let nonce_arr: [u8; 16] = nonce.try_into().unwrap();
    
    let ct_with_tag = Ascon128::encrypt(&key_arr, &nonce_arr, &pt, &ad);
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);
    
    println!("Our CT: {}", hex::encode(ct));
    println!("Our Tag: {}", hex::encode(tag));
    println!();
    
    println!("CT matches (empty): {}", ct.is_empty());
    println!("Tag matches: {}", tag == expected_tag.as_slice());
}
