// Test to debug OMAC computation
use hpcrypt_mac::AesCmac128;
use hpcrypt_aead::Aes128Eax;

#[test]
fn test_omac_empty_nonce() {
    let key_hex = "8f3f52e3c75c58f5cb261f518f4ad30a"; // Test 226 key
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    let cmac = AesCmac128::new(&key_array);

    // Test OMAC(0, "") = CMAC([0,0,...,0,0] || "")
    let mut tag_block_0 = Vec::new();
    tag_block_0.extend_from_slice(&[0u8; 15]);
    tag_block_0.push(0);
    let omac_n = cmac.compute(&tag_block_0);
    println!("OMAC(0, '') = CMAC([0,0,...,0,0]) = {}", hex::encode(omac_n));

    // Test OMAC(1, "") = CMAC([0,0,...,0,1] || "")
    let mut tag_block_1 = Vec::new();
    tag_block_1.extend_from_slice(&[0u8; 15]);
    tag_block_1.push(1);
    let omac_h = cmac.compute(&tag_block_1);
    println!("OMAC(1, '') = CMAC([0,0,...,0,1]) = {}", hex::encode(omac_h));

    // Test OMAC(2, "") = CMAC([0,0,...,0,2] || "")
    let mut tag_block_2 = Vec::new();
    tag_block_2.extend_from_slice(&[0u8; 15]);
    tag_block_2.push(2);
    let omac_c = cmac.compute(&tag_block_2);
    println!("OMAC(2, '') = CMAC([0,0,...,0,2]) = {}", hex::encode(omac_c));

    // Compute tag = N ^ H ^ C
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = omac_n[i] ^ omac_h[i] ^ omac_c[i];
    }
    println!("Expected tag from OMAC = {}", hex::encode(expected_tag));
    println!("Expected tag from test = 5adbeefc8fa9cae2b9a6db3f5f6c82e9");

    // Now test with actual AES-EAX
    let ciphertext_tag = Aes128Eax::encrypt(&key_array, b"", b"", b"");
    println!("Actual AES-EAX tag     = {}", hex::encode(&ciphertext_tag));

    assert_eq!(hex::encode(&ciphertext_tag), "5adbeefc8fa9cae2b9a6db3f5f6c82e9");
}
