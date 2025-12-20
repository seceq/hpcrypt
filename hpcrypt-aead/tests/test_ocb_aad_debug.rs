// Debug test for AAD processing
use hpcrypt_aead::Aes128Ocb;

#[test]
fn test_ocb_test3_debug() {
    // RFC 7253 Test 3
    // K: 000102030405060708090A0B0C0D0E0F
    // N: BBAA99887766554433221102
    // A: 0001020304050607 (8 bytes)
    // P: (empty)
    // Expected C: 81017F8203F081277152FADE694A0A00

    let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let nonce = hex::decode("BBAA99887766554433221102").unwrap();
    let aad = hex::decode("0001020304050607").unwrap();
    let plaintext = b"";

    let key_array: [u8; 16] = key.try_into().unwrap();

    let result = Aes128Ocb::encrypt(&key_array, &nonce, plaintext, &aad);

    println!("Expected: 81017F8203F081277152FADE694A0A00");
    println!("Got:      {}", hex::encode(&result));

    assert_eq!(
        hex::encode(&result),
        "81017f8203f081277152fade694a0a00",
        "Test 3 should pass"
    );
}

#[test]
fn test_ocb_test7_debug() {
    // RFC 7253 Test 7
    // K: 000102030405060708090A0B0C0D0E0F
    // N: BBAA99887766554433221106
    // A: (empty)
    // P: 000102030405060708090A0B0C0D0E0F (16 bytes)
    // Expected C: 5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D

    let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let nonce = hex::decode("BBAA99887766554433221106").unwrap();
    let aad: &[u8] = b"";
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();

    let key_array: [u8; 16] = key.try_into().unwrap();

    let result = Aes128Ocb::encrypt(&key_array, &nonce, &plaintext, aad);

    println!("Expected: 5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D");
    println!("Got:      {}", hex::encode(&result).to_uppercase());

    // This test has NO AAD, only plaintext, so it should help isolate issues
}
