// Minimal test case for debugging Poly1305
use hpcrypt_aead::XChaCha20Poly1305;

fn main() {
    // Test ID 4 from Wycheproof
    let key = hex::decode("303ccb2e1567c3d9f629a5c632dbc62a9a82c525674f67988b31bd1dee990538").unwrap();
    let nonce = hex::decode("05188738844ab90a8b11beef38eaec3e100d8f4f85ae7a41").unwrap();
    let aad = hex::decode("").unwrap();
    let msg = hex::decode("62").unwrap();
    let expected_ct = hex::decode("45").unwrap();
    let expected_tag = hex::decode("d15734f984d749fa3f0550a70c43dddf").unwrap();

    println!("Test ID 4: Simple 1-byte message");
    println!("Key: {}", hex::encode(&key));
    println!("Nonce: {}", hex::encode(&nonce));
    println!("Msg: {}", hex::encode(&msg));

    // Encrypt
    let encrypted = XChaCha20Poly1305::encrypt(
        key.as_slice().try_into().unwrap(),
        nonce.as_slice().try_into().unwrap(),
        &msg,
        &aad
    );

    let our_ct = &encrypted[..encrypted.len() - 16];
    let our_tag = &encrypted[encrypted.len() - 16..];

    println!("\nExpected ciphertext: {}", hex::encode(&expected_ct));
    println!("Our ciphertext:      {}", hex::encode(our_ct));
    println!("Ciphertext match: {}", our_ct == expected_ct.as_slice());

    println!("\nExpected tag: {}", hex::encode(&expected_tag));
    println!("Our tag:      {}", hex::encode(our_tag));
    println!("Tag match: {}", our_tag == expected_tag.as_slice());

    if our_tag != expected_tag.as_slice() {
        println!("\nTAG MISMATCH - This is the Poly1305 bug!");
        for (i, (exp, got)) in expected_tag.iter().zip(our_tag.iter()).enumerate() {
            if exp != got {
                println!("  Byte {}: expected {:02x}, got {:02x}", i, exp, got);
            }
        }
    } else {
        println!("\nAll correct!");
    }
}
