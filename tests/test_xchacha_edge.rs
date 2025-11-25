// Debug test for XChaCha20-Poly1305 edge case
use hpcrypt_aead::XChaCha20Poly1305;

fn main() {
    // Test 206: edge case for poly1305 key
    let key_hex = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    let nonce_hex = "000102030405060708090a0b0c0d0e0f101112133e8775b2";
    let aad_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let msg_hex = "7ee395bd21ada42ed12310d34918a28e596a49ee7a22f623d756b896663f68733e6c71a344f4726ac24e330679f25e492be08603aaa23f1e88c10299047c8e585983332a8b6eadcd9b6061b63fe3b58a2021b38c7cf379fe9a9f6d114f3cfe422f91af78c6fd87d4269af0e3e471abed457ae75c027e134c96cf4d9a4a646288";
    let ct_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let tag_hex = "4921f7c24a2d42f4da7ad9d45e8ec26c";

    let key: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
    let nonce: [u8; 24] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let msg = hex::decode(msg_hex).unwrap();
    let ct = hex::decode(ct_hex).unwrap();
    let tag = hex::decode(tag_hex).unwrap();

    let mut expected = ct.clone();
    expected.extend_from_slice(&tag);

    println!("Testing XChaCha20-Poly1305 edge case (Test 206)");
    println!("Key: {}", key_hex);
    println!("Nonce: {}", nonce_hex);
    println!("AAD length: {} bytes", aad.len());
    println!("Msg length: {} bytes", msg.len());

    // Try to decrypt
    match XChaCha20Poly1305::decrypt(&key, &nonce, &expected, &aad) {
        Some(decrypted) => {
            if decrypted == msg {
                println!("✓ Decryption successful and matches plaintext!");
            } else {
                println!("✗ Decryption succeeded but plaintext mismatch");
                println!("  Expected length: {} bytes", msg.len());
                println!("  Got length: {} bytes", decrypted.len());
                if msg.len() == decrypted.len() {
                    for (i, (expected, got)) in msg.iter().zip(decrypted.iter()).enumerate() {
                        if expected != got {
                            println!("  Byte {} differs: expected {:02x}, got {:02x}", i, expected, got);
                            if i > 10 {
                                println!("  ... (more differences)");
                                break;
                            }
                        }
                    }
                }
            }
        }
        None => {
            println!("✗ Decryption failed (tag mismatch)");

            // Let's try encrypting the plaintext and see what we get
            let encrypted = XChaCha20Poly1305::encrypt(&key, &nonce, &msg, &aad);
            println!("  Our encryption produces {} bytes (expected {})", encrypted.len(), expected.len());

            if encrypted.len() == expected.len() {
                let our_ct = &encrypted[..encrypted.len() - 16];
                let our_tag = &encrypted[encrypted.len() - 16..];

                if our_ct == &ct[..] {
                    println!("  ✓ Ciphertext matches");
                } else {
                    println!("  ✗ Ciphertext differs");
                }

                if our_tag == &tag[..] {
                    println!("  ✓ Tag matches");
                } else {
                    println!("  ✗ Tag differs");
                    println!("    Expected tag: {}", hex::encode(&tag));
                    println!("    Our tag:      {}", hex::encode(our_tag));
                }
            }
        }
    }
}
