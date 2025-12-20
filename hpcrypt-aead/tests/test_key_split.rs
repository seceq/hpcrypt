//! Test which key half to use
use hpcrypt_cipher::Aes;

fn cmac_simple(key: &[u8], message: &[u8]) -> Vec<u8> {
    let cipher = if key.len() == 16 {
        Aes::new_128(key.try_into().unwrap())
    } else {
        Aes::new_256(key.try_into().unwrap())
    };

    // Simplified CMAC for empty message
    let mut last_block = [0u8; 16];
    last_block[0] = 0x80;

    // Generate K2
    let l = cipher.encrypt_block(&[0u8; 16]);
    let mut k1 = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        k1[i] = (l[i] << 1) | carry;
        carry = l[i] >> 7;
    }
    if carry != 0 {
        k1[15] ^= 0x87;
    }

    let mut k2 = [0u8; 16];
    carry = 0;
    for i in (0..16).rev() {
        k2[i] = (k1[i] << 1) | carry;
        carry = k1[i] >> 7;
    }
    if carry != 0 {
        k2[15] ^= 0x87;
    }

    for i in 0..16 {
        last_block[i] ^= k2[i];
    }

    cipher.encrypt_block(&last_block).to_vec()
}

#[test]
fn test_which_key_half() {
    let key_hex = "2b27e429fb6c02678e589ccc4437c5adfb44b331ab6d21ea321727e6ec03d354";
    let expected_iv_hex = "b2b2354e3724dcdaa85ecf029b49a90c";

    let key = hex::decode(key_hex).unwrap();
    let expected = hex::decode(expected_iv_hex).unwrap();

    println!("\nFull key: {}", key_hex);
    println!("Expected: {}", expected_iv_hex);

    // Try first half (K1)
    let k1 = &key[..16];
    println!("\nTrying K1 (first 16 bytes): {}", hex::encode(k1));
    let result1 = cmac_simple(k1, b"");
    println!("Result: {}", hex::encode(&result1));
    println!("Match: {}", result1 == expected);

    // Try second half (K2)
    let k2 = &key[16..];
    println!("\nTrying K2 (second 16 bytes): {}", hex::encode(k2));
    let result2 = cmac_simple(k2, b"");
    println!("Result: {}", hex::encode(&result2));
    println!("Match: {}", result2 == expected);

    // Try full key
    println!("\nTrying full key (32 bytes):");
    let result3 = cmac_simple(&key, b"");
    println!("Result: {}", hex::encode(&result3));
    println!("Match: {}", result3 == expected);
}
