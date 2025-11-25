// Test to debug first few blocks of Argon2
use hpcrypt_kdf::argon2::{Argon2d, Params};

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_argon2d_first_blocks() {
    let password = decode_hex("0101010101010101010101010101010101010101010101010101010101010101");
    let salt = decode_hex("02020202020202020202020202020202");
    let secret = decode_hex("0303030303030303");
    let ad = decode_hex("040404040404040404040404");

    let params = Params::new(32, 32, 3, 4).unwrap();

    println!("\n=== Test Parameters ===");
    println!("Memory: 32 KiB");
    println!("Iterations: 3");
    println!("Parallelism: 4");
    println!("Blocks per lane: 8");
    println!("Segment length: 2");
    println!("Lane length: 8");

    let result = Argon2d::hash_with_ad(&password, &salt, &secret, &ad, &params).unwrap();

    println!("\n=== Final Result ===");
    println!("Got:      {}", encode_hex(&result));
    println!("Expected: 512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
}
