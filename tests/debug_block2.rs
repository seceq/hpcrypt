// Debug program to inspect Block[0][2]

use hpcrypt_kdf::argon2::{Argon2, Params, Variant};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let password = hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
    let salt = hex_decode("02020202020202020202020202020202");
    let secret = hex_decode("0303030303030303");
    let ad = hex_decode("040404040404040404040404");

    let params = Params::new(32, 32, 3, 4).unwrap();

    println!("=== Block[0][2] Comparison ===\n");

    // Argon2d
    println!("--- Argon2d ---");
    let argon2d = Argon2::new(Variant::Argon2d, params.clone());
    let memory_d = argon2d.debug_get_memory(&password, &salt, &secret, &ad).unwrap();
    print!("[Rust] Block[0][2][0-7]: ");
    for i in 0..8 {
        print!("{:016x} ", memory_d[2][i]);
    }
    println!();
    println!("[P-H-C] Block[0][2][0-7]: dd269d6d1fe274bd eaf87fd713312aeb 8d4ba63951096c16 426a1231958f05d5 3b8b0f1949550baa 8f61aad93507eb55 677e1f8f34ce88f2 c4b1c172380afc85");
    println!();

    // Argon2i
    println!("--- Argon2i ---");
    let argon2i = Argon2::new(Variant::Argon2i, params.clone());
    let memory_i = argon2i.debug_get_memory(&password, &salt, &secret, &ad).unwrap();
    print!("[Rust] Block[0][2][0-7]: ");
    for i in 0..8 {
        print!("{:016x} ", memory_i[2][i]);
    }
    println!();
    println!("[P-H-C] Block[0][2][0-7]: f800892a7954baa5 bb211f064d193505 2c406a2eb271e25e fa438cb81ec6e36f 9735e9adcf04badc 197193e9f53e6c35 260ee704b27a33d5 fc9e533fe0595718");
    println!();

    // Argon2id
    println!("--- Argon2id ---");
    let argon2id = Argon2::new(Variant::Argon2id, params.clone());
    let memory_id = argon2id.debug_get_memory(&password, &salt, &secret, &ad).unwrap();
    print!("[Rust] Block[0][2][0-7]: ");
    for i in 0..8 {
        print!("{:016x} ", memory_id[2][i]);
    }
    println!();
    println!("[P-H-C] Block[0][2][0-7]: 37542c2df4c423ff 6cf1d602626f0fc1 449e5a5d622d8883 79ec5285f3ba957c cc62f30b0b412ef0 b47e35f1c950a027 c5a5c6ab91729a64 020dbf60ec862cd5");
}
