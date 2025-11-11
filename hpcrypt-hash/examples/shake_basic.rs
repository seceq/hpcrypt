// SHAKE (Extendable Output Functions) usage examples
// Demonstrates SHAKE128 and SHAKE256 - variable-length hash functions

use hpcrypt_hash::sha3::{Shake128, Shake256};

fn main() {
    println!("=== SHAKE (XOF) Examples ===\n");

    // Example 1: SHAKE128 basics
    example_shake128_basic();

    // Example 2: SHAKE256 basics
    example_shake256_basic();

    // Example 3: Variable output lengths
    example_variable_lengths();

    // Example 4: Key derivation use case
    example_key_derivation();

    // Example 5: Test vectors
    example_test_vectors();
}

fn example_shake128_basic() {
    println!("1. SHAKE128 Basics:");
    println!("   SHAKE128 provides 128-bit security\n");

    let message = b"Hello, SHAKE128!";
    let mut output = vec![0u8; 32]; // 32 bytes = 256 bits output

    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut output);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHAKE128 (32 bytes): ");
    for byte in output.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_shake256_basic() {
    println!("2. SHAKE256 Basics:");
    println!("   SHAKE256 provides 256-bit security\n");

    let message = b"Hello, SHAKE256!";
    let mut output = vec![0u8; 64]; // 64 bytes = 512 bits output

    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut output);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHAKE256 (64 bytes): ");
    for byte in output.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_variable_lengths() {
    println!("3. Variable Output Lengths:");
    println!("   SHAKE can produce any length output\n");

    let message = b"variable length output";

    // 16 bytes
    let mut out_16 = vec![0u8; 16];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_16);

    print!("   SHAKE256 (16 bytes):  ");
    for byte in out_16.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 32 bytes
    let mut out_32 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_32);

    print!("   SHAKE256 (32 bytes):  ");
    for byte in out_32.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 64 bytes
    let mut out_64 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_64);

    print!("   SHAKE256 (64 bytes):  ");
    for byte in out_64.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 100 bytes
    let mut out_100 = vec![0u8; 100];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_100);

    print!("   SHAKE256 (100 bytes): ");
    for (i, byte) in out_100.iter().enumerate() {
        print!("{:02x}", byte);
        if i == 31 {
            print!("\n                         ");
        }
    }
    println!("\n");
}

fn example_key_derivation() {
    println!("4. Key Derivation Use Case:");
    println!("   Using SHAKE256 to derive multiple keys from a master secret\n");

    let master_secret = b"my_master_secret_key_material_2024";

    // Derive AES-256 key
    let mut aes_key = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(b"aes_encryption_key");
    shake.finalize(&mut aes_key);

    print!("   AES-256 key:  ");
    for byte in aes_key.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Derive HMAC key
    let mut hmac_key = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(b"hmac_key");
    shake.finalize(&mut hmac_key);

    print!("   HMAC key:     ");
    for byte in hmac_key.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Derive IV
    let mut iv = vec![0u8; 16];
    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(b"initialization_vector");
    shake.finalize(&mut iv);

    print!("   IV (16 bytes): ");
    for byte in iv.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Derive nonce
    let mut nonce = vec![0u8; 12];
    let mut shake = Shake256::new();
    shake.update(master_secret);
    shake.update(b"nonce");
    shake.finalize(&mut nonce);

    print!("   Nonce:         ");
    for byte in nonce.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_test_vectors() {
    println!("5. Official Test Vectors (Empty Input):");

    // SHAKE128 - 32 bytes output
    let mut out_128 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(b"");
    shake.finalize(&mut out_128);

    print!("   SHAKE128 (32 bytes): ");
    for byte in out_128.iter() {
        print!("{:02x}", byte);
    }
    println!();
    let expected_128 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263";
    println!("   Expected:            {}", expected_128);
    println!();

    // SHAKE256 - 64 bytes output
    let mut out_256 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(b"");
    shake.finalize(&mut out_256);

    print!("   SHAKE256 (64 bytes): ");
    for (i, byte) in out_256.iter().enumerate() {
        print!("{:02x}", byte);
        if i == 31 {
            print!("\n                        ");
        }
    }
    println!();
    let expected_256_1 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
    let expected_256_2 = "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    println!("   Expected:            {}", expected_256_1);
    println!("                        {}", expected_256_2);
}
