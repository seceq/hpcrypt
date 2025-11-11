// SHAKE (Extendable Output Functions) usage examples
// Demonstrates SHAKE128 and SHAKE256

use hpcrypt_hash::sha3::{Shake128, Shake256};

fn main() {
    println!("=== SHAKE (XOF) Examples ===\n");

    // Example 1: SHAKE128 with different output lengths
    example_shake128_variable();

    // Example 2: SHAKE256 with different output lengths
    example_shake256_variable();

    // Example 3: Incremental SHAKE128
    example_shake128_incremental();

    // Example 4: SHAKE256 for key derivation
    example_shake256_kdf();

    // Example 5: Compare SHAKE128 vs SHAKE256
    example_compare_shake();
}

fn example_shake128_variable() {
    println!("1. SHAKE128 with Variable Output Lengths:");
    let message = b"Hello, SHAKE!";

    // 16 bytes output
    let mut out_16 = vec![0u8; 16];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_16);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHAKE128 (16 bytes): ");
    for byte in out_16.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 32 bytes output
    let mut out_32 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_32);

    print!("   SHAKE128 (32 bytes): ");
    for byte in out_32.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 64 bytes output
    let mut out_64 = vec![0u8; 64];
    let mut shake = Shake128::new();
    shake.update(message);
    shake.finalize(&mut out_64);

    print!("   SHAKE128 (64 bytes): ");
    for byte in out_64.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_shake256_variable() {
    println!("2. SHAKE256 with Variable Output Lengths:");
    let message = b"Hello, SHAKE!";

    // 32 bytes output
    let mut out_32 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_32);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHAKE256 (32 bytes): ");
    for byte in out_32.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 64 bytes output
    let mut out_64 = vec![0u8; 64];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_64);

    print!("   SHAKE256 (64 bytes): ");
    for byte in out_64.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 128 bytes output
    let mut out_128 = vec![0u8; 128];
    let mut shake = Shake256::new();
    shake.update(message);
    shake.finalize(&mut out_128);

    print!("   SHAKE256 (128 bytes): ");
    for byte in out_128.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_shake128_incremental() {
    println!("3. Incremental SHAKE128:");
    let mut shake = Shake128::new();

    shake.update(b"Hello, ");
    shake.update(b"SHAKE!");

    let mut output = vec![0u8; 32];
    shake.finalize(&mut output);

    print!("   Input (parts): \"Hello, \" + \"SHAKE!\"\n");
    print!("   SHAKE128 (32 bytes): ");
    for byte in output.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_shake256_kdf() {
    println!("4. SHAKE256 for Key Derivation:");
    let seed = b"master_key_material";

    // Derive three different keys from the same seed
    let mut key1 = vec![0u8; 32]; // AES-256 key
    let mut key2 = vec![0u8; 32]; // HMAC key
    let mut key3 = vec![0u8; 16]; // IV

    // Key 1
    let mut shake = Shake256::new();
    shake.update(seed);
    shake.update(b"key1");
    shake.finalize(&mut key1);

    print!("   Seed: {:?}\n", String::from_utf8_lossy(seed));
    print!("   Key 1 (32 bytes): ");
    for byte in key1.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Key 2
    let mut shake = Shake256::new();
    shake.update(seed);
    shake.update(b"key2");
    shake.finalize(&mut key2);

    print!("   Key 2 (32 bytes): ");
    for byte in key2.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // Key 3
    let mut shake = Shake256::new();
    shake.update(seed);
    shake.update(b"key3");
    shake.finalize(&mut key3);

    print!("   Key 3 (16 bytes): ");
    for byte in key3.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_compare_shake() {
    println!("5. Compare SHAKE128 vs SHAKE256 on Empty Input:");
    let empty = b"";

    // SHAKE128
    let mut out_128 = vec![0u8; 32];
    let mut shake = Shake128::new();
    shake.update(empty);
    shake.finalize(&mut out_128);

    print!("   SHAKE128 (32 bytes): ");
    for byte in out_128.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263");

    // SHAKE256
    let mut out_256 = vec![0u8; 32];
    let mut shake = Shake256::new();
    shake.update(empty);
    shake.finalize(&mut out_256);

    print!("   SHAKE256 (32 bytes): ");
    for byte in out_256.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
}
