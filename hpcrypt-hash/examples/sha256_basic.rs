// Basic SHA-256 usage examples

use hpcrypt_hash::HashFunction;
use hpcrypt_hash::sha256::{sha256, Sha256};

fn main() {
    println!("=== SHA-256 Basic Examples ===\n");

    // Example 1: Hash a simple string
    example_simple_hash();

    // Example 2: Incremental hashing
    example_incremental();

    // Example 3: Hash empty input
    example_empty();

    // Example 4: Hash different sizes
    example_various_sizes();
}

fn example_simple_hash() {
    println!("1. Simple Hash:");
    let message = b"Hello, World!";
    let hash = sha256(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_incremental() {
    println!("2. Incremental Hashing:");
    let mut hasher = Sha256::new();

    hasher.update(b"Hello, ");
    hasher.update(b"World!");

    let hash = hasher.finalize();

    print!("   Input (parts): \"Hello, \" + \"World!\"\n");
    print!("   SHA-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_empty() {
    println!("3. Empty Input:");
    let hash = sha256(b"");

    print!("   Input: (empty)\n");
    print!("   SHA-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
}

fn example_various_sizes() {
    println!("4. Various Input Sizes:");

    // Single byte
    let hash_1 = sha256(b"a");
    print!("   1 byte ('a'): ");
    for byte in hash_1.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 55 bytes (fits in one block with padding)
    let message_55 = vec![b'a'; 55];
    let hash_55 = sha256(&message_55);
    print!("   55 bytes: ");
    for byte in hash_55.iter() {
        print!("{:02x}", byte);
    }
    println!();

    // 64 bytes (requires two blocks)
    let message_64 = vec![b'a'; 64];
    let hash_64 = sha256(&message_64);
    print!("   64 bytes: ");
    for byte in hash_64.iter() {
        print!("{:02x}", byte);
    }
    println!();
}
