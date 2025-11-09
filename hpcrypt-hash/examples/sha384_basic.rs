// Basic SHA-384 usage examples

use hpcrypt_hash::sha384::Sha384;

fn main() {
    println!("=== SHA-384 Basic Examples ===\n");

    // Example 1: Hash a simple string
    example_simple_hash();

    // Example 2: Incremental hashing
    example_incremental();

    // Example 3: Hash empty input
    example_empty();

    // Example 4: Comparing with SHA-512
    example_comparison();
}

fn example_simple_hash() {
    println!("1. Simple Hash:");
    let message = b"Hello, World!";
    let mut hasher = Sha384::new();
    hasher.update(message);
    let hash = hasher.finalize();

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA-384: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_incremental() {
    println!("2. Incremental Hashing:");
    let mut hasher = Sha384::new();

    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");

    let hash = hasher.finalize();

    print!("   Input (parts): \"The quick brown fox \" + \"jumps over the lazy dog\"\n");
    print!("   SHA-384: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_empty() {
    println!("3. Empty Input:");
    let hasher = Sha384::new();
    let hash = hasher.finalize();

    print!("   Input: (empty)\n");
    print!("   SHA-384: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da");
    println!("             274edebfe76f65fbd51ad2f14898b95b\n");
}

fn example_comparison() {
    println!("4. SHA-384 vs SHA-512:");
    let message = b"Test message";

    let mut hasher384 = Sha384::new();
    hasher384.update(message);
    let hash384 = hasher384.finalize();

    print!("   SHA-384 (48 bytes): ");
    for byte in hash384.iter() {
        print!("{:02x}", byte);
    }
    println!();

    println!("   Note: SHA-384 is a truncated version of SHA-512");
    println!("         using different initial hash values.\n");
}
