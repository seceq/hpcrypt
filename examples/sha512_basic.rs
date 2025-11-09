// Basic SHA-512 usage examples

use hpcrypt_hash::sha512::{sha512, Sha512};

fn main() {
    println!("=== SHA-512 Basic Examples ===\n");

    // Example 1: Hash a simple string
    example_simple_hash();

    // Example 2: Incremental hashing
    example_incremental();

    // Example 3: Hash empty input
    example_empty();

    // Example 4: Large data hashing
    example_large_data();
}

fn example_simple_hash() {
    println!("1. Simple Hash:");
    let message = b"Hello, World!";
    let hash = sha512(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_incremental() {
    println!("2. Incremental Hashing:");
    let mut hasher = Sha512::new();

    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");

    let hash = hasher.finalize();

    print!("   Input (parts): \"The quick brown fox \" + \"jumps over the lazy dog\"\n");
    print!("   SHA-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_empty() {
    println!("3. Empty Input:");
    let hash = sha512(b"");

    print!("   Input: (empty)\n");
    print!("   SHA-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce");
    println!("             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n");
}

fn example_large_data() {
    println!("4. Large Data Hashing:");

    // Hash 1 MB of data incrementally
    let mut hasher = Sha512::new();
    let chunk = vec![b'A'; 1024]; // 1 KB chunks

    for _ in 0..1024 {
        hasher.update(&chunk);
    }

    let hash = hasher.finalize();

    print!("   Input: 1 MB of 'A' characters\n");
    print!("   SHA-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}
