// Basic SHA3 family usage examples
// Demonstrates SHA3-224, SHA3-256, SHA3-384, and SHA3-512

use hpcrypt_hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

fn main() {
    println!("=== SHA3 Family Examples ===\n");

    // Example 1: SHA3-256
    example_sha3_256();

    // Example 2: SHA3-512
    example_sha3_512();

    // Example 3: SHA3-224
    example_sha3_224();

    // Example 4: SHA3-384
    example_sha3_384();

    // Example 5: Incremental hashing
    example_incremental();

    // Example 6: Compare all variants
    example_all_variants();
}

fn example_sha3_256() {
    println!("1. SHA3-256:");
    let message = b"Hello, SHA3!";
    let hash = Sha3_256::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_sha3_512() {
    println!("2. SHA3-512:");
    let message = b"Hello, SHA3!";
    let hash = Sha3_512::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_sha3_224() {
    println!("3. SHA3-224:");
    let message = b"Hello, SHA3!";
    let hash = Sha3_224::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-224: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_sha3_384() {
    println!("4. SHA3-384:");
    let message = b"Hello, SHA3!";
    let hash = Sha3_384::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-384: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_incremental() {
    println!("5. Incremental Hashing (SHA3-256):");
    let mut hasher = Sha3_256::new();

    hasher.update(b"Hello, ");
    hasher.update(b"SHA3!");

    let hash = hasher.finalize();

    print!("   Input (parts): \"Hello, \" + \"SHA3!\"\n");
    print!("   SHA3-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!("\n");
}

fn example_all_variants() {
    println!("6. All SHA3 Variants on Empty Input:");

    let empty = b"";

    let hash_224 = Sha3_224::digest(empty);
    print!("   SHA3-224: ");
    for byte in hash_224.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");

    let hash_256 = Sha3_256::digest(empty);
    print!("   SHA3-256: ");
    for byte in hash_256.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    let hash_384 = Sha3_384::digest(empty);
    print!("   SHA3-384: ");
    for byte in hash_384.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");

    let hash_512 = Sha3_512::digest(empty);
    print!("   SHA3-512: ");
    for byte in hash_512.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}
