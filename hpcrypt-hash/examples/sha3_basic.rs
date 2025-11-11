// Basic SHA3 family usage examples
// Demonstrates SHA3-224, SHA3-256, SHA3-384, and SHA3-512

use hpcrypt_hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

fn main() {
    println!("=== SHA3 Family Examples ===\n");

    // Example 1: SHA3-256 - Most common variant
    example_sha3_256();

    // Example 2: SHA3-512 - Higher security
    example_sha3_512();

    // Example 3: SHA3-224 - Shorter output
    example_sha3_224();

    // Example 4: SHA3-384 - Medium security
    example_sha3_384();

    // Example 5: Incremental hashing
    example_incremental();

    // Example 6: Test vectors
    example_test_vectors();
}

fn example_sha3_256() {
    println!("1. SHA3-256 (256-bit output):");
    let message = b"The quick brown fox jumps over the lazy dog";
    let hash = Sha3_256::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-256: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04\n");
}

fn example_sha3_512() {
    println!("2. SHA3-512 (512-bit output):");
    let message = b"The quick brown fox jumps over the lazy dog";
    let hash = Sha3_512::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-512: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450\n");
}

fn example_sha3_224() {
    println!("3. SHA3-224 (224-bit output):");
    let message = b"The quick brown fox jumps over the lazy dog";
    let hash = Sha3_224::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-224: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795\n");
}

fn example_sha3_384() {
    println!("4. SHA3-384 (384-bit output):");
    let message = b"The quick brown fox jumps over the lazy dog";
    let hash = Sha3_384::digest(message);

    print!("   Input: {:?}\n", String::from_utf8_lossy(message));
    print!("   SHA3-384: ");
    for byte in hash.iter() {
        print!("{:02x}", byte);
    }
    println!();
    println!("   Expected: 7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41\n");
}

fn example_incremental() {
    println!("5. Incremental Hashing:");
    println!("   Demonstrating that incremental = one-shot\n");

    let message = b"The quick brown fox jumps over the lazy dog";

    // One-shot
    let hash_oneshot = Sha3_256::digest(message);

    // Incremental
    let mut hasher = Sha3_256::new();
    hasher.update(b"The quick brown fox ");
    hasher.update(b"jumps over the lazy dog");
    let hash_incremental = hasher.finalize();

    print!("   One-shot:     ");
    for byte in hash_oneshot.iter() {
        print!("{:02x}", byte);
    }
    println!();

    print!("   Incremental:  ");
    for byte in hash_incremental.iter() {
        print!("{:02x}", byte);
    }
    println!();

    if hash_oneshot == hash_incremental {
        println!("   ✓ Results match!\n");
    } else {
        println!("   ✗ Results differ!\n");
    }
}

fn example_test_vectors() {
    println!("6. Official Test Vectors (Empty Input):");

    // SHA3-224
    let hash_224 = Sha3_224::digest(b"");
    print!("   SHA3-224: ");
    for byte in hash_224.iter() {
        print!("{:02x}", byte);
    }
    println!();
    let expected_224 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    println!("   Expected: {}", expected_224);
    println!();

    // SHA3-256
    let hash_256 = Sha3_256::digest(b"");
    print!("   SHA3-256: ");
    for byte in hash_256.iter() {
        print!("{:02x}", byte);
    }
    println!();
    let expected_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    println!("   Expected: {}", expected_256);
    println!();

    // SHA3-384
    let hash_384 = Sha3_384::digest(b"");
    print!("   SHA3-384: ");
    for byte in hash_384.iter() {
        print!("{:02x}", byte);
    }
    println!();
    let expected_384 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    println!("   Expected: {}", expected_384);
    println!();

    // SHA3-512
    let hash_512 = Sha3_512::digest(b"");
    print!("   SHA3-512: ");
    for byte in hash_512.iter() {
        print!("{:02x}", byte);
    }
    println!();
    let expected_512 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    println!("   Expected: {}", expected_512);
}
