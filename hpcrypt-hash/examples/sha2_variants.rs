use hpcrypt_hash::{HashFunction, Sha224, Sha512_224, Sha512_256};

fn main() {
    // Test SHA-224 with "abc"
    // Expected: 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
    let mut hasher = Sha224::new();
    hasher.update(b"abc");
    let result = hasher.finalize();
    println!("SHA-224(\"abc\") = {}", hex::encode(&result));
    let expected_224 =
        hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7").unwrap();
    assert_eq!(
        result.as_slice(),
        expected_224.as_slice(),
        "SHA-224 test failed"
    );
    println!("SHA-224 test passed");

    // Test SHA-512/224 with "abc"
    // Expected: 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
    let mut hasher = Sha512_224::new();
    hasher.update(b"abc");
    let result = hasher.finalize();
    println!("SHA-512/224(\"abc\") = {}", hex::encode(&result));
    let expected_512_224 =
        hex::decode("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa").unwrap();
    assert_eq!(
        result.as_slice(),
        expected_512_224.as_slice(),
        "SHA-512/224 test failed"
    );
    println!("SHA-512/224 test passed");

    // Test SHA-512/256 with "abc"
    // Expected: 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
    let mut hasher = Sha512_256::new();
    hasher.update(b"abc");
    let result = hasher.finalize();
    println!("SHA-512/256(\"abc\") = {}", hex::encode(&result));
    let expected_512_256 =
        hex::decode("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23").unwrap();
    assert_eq!(
        result.as_slice(),
        expected_512_256.as_slice(),
        "SHA-512/256 test failed"
    );
    println!("SHA-512/256 test passed");

    println!("\nAll tests passed!");
}
