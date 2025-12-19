//! Test trait-based API for hpcrypt-hash and hpcrypt-mac

use hpcrypt_hash::{HashFunction, Sha256, Sha512};
use hpcrypt_mac::{HmacSha256, HmacSha512, Mac};

#[test]
fn test_hash_function_trait() {
    // Test Sha256 via trait
    let data = b"test message";

    // Using trait method
    let hash1 = Sha256::hash(data);

    // Using instance methods
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash2 = hasher.finalize();

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
}

#[test]
fn test_hash_function_generic() {
    fn hash_with_trait<H: HashFunction>(data: &[u8]) -> H::Output {
        let mut hasher = H::new();
        hasher.update(data);
        hasher.finalize()
    }

    let data = b"generic test";

    let sha256_hash = hash_with_trait::<Sha256>(data);
    let sha512_hash = hash_with_trait::<Sha512>(data);

    assert_eq!(sha256_hash.as_ref().len(), 32);
    assert_eq!(sha512_hash.as_ref().len(), 64);
}

#[test]
fn test_mac_trait() {
    let key = b"secret key";
    let data = b"message to authenticate";

    // Using trait static method
    let tag = <HmacSha256 as Mac>::compute(key, data);

    assert_eq!(tag.len(), 32);
}

#[test]
fn test_mac_context_trait() {
    let key = b"secret key";
    let data1 = b"part 1";
    let data2 = b"part 2";

    // Streaming MAC computation
    let mut ctx = HmacSha256::new_context(key);
    ctx.update(data1);
    ctx.update(data2);
    let tag1 = ctx.finalize();

    // One-shot for comparison using trait method
    let mut combined = Vec::new();
    combined.extend_from_slice(data1);
    combined.extend_from_slice(data2);
    let tag2 = <HmacSha256 as Mac>::compute(key, &combined);

    assert_eq!(tag1, tag2);
}

#[test]
fn test_mac_generic() {
    fn authenticate<M: Mac>(key: &[u8], data: &[u8]) -> M::Output {
        M::compute(key, data)
    }

    let key = b"test key";
    let data = b"test data";

    let hmac256 = authenticate::<HmacSha256>(key, data);
    let hmac512 = authenticate::<HmacSha512>(key, data);

    assert_eq!(hmac256.as_ref().len(), 32);
    assert_eq!(hmac512.as_ref().len(), 64);
}

#[test]
fn test_finalize_reset() {
    let mut hasher = Sha256::new();
    hasher.update(b"message 1");
    let hash1 = hasher.finalize_reset();

    // hasher should be reset, ready for new data
    hasher.update(b"message 2");
    let hash2 = hasher.finalize();

    assert_ne!(hash1, hash2);
    assert_eq!(hash1.len(), 32);
    assert_eq!(hash2.len(), 32);
}
