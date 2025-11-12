//! Integration tests for hpcrypt-rng

use hpcrypt_rng::*;

#[test]
fn test_generate_random_bytes_fills_buffer() {
    let mut buf = [0u8; 32];
    generate_random_bytes(&mut buf).expect("RNG failed");

    // Should not be all zeros (probability ~1/2^256)
    assert_ne!(buf, [0u8; 32]);
}

#[test]
fn test_generate_random_bytes_uniqueness() {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    generate_random_bytes(&mut buf1).expect("RNG failed");
    generate_random_bytes(&mut buf2).expect("RNG failed");

    // Should be different (probability of collision ~1/2^256)
    assert_ne!(buf1, buf2);
}

#[test]
fn test_generate_key_different_sizes() {
    let key16: [u8; 16] = generate_key().expect("RNG failed");
    let key32: [u8; 32] = generate_key().expect("RNG failed");
    let key64: [u8; 64] = generate_key().expect("RNG failed");

    assert_ne!(key16, [0u8; 16]);
    assert_ne!(key32, [0u8; 32]);
    assert_ne!(key64, [0u8; 64]);
}

#[test]
fn test_generate_key_uniqueness() {
    let key1: [u8; 32] = generate_key().expect("RNG failed");
    let key2: [u8; 32] = generate_key().expect("RNG failed");

    assert_ne!(key1, key2);
}

#[test]
fn test_generate_nonce_standard_sizes() {
    // ChaCha20-Poly1305 / AES-GCM nonce (96 bits)
    let nonce12: [u8; 12] = generate_nonce().expect("RNG failed");
    assert_ne!(nonce12, [0u8; 12]);

    // XChaCha20-Poly1305 nonce (192 bits)
    let nonce24: [u8; 24] = generate_nonce().expect("RNG failed");
    assert_ne!(nonce24, [0u8; 24]);
}

#[test]
fn test_generate_nonce_uniqueness() {
    let nonce1: [u8; 12] = generate_nonce().expect("RNG failed");
    let nonce2: [u8; 12] = generate_nonce().expect("RNG failed");

    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_generate_salt_standard_sizes() {
    // Argon2 minimum (16 bytes)
    let salt16: [u8; 16] = generate_salt().expect("RNG failed");
    assert_ne!(salt16, [0u8; 16]);

    // Conservative (32 bytes)
    let salt32: [u8; 32] = generate_salt().expect("RNG failed");
    assert_ne!(salt32, [0u8; 32]);
}

#[test]
fn test_generate_salt_uniqueness() {
    let salt1: [u8; 16] = generate_salt().expect("RNG failed");
    let salt2: [u8; 16] = generate_salt().expect("RNG failed");

    assert_ne!(salt1, salt2);
}

#[test]
fn test_fill_various_sizes() {
    let mut tiny = [0u8; 1];
    let mut small = [0u8; 7];
    let mut medium = [0u8; 64];
    let mut large = [0u8; 1024];

    generate_random_bytes(&mut tiny).expect("RNG failed");
    generate_random_bytes(&mut small).expect("RNG failed");
    generate_random_bytes(&mut medium).expect("RNG failed");
    generate_random_bytes(&mut large).expect("RNG failed");

    // Small arrays have higher chance of being all zeros
    assert_ne!(medium, [0u8; 64]);
    assert_ne!(large, [0u8; 1024]);
}

#[cfg(feature = "std")]
#[test]
fn test_statistical_balance() {
    // Basic statistical test - check bit balance
    let mut bytes = [0u8; 1000];
    generate_random_bytes(&mut bytes).expect("RNG failed");

    let mut bit_count = 0u32;
    for byte in &bytes {
        bit_count += byte.count_ones();
    }

    // Expect ~50% ones (8000 bits total, expect ~4000 ones)
    // Allow ±15% deviation (3400-4600)
    assert!(
        bit_count >= 3400 && bit_count <= 4600,
        "Bit balance out of range: {}",
        bit_count
    );
}
