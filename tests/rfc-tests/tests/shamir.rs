//! Shamir Secret Sharing comprehensive test suite
//!
//! Tests for Shamir Secret Sharing implementation based on:
//! - Shamir, Adi (1979). "How to share a secret". Communications of the ACM. 22 (11): 612–613.
//!
//! The implementation uses GF(256) arithmetic with the AES polynomial.

use hpcrypt_threshold::shamir::{reconstruct_secret, split_secret, Share};

// ============================================================================
// BASIC FUNCTIONALITY TESTS
// ============================================================================

#[test]
fn test_basic_split_reconstruct_2_of_3() {
    let secret = b"Hello, Shamir!";
    let shares = split_secret(secret, 2, 3).unwrap();

    assert_eq!(shares.len(), 3);

    // Any 2 shares should reconstruct correctly
    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_basic_split_reconstruct_3_of_5() {
    let secret = b"Secret message for testing";
    let shares = split_secret(secret, 3, 5).unwrap();

    assert_eq!(shares.len(), 5);

    // First 3 shares
    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_basic_split_reconstruct_5_of_10() {
    let secret = b"Larger threshold scheme";
    let shares = split_secret(secret, 5, 10).unwrap();

    assert_eq!(shares.len(), 10);

    let reconstructed = reconstruct_secret(&shares[0..5]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_reconstruct_with_all_shares() {
    let secret = b"Using all shares";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Using all 5 shares (more than threshold)
    let reconstructed = reconstruct_secret(&shares).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_reconstruct_with_exact_threshold() {
    let secret = b"Exact threshold";
    let shares = split_secret(secret, 4, 4).unwrap();

    // n == k case
    let reconstructed = reconstruct_secret(&shares).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

// ============================================================================
// THRESHOLD VARIATION TESTS
// ============================================================================

#[test]
fn test_minimum_threshold_2_of_2() {
    let secret = b"Minimum threshold test";
    let shares = split_secret(secret, 2, 2).unwrap();

    assert_eq!(shares.len(), 2);

    let reconstructed = reconstruct_secret(&shares).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_threshold_2_of_255() {
    let secret = b"Maximum shares with minimum threshold";
    let shares = split_secret(secret, 2, 255).unwrap();

    assert_eq!(shares.len(), 255);

    // Any 2 shares should work
    let reconstructed = reconstruct_secret(&[shares[0].clone(), shares[254].clone()]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_threshold_128_of_255() {
    let secret = b"High threshold";
    let shares = split_secret(secret, 128, 255).unwrap();

    assert_eq!(shares.len(), 255);

    let reconstructed = reconstruct_secret(&shares[0..128]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_threshold_255_of_255() {
    let secret = b"Maximum threshold";
    let shares = split_secret(secret, 255, 255).unwrap();

    assert_eq!(shares.len(), 255);

    let reconstructed = reconstruct_secret(&shares).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

// ============================================================================
// SHARE COMBINATION TESTS
// ============================================================================

#[test]
fn test_all_combinations_3_of_5() {
    let secret = b"Test all combinations";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Test all C(5,3) = 10 combinations
    let combinations: Vec<[usize; 3]> = vec![
        [0, 1, 2],
        [0, 1, 3],
        [0, 1, 4],
        [0, 2, 3],
        [0, 2, 4],
        [0, 3, 4],
        [1, 2, 3],
        [1, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
    ];

    for combo in combinations {
        let subset = vec![
            shares[combo[0]].clone(),
            shares[combo[1]].clone(),
            shares[combo[2]].clone(),
        ];
        let reconstructed = reconstruct_secret(&subset).unwrap();
        assert_eq!(
            &reconstructed[..], secret,
            "Failed for combination {:?}",
            combo
        );
    }
}

#[test]
fn test_all_combinations_2_of_4() {
    let secret = b"Smaller combinations";
    let shares = split_secret(secret, 2, 4).unwrap();

    // Test all C(4,2) = 6 combinations
    let combinations: Vec<[usize; 2]> =
        vec![[0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3]];

    for combo in combinations {
        let subset = vec![shares[combo[0]].clone(), shares[combo[1]].clone()];
        let reconstructed = reconstruct_secret(&subset).unwrap();
        assert_eq!(
            &reconstructed[..], secret,
            "Failed for combination {:?}",
            combo
        );
    }
}

#[test]
fn test_non_contiguous_shares() {
    let secret = b"Non-contiguous";
    let shares = split_secret(secret, 3, 10).unwrap();

    // Use shares 1, 5, 9 (indices 0, 4, 8)
    let subset = vec![shares[0].clone(), shares[4].clone(), shares[8].clone()];
    let reconstructed = reconstruct_secret(&subset).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

// ============================================================================
// SECRET SIZE VARIATION TESTS
// ============================================================================

#[test]
fn test_single_byte_secret() {
    let secret = [0x42u8];
    let shares = split_secret(&secret, 2, 3).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(&reconstructed[..], &secret[..]);
}

#[test]
fn test_empty_secret_error() {
    let secret: &[u8] = &[];
    let result = split_secret(secret, 2, 3);
    assert!(result.is_err(), "Empty secret should return error");
}

#[test]
fn test_large_secret_1kb() {
    let secret: Vec<u8> = (0..1024).map(|i| i as u8).collect();
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_large_secret_10kb() {
    let secret: Vec<u8> = (0..10240).map(|i| i as u8).collect();
    let shares = split_secret(&secret, 5, 10).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..5]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_all_byte_values() {
    // Secret containing all 256 byte values
    let secret: Vec<u8> = (0..=255).collect();
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_all_zeros_secret() {
    let secret = vec![0u8; 32];
    let shares = split_secret(&secret, 2, 3).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_all_ones_secret() {
    let secret = vec![0xFFu8; 32];
    let shares = split_secret(&secret, 2, 3).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_alternating_pattern() {
    let secret: Vec<u8> = (0..64).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

// ============================================================================
// PARAMETER VALIDATION ERROR TESTS
// ============================================================================

#[test]
fn test_error_threshold_too_small() {
    let secret = b"test";
    let result = split_secret(secret, 1, 5);
    assert!(result.is_err(), "threshold=1 should error");

    let result = split_secret(secret, 0, 5);
    assert!(result.is_err(), "threshold=0 should error");
}

#[test]
fn test_error_threshold_greater_than_shares() {
    let secret = b"test";
    let result = split_secret(secret, 6, 5);
    assert!(result.is_err(), "threshold > num_shares should error");
}

#[test]
fn test_error_too_many_shares() {
    let secret = b"test";
    let result = split_secret(secret, 3, 256);
    assert!(result.is_err(), "num_shares=256 should error (max is 255)");
}

#[test]
fn test_error_reconstruct_insufficient_shares() {
    let secret = b"test";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Only 1 share
    let result = reconstruct_secret(&shares[0..1]);
    assert!(result.is_err(), "1 share should error (need at least 2)");
}

#[test]
fn test_error_reconstruct_empty_shares() {
    let empty: &[Share] = &[];
    let result = reconstruct_secret(empty);
    assert!(result.is_err(), "Empty shares should error");
}

// ============================================================================
// SHARE INTEGRITY TESTS
// ============================================================================

#[test]
fn test_share_indices_are_sequential() {
    let secret = b"test indices";
    let shares = split_secret(secret, 3, 5).unwrap();

    for (i, share) in shares.iter().enumerate() {
        assert_eq!(share.x, (i + 1) as u8, "Share index should be sequential starting from 1");
    }
}

#[test]
fn test_share_lengths_match_secret() {
    let secret = b"test share lengths";
    let shares = split_secret(secret, 3, 5).unwrap();

    for share in &shares {
        assert_eq!(share.y.len(), secret.len(), "Share y length should match secret length");
    }
}

#[test]
fn test_duplicate_share_indices_error() {
    let secret = b"test";
    let shares = split_secret(secret, 2, 3).unwrap();

    // Create duplicate by cloning
    let mut dup_shares = vec![shares[0].clone(), shares[0].clone()];
    let result = reconstruct_secret(&dup_shares);
    assert!(result.is_err(), "Duplicate share indices should error");

    // Modify x to be same
    dup_shares[1] = shares[1].clone();
    // This should work
    let result = reconstruct_secret(&dup_shares);
    assert!(result.is_ok(), "Different indices should work");
}

#[test]
fn test_mismatched_share_lengths_error() {
    let secret1 = b"short";
    let secret2 = b"longer secret";

    let shares1 = split_secret(secret1, 2, 3).unwrap();
    let shares2 = split_secret(secret2, 2, 3).unwrap();

    // Mix shares from different secrets (different lengths)
    let mixed = vec![shares1[0].clone(), shares2[1].clone()];
    let result = reconstruct_secret(&mixed);
    assert!(result.is_err(), "Mismatched share lengths should error");
}

// ============================================================================
// SECURITY PROPERTY TESTS
// ============================================================================

#[test]
fn test_insufficient_shares_produce_wrong_secret() {
    let secret = b"The real secret";
    let shares = split_secret(secret, 4, 5).unwrap();

    // Only 3 shares (threshold is 4) - reconstruction will "work" but give wrong result
    // This tests that k-1 shares are insufficient
    let partial_result = reconstruct_secret(&shares[0..3]).unwrap();

    // The result should exist but be wrong
    // (Lagrange interpolation gives a result, just not the correct polynomial)
    // Note: There's a small probability it could match by chance, but extremely unlikely
    assert_ne!(
        &partial_result[..], secret,
        "k-1 shares should not reconstruct the correct secret"
    );
}

#[test]
fn test_different_splits_produce_different_shares() {
    let secret = b"Same secret";

    let shares1 = split_secret(secret, 3, 5).unwrap();
    let shares2 = split_secret(secret, 3, 5).unwrap();

    // The random polynomial coefficients should differ
    // So at least one share should differ between splits
    let all_same = shares1
        .iter()
        .zip(shares2.iter())
        .all(|(s1, s2)| s1.y == s2.y);

    // Very unlikely to be all the same (probability ~0 for non-trivial secrets)
    assert!(
        !all_same,
        "Different splits should produce different shares (probabilistic)"
    );
}

#[test]
fn test_shares_reveal_no_obvious_pattern() {
    let secret = vec![0xAAu8; 32];
    let shares = split_secret(&secret, 3, 5).unwrap();

    // Check that shares don't obviously expose the secret
    // (They shouldn't all be 0xAA)
    for share in &shares {
        let all_same = share.y.iter().all(|&b| b == secret[0]);
        assert!(!all_same, "Shares should not expose the secret pattern");
    }
}

// ============================================================================
// DETERMINISM AND INDEPENDENCE TESTS
// ============================================================================

#[test]
fn test_share_order_independence() {
    let secret = b"Order independence test";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Reconstruct with shares in different orders
    let order1 = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
    let order2 = vec![shares[2].clone(), shares[0].clone(), shares[1].clone()];
    let order3 = vec![shares[1].clone(), shares[2].clone(), shares[0].clone()];

    let result1 = reconstruct_secret(&order1).unwrap();
    let result2 = reconstruct_secret(&order2).unwrap();
    let result3 = reconstruct_secret(&order3).unwrap();

    assert_eq!(result1, result2, "Share order should not affect result");
    assert_eq!(result2, result3, "Share order should not affect result");
    assert_eq!(&result1[..], secret);
}

#[test]
fn test_more_shares_than_threshold() {
    let secret = b"Extra shares test";
    let shares = split_secret(secret, 3, 10).unwrap();

    // Using 3 shares (threshold)
    let result3 = reconstruct_secret(&shares[0..3]).unwrap();

    // Using 7 shares (more than threshold)
    let result7 = reconstruct_secret(&shares[0..7]).unwrap();

    // Using all 10 shares
    let result10 = reconstruct_secret(&shares).unwrap();

    assert_eq!(result3, result7, "Extra shares should not change result");
    assert_eq!(result7, result10, "Extra shares should not change result");
    assert_eq!(&result3[..], secret);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_secret_with_null_bytes() {
    let secret = b"secret\x00with\x00nulls";
    let shares = split_secret(secret, 2, 3).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(&reconstructed[..], secret);
}

#[test]
fn test_high_byte_values() {
    let secret: Vec<u8> = (200..=255).collect();
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_binary_data() {
    // Random-looking binary data
    let secret: Vec<u8> = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let shares = split_secret(&secret, 4, 7).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..4]).unwrap();
    assert_eq!(reconstructed, secret);
}

// ============================================================================
// CRYPTOGRAPHIC KEY MATERIAL TESTS
// ============================================================================

#[test]
fn test_aes_key_sharing() {
    // Simulated AES-256 key
    let aes_key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let shares = split_secret(&aes_key, 3, 5).unwrap();
    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();

    assert_eq!(&reconstructed[..], &aes_key[..]);
}

#[test]
fn test_ed25519_seed_sharing() {
    // Simulated Ed25519 seed (32 bytes)
    let seed: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    let shares = split_secret(&seed, 5, 7).unwrap();
    let reconstructed = reconstruct_secret(&shares[2..7]).unwrap();

    assert_eq!(&reconstructed[..], &seed[..]);
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn test_many_reconstructions() {
    let secret = b"Repeated reconstruction test";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Reconstruct 100 times to ensure consistency
    for _ in 0..100 {
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }
}

#[test]
fn test_many_splits() {
    let secret = b"Repeated split test";

    // Split 50 times and verify each
    for _ in 0..50 {
        let shares = split_secret(secret, 3, 5).unwrap();
        let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed[..], secret);
    }
}
