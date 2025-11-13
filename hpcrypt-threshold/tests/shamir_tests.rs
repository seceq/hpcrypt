//! Comprehensive tests for Shamir Secret Sharing

use hpcrypt_threshold::shamir::*;

#[test]
fn test_split_and_reconstruct_simple() {
    let secret = [42u8; 32];
    let shares = split_secret(&secret, 3, 5).unwrap();

    // Should create exactly 5 shares
    assert_eq!(shares.len(), 5);

    // Reconstruct from exactly threshold shares
    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_reconstruct_with_more_than_threshold() {
    let secret = [0x12, 0x34, 0x56, 0x78];
    let shares = split_secret(&secret, 2, 4).unwrap();

    // Reconstruct with more than threshold
    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);

    // Reconstruct with all shares
    let reconstructed_all = reconstruct_secret(&shares).unwrap();
    assert_eq!(&secret[..], &reconstructed_all[..]);
}

#[test]
fn test_reconstruct_different_share_combinations() {
    let secret = [0xAA; 16];
    let shares = split_secret(&secret, 3, 6).unwrap();

    // Try different combinations of 3 shares
    let combos = vec![vec![0, 1, 2], vec![0, 2, 4], vec![1, 3, 5], vec![2, 4, 5]];

    for combo in combos {
        let selected: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
        let reconstructed = reconstruct_secret(&selected).unwrap();
        assert_eq!(
            &secret[..],
            &reconstructed[..],
            "Failed for combo {:?}",
            combo
        );
    }
}

#[test]
fn test_insufficient_shares_fails() {
    let secret = [0xFF; 8];
    let shares = split_secret(&secret, 4, 7).unwrap();

    // Try with fewer than threshold shares (should fail or produce wrong result)
    let result = reconstruct_secret(&shares[0..2]);

    if let Ok(reconstructed) = result {
        // If it doesn't error, it should at least produce wrong result
        assert_ne!(&secret[..], &reconstructed[..]);
    }
}

#[test]
fn test_minimum_threshold() {
    let secret = [0x11, 0x22, 0x33, 0x44];

    // Threshold of 2 (minimum practical)
    let shares = split_secret(&secret, 2, 3).unwrap();
    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_all_zero_secret() {
    let secret = [0u8; 32];
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_all_ones_secret() {
    let secret = [0xFF; 32];
    let shares = split_secret(&secret, 3, 5).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_random_pattern_secret() {
    let secret = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let shares = split_secret(&secret, 4, 8).unwrap();

    let reconstructed = reconstruct_secret(&shares[0..4]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_maximum_shares() {
    let secret = [0xAA; 16];

    // Maximum number of shares (255)
    let shares = split_secret(&secret, 2, 255).unwrap();
    assert_eq!(shares.len(), 255);

    let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_high_threshold() {
    let secret = [0x42; 8];

    // High threshold relative to total shares
    let shares = split_secret(&secret, 10, 12).unwrap();
    let reconstructed = reconstruct_secret(&shares[0..10]).unwrap();
    assert_eq!(&secret[..], &reconstructed[..]);
}

#[test]
fn test_shares_are_different() {
    let secret = [0x12; 16];
    let shares = split_secret(&secret, 3, 5).unwrap();

    // All shares should be different from each other
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(shares[i].data, shares[j].data);
        }
    }
}

#[test]
fn test_shares_different_from_secret() {
    let secret = [0x99; 16];
    let shares = split_secret(&secret, 3, 5).unwrap();

    // No share should be identical to the secret
    for share in &shares {
        assert_ne!(&share.data[..], &secret[..]);
    }
}

#[test]
fn test_deterministic_sharing() {
    let secret = [0xAB; 16];

    // Same secret should produce different shares each time (due to randomness)
    let shares1 = split_secret(&secret, 3, 5).unwrap();
    let shares2 = split_secret(&secret, 3, 5).unwrap();

    // At least one share should be different
    let mut found_difference = false;
    for i in 0..5 {
        if shares1[i].data != shares2[i].data {
            found_difference = true;
            break;
        }
    }
    assert!(found_difference, "Shares should be randomized");
}

#[test]
fn test_various_secret_sizes() {
    let sizes = [1, 4, 16, 32, 64, 128];

    for size in sizes {
        let secret = vec![0x55u8; size];
        let shares = split_secret(&secret, 2, 4).unwrap();
        let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(&secret[..], &reconstructed[..], "Failed for size {}", size);
    }
}

#[test]
fn test_error_threshold_greater_than_shares() {
    let secret = [0x42; 16];
    let result = split_secret(&secret, 6, 5);

    assert!(result.is_err(), "Should fail when threshold > total shares");
}

#[test]
fn test_error_zero_threshold() {
    let secret = [0x42; 16];
    let result = split_secret(&secret, 0, 5);

    assert!(result.is_err(), "Should fail with zero threshold");
}

#[test]
fn test_error_empty_secret() {
    let secret: &[u8] = &[];
    let result = split_secret(secret, 2, 4);

    // Should either error or handle gracefully
    if let Ok(shares) = result {
        let reconstructed = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(reconstructed.len(), 0);
    }
}
