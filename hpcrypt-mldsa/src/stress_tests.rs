//! Stress tests for ML-DSA implementation
//!
//! These tests validate robustness, edge cases, and performance characteristics.

mod tests {
    
    
    
    
    
    
    
    
    
    

    /// Test multiple sign/verify cycles with the same keypair
    #[test]
    fn test_multiple_signatures_same_keypair() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Sign and verify 100 different messages
        for i in 0..100 {
            let message = format!("Test message number {}", i);
            let msg_bytes = message.as_bytes();

            // Sign
            let sig = sign::<MlDsa65>(&sk, msg_bytes)
                .expect(&format!("Signing should succeed for message {}", i));

            // Verify with correct message
            assert!(
                verify::<MlDsa65>(&pk, msg_bytes, &sig),
                "Signature {} should verify with correct message",
                i
            );

            // Verify fails with wrong message
            let wrong_msg = format!("Wrong message {}", i);
            assert!(
                !verify::<MlDsa65>(&pk, wrong_msg.as_bytes(), &sig),
                "Signature {} should not verify with wrong message",
                i
            );
        }
    }

    /// Test signing with various message sizes
    #[test]
    fn test_variable_message_sizes() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Test message sizes: 0, 1, 16, 64, 256, 1024, 4096 bytes
        let sizes = vec![0, 1, 16, 64, 256, 1024, 4096];

        for size in sizes {
            let message = vec![0x42u8; size];

            let sig = sign::<MlDsa65>(&sk, &message)
                .expect(&format!("Signing should succeed for {} byte message", size));

            assert!(
                verify::<MlDsa65>(&pk, &message, &sig),
                "Signature should verify for {} byte message",
                size
            );

            // Check signature size is always correct
            let serialized = serialize_signature::<MlDsa65>(&sig);
            assert_eq!(
                serialized.len(),
                3309,
                "Signature size should be 3309 bytes regardless of message size"
            );
        }
    }

    /// Test all three security levels work correctly
    #[test]
    fn test_all_security_levels() {
        let seed = [99u8; 32];
        let message = b"Test message for all security levels";

        // ML-DSA-44
        {
            let (pk, sk) = keygen_from_seed::<MlDsa44>(&seed);
            let sig = sign::<MlDsa44>(&sk, message).expect("ML-DSA-44 sign should succeed");
            assert!(
                verify::<MlDsa44>(&pk, message, &sig),
                "ML-DSA-44 verify should succeed"
            );

            let serialized = serialize_signature::<MlDsa44>(&sig);
            assert_eq!(
                serialized.len(),
                2420,
                "ML-DSA-44 signature should be 2420 bytes"
            );
        }

        // ML-DSA-65
        {
            let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
            let sig = sign::<MlDsa65>(&sk, message).expect("ML-DSA-65 sign should succeed");
            assert!(
                verify::<MlDsa65>(&pk, message, &sig),
                "ML-DSA-65 verify should succeed"
            );

            let serialized = serialize_signature::<MlDsa65>(&sig);
            assert_eq!(
                serialized.len(),
                3309,
                "ML-DSA-65 signature should be 3309 bytes"
            );
        }

        // ML-DSA-87
        {
            let (pk, sk) = keygen_from_seed::<MlDsa87>(&seed);
            let sig = sign::<MlDsa87>(&sk, message).expect("ML-DSA-87 sign should succeed");
            assert!(
                verify::<MlDsa87>(&pk, message, &sig),
                "ML-DSA-87 verify should succeed"
            );

            let serialized = serialize_signature::<MlDsa87>(&sig);
            assert_eq!(
                serialized.len(),
                4627,
                "ML-DSA-87 signature should be 4627 bytes"
            );
        }
    }

    /// Test serialization/deserialization preserves signature validity
    #[test]
    fn test_serialize_deserialize_preserves_validity() {
        let seed = [123u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
        let message = b"Serialization test message";

        for i in 0..50 {
            let test_msg = format!("{} iteration {}", core::str::from_utf8(message).unwrap(), i);

            // Sign
            let sig = sign::<MlDsa65>(&sk, test_msg.as_bytes()).expect("Signing should succeed");

            // Verify original
            assert!(
                verify::<MlDsa65>(&pk, test_msg.as_bytes(), &sig),
                "Original signature should verify"
            );

            // Serialize and deserialize
            let serialized = serialize_signature::<MlDsa65>(&sig);
            let deserialized = deserialize_signature::<MlDsa65>(&serialized)
                .expect("Deserialization should succeed");

            // Verify deserialized
            assert!(
                verify::<MlDsa65>(&pk, test_msg.as_bytes(), &deserialized),
                "Deserialized signature should verify"
            );
        }
    }

    /// Test deterministic signing produces same signature
    #[test]
    fn test_deterministic_signing_consistency() {
        let seed = [77u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
        let message = b"Deterministic test";
        let rnd = [88u8; 32];

        // Sign the same message multiple times with same rnd
        let sig1 = sign_deterministic::<MlDsa65>(&sk, message, &rnd)
            .expect("First signing should succeed");
        let sig2 = sign_deterministic::<MlDsa65>(&sk, message, &rnd)
            .expect("Second signing should succeed");
        let sig3 = sign_deterministic::<MlDsa65>(&sk, message, &rnd)
            .expect("Third signing should succeed");

        // Serialize and compare
        let bytes1 = serialize_signature::<MlDsa65>(&sig1);
        let bytes2 = serialize_signature::<MlDsa65>(&sig2);
        let bytes3 = serialize_signature::<MlDsa65>(&sig3);

        assert_eq!(bytes1, bytes2, "Deterministic signatures should match");
        assert_eq!(bytes2, bytes3, "Deterministic signatures should match");

        // All should verify
        assert!(verify::<MlDsa65>(&pk, message, &sig1));
        assert!(verify::<MlDsa65>(&pk, message, &sig2));
        assert!(verify::<MlDsa65>(&pk, message, &sig3));
    }

    /// Test different seeds produce different keypairs
    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let (pk1, sk1) = keygen_from_seed::<MlDsa65>(&seed1);
        let (pk2, sk2) = keygen_from_seed::<MlDsa65>(&seed2);

        // Public keys should differ
        assert_ne!(
            pk1.rho, pk2.rho,
            "Different seeds should produce different rho"
        );
        assert_ne!(
            pk1.t1[0].coeffs[0], pk2.t1[0].coeffs[0],
            "Different seeds should produce different t1"
        );

        // Secret keys should differ
        assert_ne!(
            sk1.s1[0].coeffs[0], sk2.s1[0].coeffs[0],
            "Different seeds should produce different s1"
        );
    }

    /// Test cross-keypair signature rejection
    #[test]
    fn test_signature_only_verifies_with_correct_key() {
        let seed1 = [10u8; 32];
        let seed2 = [20u8; 32];

        let (pk1, sk1) = keygen_from_seed::<MlDsa65>(&seed1);
        let (pk2, _sk2) = keygen_from_seed::<MlDsa65>(&seed2);

        let message = b"Cross-key test";

        // Sign with sk1
        let sig = sign::<MlDsa65>(&sk1, message).expect("Signing with sk1 should succeed");

        // Verify with correct pk1
        assert!(
            verify::<MlDsa65>(&pk1, message, &sig),
            "Signature should verify with matching public key"
        );

        // Should NOT verify with wrong pk2
        assert!(
            !verify::<MlDsa65>(&pk2, message, &sig),
            "Signature should NOT verify with different public key"
        );
    }

    /// Stress test: Sign many messages rapidly (1000 signatures)
    ///
    /// Ignored by default because it's slow (~10 seconds).
    /// Run with: cargo test --lib stress_test_rapid_signing -- --ignored
    #[test]
    #[ignore]
    fn stress_test_rapid_signing() {
        let seed = [255u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        let mut success_count = 0;
        let total_attempts = 1000;

        for i in 0..total_attempts {
            let message = format!("Stress test message {}", i);

            if let Some(sig) = sign::<MlDsa65>(&sk, message.as_bytes()) {
                success_count += 1;

                // Verify every 10th signature
                if i % 10 == 0 {
                    assert!(
                        verify::<MlDsa65>(&pk, message.as_bytes(), &sig),
                        "Signature {} should verify",
                        i
                    );
                }
            }
        }

        // Should have high success rate (>90% based on rejection sampling)
        let success_rate = (success_count as f64) / (total_attempts as f64);
        assert!(
            success_rate > 0.90,
            "Success rate should be >90%, got {:.2}%",
            success_rate * 100.0
        );
    }

    /// Test edge case: empty message
    #[test]
    fn test_empty_message() {
        let seed = [0u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
        let empty_message = b"";

        let sig =
            sign::<MlDsa65>(&sk, empty_message).expect("Signing empty message should succeed");

        assert!(
            verify::<MlDsa65>(&pk, empty_message, &sig),
            "Empty message signature should verify"
        );
    }

    /// Test edge case: very long message (1MB, simulating large document)
    ///
    /// Ignored by default because it's slow.
    /// Run with: cargo test --lib test_large_message -- --ignored
    #[test]
    #[ignore]
    fn test_large_message() {
        let seed = [128u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // 1 MB message
        let large_message = vec![0x5Au8; 1024 * 1024];

        let sig = sign::<MlDsa65>(&sk, &large_message).expect("Signing 1MB message should succeed");

        assert!(
            verify::<MlDsa65>(&pk, &large_message, &sig),
            "Large message signature should verify"
        );

        // Signature size should still be constant
        let serialized = serialize_signature::<MlDsa65>(&sig);
        assert_eq!(
            serialized.len(),
            3309,
            "Signature size should be constant regardless of message size"
        );
    }
}
