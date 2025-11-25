//! ECIES (Elliptic Curve Integrated Encryption Scheme) Test Suite
//!
//! Comprehensive tests for ECIES implementations following SEC 1 v2.0.
//!
//! Tested curves:
//! - P-256 (NIST P-256 / secp256r1) - 128-bit security
//! - P-384 (NIST P-384 / secp384r1) - 192-bit security
//! - P-521 (NIST P-521 / secp521r1) - 256-bit security
//! - secp256k1 (Bitcoin/Ethereum curve) - 128-bit security

use rand::thread_rng;
use rfc_tests::TestStats;

// ============================================================================
// ECIES P-256 Tests
// ============================================================================

mod p256_tests {
    use super::*;
    use hpcrypt_ecies::EciesP256;

    #[test]
    fn test_p256_basic_encrypt_decrypt() {
        println!("\n=== ECIES P-256: Basic Encrypt/Decrypt ===");
        let mut rng = thread_rng();
        let mut stats = TestStats::new();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"Hello, ECIES P-256!";

        let ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[]).unwrap();

        if plaintext == message {
            println!("  Basic encrypt/decrypt works");
            stats.passed += 1;
        } else {
            println!("  Decrypted message doesn't match");
            stats.failed += 1;
        }

        stats.print_summary();
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn test_p256_empty_message() {
        println!("\n=== ECIES P-256: Empty Message ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Empty message encrypt/decrypt works");
    }

    #[test]
    fn test_p256_large_message() {
        println!("\n=== ECIES P-256: Large Message (1MB) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 1024 * 1024]; // 1 MB

        let ciphertext = EciesP256::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Large message (1MB) encrypt/decrypt works");
    }

    #[test]
    fn test_p256_wrong_key_fails() {
        println!("\n=== ECIES P-256: Wrong Key Detection ===");
        let mut rng = thread_rng();

        let (_, public1) = EciesP256::generate_keypair(&mut rng).unwrap();
        let (secret2, _) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext = EciesP256::encrypt(&public1, message, &[], &mut rng).unwrap();
        let result = EciesP256::decrypt(&secret2, &ciphertext, &[]);

        assert!(result.is_err() || result.unwrap() != message);
        println!("  Wrong key correctly detected/rejected");
    }

    #[test]
    fn test_p256_tampering_detected() {
        println!("\n=== ECIES P-256: Ciphertext Tampering Detection ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"Authenticated message";

        let mut ciphertext = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();

        // Tamper with ciphertext (flip a bit in the middle)
        let idx = ciphertext.len() / 2;
        ciphertext[idx] ^= 0x01;

        let result = EciesP256::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err() || result.unwrap() != message);
        println!("  Ciphertext tampering correctly detected");
    }

    #[test]
    fn test_p256_shared_info() {
        println!("\n=== ECIES P-256: Shared Info (S2) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"Message with context";
        let shared_info = b"application-context-v1";

        // Encrypt with shared info
        let ciphertext = EciesP256::encrypt(&public, message, shared_info, &mut rng).unwrap();

        // Decrypt with correct shared info
        let plaintext = EciesP256::decrypt(&secret, &ciphertext, shared_info).unwrap();
        assert_eq!(plaintext, message);
        println!("  Correct shared info decrypts successfully");

        // Decrypt with wrong shared info should fail
        let result = EciesP256::decrypt(&secret, &ciphertext, b"wrong-context");
        assert!(result.is_err());
        println!("  Wrong shared info correctly rejected");
    }

    #[test]
    fn test_p256_different_ciphertexts() {
        println!("\n=== ECIES P-256: Ephemeral Key Uniqueness ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();
        let message = b"Same message";

        // Encrypt same message twice
        let ct1 = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();
        let ct2 = EciesP256::encrypt(&public, message, &[], &mut rng).unwrap();

        // Ciphertexts should differ (different ephemeral keys)
        assert_ne!(ct1, ct2);
        println!("  Different ciphertexts for same plaintext (ephemeral keys work)");

        // Both should decrypt correctly
        let pt1 = EciesP256::decrypt(&secret, &ct1, &[]).unwrap();
        let pt2 = EciesP256::decrypt(&secret, &ct2, &[]).unwrap();
        assert_eq!(pt1, message);
        assert_eq!(pt2, message);
        println!("  Both ciphertexts decrypt correctly");
    }

    #[test]
    fn test_p256_key_sizes() {
        println!("\n=== ECIES P-256: Key Sizes ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        // P-256: 32-byte scalar, 65-byte uncompressed public key
        assert_eq!(secret.len(), 32, "P-256 secret key should be 32 bytes");
        assert_eq!(public.len(), 65, "P-256 public key should be 65 bytes");
        assert_eq!(public[0], 0x04, "P-256 public key should have 0x04 prefix");
        println!("  Secret key: {} bytes", secret.len());
        println!("  Public key: {} bytes (uncompressed)", public.len());
    }

    #[test]
    fn test_p256_ciphertext_overhead() {
        println!("\n=== ECIES P-256: Ciphertext Overhead ===");
        let mut rng = thread_rng();

        let (_, public) = EciesP256::generate_keypair(&mut rng).unwrap();

        for msg_len in [0, 16, 100, 1000] {
            let message = vec![0x42u8; msg_len];
            let ciphertext = EciesP256::encrypt(&public, &message, &[], &mut rng).unwrap();

            // P-256 overhead: 65 (ephemeral pubkey) + 12 (nonce) + 16 (tag) = 93 bytes
            let expected_overhead = 93;
            let actual_overhead = ciphertext.len() - msg_len;
            assert_eq!(actual_overhead, expected_overhead);
            println!("  Message {} bytes -> Ciphertext {} bytes (overhead: {})",
                     msg_len, ciphertext.len(), actual_overhead);
        }
    }
}

// ============================================================================
// ECIES P-384 Tests
// ============================================================================

mod p384_tests {
    use super::*;
    use hpcrypt_ecies::EciesP384;

    #[test]
    fn test_p384_basic_encrypt_decrypt() {
        println!("\n=== ECIES P-384: Basic Encrypt/Decrypt ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = b"Hello, ECIES P-384!";

        let ciphertext = EciesP384::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP384::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Basic encrypt/decrypt works");
    }

    #[test]
    fn test_p384_empty_message() {
        println!("\n=== ECIES P-384: Empty Message ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext = EciesP384::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP384::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Empty message encrypt/decrypt works");
    }

    #[test]
    fn test_p384_large_message() {
        println!("\n=== ECIES P-384: Large Message (1MB) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 1024 * 1024]; // 1 MB

        let ciphertext = EciesP384::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesP384::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Large message (1MB) encrypt/decrypt works");
    }

    #[test]
    fn test_p384_wrong_key_fails() {
        println!("\n=== ECIES P-384: Wrong Key Detection ===");
        let mut rng = thread_rng();

        let (_, public1) = EciesP384::generate_keypair(&mut rng).unwrap();
        let (secret2, _) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext = EciesP384::encrypt(&public1, message, &[], &mut rng).unwrap();
        let result = EciesP384::decrypt(&secret2, &ciphertext, &[]);

        assert!(result.is_err() || result.unwrap() != message);
        println!("  Wrong key correctly detected/rejected");
    }

    #[test]
    fn test_p384_tampering_detected() {
        println!("\n=== ECIES P-384: Ciphertext Tampering Detection ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = b"Authenticated message";

        let mut ciphertext = EciesP384::encrypt(&public, message, &[], &mut rng).unwrap();
        let idx = ciphertext.len() / 2;
        ciphertext[idx] ^= 0xFF;

        let result = EciesP384::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
        println!("  Ciphertext tampering correctly detected");
    }

    #[test]
    fn test_p384_shared_info() {
        println!("\n=== ECIES P-384: Shared Info (S2) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();
        let message = b"Message with context";
        let shared_info = b"high-security-context";

        let ciphertext = EciesP384::encrypt(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesP384::decrypt(&secret, &ciphertext, shared_info).unwrap();
        assert_eq!(plaintext, message);
        println!("  Correct shared info decrypts successfully");

        let result = EciesP384::decrypt(&secret, &ciphertext, b"wrong-context");
        assert!(result.is_err());
        println!("  Wrong shared info correctly rejected");
    }

    #[test]
    fn test_p384_key_sizes() {
        println!("\n=== ECIES P-384: Key Sizes ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP384::generate_keypair(&mut rng).unwrap();

        // P-384: 48-byte scalar, 97-byte uncompressed public key
        assert_eq!(secret.len(), 48, "P-384 secret key should be 48 bytes");
        assert_eq!(public.len(), 97, "P-384 public key should be 97 bytes");
        assert_eq!(public[0], 0x04, "P-384 public key should have 0x04 prefix");
        println!("  Secret key: {} bytes", secret.len());
        println!("  Public key: {} bytes (uncompressed)", public.len());
    }

    #[test]
    fn test_p384_ciphertext_overhead() {
        println!("\n=== ECIES P-384: Ciphertext Overhead ===");
        let mut rng = thread_rng();

        let (_, public) = EciesP384::generate_keypair(&mut rng).unwrap();

        for msg_len in [0, 16, 100, 1000] {
            let message = vec![0x42u8; msg_len];
            let ciphertext = EciesP384::encrypt(&public, &message, &[], &mut rng).unwrap();

            // P-384 overhead: 97 (ephemeral pubkey) + 12 (nonce) + 16 (tag) = 125 bytes
            let expected_overhead = 125;
            let actual_overhead = ciphertext.len() - msg_len;
            assert_eq!(actual_overhead, expected_overhead);
            println!("  Message {} bytes -> Ciphertext {} bytes (overhead: {})",
                     msg_len, ciphertext.len(), actual_overhead);
        }
    }
}

// ============================================================================
// ECIES P-521 Tests
// ============================================================================

mod p521_tests {
    use super::*;
    use hpcrypt_ecies::EciesP521;

    #[test]
    fn test_p521_basic_encrypt_decrypt() {
        println!("\n=== ECIES P-521: Basic Encrypt/Decrypt ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"Hello, ECIES P-521!";

        let ciphertext = EciesP521::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Basic encrypt/decrypt works");
    }

    #[test]
    fn test_p521_empty_message() {
        println!("\n=== ECIES P-521: Empty Message ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext = EciesP521::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Empty message encrypt/decrypt works");
    }

    #[test]
    fn test_p521_large_message() {
        println!("\n=== ECIES P-521: Large Message (1MB) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 1024 * 1024]; // 1 MB

        let ciphertext = EciesP521::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Large message (1MB) encrypt/decrypt works");
    }

    #[test]
    fn test_p521_wrong_key_fails() {
        println!("\n=== ECIES P-521: Wrong Key Detection ===");
        let mut rng = thread_rng();

        let (_, public1) = EciesP521::generate_keypair(&mut rng).unwrap();
        let (secret2, _) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext = EciesP521::encrypt(&public1, message, &[], &mut rng).unwrap();
        let result = EciesP521::decrypt(&secret2, &ciphertext, &[]);

        assert!(result.is_err() || result.unwrap() != message);
        println!("  Wrong key correctly detected/rejected");
    }

    #[test]
    fn test_p521_tampering_detected() {
        println!("\n=== ECIES P-521: Ciphertext Tampering Detection ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"Authenticated message";

        let mut ciphertext = EciesP521::encrypt(&public, message, &[], &mut rng).unwrap();
        let idx = ciphertext.len() - 5; // Tamper near the tag
        ciphertext[idx] ^= 0x01;

        let result = EciesP521::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
        println!("  Ciphertext tampering correctly detected");
    }

    #[test]
    fn test_p521_shared_info() {
        println!("\n=== ECIES P-521: Shared Info (S2) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();
        let message = b"Message with context";
        let shared_info = b"maximum-security-context";

        let ciphertext = EciesP521::encrypt(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesP521::decrypt(&secret, &ciphertext, shared_info).unwrap();
        assert_eq!(plaintext, message);
        println!("  Correct shared info decrypts successfully");

        let result = EciesP521::decrypt(&secret, &ciphertext, b"wrong-context");
        assert!(result.is_err());
        println!("  Wrong shared info correctly rejected");
    }

    #[test]
    fn test_p521_key_sizes() {
        println!("\n=== ECIES P-521: Key Sizes ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesP521::generate_keypair(&mut rng).unwrap();

        // P-521: 66-byte scalar, 133-byte uncompressed public key
        assert_eq!(secret.len(), 66, "P-521 secret key should be 66 bytes");
        assert_eq!(public.len(), 133, "P-521 public key should be 133 bytes");
        assert_eq!(public[0], 0x04, "P-521 public key should have 0x04 prefix");
        println!("  Secret key: {} bytes", secret.len());
        println!("  Public key: {} bytes (uncompressed)", public.len());
    }

    #[test]
    fn test_p521_ciphertext_overhead() {
        println!("\n=== ECIES P-521: Ciphertext Overhead ===");
        let mut rng = thread_rng();

        let (_, public) = EciesP521::generate_keypair(&mut rng).unwrap();

        for msg_len in [0, 16, 100, 1000] {
            let message = vec![0x42u8; msg_len];
            let ciphertext = EciesP521::encrypt(&public, &message, &[], &mut rng).unwrap();

            // P-521 overhead: 133 (ephemeral pubkey) + 12 (nonce) + 16 (tag) = 161 bytes
            let expected_overhead = 161;
            let actual_overhead = ciphertext.len() - msg_len;
            assert_eq!(actual_overhead, expected_overhead);
            println!("  Message {} bytes -> Ciphertext {} bytes (overhead: {})",
                     msg_len, ciphertext.len(), actual_overhead);
        }
    }
}

// ============================================================================
// ECIES secp256k1 Tests
// ============================================================================

mod secp256k1_tests {
    use super::*;
    use hpcrypt_ecies::EciesSecp256k1;

    #[test]
    fn test_secp256k1_basic_encrypt_decrypt() {
        println!("\n=== ECIES secp256k1: Basic Encrypt/Decrypt ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Hello, Bitcoin!";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Basic encrypt/decrypt works");
    }

    #[test]
    fn test_secp256k1_empty_message() {
        println!("\n=== ECIES secp256k1: Empty Message ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Empty message encrypt/decrypt works");
    }

    #[test]
    fn test_secp256k1_large_message() {
        println!("\n=== ECIES secp256k1: Large Message (1MB) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = vec![0x42u8; 1024 * 1024]; // 1 MB

        let ciphertext = EciesSecp256k1::encrypt(&public, &message, &[], &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();

        assert_eq!(plaintext, message);
        println!("  Large message (1MB) encrypt/decrypt works");
    }

    #[test]
    fn test_secp256k1_wrong_key_fails() {
        println!("\n=== ECIES secp256k1: Wrong Key Detection ===");
        let mut rng = thread_rng();

        let (_, public1) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let (secret2, _) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Secret message";

        let ciphertext = EciesSecp256k1::encrypt(&public1, message, &[], &mut rng).unwrap();
        let result = EciesSecp256k1::decrypt(&secret2, &ciphertext, &[]);

        assert!(result.is_err() || result.unwrap() != message);
        println!("  Wrong key correctly detected/rejected");
    }

    #[test]
    fn test_secp256k1_tampering_detected() {
        println!("\n=== ECIES secp256k1: Ciphertext Tampering Detection ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Authenticated message";

        let mut ciphertext = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let idx = ciphertext.len() - 1;
        ciphertext[idx] ^= 0x01;

        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]);
        assert!(result.is_err());
        println!("  Ciphertext tampering correctly detected");
    }

    #[test]
    fn test_secp256k1_shared_info() {
        println!("\n=== ECIES secp256k1: Shared Info (S2) ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Message with context";
        let shared_info = b"bitcoin-context-v1";

        let ciphertext = EciesSecp256k1::encrypt(&public, message, shared_info, &mut rng).unwrap();
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, shared_info).unwrap();
        assert_eq!(plaintext, message);
        println!("  Correct shared info decrypts successfully");

        let result = EciesSecp256k1::decrypt(&secret, &ciphertext, b"wrong-context");
        assert!(result.is_err());
        println!("  Wrong shared info correctly rejected");
    }

    #[test]
    fn test_secp256k1_key_sizes() {
        println!("\n=== ECIES secp256k1: Key Sizes ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        // secp256k1: 32-byte scalar, 65-byte uncompressed public key
        assert_eq!(secret.len(), 32, "secp256k1 secret key should be 32 bytes");
        assert_eq!(public.len(), 65, "secp256k1 public key should be 65 bytes");
        assert_eq!(public[0], 0x04, "secp256k1 public key should have 0x04 prefix");
        println!("  Secret key: {} bytes", secret.len());
        println!("  Public key: {} bytes (uncompressed)", public.len());
    }

    #[test]
    fn test_secp256k1_ciphertext_overhead() {
        println!("\n=== ECIES secp256k1: Ciphertext Overhead (Uncompressed) ===");
        let mut rng = thread_rng();

        let (_, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        for msg_len in [0, 16, 100, 1000] {
            let message = vec![0x42u8; msg_len];
            let ciphertext = EciesSecp256k1::encrypt(&public, &message, &[], &mut rng).unwrap();

            // secp256k1 overhead (uncompressed): 65 + 12 + 16 = 93 bytes
            let expected_overhead = 93;
            let actual_overhead = ciphertext.len() - msg_len;
            assert_eq!(actual_overhead, expected_overhead);
            println!("  Message {} bytes -> Ciphertext {} bytes (overhead: {})",
                     msg_len, ciphertext.len(), actual_overhead);
        }
    }

    #[test]
    fn test_secp256k1_compressed_encrypt_decrypt() {
        println!("\n=== ECIES secp256k1: Compressed Key Mode ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Hello with compression!";

        // Encrypt with compressed ephemeral key
        let ciphertext = EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Verify compressed format (first byte should be 0x02 or 0x03)
        assert!(ciphertext[0] == 0x02 || ciphertext[0] == 0x03);
        println!("  Compressed ciphertext prefix: 0x{:02x}", ciphertext[0]);

        // Decrypt should work automatically
        let plaintext = EciesSecp256k1::decrypt(&secret, &ciphertext, &[]).unwrap();
        assert_eq!(plaintext, message);
        println!("  Compressed encrypt/decrypt works");
    }

    #[test]
    fn test_secp256k1_compressed_overhead() {
        println!("\n=== ECIES secp256k1: Compressed Ciphertext Overhead ===");
        let mut rng = thread_rng();

        let (_, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

        for msg_len in [0, 16, 100, 1000] {
            let message = vec![0x42u8; msg_len];
            let ciphertext = EciesSecp256k1::encrypt_compressed(&public, &message, &[], &mut rng).unwrap();

            // secp256k1 overhead (compressed): 33 + 12 + 16 = 61 bytes
            let expected_overhead = 61;
            let actual_overhead = ciphertext.len() - msg_len;
            assert_eq!(actual_overhead, expected_overhead);
            println!("  Message {} bytes -> Ciphertext {} bytes (overhead: {})",
                     msg_len, ciphertext.len(), actual_overhead);
        }
    }

    #[test]
    fn test_secp256k1_compressed_vs_uncompressed() {
        println!("\n=== ECIES secp256k1: Compressed vs Uncompressed Comparison ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Compare modes";

        let ct_uncompressed = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let ct_compressed = EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Compressed saves 32 bytes (Y coordinate)
        let size_diff = ct_uncompressed.len() - ct_compressed.len();
        assert_eq!(size_diff, 32);
        println!("  Compressed saves {} bytes", size_diff);

        // Both should decrypt correctly
        let pt_uncompressed = EciesSecp256k1::decrypt(&secret, &ct_uncompressed, &[]).unwrap();
        let pt_compressed = EciesSecp256k1::decrypt(&secret, &ct_compressed, &[]).unwrap();
        assert_eq!(pt_uncompressed, message);
        assert_eq!(pt_compressed, message);
        println!("  Both modes decrypt correctly");

        // Overhead comparison
        println!("  Uncompressed overhead: 93 bytes");
        println!("  Compressed overhead: 61 bytes (~34% reduction)");
    }

    #[test]
    fn test_secp256k1_auto_detect_format() {
        println!("\n=== ECIES secp256k1: Auto-detect Ciphertext Format ===");
        let mut rng = thread_rng();

        let (secret, public) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
        let message = b"Auto-detect test";

        // Encrypt with both formats
        let ct_uncompressed = EciesSecp256k1::encrypt(&public, message, &[], &mut rng).unwrap();
        let ct_compressed = EciesSecp256k1::encrypt_compressed(&public, message, &[], &mut rng).unwrap();

        // Same decrypt function handles both
        let pt1 = EciesSecp256k1::decrypt(&secret, &ct_uncompressed, &[]).unwrap();
        let pt2 = EciesSecp256k1::decrypt(&secret, &ct_compressed, &[]).unwrap();

        assert_eq!(pt1, message);
        assert_eq!(pt2, message);
        println!("  Decrypt auto-detects uncompressed (0x04 prefix)");
        println!("  Decrypt auto-detects compressed (0x02/0x03 prefix)");
    }
}

// ============================================================================
// Cross-curve Security Comparison Tests
// ============================================================================

#[test]
fn test_ecies_security_comparison() {
    use hpcrypt_ecies::{EciesP256, EciesP384, EciesP521, EciesSecp256k1};

    println!("\n=== ECIES Security Level Comparison ===");
    let mut rng = thread_rng();

    // Generate keys for each curve
    let (_, pub_p256) = EciesP256::generate_keypair(&mut rng).unwrap();
    let (_, pub_p384) = EciesP384::generate_keypair(&mut rng).unwrap();
    let (_, pub_p521) = EciesP521::generate_keypair(&mut rng).unwrap();
    let (_, pub_secp256k1) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();

    let message = b"Security comparison test";

    // Get ciphertext sizes
    let ct_p256 = EciesP256::encrypt(&pub_p256, message, &[], &mut rng).unwrap();
    let ct_p384 = EciesP384::encrypt(&pub_p384, message, &[], &mut rng).unwrap();
    let ct_p521 = EciesP521::encrypt(&pub_p521, message, &[], &mut rng).unwrap();
    let ct_secp256k1 = EciesSecp256k1::encrypt(&pub_secp256k1, message, &[], &mut rng).unwrap();
    let ct_secp256k1_comp = EciesSecp256k1::encrypt_compressed(&pub_secp256k1, message, &[], &mut rng).unwrap();

    println!("  Curve         | Security | Key Size | Overhead | Ciphertext Size");
    println!("  --------------|----------|----------|----------|----------------");
    println!("  P-256         | 128-bit  | 65 bytes | 93 bytes | {} bytes", ct_p256.len());
    println!("  P-384         | 192-bit  | 97 bytes | 125 bytes| {} bytes", ct_p384.len());
    println!("  P-521         | 256-bit  | 133 bytes| 161 bytes| {} bytes", ct_p521.len());
    println!("  secp256k1     | 128-bit  | 65 bytes | 93 bytes | {} bytes", ct_secp256k1.len());
    println!("  secp256k1 cmp | 128-bit  | 33 bytes | 61 bytes | {} bytes", ct_secp256k1_comp.len());

    println!("\n  All curves operational");
}

#[test]
fn test_ecies_all_curves_roundtrip() {
    use hpcrypt_ecies::{EciesP256, EciesP384, EciesP521, EciesSecp256k1};

    println!("\n=== ECIES All Curves Round-trip Test ===");
    let mut rng = thread_rng();
    let message = b"Universal test message for all curves";

    // P-256
    let (sk_p256, pk_p256) = EciesP256::generate_keypair(&mut rng).unwrap();
    let ct_p256 = EciesP256::encrypt(&pk_p256, message, &[], &mut rng).unwrap();
    let pt_p256 = EciesP256::decrypt(&sk_p256, &ct_p256, &[]).unwrap();
    assert_eq!(pt_p256, message);
    println!("  P-256 round-trip successful");

    // P-384
    let (sk_p384, pk_p384) = EciesP384::generate_keypair(&mut rng).unwrap();
    let ct_p384 = EciesP384::encrypt(&pk_p384, message, &[], &mut rng).unwrap();
    let pt_p384 = EciesP384::decrypt(&sk_p384, &ct_p384, &[]).unwrap();
    assert_eq!(pt_p384, message);
    println!("  P-384 round-trip successful");

    // P-521
    let (sk_p521, pk_p521) = EciesP521::generate_keypair(&mut rng).unwrap();
    let ct_p521 = EciesP521::encrypt(&pk_p521, message, &[], &mut rng).unwrap();
    let pt_p521 = EciesP521::decrypt(&sk_p521, &ct_p521, &[]).unwrap();
    assert_eq!(pt_p521, message);
    println!("  P-521 round-trip successful");

    // secp256k1 (uncompressed)
    let (sk_secp, pk_secp) = EciesSecp256k1::generate_keypair(&mut rng).unwrap();
    let ct_secp = EciesSecp256k1::encrypt(&pk_secp, message, &[], &mut rng).unwrap();
    let pt_secp = EciesSecp256k1::decrypt(&sk_secp, &ct_secp, &[]).unwrap();
    assert_eq!(pt_secp, message);
    println!("  secp256k1 (uncompressed) round-trip successful");

    // secp256k1 (compressed)
    let ct_secp_comp = EciesSecp256k1::encrypt_compressed(&pk_secp, message, &[], &mut rng).unwrap();
    let pt_secp_comp = EciesSecp256k1::decrypt(&sk_secp, &ct_secp_comp, &[]).unwrap();
    assert_eq!(pt_secp_comp, message);
    println!("  secp256k1 (compressed) round-trip successful");

    println!("\n  All 5 ECIES variants operational");
}
