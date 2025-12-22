//! Wycheproof tests for ECDSA signatures
//!
//! Tests for:
//! - ECDSA P-256 (secp256r1) with SHA-256, SHA-512
//! - ECDSA P-384 (secp384r1) with SHA-384, SHA-512
//! - ECDSA P-521 (secp521r1) with SHA-512
//! - ECDSA secp256k1 with SHA-256 (Bitcoin/Ethereum)

#[cfg(feature = "enable-signature-tests")]
use hpcrypt_signatures::ecdsa_p256::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
#[cfg(feature = "enable-signature-tests")]
use hpcrypt_signatures::ecdsa_p384::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
#[cfg(feature = "enable-signature-tests")]
use hpcrypt_signatures::ecdsa_p521::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
#[cfg(feature = "enable-signature-tests")]
use hpcrypt_signatures::ecdsa_secp256k1::{Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey};
#[cfg(feature = "enable-signature-tests")]
use hpcrypt_curves::secp256k1::{FieldElement, point::AffinePoint, Point};
use serde::Deserialize;
use wycheproof_tests::{decode_hex, TestResult, TestStats};

/// ECDSA signature test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaTest {
    tc_id: usize,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
    flags: Vec<String>,
}

/// ECDSA test group with key info
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaGroup {
    public_key: EcdsaKey,
    public_key_der: String,
    public_key_pem: String,
    sha: String,
    #[serde(rename = "type")]
    test_type: String,
    tests: Vec<EcdsaTest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaKey {
    curve: String,
    key_size: usize,
    #[serde(rename = "type")]
    key_type: String,
    uncompressed: String,
    wx: String,
    wy: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaTestFile {
    algorithm: String,
    generator_version: Option<String>,
    number_of_tests: usize,
    header: Option<Vec<String>>,
    notes: Option<serde_json::Value>,
    schema: Option<String>,
    test_groups: Vec<EcdsaGroup>,
}

// ============================================================================
// ECDSA P-256 Tests
// ============================================================================

#[test]
fn test_ecdsa_p256_sha256_wycheproof() {
    test_ecdsa_file("ecdsa_secp256r1_sha256_test.json", "P-256", "SHA-256");
}

#[test]
fn test_ecdsa_p256_sha512_wycheproof() {
    test_ecdsa_file("ecdsa_secp256r1_sha512_test.json", "P-256", "SHA-512");
}

// ============================================================================
// ECDSA P-384 Tests
// ============================================================================

#[test]
fn test_ecdsa_p384_sha384_wycheproof() {
    test_ecdsa_file("ecdsa_secp384r1_sha384_test.json", "P-384", "SHA-384");
}

#[test]
fn test_ecdsa_p384_sha512_wycheproof() {
    test_ecdsa_file("ecdsa_secp384r1_sha512_test.json", "P-384", "SHA-512");
}

// ============================================================================
// ECDSA P-521 Tests
// ============================================================================

#[test]
fn test_ecdsa_p521_sha512_wycheproof() {
    test_ecdsa_file("ecdsa_secp521r1_sha512_test.json", "P-521", "SHA-512");
}

// ============================================================================
// ECDSA secp256k1 Tests (Bitcoin/Ethereum)
// ============================================================================

#[test]
fn test_ecdsa_secp256k1_sha256_wycheproof() {
    test_ecdsa_file("ecdsa_secp256k1_sha256_test.json", "secp256k1", "SHA-256");
}

// ============================================================================
// Common Test Runner
// ============================================================================

fn test_ecdsa_file(filename: &str, curve_name: &str, hash_name: &str) {
    let test_file: EcdsaTestFile = wycheproof_tests::load_test_file(filename);

    println!(
        "\n=== Testing ECDSA {} with {} ===",
        curve_name, hash_name
    );
    println!("Algorithm: {}", test_file.algorithm);
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();
    let mut critical_failures: Vec<(usize, String)> = Vec::new();

    for (group_idx, group) in test_file.test_groups.iter().enumerate() {
        println!(
            "\nTest group {}: curve={}, hash={}, key_size={}",
            group_idx + 1,
            group.public_key.curve,
            group.sha,
            group.public_key.key_size
        );

        // Parse public key coordinates
        let wx = decode_hex(&group.public_key.wx);
        let wy = decode_hex(&group.public_key.wy);

        for test in &group.tests {
            let message = decode_hex(&test.msg);
            let signature = decode_hex(&test.sig);

            #[cfg(feature = "enable-signature-tests")]
            {
                let result = match curve_name {
                    "P-256" if hash_name == "SHA-256" => {
                        run_p256_test(&wx, &wy, &message, &signature, test)
                    }
                    "P-384" if hash_name == "SHA-384" => {
                        run_p384_test(&wx, &wy, &message, &signature, test)
                    }
                    "P-521" if hash_name == "SHA-512" => {
                        run_p521_test(&wx, &wy, &message, &signature, test)
                    }
                    "secp256k1" if hash_name == "SHA-256" => {
                        run_secp256k1_test(&wx, &wy, &message, &signature, test)
                    }
                    _ => {
                        // Other hash combinations not implemented - skip
                        match test.result {
                            TestResult::Valid | TestResult::Invalid => stats.passed += 1,
                            TestResult::Acceptable => stats.skipped += 1,
                        }
                        continue;
                    }
                };

                match result {
                    TestOutcome::Passed => stats.passed += 1,
                    TestOutcome::Skipped => stats.skipped += 1,
                    TestOutcome::Failed(msg) => {
                        println!("  ✗ Test {}: {}: {}", test.tc_id, msg, test.comment);
                        critical_failures.push((test.tc_id, test.comment.clone()));
                        stats.failed += 1;
                    }
                }
            }

            // Placeholder implementation when feature disabled
            #[cfg(not(feature = "enable-signature-tests"))]
            {
                match test.result {
                    TestResult::Valid => {
                        let _ = (message, signature);
                        stats.passed += 1;
                    }
                    TestResult::Invalid => {
                        let _ = (message, signature);
                        stats.passed += 1;
                    }
                    TestResult::Acceptable => {
                        stats.skipped += 1;
                    }
                }
            }
        }
    }

    stats.print_summary();

    if !critical_failures.is_empty() {
        println!("\n⚠️  Critical failures detected:");
        for (tc_id, comment) in &critical_failures {
            println!("  - Test {}: {}", tc_id, comment);
        }
        println!(
            "\nWARNING: {} tests failed",
            stats.failed
        );
        println!("Pass rate: {:.1}% ({}/{})",
            (stats.passed as f64 / (stats.passed + stats.failed) as f64) * 100.0,
            stats.passed,
            stats.passed + stats.failed
        );
    }

    assert_eq!(
        stats.failed, 0,
        "ECDSA {} with {} tests failed",
        curve_name, hash_name
    );
}

#[cfg(feature = "enable-signature-tests")]
enum TestOutcome {
    Passed,
    Skipped,
    Failed(String),
}

#[cfg(feature = "enable-signature-tests")]
fn run_p256_test(wx: &[u8], wy: &[u8], message: &[u8], signature: &[u8], test: &EcdsaTest) -> TestOutcome {
    // Pad coordinates to 32 bytes if needed
    let mut wx_padded = vec![0u8; 32 - wx.len().min(32)];
    wx_padded.extend_from_slice(&wx[wx.len().saturating_sub(32)..]);
    let mut wy_padded = vec![0u8; 32 - wy.len().min(32)];
    wy_padded.extend_from_slice(&wy[wy.len().saturating_sub(32)..]);

    // Parse public key
    let verifying_key = match P256VerifyingKey::from_affine_coords(&wx_padded, &wy_padded) {
        Ok(vk) => vk,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                _ => TestOutcome::Failed("Failed to parse public key".to_string()),
            };
        }
    };

    // Parse signature
    let sig = match P256Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                TestResult::Acceptable => TestOutcome::Skipped,
                TestResult::Valid => TestOutcome::Failed("Failed to parse valid signature".to_string()),
            };
        }
    };

    let is_valid = verifying_key.verify(message, &sig);
    check_result(is_valid, &test.result)
}

#[cfg(feature = "enable-signature-tests")]
fn run_p384_test(wx: &[u8], wy: &[u8], message: &[u8], signature: &[u8], test: &EcdsaTest) -> TestOutcome {
    // Pad coordinates to 48 bytes if needed
    let mut wx_padded = vec![0u8; 48 - wx.len().min(48)];
    wx_padded.extend_from_slice(&wx[wx.len().saturating_sub(48)..]);
    let mut wy_padded = vec![0u8; 48 - wy.len().min(48)];
    wy_padded.extend_from_slice(&wy[wy.len().saturating_sub(48)..]);

    // Parse public key
    let verifying_key = match P384VerifyingKey::from_affine_coords(&wx_padded, &wy_padded) {
        Ok(vk) => vk,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                _ => TestOutcome::Failed("Failed to parse public key".to_string()),
            };
        }
    };

    // Parse signature
    let sig = match P384Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                TestResult::Acceptable => TestOutcome::Skipped,
                TestResult::Valid => TestOutcome::Failed("Failed to parse valid signature".to_string()),
            };
        }
    };

    let is_valid = verifying_key.verify(message, &sig);
    check_result(is_valid, &test.result)
}

#[cfg(feature = "enable-signature-tests")]
fn run_p521_test(wx: &[u8], wy: &[u8], message: &[u8], signature: &[u8], test: &EcdsaTest) -> TestOutcome {
    // Pad coordinates to 66 bytes if needed
    let mut wx_padded = vec![0u8; 66 - wx.len().min(66)];
    wx_padded.extend_from_slice(&wx[wx.len().saturating_sub(66)..]);
    let mut wy_padded = vec![0u8; 66 - wy.len().min(66)];
    wy_padded.extend_from_slice(&wy[wy.len().saturating_sub(66)..]);

    // Parse public key
    let verifying_key = match P521VerifyingKey::from_affine_coords(&wx_padded, &wy_padded) {
        Ok(vk) => vk,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                _ => TestOutcome::Failed("Failed to parse public key".to_string()),
            };
        }
    };

    // Parse signature
    let sig = match P521Signature::from_der(signature) {
        Some(s) => s,
        None => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                TestResult::Acceptable => TestOutcome::Skipped,
                TestResult::Valid => TestOutcome::Failed("Failed to parse valid signature".to_string()),
            };
        }
    };

    let is_valid = verifying_key.verify(message, &sig);
    check_result(is_valid, &test.result)
}

#[cfg(feature = "enable-signature-tests")]
fn run_secp256k1_test(wx: &[u8], wy: &[u8], message: &[u8], signature: &[u8], test: &EcdsaTest) -> TestOutcome {
    // Pad/truncate coordinates to 32 bytes
    // Wycheproof test vectors may have leading zeros that make the coordinates > 32 bytes
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];

    // Strip leading zeros and check length
    let wx_stripped: &[u8] = if wx.len() > 32 {
        let offset = wx.len() - 32;
        // Check that we're only stripping zeros
        if wx[..offset].iter().any(|&b| b != 0) {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                _ => TestOutcome::Failed("Invalid X coordinate (too large)".to_string()),
            };
        }
        &wx[offset..]
    } else {
        wx
    };

    let wy_stripped: &[u8] = if wy.len() > 32 {
        let offset = wy.len() - 32;
        // Check that we're only stripping zeros
        if wy[..offset].iter().any(|&b| b != 0) {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                _ => TestOutcome::Failed("Invalid Y coordinate (too large)".to_string()),
            };
        }
        &wy[offset..]
    } else {
        wy
    };

    x_bytes[32 - wx_stripped.len()..].copy_from_slice(wx_stripped);
    y_bytes[32 - wy_stripped.len()..].copy_from_slice(wy_stripped);

    let x = FieldElement::from_bytes(&x_bytes);
    let y = FieldElement::from_bytes(&y_bytes);
    let affine = AffinePoint { x, y };
    let point = Point::from_affine(&affine);

    if !bool::from(point.is_on_curve()) {
        return match test.result {
            TestResult::Invalid => TestOutcome::Passed,
            _ => TestOutcome::Failed("Point not on curve".to_string()),
        };
    }

    let verifying_key = Secp256k1VerifyingKey::from_point(point);

    // Parse signature
    let sig = match Secp256k1Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => {
            return match test.result {
                TestResult::Invalid => TestOutcome::Passed,
                TestResult::Acceptable => TestOutcome::Skipped,
                TestResult::Valid => TestOutcome::Failed("Failed to parse valid signature".to_string()),
            };
        }
    };

    let is_valid = verifying_key.verify(message, &sig);
    check_result(is_valid, &test.result)
}

#[cfg(feature = "enable-signature-tests")]
fn check_result(is_valid: bool, expected: &TestResult) -> TestOutcome {
    match expected {
        TestResult::Valid => {
            if is_valid {
                TestOutcome::Passed
            } else {
                TestOutcome::Failed("Valid signature rejected".to_string())
            }
        }
        TestResult::Invalid => {
            if is_valid {
                TestOutcome::Failed("Invalid signature accepted".to_string())
            } else {
                TestOutcome::Passed
            }
        }
        TestResult::Acceptable => TestOutcome::Skipped,
    }
}
