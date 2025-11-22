//! Wycheproof tests for Ed448 signatures
//!
//! Ed448 is a modern EdDSA signature scheme using Curve448 (edwards448)

use serde::Deserialize;
use wycheproof_tests::{decode_hex, TestResult, TestStats};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed448Test {
    tc_id: usize,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
    flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed448Group {
    public_key: Ed448Key,
    public_key_der: String,
    public_key_pem: String,
    #[serde(rename = "type")]
    test_type: String,
    tests: Vec<Ed448Test>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed448Key {
    curve: String,
    key_size: usize,
    pk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sk: Option<String>,
    #[serde(rename = "type")]
    key_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed448TestFile {
    algorithm: String,
    generator_version: Option<String>,
    number_of_tests: usize,
    header: Option<Vec<String>>,
    notes: Option<serde_json::Value>,
    schema: Option<String>,
    test_groups: Vec<Ed448Group>,
}

#[test]
fn test_ed448_wycheproof() {
    let test_file: Ed448TestFile = wycheproof_tests::load_test_file("ed448_test.json");

    println!("\n=== Testing {} ===", test_file.algorithm);
    println!("Total test cases: {}", test_file.number_of_tests);

    let mut stats = TestStats::new();
    let mut critical_failures: Vec<(usize, String)> = Vec::new();

    for (group_idx, group) in test_file.test_groups.iter().enumerate() {
        println!(
            "\nTest group {}: curve={}, key_size={}",
            group_idx + 1,
            group.public_key.curve,
            group.public_key.key_size
        );

        let public_key = decode_hex(&group.public_key.pk);

        // Validate key sizes
        assert_eq!(public_key.len(), 57, "Ed448 public key must be 57 bytes");
        assert_eq!(group.public_key.key_size, 448, "Ed448 key size must be 448 bits");

        for test in &group.tests {
            let message = decode_hex(&test.msg);
            let signature = decode_hex(&test.sig);

            // Convert to fixed-size arrays
            let mut pk_array = [0u8; 57];
            pk_array.copy_from_slice(&public_key);

            let mut sig_array = [0u8; 114];
            if signature.len() == 114 {
                sig_array.copy_from_slice(&signature);
            }

            // Use actual Ed448 verification
            let result = if signature.len() == 114 {
                hpcrypt_curves::ed448::verify(&pk_array, &message, &sig_array)
            } else {
                false // Invalid signature length
            };

            match test.result {
                TestResult::Valid => {
                    if !result {
                        println!("  ✗ Test {}: Valid signature rejected: {}", test.tc_id, test.comment);
                        critical_failures.push((test.tc_id, test.comment.clone()));
                        stats.failed += 1;
                    } else {
                        stats.passed += 1;
                    }
                }
                TestResult::Invalid => {
                    if result {
                        println!("  ✗ Test {}: Invalid signature accepted: {}", test.tc_id, test.comment);
                        if test.flags.contains(&"InvalidSignature".to_string()) {
                            critical_failures.push((test.tc_id, test.comment.clone()));
                        }
                        stats.failed += 1;
                    } else {
                        stats.passed += 1;
                    }
                }
                TestResult::Acceptable => {
                    stats.skipped += 1;
                }
            }
        }
    }

    stats.print_summary();

    if !critical_failures.is_empty() {
        println!("\nWARNING: Critical failures detected:");
        for (tc_id, comment) in &critical_failures {
            println!("  - Test {}: {}", tc_id, comment);
        }
    }

    assert_eq!(stats.failed, 0, "Ed448 tests failed");
}

#[cfg(test)]
mod ed448_notes {
    /// Documents Ed448 security considerations
    #[test]
    fn test_ed448_security_notes() {
        println!("\nEd448 Security Considerations:");
        println!("  - RFC 8032 standard");
        println!("  - Deterministic signatures (no nonce needed)");
        println!("  - 224-bit security level (higher than Ed25519)");
        println!("  - Larger keys: 57-byte public key, 57-byte private key");
        println!("  - Larger signatures: 114 bytes");
        println!("  - Slower than Ed25519 but higher security margin");
        println!("  - Context support (optional context string)");
        println!("  - Must validate points are on curve");
        println!("  - Resistant to timing attacks when properly implemented");
    }

}
