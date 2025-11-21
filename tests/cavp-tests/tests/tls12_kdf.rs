//! NIST CAVP/ACVP Test Vectors for TLS 1.2 KDF
//!
//! Tests TLS 1.2 Key Derivation Function (PRF) against NIST test vectors.
//! TLS 1.2 uses HMAC-based PRF for deriving master secret and key block.
//!
//! Test vectors from: tests/cavp-vectors/gen-val/json-files/TLS-v1.2-KDF-RFC7627/

#![cfg(feature = "enable-kdf-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use hpcrypt_kdf::{prf_sha256, prf_sha384, prf_sha512};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PromptFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "testType")]
    test_type: String,
    #[serde(rename = "hashAlg")]
    hash_alg: String,
    #[serde(rename = "keyBlockLength")]
    key_block_length: u32,
    #[serde(rename = "preMasterSecretLength")]
    pre_master_secret_length: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "preMasterSecret")]
    pre_master_secret: String,
    #[serde(rename = "sessionHash")]
    session_hash: String,
    #[serde(rename = "clientRandom")]
    client_random: String,
    #[serde(rename = "serverRandom")]
    server_random: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
struct ExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<ExpectedTest>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "masterSecret")]
    master_secret: String,
    #[serde(rename = "keyBlock")]
    key_block: String,
}

fn run_tls12_kdf_tests() {
    println!("\nTesting TLS 1.2 KDF");

    let prompt: PromptFile = load_test_file("TLS-v1.2-KDF-RFC7627", "prompt.json");
    let expected: ExpectedFile =
        load_test_file("TLS-v1.2-KDF-RFC7627", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == test_group.tg_id);

        if expected_group.is_none() {
            stats.skipped += test_group.tests.len();
            continue;
        }
        let expected_group = expected_group.unwrap();

        for test in &test_group.tests {
            let expected_test = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == test.tc_id);

            if expected_test.is_none() {
                stats.skipped += 1;
                continue;
            }
            let expected_test = expected_test.unwrap();

            let pre_master_secret = decode_hex(&test.pre_master_secret);
            let session_hash = decode_hex(&test.session_hash);
            let client_random = decode_hex(&test.client_random);
            let server_random = decode_hex(&test.server_random);

            let expected_master_secret = decode_hex(&expected_test.master_secret);
            let expected_key_block = decode_hex(&expected_test.key_block);

            // TLS 1.2 master secret derivation (RFC 7627 - Extended Master Secret)
            // master_secret = PRF(pre_master_secret, "extended master secret", session_hash)[0..48]
            let label = "extended master secret";
            let mut master_secret = vec![0u8; 48];

            // Key block derivation
            // key_block = PRF(master_secret, "key expansion", server_random + client_random)
            let mut seed = Vec::new();
            seed.extend_from_slice(&server_random);
            seed.extend_from_slice(&client_random);

            let key_block_len = (test_group.key_block_length / 8) as usize;
            let mut key_block = vec![0u8; key_block_len];

            // Select the appropriate hash function
            match test_group.hash_alg.as_str() {
                "SHA2-256" => {
                    prf_sha256(&pre_master_secret, label, &session_hash, &mut master_secret);
                    prf_sha256(&master_secret, "key expansion", &seed, &mut key_block);
                }
                "SHA2-384" => {
                    prf_sha384(&pre_master_secret, label, &session_hash, &mut master_secret);
                    prf_sha384(&master_secret, "key expansion", &seed, &mut key_block);
                }
                "SHA2-512" => {
                    prf_sha512(&pre_master_secret, label, &session_hash, &mut master_secret);
                    prf_sha512(&master_secret, "key expansion", &seed, &mut key_block);
                }
                _ => {
                    // Unsupported hash algorithm
                    stats.skipped += 1;
                    continue;
                }
            }

            // Verify master secret
            if master_secret != expected_master_secret {
                println!(
                    "FAIL: Test {} master secret mismatch (group {}, hash {})",
                    test.tc_id, test_group.tg_id, test_group.hash_alg
                );
                stats.failed += 1;
                continue;
            }

            // Verify key block
            if key_block == expected_key_block {
                stats.passed += 1;
            } else {
                println!(
                    "FAIL: Test {} key block mismatch (group {}, hash {})",
                    test.tc_id, test_group.tg_id, test_group.hash_alg
                );
                stats.failed += 1;
            }
        }
    }

    println!(
        "TLS 1.2 KDF Results: {} passed, {} failed, {} skipped",
        stats.passed, stats.failed, stats.skipped
    );
    assert_eq!(
        stats.failed, 0,
        "{} tests failed for TLS 1.2 KDF",
        stats.failed
    );
}

#[test]
fn test_tls12_kdf() {
    run_tls12_kdf_tests();
}
