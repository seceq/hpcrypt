//! Debug test for TC 313 (first failing prehash test)

use hpcrypt_slhdsa::{Sha2_128s, Sha2_128f, SecretKey, sign_prehash};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenPrompt {
    test_groups: Vec<SigGenTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTestGroup {
    parameter_set: String,
    signature_interface: String,
    #[serde(default)]
    pre_hash: Option<String>,
    tests: Vec<SigGenTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTestCase {
    tc_id: u32,
    sk: String,
    message: String,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    hash_alg: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpected {
    test_groups: Vec<SigGenExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpectedGroup {
    tests: Vec<SigGenExpectedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpectedCase {
    tc_id: u32,
    signature: String,
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex")
}

#[test]
fn test_debug_tc313() {
    let prompt_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json";
    let expected_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json";

    let prompt_file = File::open(prompt_path).expect("Failed to open prompt file");
    let expected_file = File::open(expected_path).expect("Failed to open expected file");

    let prompt: SigGenPrompt = serde_json::from_reader(BufReader::new(prompt_file))
        .expect("Failed to parse prompt JSON");
    let expected: SigGenExpected = serde_json::from_reader(BufReader::new(expected_file))
        .expect("Failed to parse expected JSON");

    // Find first ACTUAL prehash test
    let mut tc_count = 0;
    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            tc_count += 1;

            // Skip until we find first prehash test
            if group.pre_hash.as_deref() == Some("preHash") && tc_count >= 313 {
                println!("\n=== Test Case {} (first prehash after 313) ===", tc_count);
                println!("Parameter Set: {}", group.parameter_set);
                println!("Signature Interface: {}", group.signature_interface);
                println!("Pre-hash: {:?}", group.pre_hash);
                println!("Hash Algorithm: {:?}", test.hash_alg);
                println!("TC ID: {}", test.tc_id);
                println!("SK: {}", &test.sk[..40]);
                println!("Message length: {}", test.message.len() / 2); // hex length / 2
                println!("Context length: {}", test.context.as_ref().map(|c| c.len() / 2).unwrap_or(0));

                let sk_bytes = decode_hex(&test.sk);
                let message = decode_hex(&test.message);
                let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
                let expected_sig = decode_hex(&expected_test.signature);

                println!("\nActual SK bytes: {} bytes", sk_bytes.len());
                println!("Actual message: {} bytes", message.len());
                println!("Actual context: {} bytes", context.len());
                println!("Expected signature: {} bytes", expected_sig.len());

                // Try to deserialize SK - use correct parameter set based on test
                let sk = if group.parameter_set == "SLH-DSA-SHA2-128f" {
                    let sk_128f = SecretKey::<Sha2_128f>::from_bytes(&sk_bytes).expect("SK deserialization failed");
                    println!("\n[OK] SK deserialized successfully (Sha2_128f)");

                    // Sign with 128f
                    let hash_alg = match test.hash_alg.as_ref() {
                        Some(alg) => alg,
                        None => {
                            println!("[ERROR] No hash algorithm specified for prehash test!");
                            panic!("Missing hash_alg");
                        }
                    };
                    println!("\nAttempting sign_prehash with hash_alg: {}", hash_alg);

                    match sign_prehash(&sk_128f, &context, hash_alg, &message) {
                        Ok(sig) => {
                            println!("[OK] Signature generated successfully ({} bytes)", sig.len());
                            println!("\nExpected sig (first 32 bytes): {}", hex::encode(&expected_sig[..32]));
                            println!("Computed sig (first 32 bytes): {}", hex::encode(&sig[..32]));

                            if sig.as_slice() == expected_sig {
                                println!("\n[OK] SIGNATURES MATCH!");
                            } else {
                                println!("\n[FAIL] SIGNATURES DIFFER!");
                                // Find first difference
                                for i in 0..sig.len().min(expected_sig.len()) {
                                    if sig[i] != expected_sig[i] {
                                        println!("First difference at byte {}: computed={:02x}, expected={:02x}",
                                                i, sig[i], expected_sig[i]);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("[ERROR] Prehash signing failed: {}", e);
                            panic!("Test case failed!");
                        }
                    }
                    return;
                } else {
                    SecretKey::<Sha2_128s>::from_bytes(&sk_bytes).expect("SK deserialization failed")
                };
                println!("\n[OK] SK deserialized successfully (Sha2_128s)");

                // Try to sign
                let hash_alg = match test.hash_alg.as_ref() {
                    Some(alg) => alg,
                    None => {
                        println!("[ERROR] No hash algorithm specified for prehash test!");
                        panic!("Missing hash_alg");
                    }
                };
                println!("\nAttempting sign_prehash with hash_alg: {}", hash_alg);

                match sign_prehash(&sk, &context, hash_alg, &message) {
                    Ok(sig) => {
                        println!("[OK] Signature generated successfully ({} bytes)", sig.len());
                        println!("\nExpected sig (first 32 bytes): {}", hex::encode(&expected_sig[..32]));
                        println!("Computed sig (first 32 bytes): {}", hex::encode(&sig[..32]));

                        if sig.as_slice() == expected_sig {
                            println!("\n[OK] SIGNATURES MATCH!");
                        } else {
                            println!("\n[FAIL] SIGNATURES DIFFER!");
                            // Find first difference
                            for i in 0..sig.len().min(expected_sig.len()) {
                                if sig[i] != expected_sig[i] {
                                    println!("First difference at byte {}: computed={:02x}, expected={:02x}",
                                            i, sig[i], expected_sig[i]);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ERROR] Prehash signing failed: {}", e);
                        panic!("Test case 313 failed!");
                    }
                }

                return;
            }
        }
    }

    panic!("Test case 313 not found!");
}
