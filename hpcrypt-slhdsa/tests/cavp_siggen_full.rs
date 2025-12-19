//! Full CAVP SigGen test for working directory implementation

use hpcrypt_slhdsa::{
    Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f,
    Shake128s, Shake128f, Shake192s, Shake192f, Shake256s, Shake256f
};
use hpcrypt_slhdsa::{SecretKey, sign_internal, sign_ctx, sign_prehash};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenPrompt {
    vs_id: u32,
    test_groups: Vec<SigGenTestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTestGroup {
    tg_id: u32,
    parameter_set: String,
    deterministic: bool,
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
    vs_id: u32,
    test_groups: Vec<SigGenExpectedGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpectedGroup {
    tg_id: u32,
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

fn test_siggen<P: hpcrypt_slhdsa::ParameterSet>(
    sk_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    signature_interface: &str,
    pre_hash: Option<&str>,
    hash_alg: Option<&str>,
    expected_sig: &[u8],
    tc_id: u32,
) -> bool {
    let sk = match SecretKey::<P>::from_bytes(sk_bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Test case {} FAILED: Invalid secret key", tc_id);
            return false;
        }
    };

    // Determine which signing function to use based on interface and preHash
    let signature = match (signature_interface, pre_hash) {
        ("internal", None) => {
            // Internal interface - no domain separator
            sign_internal(&sk, message)
        }
        ("external", Some("pure")) | ("external", None) => {
            // External interface, pure mode (domain separator 0x00)
            sign_ctx(&sk, context, message)
        }
        ("external", Some("preHash")) => {
            // External interface, prehash mode (domain separator 0x01)
            let hash_alg_str = match hash_alg {
                Some(alg) => alg,
                None => {
                    eprintln!("Test case {} FAILED: preHash mode requires hashAlg", tc_id);
                    return false;
                }
            };

            match sign_prehash(&sk, context, hash_alg_str, message) {
                Ok(sig) => sig,
                Err(e) => {
                    eprintln!("Test case {} FAILED: Prehash error: {}", tc_id, e);
                    return false;
                }
            }
        }
        _ => {
            eprintln!("Test case {} FAILED: Unknown signature interface: {} / {:?}",
                     tc_id, signature_interface, pre_hash);
            return false;
        }
    };

    if signature.as_slice() == expected_sig {
        // println!("Test case {} PASSED", tc_id);
        true
    } else {
        eprintln!("Test case {} FAILED: Signature mismatch", tc_id);
        eprintln!("  Expected (first 32): {}", hex::encode(&expected_sig[..32]));
        eprintln!("  Got (first 32):      {}", hex::encode(&signature[..32]));
        if signature.len() > 32 && expected_sig.len() > 32 {
            eprintln!("  Expected (last 32):  {}", hex::encode(&expected_sig[expected_sig.len()-32..]));
            eprintln!("  Got (last 32):       {}", hex::encode(&signature[signature.len()-32..]));
        }
        false
    }
}

#[test]
fn test_cavp_siggen_full() {
    let prompt_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json";
    let expected_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json";
    
    let prompt_file = File::open(prompt_path).expect("Failed to open prompt file");
    let expected_file = File::open(expected_path).expect("Failed to open expected file");
    
    let prompt: SigGenPrompt = serde_json::from_reader(BufReader::new(prompt_file))
        .expect("Failed to parse prompt JSON");
    let expected: SigGenExpected = serde_json::from_reader(BufReader::new(expected_file))
        .expect("Failed to parse expected JSON");
    
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    
    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            let sk = decode_hex(&test.sk);
            let message = decode_hex(&test.message);
            let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
            let expected_sig = decode_hex(&expected_test.signature);

            let success = match group.parameter_set.as_str() {
                "SLH-DSA-SHA2-128s" => test_siggen::<Sha2_128s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHA2-128f" => test_siggen::<Sha2_128f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHA2-192s" => test_siggen::<Sha2_192s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHA2-192f" => test_siggen::<Sha2_192f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHA2-256s" => test_siggen::<Sha2_256s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHA2-256f" => test_siggen::<Sha2_256f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-128s" => test_siggen::<Shake128s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-128f" => test_siggen::<Shake128f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-192s" => test_siggen::<Shake192s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-192f" => test_siggen::<Shake192f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-256s" => test_siggen::<Shake256s>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                "SLH-DSA-SHAKE-256f" => test_siggen::<Shake256f>(
                    &sk, &message, &context,
                    &group.signature_interface,
                    group.pre_hash.as_deref(),
                    test.hash_alg.as_deref(),
                    &expected_sig, test.tc_id
                ),
                _ => {
                    eprintln!("SKIPPED: Unknown parameter set: {}", group.parameter_set);
                    skipped += 1;
                    continue;
                }
            };

            if success {
                passed += 1;
            } else {
                failed += 1;
            }
        }
    }
    
    println!("\n--- Test Results ---");
    println!("✓ Passed:  {}", passed);
    println!("✗ Failed:  {}", failed);
    println!("⊘ Skipped: {}", skipped);
    
    if failed > 0 {
        panic!("{} SigGen tests failed", failed);
    }
}
