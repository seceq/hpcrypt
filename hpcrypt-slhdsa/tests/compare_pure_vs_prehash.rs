//! Compare pure signing vs prehash signing to find the difference

use hpcrypt_slhdsa::{Sha2_128f, SecretKey, sign_ctx, sign_prehash};
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
    signature: String,
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex")
}

#[test]
fn compare_pure_vs_prehash() {
    let prompt_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json";
    let expected_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json";

    let prompt_file = File::open(prompt_path).expect("Failed to open prompt file");
    let expected_file = File::open(expected_path).expect("Failed to open expected file");

    let prompt: SigGenPrompt = serde_json::from_reader(BufReader::new(prompt_file))
        .expect("Failed to parse prompt JSON");
    let expected: SigGenExpected = serde_json::from_reader(BufReader::new(expected_file))
        .expect("Failed to parse expected JSON");

    println!("\n=== Comparing Pure (TC 313) vs Prehash (TC 320) ===\n");

    let mut tc_count = 0;
    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            tc_count += 1;

            // Test TC 313 (pure mode - should PASS)
            if tc_count == 313 {
                println!("TC 313 (Pure Mode):");
                println!("  Parameter Set: {}", group.parameter_set);
                println!("  PreHash: {:?}", group.pre_hash);

                let sk_bytes = decode_hex(&test.sk);
                let message = decode_hex(&test.message);
                let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
                let expected_sig = decode_hex(&expected_test.signature);

                let sk = SecretKey::<Sha2_128f>::from_bytes(&sk_bytes).expect("SK failed");
                let sig = sign_ctx(&sk, &context, &message);

                println!("  Expected (first 32): {}", hex::encode(&expected_sig[..32]));
                println!("  Computed (first 32): {}", hex::encode(&sig[..32]));
                println!("  Match: {}", sig.as_slice() == expected_sig);
            }

            // Test TC 320 (prehash mode - FAILS)
            if tc_count == 320 {
                println!("\nTC 320 (Prehash Mode):");
                println!("  Parameter Set: {}", group.parameter_set);
                println!("  PreHash: {:?}", group.pre_hash);
                println!("  Hash Alg: {:?}", test.hash_alg);

                let sk_bytes = decode_hex(&test.sk);
                let message = decode_hex(&test.message);
                let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
                let expected_sig = decode_hex(&expected_test.signature);

                let sk = SecretKey::<Sha2_128f>::from_bytes(&sk_bytes).expect("SK failed");
                let sig = sign_prehash(&sk, &context, test.hash_alg.as_ref().unwrap(), &message)
                    .expect("Prehash failed");

                println!("  Expected (first 32): {}", hex::encode(&expected_sig[..32]));
                println!("  Computed (first 32): {}", hex::encode(&sig[..32]));
                println!("  Match: {}", sig.as_slice() == expected_sig);

                // Also try signing the prehashed message with sign_ctx to see if that matches
                println!("\n  Debugging: What if we manually build M' and use sign_ctx?");
                use hpcrypt_slhdsa::prehash::build_prehash_message;
                let prehash_msg = build_prehash_message("SHA2-256", &message).unwrap();

                // Build M' = 0x01 || len(ctx) || ctx || OID || PH(M)
                let mut m_prime = Vec::new();
                m_prime.push(1u8);
                m_prime.push(context.len() as u8);
                m_prime.extend_from_slice(&context);
                m_prime.extend_from_slice(&prehash_msg);

                println!("  M' length: {} bytes", m_prime.len());
                println!("  M' (first 32): {}", hex::encode(&m_prime[..32.min(m_prime.len())]));

                return;
            }
        }
    }
}
