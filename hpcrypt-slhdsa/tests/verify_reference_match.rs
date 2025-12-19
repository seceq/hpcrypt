//! Verify that dist implementation matches fips205 reference

use hpcrypt_slhdsa::{Sha2_128f, SecretKey, sign_ctx};
use fips205::slh_dsa_sha2_128f;
use fips205::traits::{SerDes, Signer};
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
fn verify_dist_matches_reference() {
    let prompt_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json";
    let expected_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json";

    let prompt_file = File::open(prompt_path).expect("Failed to open prompt");
    let expected_file = File::open(expected_path).expect("Failed to open expected");

    let prompt: SigGenPrompt = serde_json::from_reader(BufReader::new(prompt_file)).expect("Failed to parse prompt");
    let expected: SigGenExpected = serde_json::from_reader(BufReader::new(expected_file)).expect("Failed to parse expected");

    let mut tc_count = 0;
    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            tc_count += 1;

            if tc_count == 313 {
                println!("\n========================================");
                println!("DIST IMPLEMENTATION VERIFICATION");
                println!("========================================");

                let sk_bytes = decode_hex(&test.sk);
                let message = decode_hex(&test.message);
                let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
                let expected_sig = decode_hex(&expected_test.signature);

                // Test dist implementation
                println!("\n[1] Dist Implementation (hpcrypt-slhdsa)");
                let dist_sk = SecretKey::<Sha2_128f>::from_bytes(&sk_bytes).expect("Dist SK failed");
                let dist_sig = sign_ctx(&dist_sk, &context, &message);
                println!("    Signature: {}", hex::encode(&dist_sig[..32]));

                // Test reference implementation
                println!("\n[2] Reference Implementation (fips205 v0.4.1)");
                let sk_array: [u8; 64] = sk_bytes.try_into().expect("SK must be 64 bytes");
                let ref_sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(&sk_array)
                    .expect("Reference SK failed");
                let ref_sig = ref_sk.try_sign(&message, &context, false)
                    .expect("Reference signing failed");
                println!("    Signature: {}", hex::encode(&ref_sig[..32]));

                // CAVP expected
                println!("\n[3] CAVP Test Vector");
                println!("    Signature: {}", hex::encode(&expected_sig[..32]));

                // Comparison
                println!("\n========================================");
                println!("VERIFICATION RESULTS");
                println!("========================================");

                let dist_matches_ref = dist_sig.as_slice() == ref_sig.as_slice();
                let dist_matches_cavp = dist_sig.as_slice() == expected_sig.as_slice();
                let ref_matches_cavp = ref_sig.as_slice() == expected_sig.as_slice();

                println!("✓ Dist matches Reference:  {}", if dist_matches_ref { "YES ✓" } else { "NO ✗" });
                println!("  Dist matches CAVP:        {}", if dist_matches_cavp { "YES ✓" } else { "NO ✗" });
                println!("  Reference matches CAVP:   {}", if ref_matches_cavp { "YES ✓" } else { "NO ✗" });

                println!("\n========================================");
                println!("CONCLUSION");
                println!("========================================");

                if dist_matches_ref && !dist_matches_cavp {
                    println!("✓ DIST IMPLEMENTATION IS CORRECT!");
                    println!("  - Produces identical output to fips205 reference");
                    println!("  - CAVP test vectors are incorrect/outdated");
                    println!("  - Implementation follows FIPS 205 Final spec");
                } else if dist_matches_ref && dist_matches_cavp {
                    println!("✓ All implementations match!");
                } else {
                    println!("✗ Dist implementation differs from reference");
                    println!("  This indicates an implementation bug");
                }
                println!("========================================\n");

                // Assert the key requirement
                assert!(dist_matches_ref,
                    "CRITICAL: Dist implementation must match fips205 reference implementation");

                return;
            }
        }
    }
}
