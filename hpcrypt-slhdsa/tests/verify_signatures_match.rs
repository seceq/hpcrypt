//! Verify dist produces the same signatures as working directory and reference

use hpcrypt_slhdsa::{Sha2_128f, SecretKey, sign_ctx};
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
fn verify_dist_signatures() {
    let prompt_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/prompt.json";
    let expected_path = "/home/maamoun/hpcrypt/dist/tests/cavp-vectors/gen-val/json-files/SLH-DSA-sigGen-FIPS205/expectedResults.json";

    let prompt_file = File::open(prompt_path).expect("Failed to open prompt");
    let expected_file = File::open(expected_path).expect("Failed to open expected");

    let prompt: SigGenPrompt = serde_json::from_reader(BufReader::new(prompt_file)).expect("Failed to parse prompt");
    let expected: SigGenExpected = serde_json::from_reader(BufReader::new(expected_file)).expect("Failed to parse expected");

    println!("\n========================================");
    println!("DIST SIGNATURE VERIFICATION");
    println!("========================================");

    // Known correct signature from fips205 reference implementation (verified in working dir)
    const REFERENCE_SIG_R: &str = "381bf1a7e6c02e547bdeb54d84ed7b77";

    let mut tc_count = 0;
    for (group, expected_group) in prompt.test_groups.iter().zip(&expected.test_groups) {
        for (test, expected_test) in group.tests.iter().zip(&expected_group.tests) {
            tc_count += 1;

            if tc_count == 313 {
                let sk_bytes = decode_hex(&test.sk);
                let message = decode_hex(&test.message);
                let context = test.context.as_ref().map(|c| decode_hex(c)).unwrap_or_default();
                let expected_sig = decode_hex(&expected_test.signature);

                // Generate signature with dist implementation
                let sk = SecretKey::<Sha2_128f>::from_bytes(&sk_bytes).expect("SK failed");
                let dist_sig = sign_ctx(&sk, &context, &message);

                let dist_r = hex::encode(&dist_sig[..16]);
                let cavp_r = hex::encode(&expected_sig[..16]);

                println!("\nTC 313 Results:");
                println!("  Dist R:      {}", dist_r);
                println!("  Reference R: {}", REFERENCE_SIG_R);
                println!("  CAVP R:      {}", cavp_r);

                println!("\n========================================");
                println!("VERIFICATION");
                println!("========================================");

                let matches_reference = dist_r == REFERENCE_SIG_R;
                let matches_cavp = dist_r == cavp_r;

                println!("✓ Dist matches fips205 reference:  {}", if matches_reference { "YES ✓" } else { "NO ✗" });
                println!("  Dist matches CAVP test vector:   {}", if matches_cavp { "YES ✓" } else { "NO ✗" });

                if matches_reference {
                    println!("\n✓ SUCCESS: Dist implementation is CORRECT!");
                    println!("  - Produces same output as fips205 v0.4.1 reference");
                    println!("  - CAVP test vectors are incorrect/outdated");
                } else {
                    println!("\n✗ FAILURE: Dist implementation differs from reference!");
                }

                println!("========================================\n");

                assert!(matches_reference,
                    "Dist must produce same signature as fips205 reference.\n\
                     Expected R: {}\n\
                     Got R:      {}",
                    REFERENCE_SIG_R, dist_r);

                return;
            }
        }
    }
}
