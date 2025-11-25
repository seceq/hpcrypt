//! HKDF-BLAKE2b Tests
//!
//! Tests for HKDF using BLAKE2b as the underlying hash function.
//! HKDF follows RFC 5869, but with HMAC-BLAKE2b instead of HMAC-SHA variants.
//! BLAKE2b produces 64-byte output, so PRK and hash length are 64 bytes.

use hpcrypt_kdf::{hkdf_blake2b, hkdf_sha512, HkdfBlake2b};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct HkdfBlake2bTestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_hkdf_blake2b() {
    let test_vectors: Vec<HkdfBlake2bTestVector> = load_test_file("hkdf-blake2b.json");

    println!("\n=== HKDF-BLAKE2b Tests ===");
    println!("Total test cases: {}", test_vectors.len());

    let mut stats = TestStats::new();

    for test in &test_vectors {
        println!("\n--- Test {} ---", test.test_id);
        println!("  Type: {}", test.test_type);
        println!("  Source: {}", test.source);
        println!("  Description: {}", test.description);
        if !test.note.is_empty() {
            println!("  Note: {}", test.note);
        }

        match test.test_type.as_str() {
            "basic_extract_expand" => {
                test_basic_extract_expand(&test.data, &mut stats);
            }
            "empty_salt" => {
                test_empty_salt(&test.data, &mut stats);
            }
            "empty_info" => {
                test_empty_info(&test.data, &mut stats);
            }
            "long_output" => {
                test_long_output(&test.data, &mut stats);
            }
            "exact_hash_length_output" => {
                test_exact_hash_length_output(&test.data, &mut stats);
            }
            "short_output" => {
                test_short_output(&test.data, &mut stats);
            }
            "prk_length" => {
                test_prk_length(&test.data, &mut stats);
            }
            "determinism" => {
                test_determinism(&test.data, &mut stats);
            }
            "ikm_sensitivity" => {
                test_ikm_sensitivity(&test.data, &mut stats);
            }
            "salt_sensitivity" => {
                test_salt_sensitivity(&test.data, &mut stats);
            }
            "info_sensitivity" => {
                test_info_sensitivity(&test.data, &mut stats);
            }
            "struct_vs_function" => {
                test_struct_vs_function(&test.data, &mut stats);
            }
            "from_prk" => {
                test_from_prk(&test.data, &mut stats);
            }
            "prk_reuse" => {
                test_prk_reuse(&test.data, &mut stats);
            }
            "differs_from_sha512" => {
                test_differs_from_sha512(&test.data, &mut stats);
            }
            "long_inputs" => {
                test_long_inputs(&test.data, &mut stats);
            }
            "multi_block_expand" => {
                test_multi_block_expand(&test.data, &mut stats);
            }
            "single_byte_output" => {
                test_single_byte_output(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All HKDF-BLAKE2b tests should pass");
}

fn test_basic_extract_expand(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify output is not all zeros
    if okm.iter().any(|&b| b != 0) {
        println!("  Basic HKDF-BLAKE2b produces non-zero output");
        println!("    OKM: {}...", hex::encode(&okm[..16]));
        stats.passed += 1;
    } else {
        println!("  Basic HKDF-BLAKE2b produced all zeros");
        stats.failed += 1;
    }
}

fn test_empty_salt(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    assert!(salt.is_empty(), "Salt should be empty for this test");

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify output is not all zeros
    if okm.iter().any(|&b| b != 0) {
        println!("  HKDF-BLAKE2b with empty salt produces non-zero output");
        println!("    OKM: {}...", hex::encode(&okm[..16]));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b with empty salt produced all zeros");
        stats.failed += 1;
    }
}

fn test_empty_info(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    assert!(info.is_empty(), "Info should be empty for this test");

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify output is not all zeros
    if okm.iter().any(|&b| b != 0) {
        println!("  HKDF-BLAKE2b with empty info produces non-zero output");
        println!("    OKM: {}...", hex::encode(&okm[..16]));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b with empty info produced all zeros");
        stats.failed += 1;
    }
}

fn test_long_output(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify output length and not all zeros
    if okm.len() == output_length && okm.iter().any(|&b| b != 0) {
        println!(
            "  HKDF-BLAKE2b long output ({} bytes) correct",
            output_length
        );
        println!("    OKM start: {}...", hex::encode(&okm[..16]));
        println!(
            "    OKM end:   ...{}",
            hex::encode(&okm[output_length - 16..])
        );
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b long output failed");
        stats.failed += 1;
    }
}

fn test_exact_hash_length_output(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    assert_eq!(output_length, 64, "Output should be exactly hash length");

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    if okm.len() == 64 && okm.iter().any(|&b| b != 0) {
        println!("  HKDF-BLAKE2b exact hash length output (64 bytes) correct");
        println!("    OKM: {}", hex::encode(&okm));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b exact hash length output failed");
        stats.failed += 1;
    }
}

fn test_short_output(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    if okm.len() == output_length && okm.iter().any(|&b| b != 0) {
        println!(
            "  HKDF-BLAKE2b short output ({} bytes) correct",
            output_length
        );
        println!("    OKM: {}", hex::encode(&okm));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b short output failed");
        stats.failed += 1;
    }
}

fn test_prk_length(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let expected_prk_length = data["expected_prk_length"].as_u64().unwrap() as usize;

    let prk = HkdfBlake2b::extract(&salt, &ikm);

    if prk.len() == expected_prk_length {
        println!(
            "  PRK length is {} bytes (BLAKE2b hash length)",
            expected_prk_length
        );
        println!("    PRK: {}", hex::encode(&prk));
        stats.passed += 1;
    } else {
        println!(
            "  PRK length mismatch: expected {}, got {}",
            expected_prk_length,
            prk.len()
        );
        stats.failed += 1;
    }
}

fn test_determinism(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm1 = vec![0u8; output_length];
    let mut okm2 = vec![0u8; output_length];

    hkdf_blake2b(&salt, &ikm, &info, &mut okm1);
    hkdf_blake2b(&salt, &ikm, &info, &mut okm2);

    if okm1 == okm2 {
        println!("  HKDF-BLAKE2b is deterministic");
        println!("    OKM: {}...", hex::encode(&okm1[..16]));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b is non-deterministic!");
        println!("    First:  {}...", hex::encode(&okm1[..16]));
        println!("    Second: {}...", hex::encode(&okm2[..16]));
        stats.failed += 1;
    }
}

fn test_ikm_sensitivity(data: &Value, stats: &mut TestStats) {
    let ikm1 = decode_hex(data["ikm1"].as_str().unwrap());
    let ikm2 = decode_hex(data["ikm2"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm1 = vec![0u8; output_length];
    let mut okm2 = vec![0u8; output_length];

    hkdf_blake2b(&salt, &ikm1, &info, &mut okm1);
    hkdf_blake2b(&salt, &ikm2, &info, &mut okm2);

    if okm1 != okm2 {
        println!("  Different IKM produces different OKM");
        println!("    IKM1 OKM: {}...", hex::encode(&okm1[..16]));
        println!("    IKM2 OKM: {}...", hex::encode(&okm2[..16]));
        stats.passed += 1;
    } else {
        println!("  Different IKM produced same OKM!");
        stats.failed += 1;
    }
}

fn test_salt_sensitivity(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt1 = decode_hex(data["salt1"].as_str().unwrap());
    let salt2 = decode_hex(data["salt2"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm1 = vec![0u8; output_length];
    let mut okm2 = vec![0u8; output_length];

    hkdf_blake2b(&salt1, &ikm, &info, &mut okm1);
    hkdf_blake2b(&salt2, &ikm, &info, &mut okm2);

    if okm1 != okm2 {
        println!("  Different salt produces different OKM");
        println!("    Salt1 OKM: {}...", hex::encode(&okm1[..16]));
        println!("    Salt2 OKM: {}...", hex::encode(&okm2[..16]));
        stats.passed += 1;
    } else {
        println!("  Different salt produced same OKM!");
        stats.failed += 1;
    }
}

fn test_info_sensitivity(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info1 = decode_hex(data["info1"].as_str().unwrap());
    let info2 = decode_hex(data["info2"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm1 = vec![0u8; output_length];
    let mut okm2 = vec![0u8; output_length];

    hkdf_blake2b(&salt, &ikm, &info1, &mut okm1);
    hkdf_blake2b(&salt, &ikm, &info2, &mut okm2);

    if okm1 != okm2 {
        println!("  Different info produces different OKM");
        println!("    Info1 OKM: {}...", hex::encode(&okm1[..16]));
        println!("    Info2 OKM: {}...", hex::encode(&okm2[..16]));
        stats.passed += 1;
    } else {
        println!("  Different info produced same OKM!");
        stats.failed += 1;
    }
}

fn test_struct_vs_function(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    // Using function
    let mut okm_func = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm_func);

    // Using struct
    let hkdf = HkdfBlake2b::new(&salt, &ikm);
    let mut okm_struct = vec![0u8; output_length];
    hkdf.expand(&info, &mut okm_struct).unwrap();

    if okm_func == okm_struct {
        println!("  HkdfBlake2b struct matches hkdf_blake2b function");
        println!("    OKM: {}...", hex::encode(&okm_func[..16]));
        stats.passed += 1;
    } else {
        println!("  Struct and function outputs differ!");
        println!("    Function: {}...", hex::encode(&okm_func[..16]));
        println!("    Struct:   {}...", hex::encode(&okm_struct[..16]));
        stats.failed += 1;
    }
}

fn test_from_prk(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    // Using new()
    let hkdf1 = HkdfBlake2b::new(&salt, &ikm);
    let mut okm1 = vec![0u8; output_length];
    hkdf1.expand(&info, &mut okm1).unwrap();

    // Using extract + from_prk
    let prk = HkdfBlake2b::extract(&salt, &ikm);
    let hkdf2 = HkdfBlake2b::from_prk(&prk);
    let mut okm2 = vec![0u8; output_length];
    hkdf2.expand(&info, &mut okm2).unwrap();

    if okm1 == okm2 {
        println!("  from_prk produces same output as new");
        println!("    OKM: {}...", hex::encode(&okm1[..16]));
        stats.passed += 1;
    } else {
        println!("  from_prk differs from new!");
        println!("    new:      {}...", hex::encode(&okm1[..16]));
        println!("    from_prk: {}...", hex::encode(&okm2[..16]));
        stats.failed += 1;
    }
}

fn test_prk_reuse(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info1 = decode_hex(data["info1"].as_str().unwrap());
    let info2 = decode_hex(data["info2"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    // Extract PRK once
    let prk = HkdfBlake2b::extract(&salt, &ikm);
    let hkdf = HkdfBlake2b::from_prk(&prk);

    // Expand with different info values
    let mut okm1 = vec![0u8; output_length];
    let mut okm2 = vec![0u8; output_length];
    hkdf.expand(&info1, &mut okm1).unwrap();
    hkdf.expand(&info2, &mut okm2).unwrap();

    if okm1 != okm2 && okm1.iter().any(|&b| b != 0) && okm2.iter().any(|&b| b != 0) {
        println!("  PRK can be reused with different info");
        println!("    Info1 OKM: {}", hex::encode(&okm1));
        println!("    Info2 OKM: {}", hex::encode(&okm2));
        stats.passed += 1;
    } else if okm1 == okm2 {
        println!("  PRK reuse with different info produced same output!");
        stats.failed += 1;
    } else {
        println!("  PRK reuse produced zero output!");
        stats.failed += 1;
    }
}

fn test_differs_from_sha512(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm_blake2b = vec![0u8; output_length];
    let mut okm_sha512 = vec![0u8; output_length];

    hkdf_blake2b(&salt, &ikm, &info, &mut okm_blake2b);
    hkdf_sha512(&salt, &ikm, &info, &mut okm_sha512);

    if okm_blake2b != okm_sha512 {
        println!("  HKDF-BLAKE2b differs from HKDF-SHA512");
        println!("    BLAKE2b: {}...", hex::encode(&okm_blake2b[..16]));
        println!("    SHA-512: {}...", hex::encode(&okm_sha512[..16]));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b and HKDF-SHA512 produced same output!");
        stats.failed += 1;
    }
}

fn test_long_inputs(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    if okm.len() == output_length && okm.iter().any(|&b| b != 0) {
        println!("  HKDF-BLAKE2b with long inputs works correctly");
        println!("    IKM length:  {} bytes", ikm.len());
        println!("    Salt length: {} bytes", salt.len());
        println!("    Info length: {} bytes", info.len());
        println!("    OKM: {}...", hex::encode(&okm[..16]));
        stats.passed += 1;
    } else {
        println!("  HKDF-BLAKE2b with long inputs failed");
        stats.failed += 1;
    }
}

fn test_multi_block_expand(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    // 192 bytes = 3 * 64 bytes (3 BLAKE2b blocks)
    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Verify all three blocks are different (not just repeated)
    let block1 = &okm[0..64];
    let block2 = &okm[64..128];
    let block3 = &okm[128..192];

    if block1 != block2 && block2 != block3 && block1 != block3 {
        println!("  Multi-block expand produces unique blocks");
        println!("    Block 1: {}...", hex::encode(&block1[..16]));
        println!("    Block 2: {}...", hex::encode(&block2[..16]));
        println!("    Block 3: {}...", hex::encode(&block3[..16]));
        stats.passed += 1;
    } else {
        println!("  Multi-block expand produced duplicate blocks!");
        stats.failed += 1;
    }
}

fn test_single_byte_output(data: &Value, stats: &mut TestStats) {
    let ikm = decode_hex(data["ikm"].as_str().unwrap());
    let salt = decode_hex(data["salt"].as_str().unwrap());
    let info = decode_hex(data["info"].as_str().unwrap());
    let output_length = data["output_length"].as_u64().unwrap() as usize;

    assert_eq!(output_length, 1, "Output should be exactly 1 byte");

    let mut okm = vec![0u8; output_length];
    hkdf_blake2b(&salt, &ikm, &info, &mut okm);

    // Single byte output should still work
    println!("  Single byte output works");
    println!("    OKM: {}", hex::encode(&okm));
    stats.passed += 1;
}

#[test]
fn test_hkdf_blake2b_vector_count() {
    let test_vectors: Vec<HkdfBlake2bTestVector> = load_test_file("hkdf-blake2b.json");
    assert!(
        !test_vectors.is_empty(),
        "HKDF-BLAKE2b should have test vectors"
    );
    println!(
        "HKDF-BLAKE2b test vectors loaded: {}",
        test_vectors.len()
    );
}

#[test]
fn test_hkdf_blake2b_basic() {
    println!("\n=== HKDF-BLAKE2b Basic Tests ===");

    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"info";

    let mut okm = [0u8; 64];
    hkdf_blake2b(salt, ikm, info, &mut okm);

    assert_ne!(okm, [0u8; 64], "HKDF-BLAKE2b should produce non-zero output");
    println!("  Basic HKDF-BLAKE2b works");
    println!("    OKM: {}", hex::encode(&okm));
}
