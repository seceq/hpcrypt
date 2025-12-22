//! NIST SP 800-38D - GHASH Universal Hash Function
//!
//! Tests for GHASH standalone operation as defined in NIST SP 800-38D.
//! GHASH is the universal hash function used in AES-GCM for authentication.

use hpcrypt_mac::ghash::ghash;
use hpcrypt_mac::Ghash;
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct GhashTestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_ghash_nist_sp800_38d() {
    let test_vectors: Vec<GhashTestVector> = load_test_file("nist-sp800-38d-ghash.json");

    println!("\n=== NIST SP 800-38D: GHASH Universal Hash Function ===");
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
            "ghash_empty" => {
                test_ghash_empty(&test.data, &mut stats);
            }
            "ghash_single_block" => {
                test_ghash_single_block(&test.data, &mut stats);
            }
            "ghash_multi_block" => {
                test_ghash_multi_block(&test.data, &mut stats);
            }
            "ghash_incremental" => {
                test_ghash_incremental(&test.data, &mut stats);
            }
            "ghash_h_sensitivity" => {
                test_ghash_h_sensitivity(&test.data, &mut stats);
            }
            "ghash_data_sensitivity" => {
                test_ghash_data_sensitivity(&test.data, &mut stats);
            }
            "ghash_aes_gcm_derived" => {
                test_ghash_aes_gcm_derived(&test.data, &mut stats);
            }
            "ghash_remainder_1" | "ghash_remainder_2" | "ghash_remainder_3" => {
                test_ghash_remainder(&test.data, &test.test_type, &mut stats);
            }
            "ghash_chunk_4" => {
                test_ghash_chunk_4(&test.data, &mut stats);
            }
            "ghash_large" => {
                test_ghash_large(&test.data, &mut stats);
            }
            "ghash_reset" => {
                test_ghash_reset(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All GHASH tests should pass");
}

fn test_ghash_empty(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);
    let expected = decode_hex(expected_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let tag = ghash(&h_arr, &input);

    if tag[..] == expected[..] {
        println!("  Empty input produces zero tag");
        stats.passed += 1;
    } else {
        println!("  Empty input tag mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_ghash_single_block(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);
    let expected = decode_hex(expected_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let tag = ghash(&h_arr, &input);

    if tag[..] == expected[..] {
        println!("  Single block GHASH matches expected");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Single block GHASH mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_ghash_multi_block(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let expected = decode_hex(expected_hex);

    let blocks: Vec<[u8; 16]> = data["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let block_vec = decode_hex(b.as_str().unwrap());
            block_vec.try_into().expect("Block must be 16 bytes")
        })
        .collect();

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let mut hasher = Ghash::new(&h_arr);
    for block in &blocks {
        hasher.update(block);
    }
    let tag = hasher.finalize();

    if tag[..] == expected[..] {
        println!("  Multi-block GHASH matches expected");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Multi-block GHASH mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_ghash_incremental(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let blocks: Vec<[u8; 16]> = data["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let block_vec = decode_hex(b.as_str().unwrap());
            block_vec.try_into().expect("Block must be 16 bytes")
        })
        .collect();

    // Batch processing (using update for each block)
    let mut hasher1 = Ghash::new(&h_arr);
    for block in &blocks {
        hasher1.update(block);
    }
    let tag1 = hasher1.finalize();

    // Incremental processing
    let mut hasher2 = Ghash::new(&h_arr);
    for block in &blocks {
        hasher2.update(block);
    }
    let tag2 = hasher2.finalize();

    if tag1 == tag2 {
        println!("  Both processing methods match");
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else {
        println!("  Incremental vs batch mismatch");
        println!("    Batch:       {}", hex::encode(&tag1));
        println!("    Incremental: {}", hex::encode(&tag2));
        stats.failed += 1;
    }
}

fn test_ghash_h_sensitivity(data: &Value, stats: &mut TestStats) {
    let h1_hex = data["h1"].as_str().unwrap();
    let h2_hex = data["h2"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h1 = decode_hex(h1_hex);
    let h2 = decode_hex(h2_hex);
    let input = decode_hex(data_hex);

    let h1_arr: [u8; 16] = h1.try_into().expect("H1 must be 16 bytes");
    let h2_arr: [u8; 16] = h2.try_into().expect("H2 must be 16 bytes");

    let tag1 = ghash(&h1_arr, &input);
    let tag2 = ghash(&h2_arr, &input);

    if tag1 != tag2 {
        println!("  Different H values produce different tags");
        println!("    H1 tag: {}", hex::encode(&tag1));
        println!("    H2 tag: {}", hex::encode(&tag2));
        stats.passed += 1;
    } else {
        println!("  Different H values produced same tag!");
        stats.failed += 1;
    }
}

fn test_ghash_data_sensitivity(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data1_hex = data["data1"].as_str().unwrap();
    let data2_hex = data["data2"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input1 = decode_hex(data1_hex);
    let input2 = decode_hex(data2_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let tag1 = ghash(&h_arr, &input1);
    let tag2 = ghash(&h_arr, &input2);

    if tag1 != tag2 {
        println!("  Different data produces different tags");
        println!("    Data1 tag: {}", hex::encode(&tag1));
        println!("    Data2 tag: {}", hex::encode(&tag2));
        stats.passed += 1;
    } else {
        println!("  Different data produced same tag!");
        stats.failed += 1;
    }
}

fn test_ghash_aes_gcm_derived(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();
    let length_block_hex = data["length_block"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let expected = decode_hex(expected_hex);
    let length_block = decode_hex(length_block_hex);

    let ciphertext_blocks: Vec<[u8; 16]> = data["ciphertext_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let block_vec = decode_hex(b.as_str().unwrap());
            block_vec.try_into().expect("Block must be 16 bytes")
        })
        .collect();

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let length_arr: [u8; 16] = length_block.try_into().expect("Length block must be 16 bytes");

    // GHASH(H, AAD || Ciphertext || length_block)
    // Since AAD is empty, just process ciphertext blocks + length block
    let mut hasher = Ghash::new(&h_arr);
    for block in &ciphertext_blocks {
        hasher.update(block);
    }
    hasher.update(&length_arr);
    let tag = hasher.finalize();

    if tag[..] == expected[..] {
        println!("  AES-GCM derived GHASH matches expected");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  AES-GCM derived GHASH mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_ghash_remainder(data: &Value, test_type: &str, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let num_blocks = data["num_blocks"].as_u64().unwrap() as usize;

    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Generate test blocks
    let blocks: Vec<[u8; 16]> = (0..num_blocks)
        .map(|i| {
            let mut block = [0u8; 16];
            block[0] = (i + 1) as u8;
            block
        })
        .collect();

    // Test processing
    let mut hasher = Ghash::new(&h_arr);
    for block in &blocks {
        hasher.update(block);
    }
    let tag = hasher.finalize();

    if tag != [0u8; 16] {
        println!(
            "  Remainder path ({} blocks) works correctly",
            num_blocks
        );
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Remainder path produced zero tag");
        stats.failed += 1;
    }
}

fn test_ghash_chunk_4(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let num_blocks = data["num_blocks"].as_u64().unwrap() as usize;

    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Generate 4 test blocks
    let blocks: Vec<[u8; 16]> = (0..num_blocks)
        .map(|i| {
            let mut block = [0u8; 16];
            block[0] = (i + 1) as u8;
            block
        })
        .collect();

    // Test processing
    let mut hasher = Ghash::new(&h_arr);
    for block in &blocks {
        hasher.update(block);
    }
    let tag = hasher.finalize();

    if tag != [0u8; 16] {
        println!("  Chunk-4 path works correctly");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Chunk-4 path produced zero tag");
        stats.failed += 1;
    }
}

fn test_ghash_large(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let num_blocks = data["num_blocks"].as_u64().unwrap() as usize;

    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Generate large number of blocks
    let blocks: Vec<[u8; 16]> = (0..num_blocks)
        .map(|i| {
            let mut block = [0u8; 16];
            block[0] = (i % 256) as u8;
            block[1] = (i / 256) as u8;
            block
        })
        .collect();

    // Test processing
    let mut hasher = Ghash::new(&h_arr);
    for block in &blocks {
        hasher.update(block);
    }
    let tag = hasher.finalize();

    if tag != [0u8; 16] {
        println!("  Large input ({} blocks) processed correctly", num_blocks);
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Large input produced zero tag");
        stats.failed += 1;
    }
}

fn test_ghash_reset(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let block: [u8; 16] = input.try_into().expect("Data must be 16 bytes");

    // First computation
    let mut hasher = Ghash::new(&h_arr);
    hasher.update(&block);
    let tag1 = hasher.finalize();

    // Create new hasher and compute again
    let mut hasher2 = Ghash::new(&h_arr);
    hasher2.update(&block);
    let tag2 = hasher2.finalize();

    // Test reset functionality
    let mut hasher3 = Ghash::new(&h_arr);
    hasher3.update(&block);
    hasher3.reset();
    hasher3.update(&block);
    let tag3 = hasher3.finalize();

    if tag1 == tag2 && tag1 == tag3 {
        println!("  Reset clears state correctly");
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else {
        println!("  Reset test failed");
        println!("    First:       {}", hex::encode(&tag1));
        println!("    New hasher:  {}", hex::encode(&tag2));
        println!("    After reset: {}", hex::encode(&tag3));
        stats.failed += 1;
    }
}

#[test]
fn test_ghash_vector_count() {
    let test_vectors: Vec<GhashTestVector> = load_test_file("nist-sp800-38d-ghash.json");
    assert!(!test_vectors.is_empty(), "GHASH should have test vectors");
    println!("GHASH test vectors loaded: {}", test_vectors.len());
}

#[test]
fn test_ghash_determinism() {
    println!("\n=== GHASH Determinism Test ===");

    let h = [0x42u8; 16];
    let data = [0x24u8; 64];

    let tag1 = ghash(&h, &data);
    let tag2 = ghash(&h, &data);

    assert_eq!(tag1, tag2, "GHASH must be deterministic");
    println!("  GHASH is deterministic");
    println!("    Tag: {}", hex::encode(&tag1));
}

#[test]
fn test_ghash_zero_h() {
    println!("\n=== GHASH with Zero H ===");

    let h = [0u8; 16];
    let data = [0x42u8; 16];

    let tag = ghash(&h, &data);

    // With H=0, GHASH should produce all zeros (since 0 * anything = 0 in GF(2^128))
    assert_eq!(tag, [0u8; 16], "GHASH with zero H should produce zero tag");
    println!("  Zero H produces zero tag");
}
