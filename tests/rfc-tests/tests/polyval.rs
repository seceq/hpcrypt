//! RFC 8452 - POLYVAL Universal Hash Function
//!
//! Tests for POLYVAL standalone operation as defined in RFC 8452.
//! POLYVAL is the universal hash function used in AES-GCM-SIV for authentication.
//! It differs from GHASH in polynomial and byte ordering.

use hpcrypt_mac::{polyval, Polyval};
use rfc_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct PolyvalTestVector {
    test_id: u32,
    test_type: String,
    source: String,
    description: String,
    note: String,
    #[serde(flatten)]
    data: Value,
}

#[test]
fn test_polyval_rfc8452() {
    let test_vectors: Vec<PolyvalTestVector> = load_test_file("rfc8452-polyval.json");

    println!("\n=== RFC 8452: POLYVAL Universal Hash Function ===");
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
            "polyval_empty" => {
                test_polyval_empty(&test.data, &mut stats);
            }
            "polyval_single_block" => {
                test_polyval_single_block(&test.data, &mut stats);
            }
            "polyval_rfc8452_a1" => {
                test_polyval_rfc8452_a1(&test.data, &mut stats);
            }
            "polyval_incremental" => {
                test_polyval_incremental(&test.data, &mut stats);
            }
            "polyval_h_sensitivity" => {
                test_polyval_h_sensitivity(&test.data, &mut stats);
            }
            "polyval_data_sensitivity" => {
                test_polyval_data_sensitivity(&test.data, &mut stats);
            }
            "polyval_partial_block" => {
                test_polyval_partial_block(&test.data, &mut stats);
            }
            "polyval_multi_block" => {
                test_polyval_multi_block(&test.data, &mut stats);
            }
            "polyval_reset" => {
                test_polyval_reset(&test.data, &mut stats);
            }
            "polyval_zero_h" => {
                test_polyval_zero_h(&test.data, &mut stats);
            }
            "polyval_large" => {
                test_polyval_large(&test.data, &mut stats);
            }
            "polyval_vs_ghash" => {
                test_polyval_vs_ghash(&test.data, &mut stats);
            }
            "polyval_determinism" => {
                test_polyval_determinism(&test.data, &mut stats);
            }
            _ => {
                println!("  Unknown test type: {}", test.test_type);
                stats.skipped += 1;
            }
        }
    }

    stats.print_summary();
    assert_eq!(stats.failed, 0, "All POLYVAL tests should pass");
}

fn test_polyval_empty(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);
    let expected = decode_hex(expected_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let tag = polyval(&h_arr, &input);

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

fn test_polyval_single_block(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let tag = polyval(&h_arr, &input);

    if expected_hex == "COMPUTE" {
        // Property test: just verify it produces a non-zero tag for non-zero input
        if tag != [0u8; 16] || input.iter().all(|&b| b == 0) {
            println!("  Single block POLYVAL produces valid output");
            println!("    Tag: {}", hex::encode(&tag));
            stats.passed += 1;
        } else {
            println!("  Single block POLYVAL produced zero for non-zero input");
            stats.failed += 1;
        }
    } else {
        let expected = decode_hex(expected_hex);
        if tag[..] == expected[..] {
            println!("  Single block POLYVAL matches expected");
            println!("    Tag: {}", hex::encode(&tag));
            stats.passed += 1;
        } else {
            println!("  Single block POLYVAL mismatch");
            println!("    Expected: {}", hex::encode(&expected));
            println!("    Got:      {}", hex::encode(&tag));
            stats.failed += 1;
        }
    }
}

fn test_polyval_rfc8452_a1(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let expected = decode_hex(expected_hex);

    let blocks: Vec<Vec<u8>> = data["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| decode_hex(b.as_str().unwrap()))
        .collect();

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let mut hasher = Polyval::new(&h_arr);

    for block in &blocks {
        let block_arr: [u8; 16] = block.clone().try_into().expect("Block must be 16 bytes");
        hasher.update_block(&block_arr);
    }
    let tag = hasher.finalize();

    if tag[..] == expected[..] {
        println!("  RFC 8452 Appendix A POLYVAL matches expected");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  RFC 8452 Appendix A POLYVAL mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_polyval_incremental(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let blocks: Vec<Vec<u8>> = data["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| decode_hex(b.as_str().unwrap()))
        .collect();

    // Batch processing using update_block
    let mut hasher1 = Polyval::new(&h_arr);
    for block in &blocks {
        let block_arr: [u8; 16] = block.clone().try_into().expect("Block must be 16 bytes");
        hasher1.update_block(&block_arr);
    }
    let tag1 = hasher1.finalize();

    // Incremental processing using update
    let mut hasher2 = Polyval::new(&h_arr);
    let all_data: Vec<u8> = blocks.iter().flat_map(|b| b.iter().copied()).collect();
    hasher2.update(&all_data);
    let tag2 = hasher2.finalize();

    if tag1 == tag2 {
        println!("  Incremental matches batch processing");
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else {
        println!("  Incremental vs batch mismatch");
        println!("    Batch:       {}", hex::encode(&tag1));
        println!("    Incremental: {}", hex::encode(&tag2));
        stats.failed += 1;
    }
}

fn test_polyval_h_sensitivity(data: &Value, stats: &mut TestStats) {
    let h1_hex = data["h1"].as_str().unwrap();
    let h2_hex = data["h2"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h1 = decode_hex(h1_hex);
    let h2 = decode_hex(h2_hex);
    let input = decode_hex(data_hex);

    let h1_arr: [u8; 16] = h1.try_into().expect("H1 must be 16 bytes");
    let h2_arr: [u8; 16] = h2.try_into().expect("H2 must be 16 bytes");

    let tag1 = polyval(&h1_arr, &input);
    let tag2 = polyval(&h2_arr, &input);

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

fn test_polyval_data_sensitivity(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data1_hex = data["data1"].as_str().unwrap();
    let data2_hex = data["data2"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input1 = decode_hex(data1_hex);
    let input2 = decode_hex(data2_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let tag1 = polyval(&h_arr, &input1);
    let tag2 = polyval(&h_arr, &input2);

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

fn test_polyval_partial_block(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Using update (which handles padding)
    let tag = polyval(&h_arr, &input);

    // Manually pad and compare
    let mut padded = [0u8; 16];
    padded[..input.len()].copy_from_slice(&input);
    let tag_padded = polyval(&h_arr, &padded);

    if tag == tag_padded {
        println!("  Partial block zero-padded correctly");
        println!("    Tag: {}", hex::encode(&tag));
        stats.passed += 1;
    } else {
        println!("  Partial block padding mismatch");
        println!("    Partial:    {}", hex::encode(&tag));
        println!("    Padded:     {}", hex::encode(&tag_padded));
        stats.failed += 1;
    }
}

fn test_polyval_multi_block(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let num_blocks = data["num_blocks"].as_u64().unwrap() as usize;

    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Generate test blocks
    let mut all_data = Vec::new();
    for i in 0..num_blocks {
        let mut block = [0u8; 16];
        block[0] = (i + 1) as u8;
        all_data.extend_from_slice(&block);
    }

    // Using one-shot function
    let tag1 = polyval(&h_arr, &all_data);

    // Using incremental update
    let mut hasher = Polyval::new(&h_arr);
    hasher.update(&all_data);
    let tag2 = hasher.finalize();

    if tag1 == tag2 && tag1 != [0u8; 16] {
        println!("  Multi-block ({} blocks) processed correctly", num_blocks);
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else if tag1 != tag2 {
        println!("  Multi-block mismatch");
        println!("    One-shot:    {}", hex::encode(&tag1));
        println!("    Incremental: {}", hex::encode(&tag2));
        stats.failed += 1;
    } else {
        println!("  Multi-block produced zero tag");
        stats.failed += 1;
    }
}

fn test_polyval_reset(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // First computation
    let mut hasher = Polyval::new(&h_arr);
    hasher.update(&input);
    let tag1 = hasher.finalize();

    // Create new hasher and compute again
    let mut hasher2 = Polyval::new(&h_arr);
    hasher2.update(&input);
    let tag2 = hasher2.finalize();

    // Test reset functionality
    let mut hasher3 = Polyval::new(&h_arr);
    hasher3.update(&input);
    hasher3.reset();
    hasher3.update(&input);
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

fn test_polyval_zero_h(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();
    let expected_hex = data["expected_tag"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);
    let expected = decode_hex(expected_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");
    let tag = polyval(&h_arr, &input);

    if tag[..] == expected[..] {
        println!("  Zero H produces zero tag");
        stats.passed += 1;
    } else {
        println!("  Zero H tag mismatch");
        println!("    Expected: {}", hex::encode(&expected));
        println!("    Got:      {}", hex::encode(&tag));
        stats.failed += 1;
    }
}

fn test_polyval_large(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let num_blocks = data["num_blocks"].as_u64().unwrap() as usize;

    let h = decode_hex(h_hex);
    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    // Generate large number of blocks
    let mut all_data = Vec::new();
    for i in 0..num_blocks {
        let mut block = [0u8; 16];
        block[0] = (i % 256) as u8;
        block[1] = (i / 256) as u8;
        all_data.extend_from_slice(&block);
    }

    // Using one-shot function
    let tag1 = polyval(&h_arr, &all_data);

    // Using incremental update
    let mut hasher = Polyval::new(&h_arr);
    hasher.update(&all_data);
    let tag2 = hasher.finalize();

    if tag1 == tag2 && tag1 != [0u8; 16] {
        println!("  Large input ({} blocks) processed correctly", num_blocks);
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else if tag1 != tag2 {
        println!("  Large input mismatch");
        println!("    One-shot:    {}", hex::encode(&tag1));
        println!("    Incremental: {}", hex::encode(&tag2));
        stats.failed += 1;
    } else {
        println!("  Large input produced zero tag");
        stats.failed += 1;
    }
}

fn test_polyval_vs_ghash(data: &Value, stats: &mut TestStats) {
    use hpcrypt_mac::ghash::ghash;

    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let polyval_tag = polyval(&h_arr, &input);
    let ghash_tag = ghash(&h_arr, &input);

    if polyval_tag != ghash_tag {
        println!("  POLYVAL differs from GHASH (different polynomials)");
        println!("    POLYVAL: {}", hex::encode(&polyval_tag));
        println!("    GHASH:   {}", hex::encode(&ghash_tag));
        stats.passed += 1;
    } else {
        println!("  POLYVAL and GHASH produced same output!");
        println!("    This should not happen - they use different field representations");
        stats.failed += 1;
    }
}

fn test_polyval_determinism(data: &Value, stats: &mut TestStats) {
    let h_hex = data["h"].as_str().unwrap();
    let data_hex = data["data"].as_str().unwrap();

    let h = decode_hex(h_hex);
    let input = decode_hex(data_hex);

    let h_arr: [u8; 16] = h.try_into().expect("H must be 16 bytes");

    let tag1 = polyval(&h_arr, &input);
    let tag2 = polyval(&h_arr, &input);

    if tag1 == tag2 {
        println!("  POLYVAL is deterministic");
        println!("    Tag: {}", hex::encode(&tag1));
        stats.passed += 1;
    } else {
        println!("  POLYVAL is non-deterministic!");
        println!("    First:  {}", hex::encode(&tag1));
        println!("    Second: {}", hex::encode(&tag2));
        stats.failed += 1;
    }
}

#[test]
fn test_polyval_vector_count() {
    let test_vectors: Vec<PolyvalTestVector> = load_test_file("rfc8452-polyval.json");
    assert!(!test_vectors.is_empty(), "POLYVAL should have test vectors");
    println!("POLYVAL test vectors loaded: {}", test_vectors.len());
}

#[test]
fn test_polyval_clmul_basic() {
    println!("\n=== POLYVAL CLMUL Basic Tests ===");

    let h = [0x42u8; 16];
    let data = [0x24u8; 64];

    let tag = polyval(&h, &data);

    assert_ne!(tag, [0u8; 16], "Non-zero input should produce non-zero tag");
    println!("  CLMUL produces non-zero output");
    println!("    Tag: {}", hex::encode(&tag));
}
