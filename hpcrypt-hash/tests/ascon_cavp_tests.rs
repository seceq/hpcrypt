//! NIST CAVP (Cryptographic Algorithm Validation Program) tests for Ascon
//!
//! These tests validate against the official NIST SP 800-232 test vectors
//! for the Ascon family of cryptographic algorithms.
//!
//! Test vector sources:
//! - LWC_HASH_KAT_128_256.txt - Ascon-Hash test vectors
//! - LWC_XOF_KAT_128_512.txt - Ascon-XOF test vectors
//! - LWC_CXOF_KAT_128_512.txt - Ascon-cXOF test vectors
//!
//! To run these tests:
//!   cargo test --test ascon_cavp_tests -- --nocapture

use hpcrypt_hash::ascon::{AsconCxof, AsconHash, AsconXof};

/// Parse hex string to bytes
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Default, Debug)]
struct HashVector {
    count: usize,
    msg: Vec<u8>,
    md: Vec<u8>,
}

#[derive(Default, Debug)]
struct XofVector {
    count: usize,
    msg: Vec<u8>,
    md: Vec<u8>,
}

#[derive(Default, Debug)]
struct CxofVector {
    count: usize,
    msg: Vec<u8>,
    z: Vec<u8>, // customization string
    md: Vec<u8>,
}

/// Parse Ascon-Hash KAT file
fn parse_hash_kat(content: &str) -> Vec<HashVector> {
    let mut vectors = Vec::new();
    let mut current = HashVector::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(value) = line.strip_prefix("Count = ") {
            if current.count > 0 {
                vectors.push(current);
            }
            current = HashVector::default();
            current.count = value.parse().unwrap();
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            current.msg = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("MD = ") {
            current.md = hex_decode(value);
        }
    }

    if current.count > 0 {
        vectors.push(current);
    }

    vectors
}

/// Parse Ascon-XOF KAT file
fn parse_xof_kat(content: &str) -> Vec<XofVector> {
    let mut vectors = Vec::new();
    let mut current = XofVector::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(value) = line.strip_prefix("Count = ") {
            if current.count > 0 {
                vectors.push(current);
            }
            current = XofVector::default();
            current.count = value.parse().unwrap();
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            current.msg = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("MD = ") {
            current.md = hex_decode(value);
        }
    }

    if current.count > 0 {
        vectors.push(current);
    }

    vectors
}

/// Parse Ascon-cXOF KAT file
fn parse_cxof_kat(content: &str) -> Vec<CxofVector> {
    let mut vectors = Vec::new();
    let mut current = CxofVector::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(value) = line.strip_prefix("Count = ") {
            if current.count > 0 {
                vectors.push(current);
            }
            current = CxofVector::default();
            current.count = value.parse().unwrap();
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            current.msg = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("Z = ") {
            current.z = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("MD = ") {
            current.md = hex_decode(value);
        }
    }

    if current.count > 0 {
        vectors.push(current);
    }

    vectors
}

#[test]
#[ignore] // Run with: cargo test --test ascon_cavp_tests test_ascon_hash_cavp -- --ignored --nocapture
fn test_ascon_hash_cavp() {
    let kat_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dist/tests/cavp-vectors/gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Ascon.Tests/SP800_232/KATFiles/LWC_HASH_KAT_128_256.txt"
    );

    let kat_content = match std::fs::read_to_string(kat_path) {
        Ok(content) => content,
        Err(_) => {
            println!("⚠️  KAT file not found at: {}", kat_path);
            println!("   Skipping CAVP test");
            return;
        }
    };

    let vectors = parse_hash_kat(&kat_content);
    println!("Loaded {} Ascon-Hash KAT vectors", vectors.len());

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        let digest = AsconHash::hash(&vector.msg);

        if digest.to_vec() == vector.md {
            passed += 1;
        } else {
            println!(
                "❌ Count {} FAILED - Msg len: {}",
                vector.count,
                vector.msg.len()
            );
            println!(
                "   Expected: {}",
                hex::encode(&vector.md[..vector.md.len().min(32)])
            );
            println!(
                "   Got:      {}",
                hex::encode(&digest[..digest.len().min(32)])
            );
            failed += 1;
        }

        if (passed + failed) % 100 == 0 {
            println!("✅ Progress: {}/{} vectors", passed + failed, vectors.len());
        }
    }

    println!("\n=== Ascon-Hash CAVP Test Results ===");
    println!("Total vectors: {}", vectors.len());
    println!("Passed: {} ({}%)", passed, (passed * 100) / vectors.len());
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some Ascon-Hash CAVP vectors failed!");
}

#[test]
#[ignore] // Run with: cargo test --test ascon_cavp_tests test_ascon_xof_cavp -- --ignored --nocapture
fn test_ascon_xof_cavp() {
    let kat_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dist/tests/cavp-vectors/gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Ascon.Tests/SP800_232/KATFiles/LWC_XOF_KAT_128_512.txt"
    );

    let kat_content = match std::fs::read_to_string(kat_path) {
        Ok(content) => content,
        Err(_) => {
            println!("⚠️  KAT file not found at: {}", kat_path);
            println!("   Skipping CAVP test");
            return;
        }
    };

    let vectors = parse_xof_kat(&kat_content);
    println!("Loaded {} Ascon-XOF KAT vectors", vectors.len());

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        let mut output = vec![0u8; vector.md.len()];
        AsconXof::hash(&vector.msg, &mut output);

        if output == vector.md {
            passed += 1;
        } else {
            println!(
                "❌ Count {} FAILED - Msg len: {}, Output len: {}",
                vector.count,
                vector.msg.len(),
                vector.md.len()
            );
            println!(
                "   Expected: {}",
                hex::encode(&vector.md[..vector.md.len().min(32)])
            );
            println!(
                "   Got:      {}",
                hex::encode(&output[..output.len().min(32)])
            );
            failed += 1;
        }

        if (passed + failed) % 100 == 0 {
            println!("✅ Progress: {}/{} vectors", passed + failed, vectors.len());
        }
    }

    println!("\n=== Ascon-XOF CAVP Test Results ===");
    println!("Total vectors: {}", vectors.len());
    println!("Passed: {} ({}%)", passed, (passed * 100) / vectors.len());
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some Ascon-XOF CAVP vectors failed!");
}

#[test]
#[ignore] // Run with: cargo test --test ascon_cavp_tests test_ascon_cxof_cavp -- --ignored --nocapture
fn test_ascon_cxof_cavp() {
    let kat_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dist/tests/cavp-vectors/gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Ascon.Tests/SP800_232/KATFiles/LWC_CXOF_KAT_128_512.txt"
    );

    let kat_content = match std::fs::read_to_string(kat_path) {
        Ok(content) => content,
        Err(_) => {
            println!("⚠️  KAT file not found at: {}", kat_path);
            println!("   Skipping CAVP test");
            return;
        }
    };

    let vectors = parse_cxof_kat(&kat_content);
    println!("Loaded {} Ascon-cXOF KAT vectors", vectors.len());

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        let mut output = vec![0u8; vector.md.len()];
        AsconCxof::hash(&vector.z, &vector.msg, &mut output);

        if output == vector.md {
            passed += 1;
        } else {
            println!(
                "❌ Count {} FAILED - Msg len: {}, Z len: {}, Output len: {}",
                vector.count,
                vector.msg.len(),
                vector.z.len(),
                vector.md.len()
            );
            println!(
                "   Expected: {}",
                hex::encode(&vector.md[..vector.md.len().min(32)])
            );
            println!(
                "   Got:      {}",
                hex::encode(&output[..output.len().min(32)])
            );
            failed += 1;
        }

        if (passed + failed) % 100 == 0 {
            println!("✅ Progress: {}/{} vectors", passed + failed, vectors.len());
        }
    }

    println!("\n=== Ascon-cXOF CAVP Test Results ===");
    println!("Total vectors: {}", vectors.len());
    println!("Passed: {} ({}%)", passed, (passed * 100) / vectors.len());
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some Ascon-cXOF CAVP vectors failed!");
}

#[test]
#[ignore] // Run with: cargo test --test ascon_cavp_tests test_all_ascon_cavp -- --ignored --nocapture
fn test_all_ascon_cavp() {
    println!("\n🧪 Running ALL Ascon CAVP tests...\n");

    test_ascon_hash_cavp();
    println!();

    test_ascon_xof_cavp();
    println!();

    test_ascon_cxof_cavp();
    println!();

    println!("✅ ALL Ascon CAVP tests completed successfully!");
}
