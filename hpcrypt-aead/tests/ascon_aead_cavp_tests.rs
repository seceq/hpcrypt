//! NIST CAVP tests for Ascon-AEAD (Ascon-128a)
//!
//! These tests validate against the official NIST SP 800-232 test vectors
//! for Ascon-AEAD128 (also known as Ascon-128a).
//!
//! Test vector source: LWC_AEAD_KAT_128_128.txt
//!
//! To run:
//!   cargo test --test ascon_aead_cavp_tests -- --nocapture
//!   cargo test --test ascon_aead_cavp_tests -- --ignored --nocapture

use hpcrypt_aead::ascon::Ascon128Nist;

/// Parse hex string to bytes
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Default, Debug)]
struct AeadVector {
    count: usize,
    key: Vec<u8>,
    nonce: Vec<u8>,
    pt: Vec<u8>,
    ad: Vec<u8>,
    ct: Vec<u8>, // ciphertext + tag
}

/// Parse Ascon-AEAD KAT file
fn parse_aead_kat(content: &str) -> Vec<AeadVector> {
    let mut vectors = Vec::new();
    let mut current = AeadVector::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(value) = line.strip_prefix("Count = ") {
            if current.count > 0 {
                vectors.push(current);
            }
            current = AeadVector::default();
            current.count = value.parse().unwrap();
        } else if let Some(value) = line.strip_prefix("Key = ") {
            current.key = hex_decode(value);
        } else if let Some(value) = line.strip_prefix("Nonce = ") {
            current.nonce = hex_decode(value);
        } else if let Some(value) = line.strip_prefix("PT = ") {
            current.pt = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("AD = ") {
            current.ad = if value.is_empty() {
                Vec::new()
            } else {
                hex_decode(value)
            };
        } else if let Some(value) = line.strip_prefix("CT = ") {
            current.ct = hex_decode(value);
        }
    }

    if current.count > 0 {
        vectors.push(current);
    }

    vectors
}

#[test]
fn test_ascon_aead_basic_vectors() {
    // Test a few basic vectors inline to ensure basic functionality
    let vectors = vec![
        (
            // Count 1: Empty PT, Empty AD
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F"),
            hex_literal::hex!("101112131415161718191A1B1C1D1E1F"),
            &b""[..],
            &b""[..],
            hex_literal::hex!("4F9C278211BEC9316BF68F46EE8B2EC6"),
        ),
        (
            // Count 2: Empty PT, 1 byte AD
            hex_literal::hex!("000102030405060708090A0B0C0D0E0F"),
            hex_literal::hex!("101112131415161718191A1B1C1D1E1F"),
            &b""[..],
            &hex_literal::hex!("30")[..],
            hex_literal::hex!("CCCB674FE18A09A285D6AB11B35675C0"),
        ),
    ];

    for (i, (key, nonce, pt, ad, expected_ct)) in vectors.iter().enumerate() {
        // Test encryption
        let encrypted = Ascon128Nist::encrypt(key, nonce, pt, ad);
        assert_eq!(
            &encrypted[..],
            &expected_ct[..],
            "Encryption failed for vector {}",
            i + 1
        );

        // Test decryption
        let decrypted = Ascon128Nist::decrypt(key, nonce, &encrypted, ad);
        assert!(
            decrypted.is_some(),
            "Decryption failed for vector {}",
            i + 1
        );
        assert_eq!(
            &decrypted.unwrap()[..],
            *pt,
            "Decrypted plaintext mismatch for vector {}",
            i + 1
        );
    }
}

#[test]
#[ignore] // Run with: cargo test --test ascon_aead_cavp_tests test_ascon_aead_cavp_full -- --ignored --nocapture
fn test_ascon_aead_cavp_full() {
    // Path to CAVP test vectors
    let kat_paths = [
        // First try the root tests/kat directory
        concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/kat/LWC_AEAD_KAT_128_128.txt"),
        // Then try the dist directory
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dist/tests/cavp-vectors/gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Ascon.Tests/SP800_232/KATFiles/LWC_AEAD_KAT_128_128.txt"
        ),
    ];

    let mut kat_content = None;
    let mut used_path = String::new();

    for path in &kat_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            kat_content = Some(content);
            used_path = path.to_string();
            break;
        }
    }

    let kat_content = match kat_content {
        Some(content) => content,
        None => {
            println!("⚠️  KAT file not found at any of the following paths:");
            for path in &kat_paths {
                println!("   - {}", path);
            }
            println!("   Skipping CAVP test");
            return;
        }
    };

    println!("📁 Using KAT file: {}", used_path);

    let vectors = parse_aead_kat(&kat_content);
    println!("Loaded {} Ascon-AEAD KAT vectors", vectors.len());

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        // Convert to fixed-size arrays
        if vector.key.len() != 16 || vector.nonce.len() != 16 {
            println!(
                "⚠️  Count {} SKIPPED - Invalid key/nonce size",
                vector.count
            );
            continue;
        }

        let key: [u8; 16] = vector.key.as_slice().try_into().unwrap();
        let nonce: [u8; 16] = vector.nonce.as_slice().try_into().unwrap();

        // Test encryption
        let encrypted = Ascon128Nist::encrypt(&key, &nonce, &vector.pt, &vector.ad);

        if encrypted != vector.ct {
            println!(
                "❌ Count {} FAILED (encryption) - PT len: {}, AD len: {}",
                vector.count,
                vector.pt.len(),
                vector.ad.len()
            );
            println!(
                "   Expected: {}",
                hex::encode(&vector.ct[..vector.ct.len().min(32)])
            );
            println!(
                "   Got:      {}",
                hex::encode(&encrypted[..encrypted.len().min(32)])
            );
            failed += 1;
            continue;
        }

        // Test decryption
        let decrypted = Ascon128Nist::decrypt(&key, &nonce, &vector.ct, &vector.ad);

        if let Some(pt) = decrypted {
            if pt != vector.pt {
                println!(
                    "❌ Count {} FAILED (decryption mismatch) - PT len: {}, AD len: {}",
                    vector.count,
                    vector.pt.len(),
                    vector.ad.len()
                );
                println!(
                    "   Expected PT: {}",
                    hex::encode(&vector.pt[..vector.pt.len().min(32)])
                );
                println!("   Got PT:      {}", hex::encode(&pt[..pt.len().min(32)]));
                failed += 1;
                continue;
            }
        } else {
            println!(
                "❌ Count {} FAILED (decryption returned None) - PT len: {}, AD len: {}",
                vector.count,
                vector.pt.len(),
                vector.ad.len()
            );
            failed += 1;
            continue;
        }

        passed += 1;

        // Print progress every 100 vectors
        if (passed + failed) % 100 == 0 {
            println!("✅ Progress: {}/{} vectors", passed + failed, vectors.len());
        }
    }

    println!("\n=== Ascon-AEAD (Ascon-128a) CAVP Test Results ===");
    println!("Total vectors: {}", vectors.len());
    println!(
        "Passed: {} ({:.1}%)",
        passed,
        (passed as f64 * 100.0) / vectors.len() as f64
    );
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some Ascon-AEAD CAVP vectors failed!");
}
