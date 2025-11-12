// Debug test for serialization issue

use mldsa::keygen::keygen_from_seed;
use mldsa::sign::sign;
use mldsa::verify::verify;
use mldsa::params::MlDsa65;
use mldsa::serialize::{serialize_signature, deserialize_signature};

#[test]
fn test_serialization_debug() {
    let seed = [123u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"Test message";

    eprintln!("\n=== SIGNING ===");
    let sig = sign::<MlDsa65>(&sk, message).expect("Signing should succeed");

    eprintln!("\n=== ORIGINAL SIGNATURE ===");
    eprintln!("c_tilde len: {}", sig.c_tilde.len());
    eprintln!("c_tilde[0..8]: {:02x?}", &sig.c_tilde[..8]);
    eprintln!("z len: {}", sig.z.len());
    eprintln!("z[0].coeffs[0..4]: {:?}", &sig.z[0].coeffs[0..4]);
    eprintln!("h len: {}", sig.h.len());
    eprintln!("h[0].coeffs[0..8]: {:?}", &sig.h[0].coeffs[0..8]);

    // Count hints
    let mut hint_count = 0;
    for poly in &sig.h {
        for &coeff in &poly.coeffs {
            if coeff != 0 {
                hint_count += 1;
            }
        }
    }
    eprintln!("Total hints: {}", hint_count);

    eprintln!("\n=== VERIFY ORIGINAL ===");
    let verify_original = verify::<MlDsa65>(&pk, message, &sig);
    eprintln!("Original verifies: {}", verify_original);
    assert!(verify_original, "Original signature should verify");

    eprintln!("\n=== SERIALIZATION ===");
    let serialized = serialize_signature::<MlDsa65>(&sig);
    eprintln!("Serialized len: {}", serialized.len());
    eprintln!("Serialized[0..16]: {:02x?}", &serialized[..16]);

    eprintln!("\n=== DESERIALIZATION ===");
    let deserialized = deserialize_signature::<MlDsa65>(&serialized)
        .expect("Deserialization should succeed");

    eprintln!("\n=== DESERIALIZED SIGNATURE ===");
    eprintln!("c_tilde len: {}", deserialized.c_tilde.len());
    eprintln!("c_tilde[0..8]: {:02x?}", &deserialized.c_tilde[..8]);
    eprintln!("z len: {}", deserialized.z.len());
    eprintln!("z[0].coeffs[0..4]: {:?}", &deserialized.z[0].coeffs[0..4]);
    eprintln!("h len: {}", deserialized.h.len());
    eprintln!("h[0].coeffs[0..8]: {:?}", &deserialized.h[0].coeffs[0..8]);

    // Count hints in deserialized
    let mut hint_count_deser = 0;
    for poly in &deserialized.h {
        for &coeff in &poly.coeffs {
            if coeff != 0 {
                hint_count_deser += 1;
            }
        }
    }
    eprintln!("Total hints: {}", hint_count_deser);

    eprintln!("\n=== COMPARISON ===");
    eprintln!("c_tilde match: {}", sig.c_tilde == deserialized.c_tilde);
    eprintln!("z match: {}", sig.z == deserialized.z);
    eprintln!("h match: {}", sig.h == deserialized.h);
    eprintln!("hint count match: {}", hint_count == hint_count_deser);

    // Check individual mismatches
    for i in 0..sig.h.len() {
        for j in 0..256 {
            if sig.h[i].coeffs[j] != deserialized.h[i].coeffs[j] {
                eprintln!("Hint mismatch at h[{}].coeffs[{}]: original={}, deserialized={}",
                    i, j, sig.h[i].coeffs[j], deserialized.h[i].coeffs[j]);
            }
        }
    }

    eprintln!("\n=== VERIFY DESERIALIZED ===");
    let verify_deserialized = verify::<MlDsa65>(&pk, message, &deserialized);
    eprintln!("Deserialized verifies: {}", verify_deserialized);

    assert!(verify_deserialized, "Deserialized signature should verify");
}
