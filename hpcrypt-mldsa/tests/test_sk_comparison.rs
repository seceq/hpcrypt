//! Debug test to compare original and deserialized secret keys

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::MlDsa44;
use hpcrypt_mldsa::serialize::{deserialize_secret_key, serialize_secret_key};

#[test]
fn test_compare_secret_keys() {
    println!("\n=== Comparing Original vs Deserialized Secret Key ===\n");

    let (pk, sk_orig) = keygen::<MlDsa44>();

    // Serialize and deserialize
    let sk_bytes = serialize_secret_key::<MlDsa44>(&sk_orig);
    let sk_deser = deserialize_secret_key::<MlDsa44>(&sk_bytes)
        .expect("Deserialization failed");

    // Compare rho
    println!("Comparing rho...");
    assert_eq!(sk_orig.rho, sk_deser.rho, "rho mismatch");
    println!("  ✓ rho matches");

    // Compare k
    println!("Comparing k...");
    assert_eq!(sk_orig.k, sk_deser.k, "k mismatch");
    println!("  ✓ k matches");

    // Compare tr
    println!("Comparing tr...");
    assert_eq!(sk_orig.tr, sk_deser.tr, "tr mismatch");
    println!("  ✓ tr matches");

    // Compare s1
    println!("Comparing s1 (length: {})...", sk_orig.s1.len());
    assert_eq!(sk_orig.s1.len(), sk_deser.s1.len(), "s1 length mismatch");
    for (i, (orig, deser)) in sk_orig.s1.iter().zip(sk_deser.s1.iter()).enumerate() {
        for (j, (&o, &d)) in orig.coeffs.iter().zip(deser.coeffs.iter()).enumerate() {
            if o != d {
                println!("  ✗ s1[{}][{}]: orig={}, deser={}", i, j, o, d);
                panic!("s1 coefficient mismatch");
            }
        }
    }
    println!("  ✓ s1 matches");

    // Compare s2
    println!("Comparing s2 (length: {})...", sk_orig.s2.len());
    assert_eq!(sk_orig.s2.len(), sk_deser.s2.len(), "s2 length mismatch");
    for (i, (orig, deser)) in sk_orig.s2.iter().zip(sk_deser.s2.iter()).enumerate() {
        for (j, (&o, &d)) in orig.coeffs.iter().zip(deser.coeffs.iter()).enumerate() {
            if o != d {
                println!("  ✗ s2[{}][{}]: orig={}, deser={}", i, j, o, d);
                panic!("s2 coefficient mismatch");
            }
        }
    }
    println!("  ✓ s2 matches");

    // Compare t0
    println!("Comparing t0 (length: {})...", sk_orig.t0.len());
    assert_eq!(sk_orig.t0.len(), sk_deser.t0.len(), "t0 length mismatch");
    for (i, (orig, deser)) in sk_orig.t0.iter().zip(sk_deser.t0.iter()).enumerate() {
        for (j, (&o, &d)) in orig.coeffs.iter().zip(deser.coeffs.iter()).enumerate() {
            if o != d {
                println!("  ✗ t0[{}][{}]: orig={}, deser={}", i, j, o, d);
                panic!("t0 coefficient mismatch");
            }
        }
    }
    println!("  ✓ t0 matches");

    // Compare cached_a_ntt
    println!("Comparing cached_a_ntt ({}x{})...", sk_orig.cached_a_ntt.len(), sk_orig.cached_a_ntt[0].len());
    assert_eq!(sk_orig.cached_a_ntt.len(), sk_deser.cached_a_ntt.len(), "cached_a_ntt rows mismatch");
    assert_eq!(sk_orig.cached_a_ntt[0].len(), sk_deser.cached_a_ntt[0].len(), "cached_a_ntt cols mismatch");

    let mut mismatch_count = 0;
    for (i, (orig_row, deser_row)) in sk_orig.cached_a_ntt.iter().zip(sk_deser.cached_a_ntt.iter()).enumerate() {
        for (j, (orig_poly, deser_poly)) in orig_row.iter().zip(deser_row.iter()).enumerate() {
            for (k, (&o, &d)) in orig_poly.coeffs.iter().zip(deser_poly.coeffs.iter()).enumerate() {
                if o != d {
                    if mismatch_count < 5 {
                        println!("  ✗ cached_a_ntt[{}][{}][{}]: orig={}, deser={}", i, j, k, o, d);
                    }
                    mismatch_count += 1;
                }
            }
        }
    }

    if mismatch_count > 0 {
        println!("  ✗ cached_a_ntt has {} coefficient mismatches!", mismatch_count);
        println!("\n=== THIS IS THE BUG! ===");
        println!("The cached matrix A is NOT matching after deserialization.");
        println!("This explains why signatures fail - the matrix used during signing is wrong!");
        panic!("cached_a_ntt mismatch");
    } else {
        println!("  ✓ cached_a_ntt matches");
    }

    println!("\n✓ All fields match - secret key deserialization is correct");
}
