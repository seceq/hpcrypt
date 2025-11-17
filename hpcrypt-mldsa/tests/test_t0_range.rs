//! Test to check the range of t0 values

use hpcrypt_mldsa::keygen::keygen;
use hpcrypt_mldsa::params::{MlDsa44, DsaParams};

#[test]
fn test_t0_value_range() {
    println!("\n=== Checking t0 value range for ML-DSA-44 ===");
    println!("d = {}", MlDsa44::D);
    println!("Expected range: (-2^(d-1), 2^(d-1)] = (-{}, {}]", 1 << (MlDsa44::D - 1), 1 << (MlDsa44::D - 1));

    let (_pk, sk) = keygen::<MlDsa44>();

    let half = 1i32 << (MlDsa44::D - 1);  // 2^12 = 4096 for ML-DSA-44
    let mut min_val = i32::MAX;
    let mut max_val = i32::MIN;
    let mut at_boundary = Vec::new();

    for (i, t0_poly) in sk.t0.iter().enumerate() {
        for (j, &coeff) in t0_poly.coeffs.iter().enumerate() {
            min_val = min_val.min(coeff);
            max_val = max_val.max(coeff);

            // Check for boundary values
            if coeff == half || coeff == -half {
                at_boundary.push((i, j, coeff));
            }
            if coeff.abs() > half {
                println!("  ✗ t0[{}][{}] = {} is outside expected range!", i, j, coeff);
            }
        }
    }

    println!("Actual range: [{}, {}]", min_val, max_val);
    println!("Boundary values (±{}): {:?}", half, at_boundary);

    if !at_boundary.is_empty() {
        println!("\nNOTE: Found {} coefficients at the boundary value ±{}", at_boundary.len(), half);
        println!("This might cause serialization issues if not handled correctly!");
    }
}
