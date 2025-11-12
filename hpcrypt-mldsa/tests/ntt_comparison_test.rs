// Test to compare C FFI NTT vs Native Rust NTT output
// This will help identify exactly where the implementations diverge

use mldsa::poly::Poly;

#[test]
fn compare_ntt_implementations() {
    println!("\nNTT Comparison Test - C FFI vs Native Rust");
    println!("===========================================\n");

    // Create a test polynomial with known values
    let mut test_poly = Poly::new();
    for i in 0..256 {
        test_poly.coeffs[i] = (i as i32 * 1234 + 5678) % mldsa::params::Q;
    }

    println!("Input polynomial (first 16 coeffs):");
    for i in 0..16 {
        print!("{:8} ", test_poly.coeffs[i]);
        if (i + 1) % 8 == 0 {
            println!();
        }
    }
    println!();

    // Test with C FFI (default)
    let mut poly_c = test_poly.clone();
    mldsa::simd::avx2::init_qdata();
    unsafe {
        mldsa::simd::avx2::ntt_avx2_ffi(&mut poly_c);
    }

    // Test with Native Rust
    let mut poly_rust = test_poly.clone();
    unsafe {
        mldsa::simd::ntt_native::ntt_native(&mut poly_rust);
    }

    // Compare outputs
    println!("Forward NTT Comparison:");
    println!("Index | C FFI      | Native Rust | Difference");
    println!("------|------------|-------------|------------");

    let mut mismatch_count = 0;
    let mut first_mismatch_idx = None;
    for i in 0..256 {
        let diff = poly_c.coeffs[i] - poly_rust.coeffs[i];
        if diff != 0 {
            if first_mismatch_idx.is_none() {
                first_mismatch_idx = Some(i);
            }
            if mismatch_count < 20 {
                println!("{:5} | {:10} | {:11} | {:10}", i, poly_c.coeffs[i], poly_rust.coeffs[i], diff);
            }
            mismatch_count += 1;
        }
    }

    if mismatch_count > 20 {
        println!("... ({} total mismatches, showing first 20)", mismatch_count);
    }

    if mismatch_count == 0 {
        println!("✓ Forward NTT: All 256 coefficients match!");
    } else {
        println!("\n✗ Forward NTT: {} mismatches found", mismatch_count);
        println!("  First mismatch at index: {}", first_mismatch_idx.unwrap());
    }

    // Now test inverse NTT
    println!("\n\nInverse NTT Comparison:");

    let mut poly_c_inv = poly_c.clone();
    unsafe {
        mldsa::simd::avx2::invntt_avx2_ffi(&mut poly_c_inv);
    }

    let mut poly_rust_inv = poly_rust.clone();
    unsafe {
        mldsa::simd::ntt_native::invntt_native(&mut poly_rust_inv);
    }

    println!("Index | C FFI      | Native Rust | Difference");
    println!("------|------------|-------------|------------");

    let mut inv_mismatch_count = 0;
    let mut first_inv_mismatch_idx = None;
    for i in 0..256 {
        let diff = poly_c_inv.coeffs[i] - poly_rust_inv.coeffs[i];
        if diff != 0 {
            if first_inv_mismatch_idx.is_none() {
                first_inv_mismatch_idx = Some(i);
            }
            if inv_mismatch_count < 20 {
                println!("{:5} | {:10} | {:11} | {:10}", i, poly_c_inv.coeffs[i], poly_rust_inv.coeffs[i], diff);
            }
            inv_mismatch_count += 1;
        }
    }

    if inv_mismatch_count > 20 {
        println!("... ({} total mismatches, showing first 20)", inv_mismatch_count);
    }

    if inv_mismatch_count == 0 {
        println!("✓ Inverse NTT: All 256 coefficients match!");
    } else {
        println!("\n✗ Inverse NTT: {} mismatches found", inv_mismatch_count);
        if let Some(idx) = first_inv_mismatch_idx {
            println!("  First mismatch at index: {}", idx);
        }
    }

    // Check round-trip
    println!("\n\nRound-trip Test (should recover original):");
    println!("Index | Original   | C FFI      | Native Rust | C Diff | Rust Diff");
    println!("------|------------|------------|-------------|--------|----------");

    let mut c_roundtrip_errors = 0;
    let mut rust_roundtrip_errors = 0;

    for i in 0..16 {
        let orig = test_poly.coeffs[i];
        let c_result = poly_c_inv.coeffs[i];
        let rust_result = poly_rust_inv.coeffs[i];
        let c_diff = orig - c_result;
        let rust_diff = orig - rust_result;

        if c_diff != 0 {
            c_roundtrip_errors += 1;
        }
        if rust_diff != 0 {
            rust_roundtrip_errors += 1;
        }

        println!("{:5} | {:10} | {:10} | {:11} | {:6} | {:9}",
                 i, orig, c_result, rust_result, c_diff, rust_diff);
    }

    println!("\nSummary:");
    println!("  C FFI round-trip errors: {}", c_roundtrip_errors);
    println!("  Native Rust round-trip errors: {}", rust_roundtrip_errors);

    // For CI: assert the implementations match
    assert_eq!(mismatch_count, 0, "Forward NTT implementations should match");
    assert_eq!(inv_mismatch_count, 0, "Inverse NTT implementations should match");
}
