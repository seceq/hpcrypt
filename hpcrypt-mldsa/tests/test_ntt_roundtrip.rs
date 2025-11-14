//! Test NTT round-trip property to verify correctness

use hpcrypt_mldsa::ntt::{inv_ntt, ntt};
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::sampling::sample_poly_eta;
use hpcrypt_mldsa::symmetric::expand_s;

#[test]
fn test_ntt_roundtrip_with_kat_seed() {
    // Test seed from KAT
    let test_xi: [u8; 32] = [
        0xf6, 0x96, 0x48, 0x40, 0x48, 0xec, 0x21, 0xf9, 0x6c, 0xf5, 0x0a, 0x56, 0xd0, 0x75, 0x9c,
        0x44, 0x8f, 0x37, 0x79, 0x75, 0x2f, 0x03, 0x83, 0xd3, 0x74, 0x49, 0x69, 0x06, 0x94, 0xcf,
        0x7a, 0x68,
    ];

    // Expand to get rho'
    let mut seedbuf = [0u8; 34];
    seedbuf[..32].copy_from_slice(&test_xi);
    seedbuf[32] = 6; // K
    seedbuf[33] = 5; // L

    let expanded = hpcrypt_mldsa::symmetric::h128(&seedbuf);
    let rho_prime: [u8; 64] = expanded[32..96].try_into().unwrap();

    // Sample s1[0] - the actual polynomial from KAT
    let mut xof = expand_s(&rho_prime, 0);
    let s1_0 = sample_poly_eta(&mut xof, 4); // eta=4 for ML-DSA-65

    println!("Original s1[0] first 8: {:?}", &s1_0.coeffs[0..8]);

    // Apply NTT
    let s1_0_ntt = ntt(&s1_0);
    println!("After NTT first 8: {:?}", &s1_0_ntt.coeffs[0..8]);

    // Apply INVNTT
    let recovered_mont = inv_ntt(&s1_0_ntt);
    println!(
        "After INVNTT (Montgomery form) first 8: {:?}",
        &recovered_mont.coeffs[0..8]
    );

    // Convert from Montgomery form and reduce to centered representation
    let mut recovered = Poly::new();
    const Q: i32 = 8380417;
    for i in 0..256 {
        let mut val = hpcrypt_mldsa::ntt::from_montgomery(recovered_mont.coeffs[i]);
        // Convert from [0, Q) to centered representation [-(Q-1)/2, (Q-1)/2]
        if val > Q / 2 {
            val -= Q;
        }
        recovered.coeffs[i] = val;
    }
    println!(
        "After from_montgomery (centered) first 8: {:?}",
        &recovered.coeffs[0..8]
    );

    // Check if round-trip works EXACTLY
    let mut errors = 0;
    let mut max_error = 0i32;

    for i in 0..256 {
        let diff = (s1_0.coeffs[i] - recovered.coeffs[i]).abs();
        if diff > 0 {
            if errors < 10 {
                println!(
                    "Mismatch at index {}: original={}, recovered={}, diff={}",
                    i, s1_0.coeffs[i], recovered.coeffs[i], diff
                );
            }
            errors += 1;
            if diff > max_error {
                max_error = diff;
            }
        }
    }

    if errors == 0 {
        println!("\n NTT round-trip PERFECT: INVNTT(NTT(x)) == x for all 256 coefficients");
    } else {
        println!("\n NTT round-trip FAILED: {} mismatches out of 256", errors);
        println!("   Max error: {}", max_error);
        panic!("NTT round-trip test failed - NTT is mathematically incorrect!");
    }
}

#[test]
fn test_ntt_roundtrip_simple() {
    // Test with a simple known polynomial
    let mut poly = Poly::new();
    poly.coeffs[0] = 1;
    poly.coeffs[1] = 2;
    poly.coeffs[2] = -3;
    poly.coeffs[3] = 4;

    println!("Simple test - Original: {:?}", &poly.coeffs[0..4]);

    let ntt_poly = ntt(&poly);
    println!("After NTT: {:?}", &ntt_poly.coeffs[0..4]);

    let recovered_mont = inv_ntt(&ntt_poly);
    let mut recovered = Poly::new();
    const Q: i32 = 8380417;
    for i in 0..256 {
        let mut val = hpcrypt_mldsa::ntt::from_montgomery(recovered_mont.coeffs[i]);
        // Convert from [0, Q) to centered representation
        if val > Q / 2 {
            val -= Q;
        }
        recovered.coeffs[i] = val;
    }
    println!("After INVNTT: {:?}", &recovered.coeffs[0..4]);

    for i in 0..256 {
        assert_eq!(
            poly.coeffs[i], recovered.coeffs[i],
            "Mismatch at index {}: {} != {}",
            i, poly.coeffs[i], recovered.coeffs[i]
        );
    }

    println!(" Simple NTT round-trip test PASSED");
}
