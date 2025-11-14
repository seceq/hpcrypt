// Test to compare w1 from signing vs w1' from verification

use hpcrypt_mldsa::hints::use_hint_poly;
use hpcrypt_mldsa::keygen::keygen_from_seed;
use hpcrypt_mldsa::ntt::{matrix_vector_mul_ntt, ntt, poly_mul_ntt};
use hpcrypt_mldsa::params::{DsaParams, MlDsa65, Q};
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::rounding::high_bits;
use hpcrypt_mldsa::sampling::{expand_matrix_a, sample_in_ball};
use hpcrypt_mldsa::sign::sign;

#[test]
fn test_w1_recovery() {
    let seed = [0u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"";

    println!("Signing...");
    let sig = sign::<MlDsa65>(&sk, message).expect("Signing failed");

    println!("\n=== RECONSTRUCT W FROM VERIFICATION ===");

    let matrix_a = expand_matrix_a::<MlDsa65>(&pk.rho);
    let c = sample_in_ball(&sig.c_tilde, MlDsa65::TAU);

    // Compute w' = A·z - c·t1·2^d (same as in verify.rs)
    let mut z_ntt = Vec::with_capacity(MlDsa65::L);
    for z_i in &sig.z {
        z_ntt.push(ntt(z_i));
    }
    let az = matrix_vector_mul_ntt(&matrix_a, &z_ntt, MlDsa65::K, MlDsa65::L);

    let two_pow_d = 1i32 << MlDsa65::D;
    let mut w_prime = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        // Compute t1·2^d
        let mut t1_scaled = Poly::new();
        for j in 0..256 {
            t1_scaled.coeffs[j] = pk.t1[i].coeffs[j] << MlDsa65::D;
        }

        // c·(t1·2^d)
        let c_t1_scaled = poly_mul_ntt(&c, &t1_scaled);

        // w' = A·z - c·(t1·2^d)
        let mut wp = az[i].sub(&c_t1_scaled);
        wp.reduce();
        w_prime.push(wp);
    }

    println!("w'[0].coeffs[0..8]: {:?}", &w_prime[0].coeffs[0..8]);

    // Now extract w1_prime using hints (same as verify.rs)
    let mut w1_prime = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let w1_prime_i = use_hint_poly(&sig.h[i], &w_prime[i], 2 * MlDsa65::GAMMA2);
        w1_prime.push(w1_prime_i);
    }

    println!("w1_prime[0].coeffs[0..8]: {:?}", &w1_prime[0].coeffs[0..8]);

    // Also compute w1 WITHOUT hints for comparison
    let mut w1_no_hint = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut w1_i = Poly::new();
        for j in 0..256 {
            w1_i.coeffs[j] = high_bits(w_prime[i].coeffs[j], 2 * MlDsa65::GAMMA2);
        }
        w1_no_hint.push(w1_i);
    }

    println!(
        "w1 (no hint)[0].coeffs[0..8]: {:?}",
        &w1_no_hint[0].coeffs[0..8]
    );

    // Now reconstruct what w1 SHOULD be from signing
    // We know: w' = w - c·s2 + c·t0
    // So: w = w' + c·s2 - c·t0

    let mut cs2 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        cs2.push(poly_mul_ntt(&c, &sk.s2[i]));
    }

    let mut ct0 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        ct0.push(poly_mul_ntt(&c, &sk.t0[i]));
    }

    let mut w = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut w_i = w_prime[i].add(&cs2[i]).sub(&ct0[i]);
        w_i.reduce();
        w.push(w_i);
    }

    println!("\n=== RECONSTRUCTED W (from w' + c·s2 - c·t0) ===");
    println!("w[0].coeffs[0..8]: {:?}", &w[0].coeffs[0..8]);

    // Extract w1 from reconstructed w
    let mut w1_expected = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut w1_i = Poly::new();
        for j in 0..256 {
            w1_i.coeffs[j] = high_bits(w[i].coeffs[j], 2 * MlDsa65::GAMMA2);
        }
        w1_expected.push(w1_i);
    }

    println!(
        "w1 (expected)[0].coeffs[0..8]: {:?}",
        &w1_expected[0].coeffs[0..8]
    );

    println!("\n=== COMPARISON ===");
    println!(
        "w1_prime (with hints)  [0].coeffs[0..8]: {:?}",
        &w1_prime[0].coeffs[0..8]
    );
    println!(
        "w1_expected (from w)   [0].coeffs[0..8]: {:?}",
        &w1_expected[0].coeffs[0..8]
    );
    println!(
        "w1_no_hint (from w')   [0].coeffs[0..8]: {:?}",
        &w1_no_hint[0].coeffs[0..8]
    );

    // Check if they match
    let mut all_match = true;
    for i in 0..MlDsa65::K {
        for j in 0..256 {
            if w1_prime[i].coeffs[j] != w1_expected[i].coeffs[j] {
                all_match = false;
                println!("\nMismatch at w1[{}].coeffs[{}]:", i, j);
                println!("  w1_prime: {}", w1_prime[i].coeffs[j]);
                println!("  w1_expected: {}", w1_expected[i].coeffs[j]);
                if j > 10 {
                    println!("... (showing first 10 mismatches)");
                    break;
                }
            }
        }
        if !all_match {
            break;
        }
    }

    if all_match {
        println!("\n SUCCESS! w1_prime = w1_expected");
        println!("The hints correctly recover w1 from w'");
    } else {
        println!("\n FAILURE! w1_prime ≠ w1_expected");
        println!("The hints are NOT working correctly");
    }
}
