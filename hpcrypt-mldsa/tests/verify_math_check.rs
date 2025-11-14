// Test to verify the mathematical relationship: w' = w - c·s2 + c·t0

use hpcrypt_mldsa::keygen::keygen_from_seed;
use hpcrypt_mldsa::ntt::poly_mul_ntt;
use hpcrypt_mldsa::params::Q;
use hpcrypt_mldsa::params::{DsaParams, MlDsa65};
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::sampling::{expand_matrix_a, sample_in_ball};
use hpcrypt_mldsa::sign::sign;

#[test]
fn test_verify_mathematical_relationship() {
    let seed = [0u8; 32];
    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"";

    eprintln!("Signing...");
    let sig = sign::<MlDsa65>(&sk, message).expect("Signing failed");

    eprintln!("\nSignature created successfully");

    // Step 1: Expand matrix A
    let matrix_a = expand_matrix_a::<MlDsa65>(&pk.rho);

    // Step 2: Sample challenge c
    let c = sample_in_ball(&sig.c_tilde, MlDsa65::TAU);

    // Step 3: Compute A·z
    let mut az = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut az_i = Poly::new();
        for j in 0..MlDsa65::L {
            let prod = poly_mul_ntt(&matrix_a[i][j], &sig.z[j]);
            az_i = az_i.add(&prod);
        }
        az_i.reduce();
        az.push(az_i);
    }

    eprintln!("A·z[0].coeffs[0..4]: {:?}", &az[0].coeffs[0..4]);

    // Step 4: Compute c·t1·2^d
    let two_pow_d = 1i32 << MlDsa65::D;

    let mut ct1_scaled = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let ct1 = poly_mul_ntt(&c, &pk.t1[i]);

        let mut ct1_2d = Poly::new();
        for j in 0..256 {
            ct1_2d.coeffs[j] =
                ((ct1.coeffs[j] as i64 * two_pow_d as i64).rem_euclid(Q as i64)) as i32;
        }
        ct1_scaled.push(ct1_2d);
    }

    eprintln!(
        "c·t1·2^d[0].coeffs[0..4]: {:?}",
        &ct1_scaled[0].coeffs[0..4]
    );

    // Step 5: Compute w' = A·z - c·t1·2^d
    let mut w_prime = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut wp = az[i].sub(&ct1_scaled[i]);
        wp.reduce();
        w_prime.push(wp);
    }

    eprintln!("w'[0].coeffs[0..4]: {:?}", &w_prime[0].coeffs[0..4]);

    // Compute c·s2
    let mut cs2 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let cs2_i = poly_mul_ntt(&c, &sk.s2[i]);
        cs2.push(cs2_i);
    }

    eprintln!("c·s2[0].coeffs[0..4]: {:?}", &cs2[0].coeffs[0..4]);

    // Compute c·t0
    let mut ct0 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let ct0_i = poly_mul_ntt(&c, &sk.t0[i]);
        ct0.push(ct0_i);
    }

    eprintln!("c·t0[0].coeffs[0..4]: {:?}", &ct0[0].coeffs[0..4]);

    // Compute w = w' + c·s2 - c·t0  (reconstructed w)
    let mut w_reconstructed = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut w_i = w_prime[i].add(&cs2[i]).sub(&ct0[i]);
        w_i.reduce();
        w_reconstructed.push(w_i);
    }

    eprintln!("\nReconstructed w (should equal A·y from signing):");
    eprintln!("w[0].coeffs[0..4]: {:?}", &w_reconstructed[0].coeffs[0..4]);

    // Compute c·s1
    let mut cs1 = Vec::with_capacity(MlDsa65::L);
    for i in 0..MlDsa65::L {
        let cs1_i = poly_mul_ntt(&c, &sk.s1[i]);
        cs1.push(cs1_i);
    }

    // Compute y = z - c·s1
    let mut y = Vec::with_capacity(MlDsa65::L);
    for i in 0..MlDsa65::L {
        let mut y_i = sig.z[i].sub(&cs1[i]);
        y_i.reduce();
        y.push(y_i);
    }

    eprintln!("\nReconstructed y (from z - c·s1):");
    eprintln!("y[0].coeffs[0..4]: {:?}", &y[0].coeffs[0..4]);

    // Compute A·y
    let mut ay = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut ay_i = Poly::new();
        for j in 0..MlDsa65::L {
            let prod = poly_mul_ntt(&matrix_a[i][j], &y[j]);
            ay_i = ay_i.add(&prod);
        }
        ay_i.reduce();
        ay.push(ay_i);
    }

    eprintln!("\nA·y[0].coeffs[0..4]: {:?}", &ay[0].coeffs[0..4]);

    eprintln!("\n=== COMPARISON ===");
    eprintln!("A·y[0].coeffs[0..4]:         {:?}", &ay[0].coeffs[0..4]);
    eprintln!(
        "w_reconstructed[0].coeffs[0..4]: {:?}",
        &w_reconstructed[0].coeffs[0..4]
    );

    // Compute A·s1 using the SAME method as keygen
    // This is critical - must match the keygen approach exactly
    let mut s1_ntt = Vec::with_capacity(MlDsa65::L);
    for s1_i in &sk.s1 {
        s1_ntt.push(hpcrypt_mldsa::ntt::ntt(s1_i));
    }

    let as1 = hpcrypt_mldsa::ntt::matrix_vector_mul_ntt(&matrix_a, &s1_ntt, MlDsa65::K, MlDsa65::L);

    let mut c_as1 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let c_as1_i = poly_mul_ntt(&c, &as1[i]);
        c_as1.push(c_as1_i);
    }

    // A·y should equal A·z - c·A·s1
    eprintln!("\n=== TESTING: A·y vs A·z - c·A·s1 ===");
    let mut ay_check = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut check = az[i].sub(&c_as1[i]);
        check.reduce();
        ay_check.push(check);
    }
    eprintln!("A·y[0].coeffs[0..4]:           {:?}", &ay[0].coeffs[0..4]);
    eprintln!(
        "A·z - c·A·s1 [0].coeffs[0..4]: {:?}",
        &ay_check[0].coeffs[0..4]
    );

    // Also check: t = A·s1 + s2
    eprintln!("\n=== TESTING: t vs A·s1 + s2 ===");
    // We need to get t from keygen, but we don't have it directly
    // We can reconstruct it from t1 and t0
    let mut t_from_t1t0 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut t_i = Poly::new();
        for j in 0..256 {
            // t = 2^d·t1 + t0
            t_i.coeffs[j] = ((pk.t1[i].coeffs[j] as i64 * two_pow_d as i64
                + sk.t0[i].coeffs[j] as i64)
                .rem_euclid(Q as i64)) as i32;
        }
        t_from_t1t0.push(t_i);
    }

    let mut t_from_as1_s2 = Vec::with_capacity(MlDsa65::K);
    for i in 0..MlDsa65::K {
        let mut t_i = as1[i].add(&sk.s2[i]);
        t_i.reduce();
        t_from_as1_s2.push(t_i);
    }

    eprintln!(
        "t (from t1,t0)[0].coeffs[0..4]:     {:?}",
        &t_from_t1t0[0].coeffs[0..4]
    );
    eprintln!(
        "t (from A·s1+s2)[0].coeffs[0..4]:   {:?}",
        &t_from_as1_s2[0].coeffs[0..4]
    );

    // Check all coefficients
    let mut all_match = true;
    for i in 0..256 {
        if ay[0].coeffs[i] != w_reconstructed[0].coeffs[i] {
            all_match = false;
            eprintln!(
                "Mismatch at coeff[{}]: A·y={}, w_recon={}, diff={}",
                i,
                ay[0].coeffs[i],
                w_reconstructed[0].coeffs[i],
                (ay[0].coeffs[i] - w_reconstructed[0].coeffs[i]).abs()
            );
        }
    }

    assert!(
        all_match,
        "The mathematical relationship w' = w - c·s2 + c·t0 does not hold!"
    );
}
