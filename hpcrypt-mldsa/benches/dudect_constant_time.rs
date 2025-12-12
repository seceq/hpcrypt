//! Constant-time verification using DudeCT (Dude, is my Code Constant Time?)
//!
//! This benchmark uses statistical testing to verify that cryptographic operations
//! execute in constant time, regardless of secret inputs.
//!
//! DudeCT performs Welch's t-test to detect timing differences between two classes
//! of inputs. A t-statistic > 4.5 indicates a timing leak with high confidence.
//!
//! Run with: cargo bench --bench dudect_constant_time

use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use hpcrypt_mldsa::constant_time::{ct_compare, ct_select_i32};
use hpcrypt_mldsa::keygen::keygen_from_seed;
use hpcrypt_mldsa::params::{MlDsa65, Q};
use hpcrypt_mldsa::poly::Poly;
use hpcrypt_mldsa::sign::sign;
use hpcrypt_mldsa::verify::verify;

/// Test constant-time comparison of byte arrays
fn ct_compare_timing(runner: &mut CtRunner, _rng: &mut BenchRng) {
    const SIZE: usize = 32;

    let left_a = [0x42u8; SIZE];
    let left_b = [0x43u8; SIZE]; // Different from left_a

    let right_same = [0x42u8; SIZE]; // Same as left_a
    let right_different = [0xFFu8; SIZE]; // Very different

    runner.run_one(Class::Left, || {
        // Class Left: comparing equal arrays
        ct_compare(&left_a, &right_same)
    });

    runner.run_one(Class::Right, || {
        // Class Right: comparing different arrays
        ct_compare(&left_b, &right_different)
    });
}

/// Test constant-time selection (ct_select_i32)
fn ct_select_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    let value_a = rng.gen::<i32>() % Q;
    let value_b = rng.gen::<i32>() % Q;

    runner.run_one(Class::Left, || {
        // Class Left: condition is true (select first value)
        ct_select_i32(1, value_a, value_b)
    });

    runner.run_one(Class::Right, || {
        // Class Right: condition is false (select second value)
        ct_select_i32(0, value_a, value_b)
    });
}

/// Test signing operation for constant-time behavior
/// This is critical - signing time should not depend on the secret key or message
fn sign_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Generate two different secret keys
    let mut seed1 = [0u8; 32];
    let mut seed2 = [0u8; 32];

    for i in 0..32 {
        seed1[i] = rng.gen();
        seed2[i] = rng.gen();
    }

    let (_pk1, sk1) = keygen_from_seed::<MlDsa65>(&seed1);
    let (_pk2, sk2) = keygen_from_seed::<MlDsa65>(&seed2);

    // Same message for both
    let message = b"Test message for constant-time verification";

    runner.run_one(Class::Left, || {
        let _ = sign(&sk1, message);
    });

    runner.run_one(Class::Right, || {
        let _ = sign(&sk2, message);
    });
}

/// Test signature verification for constant-time behavior
/// Verification should not leak whether the signature is valid or invalid
fn verify_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = rng.gen();
    }

    let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);
    let message = b"Test message for verification timing";

    // Create a valid signature
    let valid_sig = sign(&sk, message).expect("Signing should succeed");

    // Create an invalid signature by modifying the valid one
    let mut invalid_sig = valid_sig.clone();
    // Modify c_tilde to make it invalid
    if !invalid_sig.c_tilde.is_empty() {
        invalid_sig.c_tilde[0] ^= 0xFF;
    }

    runner.run_one(Class::Left, || {
        // Class Left: verify valid signature
        let _ = verify(&pk, message, &valid_sig);
    });

    runner.run_one(Class::Right, || {
        // Class Right: verify invalid signature
        let _ = verify(&pk, message, &invalid_sig);
    });
}

/// Test NTT (Number Theoretic Transform) for constant-time behavior
fn ntt_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    use hpcrypt_mldsa::ntt::{inv_ntt, ntt};

    // Create two different polynomials
    let mut coeffs1 = [0i32; 256];
    let mut coeffs2 = [0i32; 256];

    for i in 0..256 {
        coeffs1[i] = (rng.gen::<i32>() % Q + Q) % Q;
        coeffs2[i] = (rng.gen::<i32>() % Q + Q) % Q;
    }

    let poly1 = Poly::from_coeffs(coeffs1);
    let poly2 = Poly::from_coeffs(coeffs2);

    runner.run_one(Class::Left, || {
        let ntt_poly = ntt(&poly1);
        let _ = inv_ntt(&ntt_poly);
    });

    runner.run_one(Class::Right, || {
        let ntt_poly = ntt(&poly2);
        let _ = inv_ntt(&ntt_poly);
    });
}

/// Test polynomial coefficient bounds checking
/// Should not leak which coefficients exceeded bounds
fn coefficient_check_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    const N: usize = 256;

    // Polynomial with all small coefficients
    let mut small_coeffs = [0i32; N];
    for i in 0..N {
        small_coeffs[i] = (rng.gen::<u8>() % 10) as i32;
    }

    // Polynomial with some large coefficients
    let mut large_coeffs = [0i32; N];
    for i in 0..N {
        if i % 2 == 0 {
            large_coeffs[i] = (rng.gen::<i32>() % 1000) + 5000;
        } else {
            large_coeffs[i] = (rng.gen::<u8>() % 10) as i32;
        }
    }

    let small_poly = Poly::from_coeffs(small_coeffs);
    let large_poly = Poly::from_coeffs(large_coeffs);

    runner.run_one(Class::Left, || {
        let _ = small_poly.infinity_norm();
    });

    runner.run_one(Class::Right, || {
        let _ = large_poly.infinity_norm();
    });
}

/// Test deserialization for constant-time behavior
/// Should not leak information about the structure of serialized data
fn deserialization_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    use hpcrypt_mldsa::serialize::{deserialize_public_key, serialize_public_key};

    let mut seed1 = [0u8; 32];
    let mut seed2 = [0u8; 32];
    for i in 0..32 {
        seed1[i] = rng.gen();
        seed2[i] = rng.gen();
    }

    let (pk1, _) = keygen_from_seed::<MlDsa65>(&seed1);
    let (pk2, _) = keygen_from_seed::<MlDsa65>(&seed2);

    let bytes1 = serialize_public_key(&pk1);
    let bytes2 = serialize_public_key(&pk2);

    runner.run_one(Class::Left, || {
        let _ = deserialize_public_key::<MlDsa65>(&bytes1);
    });

    runner.run_one(Class::Right, || {
        let _ = deserialize_public_key::<MlDsa65>(&bytes2);
    });
}

ctbench_main!(
    ct_compare_timing,
    ct_select_timing,
    sign_timing,
    verify_timing,
    ntt_timing,
    coefficient_check_timing,
    deserialization_timing
);
