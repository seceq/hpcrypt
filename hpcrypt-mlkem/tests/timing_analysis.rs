//! Timing Analysis Tests for ML-KEM
//!
//! These tests verify that critical operations run in constant time
//! to prevent timing side-channel attacks.
//!
//! # Critical Operations
//!
//! The following operations must be constant-time:
//! 1. Decapsulation (ML-KEM.Decaps)
//! 2. Ciphertext comparison
//! 3. Key material handling
//! 4. Implicit rejection path
//!
//! # Test Methodology
//!
//! We use statistical timing analysis (Welch's t-test) to detect timing differences
//! between:
//! - Valid vs invalid ciphertexts
//! - Different secret keys
//! - Successful vs failed decapsulation
//!
//! A |t-statistic| > 4.5 indicates a potential timing leak.

#![cfg(all(feature = "timing-tests", feature = "std"))]

#[cfg(test)]
mod tests {
    use hpcrypt_mlkem::timing::TimingAnalyzer;
    use hpcrypt_mlkem::{KeyPair, MlKem768};
    use std::hint::black_box;

    // Note: These tests are statistical and may occasionally produce false positives
    // They are designed to catch obvious timing violations

    #[test]
    fn timing_constant_time_comparison() {
        // Test that our constant-time comparison is indeed constant-time
        use hpcrypt_mlkem::ct_verify::ct_eq;

        let mut analyzer = TimingAnalyzer::new();

        let a = [0x42u8; 32];
        let b_same = [0x42u8; 32];
        let b_diff = [0x43u8; 32];

        let result = analyzer.analyze(
            5000,
            100,
            || {
                // Class A: comparison returns 1 (equal)
                black_box(ct_eq(&a, black_box(&b_same)));
            },
            || {
                // Class B: comparison returns 0 (not equal)
                black_box(ct_eq(&a, black_box(&b_diff)));
            },
        );

        println!(
            "Constant-time comparison: t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        assert!(
            !result.is_leaking(),
            "Constant-time comparison leaked: t = {:.2}",
            result.t_statistic
        );
    }

    #[test]
    fn timing_decapsulation_valid_vs_invalid() {
        // Test that decapsulation timing doesn't depend on ciphertext validity
        let keypair = KeyPair::from_seed::<MlKem768>(&[0x42; 32]);

        // Generate valid ciphertext
        let (valid_ct, _) = keypair.encapsulate::<MlKem768>();

        // Create invalid ciphertext (corrupted)
        let mut invalid_ct = valid_ct.clone();
        invalid_ct[0] ^= 0xFF;
        invalid_ct[100] ^= 0xAA;
        invalid_ct[500] ^= 0x55;

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            50,
            || {
                // Class A: valid ciphertext
                black_box(keypair.decapsulate::<MlKem768>(black_box(&valid_ct)));
            },
            || {
                // Class B: invalid ciphertext (triggers implicit rejection)
                black_box(keypair.decapsulate::<MlKem768>(black_box(&invalid_ct)));
            },
        );

        println!(
            "Decapsulation (valid vs invalid): t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        // This is a critical test - decapsulation must be constant-time
        // to prevent timing attacks
        assert!(
            !result.is_leaking(),
            "Decapsulation timing depends on ciphertext validity: t = {:.2}\n\
             Mean valid: {:.0} ns, Mean invalid: {:.0} ns",
            result.t_statistic,
            result.mean_a,
            result.mean_b
        );
    }

    #[test]
    fn timing_decapsulation_different_keys() {
        // Test that decapsulation timing doesn't depend on key material
        let keypair1 = KeyPair::from_seed::<MlKem768>(&[0x01; 32]);
        let keypair2 = KeyPair::from_seed::<MlKem768>(&[0x02; 32]);

        // Generate ciphertext with first key
        let (ct, _) = keypair1.encapsulate::<MlKem768>();

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            50,
            || {
                // Class A: correct key
                black_box(keypair1.decapsulate::<MlKem768>(black_box(&ct)));
            },
            || {
                // Class B: wrong key (implicit rejection)
                black_box(keypair2.decapsulate::<MlKem768>(black_box(&ct)));
            },
        );

        println!(
            "Decapsulation (correct vs wrong key): t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        assert!(
            !result.is_leaking(),
            "Decapsulation timing depends on key correctness: t = {:.2}",
            result.t_statistic
        );
    }

    #[test]
    fn timing_encapsulation_message_independence() {
        // Test that encapsulation timing doesn't depend on the message
        // (though this is less critical than decapsulation)
        let keypair = KeyPair::from_seed::<MlKem768>(&[0x77; 32]);

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            50,
            || {
                // Class A: encapsulation (random message internally)
                black_box(keypair.encapsulate::<MlKem768>());
            },
            || {
                // Class B: encapsulation (different random message)
                black_box(keypair.encapsulate::<MlKem768>());
            },
        );

        println!(
            "Encapsulation timing: t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        // Encapsulation should be constant-time
        assert!(
            !result.is_leaking(),
            "Encapsulation timing varies: t = {:.2}",
            result.t_statistic
        );
    }

    #[test]
    fn timing_keygen_determinism() {
        // Test that key generation with same seed is consistent
        let seed1 = [0x42; 32];
        let seed2 = [0x43; 32];

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            500,
            50,
            || {
                // Class A: keygen with seed1
                black_box(KeyPair::from_seed::<MlKem768>(black_box(&seed1)));
            },
            || {
                // Class B: keygen with seed2
                black_box(KeyPair::from_seed::<MlKem768>(black_box(&seed2)));
            },
        );

        println!(
            "Key generation timing: t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        // Key generation timing can vary slightly due to rejection sampling
        // but shouldn't have huge differences
        assert!(
            result.t_statistic.abs() < 10.0,
            "Key generation timing varies significantly: t = {:.2}",
            result.t_statistic
        );
    }

    #[test]
    fn timing_ct_select_constant_time() {
        // Test that constant-time select is truly constant-time
        use hpcrypt_mlkem::ct_verify::ct_select;

        let a = vec![0x11u8; 64];
        let b = vec![0x22u8; 64];

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            10000,
            100,
            || {
                // Class A: select a (condition = true)
                black_box(ct_select(true, black_box(&a), black_box(&b)));
            },
            || {
                // Class B: select b (condition = false)
                black_box(ct_select(false, black_box(&a), black_box(&b)));
            },
        );

        println!(
            "Constant-time select: t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        assert!(
            !result.is_leaking(),
            "Constant-time select leaked: t = {:.2}",
            result.t_statistic
        );
    }

    #[test]
    fn timing_batch_decapsulation_consistency() {
        // Test that decapsulation timing is consistent across multiple operations
        let keypair = KeyPair::from_seed::<MlKem768>(&[0x88; 32]);

        let (ct1, _) = keypair.encapsulate::<MlKem768>();
        let (ct2, _) = keypair.encapsulate::<MlKem768>();

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            50,
            || {
                // Class A: decapsulate first ciphertext
                black_box(keypair.decapsulate::<MlKem768>(black_box(&ct1)));
            },
            || {
                // Class B: decapsulate second ciphertext
                black_box(keypair.decapsulate::<MlKem768>(black_box(&ct2)));
            },
        );

        println!(
            "Batch decapsulation consistency: t = {:.2}, confidence = {:.1}%",
            result.t_statistic,
            result.confidence()
        );

        assert!(
            !result.is_leaking(),
            "Decapsulation timing varies between ciphertexts: t = {:.2}",
            result.t_statistic
        );
    }

    // Negative test: Verify our timing analysis can detect obvious leaks
    #[test]
    fn timing_sanity_check_obvious_leak() {
        // This test verifies that our timing analysis framework can detect
        // an obvious timing leak

        let mut analyzer = TimingAnalyzer::new();

        let result = analyzer.analyze(
            1000,
            50,
            || {
                // Class A: fast operation
                black_box(1 + 1);
            },
            || {
                // Class B: slow operation
                for _ in 0..100 {
                    black_box(1 + 1);
                }
            },
        );

        println!("Sanity check (obvious leak): t = {:.2}", result.t_statistic);

        // This SHOULD be flagged as leaking
        assert!(
            result.is_leaking(),
            "Timing analysis failed to detect obvious leak: t = {:.2}",
            result.t_statistic
        );
    }
}
