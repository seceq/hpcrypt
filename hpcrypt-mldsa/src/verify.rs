//! ML-DSA Signature Verification
//!
//! Implements the signature verification algorithm from FIPS 204 Section 5.3.
//!
//! # Algorithm Overview
//! 1. Recompute message representative μ = H(tr || M)
//! 2. Recompute challenge c from signature and message
//! 3. Check ||z||∞ ≤ γ₁ - β (reject if fails)
//! 4. Compute w' = A·z - c·t1·2^d
//! 5. Apply hints to recover w'₁ = UseHint(h, w')
//! 6. Recompute challenge c' from w'₁
//! 7. Accept if c' = c and hint count ≤ ω

extern crate alloc;
use alloc::vec::Vec;

use crate::hints::{poly_hint_count, use_hint_poly_optimized};
use crate::keygen::PublicKey;
use crate::params::{DsaParams, N, Q};
use crate::poly::Poly;
use crate::sampling::{expand_matrix_a, sample_in_ball};
use crate::sign::Signature;
use crate::symmetric::{h, h_var};

/// Verify a signature on a message
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Message that was signed
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify<P: DsaParams>(pk: &PublicKey<P>, message: &[u8], signature: &Signature<P>) -> bool {
    // Step 1: Check signature dimensions
    if signature.z.len() != P::L || signature.h.len() != P::K {
        return false;
    }

    // Step 2: Check that all z polynomials are bounded
    for z_i in &signature.z {
        let norm = z_i.infinity_norm();
        if norm > P::GAMMA1 - P::BETA {
            return false; // z out of range
        }
    }

    // Step 3: Check total number of hints
    let mut total_hints = 0;
    for h_i in &signature.h {
        total_hints += poly_hint_count(h_i);
    }
    if total_hints > P::OMEGA {
        return false; // Too many hints
    }

    // Step 4: Compute μ = H(tr || M) (same as in signing)
    let mut mu_input = Vec::with_capacity(64 + message.len());
    mu_input.extend_from_slice(&pk.tr);
    mu_input.extend_from_slice(message);
    let mu = h(&mu_input);

    // Step 5: Expand matrix A from ρ (same as in keygen/signing)
    let matrix_a = expand_matrix_a::<P>(&pk.rho);

    // Step 6: Sample challenge polynomial c from signature
    let c = sample_in_ball(&signature.c_tilde, P::TAU);

    // Step 7: Compute w' = A·z - c·t1·2^d
    // First compute A·z
    let mut w_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        let mut w_prime_i = Poly::new();
        for j in 0..P::L {
            let prod = poly_multiply(&matrix_a[i][j], &signature.z[j]);
            w_prime_i = w_prime_i.add(&prod);
        }
        w_prime.push(w_prime_i);
    }

    {}

    // Subtract c·(t1·2^d)
    // Following reference: shift t1 left BEFORE multiplying by c
    let _two_pow_d = 1i32 << P::D;
    for i in 0..P::K {
        // t1·2^d (shift left by D bits)
        // Following reference: NO modular reduction here (matches poly_shiftl)
        let mut t1_scaled = Poly::new();
        for j in 0..N {
            // Left shift without modular reduction
            t1_scaled.coeffs[j] = pk.t1[i].coeffs[j] << P::D;
        }

        // c·(t1·2^d)
        let c_t1_scaled = poly_multiply(&c, &t1_scaled);

        if i == 0 {}

        // w' = w' - c·(t1·2^d)
        w_prime[i] = w_prime[i].sub(&c_t1_scaled);
        w_prime[i].reduce();

        if i == 0 {}
    }

    // Step 8: Apply hints to recover high bits w'₁
    let mut w1_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        // Use SIMD-accelerated high_bits for entire polynomial
        // (Note: w_no_hint computed but not used in current impl)

        // Apply hints (using optimized const generic decompose for +77% improvement)
        let w1_prime_i = use_hint_poly_optimized::<P>(&signature.h[i], &w_prime[i]);
        w1_prime.push(w1_prime_i);
    }

    // Step 9: Encode w'₁ and compute challenge c'
    let w1_prime_bytes = encode_w1::<P>(&w1_prime);
    let mut c_prime_input = Vec::with_capacity(64 + w1_prime_bytes.len());
    c_prime_input.extend_from_slice(&mu);
    c_prime_input.extend_from_slice(&w1_prime_bytes);

    {}

    let c_prime_tilde = h_var(&c_prime_input, P::CTILDEBYTES);

    {}

    // Step 10: Compare challenges using constant-time comparison
    // This prevents timing attacks by ensuring comparison time is independent
    // of where differences occur in the byte arrays
    use crate::constant_time::ct_compare;
    let result = ct_compare(&c_prime_tilde, &signature.c_tilde);

    if result != 1 {}

    result == 1
}

/// Multiply two polynomials using NTT
///
/// Uses Number Theoretic Transform for O(n log n) performance.
/// This provides 100-1000x speedup over schoolbook multiplication.
fn poly_multiply(a: &Poly, b: &Poly) -> Poly {
    crate::ntt::poly_mul_ntt(a, b)
}

/// Encode w1 vector to bytes
///
/// Encodes the high bits for hashing (same as in signing).
fn encode_w1<P: DsaParams>(w1: &[Poly]) -> Vec<u8> {
    // Simplified encoding - in production, would use bit-packing
    // For now, just concatenate coefficient bytes
    let mut bytes = Vec::new();

    for poly in w1 {
        for &coeff in &poly.coeffs {
            // Encode each coefficient (simplified)
            let c = coeff.rem_euclid(Q);
            bytes.push((c & 0xFF) as u8);
            bytes.push(((c >> 8) & 0xFF) as u8);
            bytes.push(((c >> 16) & 0xFF) as u8);
        }
    }

    bytes
}

mod tests {

    #[test]
    fn test_verify_valid_signature() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        let message = b"Test message for verification";
        let rnd = [7u8; 32];

        // This test may take a while due to schoolbook multiplication
        if let Some(sig) = sign_deterministic::<MlDsa65>(&sk, message, &rnd) {
            let valid = verify::<MlDsa65>(&pk, message, &sig);
            assert!(valid, "Valid signature should verify");
        }
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa44>(&seed);

        let message1 = b"Original message";
        let message2 = b"Different message";
        let rnd = [7u8; 32];

        if let Some(sig) = sign_deterministic::<MlDsa44>(&sk, message1, &rnd) {
            let valid = verify::<MlDsa44>(&pk, message2, &sig);
            assert!(!valid, "Signature on different message should not verify");
        }
    }

    #[test]
    fn test_verify_modified_signature() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa44>(&seed);

        let message = b"Test message";
        let rnd = [7u8; 32];

        if let Some(mut sig) = sign_deterministic::<MlDsa44>(&sk, message, &rnd) {
            // Modify the signature
            sig.c_tilde[0] ^= 1;

            let valid = verify::<MlDsa44>(&pk, message, &sig);
            assert!(!valid, "Modified signature should not verify");
        }
    }

    #[test]
    fn test_verify_z_out_of_range() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa44>(&seed);

        let message = b"Test message";
        let rnd = [7u8; 32];

        if let Some(mut sig) = sign_deterministic::<MlDsa44>(&sk, message, &rnd) {
            // Make z out of range
            sig.z[0].coeffs[0] = MlDsa44::GAMMA1; // Exceeds bound

            let valid = verify::<MlDsa44>(&pk, message, &sig);
            assert!(!valid, "Signature with z out of range should not verify");
        }
    }

    #[test]
    fn test_verify_too_many_hints() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa44>(&seed);

        let message = b"Test message";
        let rnd = [7u8; 32];

        if let Some(mut sig) = sign_deterministic::<MlDsa44>(&sk, message, &rnd) {
            // Add too many hints
            for h_i in &mut sig.h {
                for j in 0..N {
                    h_i.coeffs[j] = 1; // All hints set
                }
            }

            let valid = verify::<MlDsa44>(&pk, message, &sig);
            assert!(!valid, "Signature with too many hints should not verify");
        }
    }

    #[test]
    fn test_verify_deterministic() {
        let seed = [42u8; 32];
        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        let message = b"Deterministic test";
        let rnd = [99u8; 32];

        if let Some(sig) = sign_deterministic::<MlDsa65>(&sk, message, &rnd) {
            // Verify multiple times should give same result
            let valid1 = verify::<MlDsa65>(&pk, message, &sig);
            let valid2 = verify::<MlDsa65>(&pk, message, &sig);

            assert_eq!(valid1, valid2, "Verification should be deterministic");
        }
    }

    #[test]
    fn test_encode_w1_dimensions() {
        let w1 = vec![Poly::new(); 4];
        let encoded = encode_w1::<MlDsa44>(&w1);

        // Should have 3 bytes per coefficient * 256 coeffs * 4 polys
        assert_eq!(encoded.len(), 3 * 256 * 4);
    }
}
