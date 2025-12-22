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
//!
//! # Optimization
//!
//! This implementation uses pre-computed NTT-domain values from the PublicKey:
//! - `cached_a_ntt`: Matrix A in NTT form (saves ~81µs per verify)
//! - `t1_scaled_ntt`: t1*2^d in NTT form (saves ~6.7µs per verify)
//!
//! Total speedup: ~58% (from ~150µs to ~62µs for ML-DSA-65)

extern crate alloc;
use alloc::vec::Vec;

use crate::keygen::PublicKey;
use crate::sign::Signature;
use crate::params::{DsaParams, N, Q};
use crate::poly::Poly;
use crate::hints::{use_hint_poly_optimized, poly_hint_count};
use crate::sampling::sample_in_ball;
use crate::symmetric::{h, h_var};
use crate::ntt::{ntt, inv_ntt, ntt_multiply, reduce32};

/// Verify a signature on a message
///
/// # Arguments
/// * `pk` - Public key (with pre-computed NTT caches)
/// * `message` - Message that was signed
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
///
/// # Performance
///
/// This function uses pre-computed values from `pk.cached_a_ntt` and
/// `pk.t1_scaled_ntt` to achieve ~58% speedup over naive implementation.
pub fn verify<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    signature: &Signature<P>,
) -> bool {
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

    // Step 5: Sample challenge polynomial c from signature
    let c = sample_in_ball(&signature.c_tilde, P::TAU);

    // OPTIMIZATION: Transform z and c to NTT domain once
    let z_ntt: Vec<Poly> = signature.z.iter().map(|p| ntt(p)).collect();
    let c_ntt = ntt(&c);

    // Step 6: Compute w' = A·z - c·t1·2^d using NTT-domain operations
    //
    // OPTIMIZATION: Use pre-computed pk.cached_a_ntt instead of expanding A
    // This saves ~63µs (matrix expansion) + ~18µs (NTT conversion) per verify
    let mut w_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        // A[i]·z in NTT domain (pointwise multiply and accumulate)
        let mut acc_ntt = ntt_multiply(&pk.cached_a_ntt[i][0], &z_ntt[0]);
        for j in 1..P::L {
            let prod_ntt = ntt_multiply(&pk.cached_a_ntt[i][j], &z_ntt[j]);
            // SIMD-accelerated accumulation when available
            #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
            {
                if hpcrypt_core::cpufeatures::has_avx2() {
                    unsafe {
                        crate::intrinsics::avx2::poly::poly_add_acc_lazy(
                            &mut acc_ntt.coeffs,
                            &prod_ntt.coeffs,
                        );
                    }
                } else {
                    for k in 0..N {
                        acc_ntt.coeffs[k] += prod_ntt.coeffs[k];
                    }
                }
            }
            // Scalar fallback (also used for NEON - NEON poly_add is slower)
            #[cfg(not(all(feature = "avx2", feature = "std", target_arch = "x86_64")))]
            {
                for k in 0..N {
                    acc_ntt.coeffs[k] += prod_ntt.coeffs[k];
                }
            }
        }

        // OPTIMIZATION: Use pre-computed pk.t1_scaled_ntt instead of computing t1*2^d
        // This saves ~6.7µs per verify
        let c_t1_ntt = ntt_multiply(&c_ntt, &pk.t1_scaled_ntt[i]);

        // w' = A·z - c·(t1·2^d) in NTT domain - SIMD accelerated
        #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
        {
            if hpcrypt_core::cpufeatures::has_avx2() {
                unsafe {
                    crate::intrinsics::avx2::poly::poly_sub_acc_lazy(
                        &mut acc_ntt.coeffs,
                        &c_t1_ntt.coeffs,
                    );
                }
            } else {
                for k in 0..N {
                    acc_ntt.coeffs[k] -= c_t1_ntt.coeffs[k];
                }
            }
        }
        // Scalar fallback (also used for NEON - NEON poly_sub is slower)
        #[cfg(not(all(feature = "avx2", feature = "std", target_arch = "x86_64")))]
        {
            for k in 0..N {
                acc_ntt.coeffs[k] -= c_t1_ntt.coeffs[k];
            }
        }

        // Reduce before inverse NTT - SIMD accelerated
        #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
        {
            if hpcrypt_core::cpufeatures::has_avx2() {
                unsafe {
                    crate::intrinsics::avx2::poly::poly_reduce32(&mut acc_ntt.coeffs);
                }
            } else {
                for k in 0..N {
                    acc_ntt.coeffs[k] = reduce32(acc_ntt.coeffs[k]);
                }
            }
        }
        // Scalar fallback (also used for NEON - NEON poly_reduce is slower)
        #[cfg(not(all(feature = "avx2", feature = "std", target_arch = "x86_64")))]
        {
            for k in 0..N {
                acc_ntt.coeffs[k] = reduce32(acc_ntt.coeffs[k]);
            }
        }

        // Transform back to coefficient domain
        let mut w_prime_i = inv_ntt(&acc_ntt);

        // Normalize coefficients to [0, Q) for hint operations
        w_prime_i.reduce();

        w_prime.push(w_prime_i);
    }

    // Step 7: Apply hints to recover high bits w'₁
    let mut w1_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        // Apply hints (using optimized const generic decompose for +77% improvement)
        let w1_prime_i = use_hint_poly_optimized::<P>(&signature.h[i], &w_prime[i]);
        w1_prime.push(w1_prime_i);
    }

    // Step 8: Encode w'₁ and compute challenge c'
    let w1_prime_bytes = encode_w1::<P>(&w1_prime);
    let mut c_prime_input = Vec::with_capacity(64 + w1_prime_bytes.len());
    c_prime_input.extend_from_slice(&mu);
    c_prime_input.extend_from_slice(&w1_prime_bytes);

    let c_prime_tilde = h_var(&c_prime_input, P::CTILDEBYTES);

    // Step 9: Compare challenges using constant-time comparison
    // This prevents timing attacks by ensuring comparison time is independent
    // of where differences occur in the byte arrays
    use crate::constant_time::ct_compare;
    let result = ct_compare(&c_prime_tilde, &signature.c_tilde);

    result == 1
}

/// Verify a signature using pre-computed μ (for ACVP internal interface tests)
///
/// This function accepts the 64-byte message hash μ directly, bypassing the
/// μ = H(tr || M) computation. Used for ACVP internal interface tests where μ
/// is provided in the test vector.
///
/// # Arguments
/// * `pk` - Public key
/// * `mu` - Pre-computed 64-byte message hash
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_with_mu<P: DsaParams>(
    pk: &PublicKey<P>,
    mu: &[u8; 64],
    signature: &Signature<P>,
) -> bool {
    // Step 1: Check signature dimensions
    if signature.z.len() != P::L || signature.h.len() != P::K {
        return false;
    }

    // Step 2: Check that all z polynomials are bounded
    for z_i in &signature.z {
        let norm = z_i.infinity_norm();
        if norm > P::GAMMA1 - P::BETA {
            return false;
        }
    }

    // Step 3: Check total number of hints
    let mut total_hints = 0;
    for h_i in &signature.h {
        total_hints += poly_hint_count(h_i);
    }
    if total_hints > P::OMEGA {
        return false;
    }

    // Step 4: Use pre-computed μ (skip H(tr || M) computation)
    // μ is provided directly for internal interface tests

    // Step 5: Sample challenge polynomial c from signature
    let c = sample_in_ball(&signature.c_tilde, P::TAU);

    // Transform z and c to NTT domain
    let z_ntt: Vec<Poly> = signature.z.iter().map(|p| ntt(p)).collect();
    let c_ntt = ntt(&c);

    // Step 6: Compute w' = A·z - c·t1·2^d using NTT-domain operations
    let mut w_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        let mut acc_ntt = ntt_multiply(&pk.cached_a_ntt[i][0], &z_ntt[0]);
        for j in 1..P::L {
            let prod_ntt = ntt_multiply(&pk.cached_a_ntt[i][j], &z_ntt[j]);
            for k in 0..N {
                acc_ntt.coeffs[k] += prod_ntt.coeffs[k];
            }
        }

        let c_t1_ntt = ntt_multiply(&c_ntt, &pk.t1_scaled_ntt[i]);
        for k in 0..N {
            acc_ntt.coeffs[k] -= c_t1_ntt.coeffs[k];
        }

        for k in 0..N {
            acc_ntt.coeffs[k] = reduce32(acc_ntt.coeffs[k]);
        }

        let mut w_prime_i = inv_ntt(&acc_ntt);
        w_prime_i.reduce();
        w_prime.push(w_prime_i);
    }

    // Step 7: Apply hints to recover high bits w'₁
    let mut w1_prime = Vec::with_capacity(P::K);
    for i in 0..P::K {
        let w1_prime_i = use_hint_poly_optimized::<P>(&signature.h[i], &w_prime[i]);
        w1_prime.push(w1_prime_i);
    }

    // Step 8: Encode w'₁ and compute challenge c'
    let w1_prime_bytes = encode_w1::<P>(&w1_prime);
    let mut c_prime_input = Vec::with_capacity(64 + w1_prime_bytes.len());
    c_prime_input.extend_from_slice(mu);
    c_prime_input.extend_from_slice(&w1_prime_bytes);

    let c_prime_tilde = h_var(&c_prime_input, P::CTILDEBYTES);

    // Step 9: Compare challenges using constant-time comparison
    use crate::constant_time::ct_compare;
    let result = ct_compare(&c_prime_tilde, &signature.c_tilde);

    result == 1
}

/// Encode w1 vector to bytes using FIPS 204 SimpleBitPack
#[inline]
fn encode_w1<P: DsaParams>(w1: &[Poly]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::W1_ENCODED_SIZE);

    if P::W1_BITS == 4 {
        for poly in w1 {
            for chunk in poly.coeffs.chunks_exact(2) {
                let c0 = chunk[0] as u8 & 0x0F;
                let c1 = chunk[1] as u8 & 0x0F;
                bytes.push(c0 | (c1 << 4));
            }
        }
    } else if P::W1_BITS == 6 {
        for poly in w1 {
            for chunk in poly.coeffs.chunks_exact(4) {
                let c0 = chunk[0] as u8 & 0x3F;
                let c1 = chunk[1] as u8 & 0x3F;
                let c2 = chunk[2] as u8 & 0x3F;
                let c3 = chunk[3] as u8 & 0x3F;
                bytes.push(c0 | (c1 << 6));
                bytes.push((c1 >> 2) | (c2 << 4));
                bytes.push((c2 >> 4) | (c3 << 2));
            }
        }
    } else {
        unreachable!("Unsupported W1_BITS value");
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_from_seed;
    use crate::params::{MlDsa44, MlDsa65};
    use crate::sign::sign_deterministic;
    extern crate alloc;
    use alloc::vec;

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

        // ML-DSA-44: 6-bit packing, 4 polys * 256 coeffs * 6 bits / 8 = 768 bytes
        assert_eq!(encoded.len(), MlDsa44::W1_ENCODED_SIZE);
        assert_eq!(encoded.len(), 4 * 256 * 6 / 8); // 768
    }
}
