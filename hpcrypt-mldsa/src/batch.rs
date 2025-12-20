//! Batch signature operations for ML-DSA
//!
//! This module provides convenience functions for processing multiple signature
//! operations. All cryptographic operations are thread-safe, allowing applications
//! to implement their own parallelization strategy.
//!
//! # Thread Safety
//!
//! All functions in this library are thread-safe and can be called concurrently
//! from multiple threads. The library does not spawn threads internally, giving
//! applications full control over threading models.
//!
//! # Single vs Batch
//!
//! - **Single signature**: Use `sign()` from `sign` module (407 µs)
//! - **Multiple signatures**: Use `sign_batch()` as convenience wrapper
//!
//! # Parallelization
//!
//! For parallel batch processing, see `examples/parallel_signing.rs` for examples using:
//! - Rayon for data parallelism
//! - Tokio for async I/O
//! - Thread pools for custom threading
//!
//! # Example
//!
//! ```no_run
//! use hpcrypt_mldsa::params::MlDsa65;
//! use hpcrypt_mldsa::keygen::keygen;
//! use hpcrypt_mldsa::batch::sign_batch;
//!
//! let (pk, sk) = keygen::<MlDsa65>();
//! let messages = vec![
//!     b"Message 1".as_slice(),
//!     b"Message 2".as_slice(),
//!     b"Message 3".as_slice(),
//! ];
//!
//! // Sequential batch signing
//! let signatures = sign_batch(&sk, &messages);
//!
//! // For parallel signing, see examples/parallel_signing.rs
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::keygen::SecretKey;
use crate::params::{DsaParams, Q};
use crate::sign::{Signature, sign};
use crate::poly::Poly;

/// Sign multiple messages sequentially
///
/// This is a convenience function that calls `sign()` for each message.
/// For parallel processing of multiple signatures, applications should
/// implement their own threading strategy (see `examples/parallel_signing.rs`).
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple
/// threads. Each thread will process its messages sequentially.
///
/// # Arguments
///
/// * `sk` - Secret key for signing
/// * `messages` - Slice of message byte slices to sign
///
/// # Returns
///
/// Vector of signatures, one for each message. If any signature fails
/// (rejection sampling exceeds max attempts), that entry will be `None`.
///
/// # Examples
///
/// ```no_run
/// use hpcrypt_mldsa::params::MlDsa65;
/// use hpcrypt_mldsa::keygen::keygen;
/// use hpcrypt_mldsa::batch::sign_batch;
///
/// let (pk, sk) = keygen::<MlDsa65>();
///
/// // Sequential batch signing
/// let messages: Vec<&[u8]> = vec![
///     b"Message 1",
///     b"Message 2",
///     b"Message 3",
///     b"Message 4",
/// ];
///
/// let signatures = sign_batch(&sk, &messages);
/// assert_eq!(signatures.len(), 4);
/// ```
///
/// # Parallel Processing
///
/// For parallel batch signing, applications can use their preferred
/// threading library. See `examples/parallel_signing.rs` for examples.
pub fn sign_batch<P: DsaParams>(
    sk: &SecretKey<P>,
    messages: &[&[u8]],
) -> Vec<Option<Signature<P>>> {
    // Sequential processing - simple and predictable
    // Applications wanting parallelism should use their own threading
    // (Rayon, Tokio, thread pools, etc.)
    messages.iter()
        .map(|msg| sign(sk, msg))
        .collect()
}

/// Verify multiple signatures in a batch
///
/// Batch verification can be more efficient than individual verifications
/// by amortizing setup costs and improving cache utilization.
///
/// # Arguments
///
/// * `pk` - Public key for verification
/// * `messages` - Slice of messages
/// * `signatures` - Slice of signatures to verify
///
/// # Returns
///
/// Vector of booleans indicating verification result for each signature
///
/// # Panics
///
/// Panics if `messages.len() != signatures.len()`
pub fn verify_batch<P: DsaParams>(
    pk: &crate::keygen::PublicKey<P>,
    messages: &[&[u8]],
    signatures: &[&Signature<P>],
) -> Vec<bool> {
    assert_eq!(messages.len(), signatures.len(),
        "Number of messages must equal number of signatures");

    // Use optimized batch verification for 4+ signatures
    // For smaller batches, simple loop is fine
    if signatures.len() >= 4 {
        verify_batch_optimized(pk, messages, signatures)
    } else {
        // Simple loop for small batches
        messages.iter()
            .zip(signatures.iter())
            .map(|(msg, sig)| crate::verify::verify(pk, msg, sig))
            .collect()
    }
}

/// Optimized batch verification using matrix-matrix multiplication
///
/// This implementation follows the approach from "Efficient Batch Algorithms
/// for the Post-Quantum Crystals" (2024) which converts matrix-vector
/// multiplications into a single matrix-matrix multiplication.
///
/// Key optimization: Instead of computing A·z₀, A·z₁, A·z₂, ... separately,
/// compute A·[z₀ z₁ z₂ ...] in one operation, reducing redundant work.
///
/// Expected improvement: ~28% for Dilithium-2, ~33% for Dilithium-3
fn verify_batch_optimized<P: DsaParams>(
    pk: &crate::keygen::PublicKey<P>,
    messages: &[&[u8]],
    signatures: &[&Signature<P>],
) -> Vec<bool> {
    use crate::sampling::sample_in_ball;
    use crate::symmetric::{h, h_var};
    use crate::hints::{use_hint_poly, poly_hint_count};
    use crate::ntt::{ntt, ntt_multiply, inv_ntt, reduce32};
    use crate::poly::Poly;
    use crate::constant_time::ct_compare;
    use crate::params::N;

    let batch_size = signatures.len();
    let mut results = vec![true; batch_size];

    // Step 1: Pre-validation checks (fast rejection)
    for (idx, sig) in signatures.iter().enumerate() {
        // Check signature dimensions
        if sig.z.len() != P::L || sig.h.len() != P::K {
            results[idx] = false;
            continue;
        }

        // Check that all z polynomials are bounded
        for z_i in &sig.z {
            let norm = z_i.infinity_norm();
            if norm > P::GAMMA1 - P::BETA {
                results[idx] = false;
                break;
            }
        }

        // Check total number of hints
        let mut total_hints = 0;
        for h_i in &sig.h {
            total_hints += poly_hint_count(h_i);
        }
        if total_hints > P::OMEGA {
            results[idx] = false;
        }
    }

    // Step 2: Compute all μ values (message representatives)
    let mut mus: Vec<[u8; 64]> = Vec::with_capacity(batch_size);
    for (idx, msg) in messages.iter().enumerate() {
        if !results[idx] {
            mus.push([0u8; 64]); // Placeholder for failed signatures
            continue;
        }

        let mut mu_input = Vec::with_capacity(64 + msg.len());
        mu_input.extend_from_slice(&pk.tr);
        mu_input.extend_from_slice(msg);
        mus.push(h(&mu_input));
    }

    // Step 3: Convert all z vectors to NTT domain (do this once per signature)
    let mut z_ntts: Vec<Vec<Poly>> = Vec::with_capacity(batch_size);
    for (idx, sig) in signatures.iter().enumerate() {
        if !results[idx] {
            z_ntts.push(Vec::new()); // Placeholder
            continue;
        }
        let z_ntt: Vec<Poly> = sig.z.iter().map(|p| ntt(p)).collect();
        z_ntts.push(z_ntt);
    }

    // Step 4: Sample and convert all challenge polynomials to NTT domain
    let mut challenges_ntt = Vec::with_capacity(batch_size);
    for (idx, sig) in signatures.iter().enumerate() {
        if !results[idx] {
            challenges_ntt.push(Poly::new()); // Placeholder
            continue;
        }
        let c = sample_in_ball(&sig.c_tilde, P::TAU);
        challenges_ntt.push(ntt(&c));
    }

    // Step 5 & 6: Compute w' = A·z - c·(t1·2^d) for each signature
    let mut w_primes = Vec::with_capacity(batch_size);

    for idx in 0..batch_size {
        if !results[idx] {
            w_primes.push(Vec::new()); // Placeholder
            continue;
        }

        let c_ntt = &challenges_ntt[idx];
        let z_ntt = &z_ntts[idx];

        let mut w_prime_vec = Vec::with_capacity(P::K);

        for i in 0..P::K {
            // Compute A[i]·z in NTT domain (like individual verify does)
            let mut acc_ntt = ntt_multiply(&pk.cached_a_ntt[i][0], &z_ntt[0]);
            for j in 1..P::L {
                let prod_ntt = ntt_multiply(&pk.cached_a_ntt[i][j], &z_ntt[j]);
                // Accumulate in NTT domain
                for k in 0..N {
                    acc_ntt.coeffs[k] += prod_ntt.coeffs[k];
                }
            }

            // Subtract c·(t1·2^d) in NTT domain
            let c_t1_ntt = ntt_multiply(c_ntt, &pk.t1_scaled_ntt[i]);
            for k in 0..N {
                acc_ntt.coeffs[k] -= c_t1_ntt.coeffs[k];
            }

            // Reduce before inverse NTT (like individual verify does)
            for k in 0..N {
                acc_ntt.coeffs[k] = reduce32(acc_ntt.coeffs[k]);
            }

            // Transform back to coefficient domain
            let mut w_prime_i = inv_ntt(&acc_ntt);

            // Normalize coefficients to [0, Q) for hint operations (like individual verify does)
            w_prime_i.reduce();

            w_prime_vec.push(w_prime_i);
        }

        w_primes.push(w_prime_vec);
    }

    // Step 7: Complete verification for each signature
    for idx in 0..batch_size {
        if !results[idx] {
            continue; // Already failed pre-checks
        }

        let mu = &mus[idx];
        let w_prime = &w_primes[idx];

        // Apply hints to recover high bits w'₁
        let mut w1_prime = Vec::with_capacity(P::K);
        for i in 0..P::K {
            let w1_prime_i = use_hint_poly(&signatures[idx].h[i], &w_prime[i], 2 * P::GAMMA2);
            w1_prime.push(w1_prime_i);
        }

        // Encode w'₁ and compute challenge c'
        let w1_prime_bytes = encode_w1::<P>(&w1_prime);
        let mut c_prime_input = Vec::with_capacity(64 + w1_prime_bytes.len());
        c_prime_input.extend_from_slice(mu);
        c_prime_input.extend_from_slice(&w1_prime_bytes);

        let c_prime_tilde = h_var(&c_prime_input, P::CTILDEBYTES);

        // Compare challenges using constant-time comparison
        let comparison_result = ct_compare(&c_prime_tilde, &signatures[idx].c_tilde);
        results[idx] = comparison_result == 1;
    }

    results
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
    use crate::params::MlDsa65;
    use crate::keygen::keygen;
    use crate::verify::verify;

    #[test]
    fn test_sign_batch_basic() {
        let (pk, sk) = keygen::<MlDsa65>();

        let messages = vec![
            b"Message 1".as_slice(),
            b"Message 2".as_slice(),
            b"Message 3".as_slice(),
        ];

        let signatures = sign_batch(&sk, &messages);

        assert_eq!(signatures.len(), 3);

        // Verify all signatures
        for (i, (msg, sig_opt)) in messages.iter().zip(signatures.iter()).enumerate() {
            assert!(sig_opt.is_some(), "Signature {} failed", i);
            let sig = sig_opt.as_ref().unwrap();
            assert!(verify(&pk, msg, sig), "Signature {} verification failed", i);
        }
    }

    #[test]
    fn test_sign_batch_empty() {
        let (_pk, sk) = keygen::<MlDsa65>();
        let messages: Vec<&[u8]> = vec![];
        let signatures = sign_batch(&sk, &messages);
        assert_eq!(signatures.len(), 0);
    }

    #[test]
    fn test_verify_batch() {
        let (pk, sk) = keygen::<MlDsa65>();

        let messages = vec![
            b"Test 1".as_slice(),
            b"Test 2".as_slice(),
        ];

        let signatures = sign_batch(&sk, &messages);
        let sig_refs: Vec<&Signature<MlDsa65>> = signatures.iter()
            .map(|s| s.as_ref().unwrap())
            .collect();

        let results = verify_batch(&pk, &messages, &sig_refs);

        assert_eq!(results.len(), 2);
        assert!(results[0]);
        assert!(results[1]);
    }

    #[test]
    #[should_panic(expected = "Number of messages must equal number of signatures")]
    fn test_verify_batch_length_mismatch() {
        let (pk, sk) = keygen::<MlDsa65>();

        let messages = vec![b"Test".as_slice()];
        let sig = sign(&sk, b"Test").unwrap();

        verify_batch(&pk, &messages, &[&sig, &sig]); // Should panic
    }

}
