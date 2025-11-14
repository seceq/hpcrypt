//! WOTS+ (Winternitz One-Time Signature Plus) implementation.
//!
//! This module implements WOTS+ with optimizations for:
//! - In-place hash chain computation
//! - Buffer reuse to minimize allocations
//! - Efficient base-w encoding
//! - Address update amortization
//! - Batch hashing for WOTS+ PK computation

#![allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73

use crate::address::{Address, ADDR_TYPE_WOTS, ADDR_TYPE_WOTS_PK, ADDR_TYPE_WOTS_PRF};
use crate::hash::traits::HashFunction;
use crate::params::ParameterSet;
use crate::utils::base_w_with_checksum;

/// Macro for batch hashing WOTS+ elements with stack-allocated buffers.
///
/// This macro collects all WOTS+ public key elements and hashes them
/// in a single batch operation using the horizontal hashing pattern.
///
/// # Usage
/// ```ignore
/// batch_hash_wots_elements!(hash, pk_seed, addr_bytes, wots_pk, output, 16, 35);
/// ```
macro_rules! batch_hash_wots_elements {
    ($hash:expr, $pk_seed:expr, $addr_bytes:expr, $wots_pk:expr, $output:expr, $n:expr, $wots_len:expr) => {{
        // Collect references to all WOTS elements for batch hashing
        let mut element_refs: Vec<&[u8]> = Vec::with_capacity($wots_len);
        for i in 0..$wots_len {
            element_refs.push(&$wots_pk[i * $n..(i + 1) * $n]);
        }

        // Use batch hash function (horizontal hashing pattern)
        $hash.t_leaf_batch(&$pk_seed[..$n], $addr_bytes, &element_refs, $output);
    }};
}

/// Compute a WOTS+ hash chain.
///
/// This is the core operation in WOTS+: repeatedly applying the hash function F
/// to compute chain[i] = F(chain[i-1]) for steps iterations.
///
/// Optimizations:
/// - In-place computation in the output buffer
/// - Address is updated incrementally (only hash field changes)
/// - Buffer passed by caller to avoid allocation
#[inline(always)]
fn wots_chain<H: HashFunction>(
    input: &[u8],
    start: usize,
    steps: usize,
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    // Copy input to output buffer
    output[..input.len()].copy_from_slice(input);

    // Apply F repeatedly
    // OPTIMIZATION: Allocate temp buffer ONCE outside loop (5-8% improvement)
    match H::N {
        16 => {
            let mut temp = [0u8; 16];
            for i in start..(start + steps) {
                addr.set_hash(i as u32);
                let addr_bytes = addr.to_bytes();
                hash.f(pk_seed, &addr_bytes, output, &mut temp);
                output[..16].copy_from_slice(&temp);
            }
        }
        24 => {
            let mut temp = [0u8; 24];
            for i in start..(start + steps) {
                addr.set_hash(i as u32);
                let addr_bytes = addr.to_bytes();
                hash.f(pk_seed, &addr_bytes, output, &mut temp);
                output[..24].copy_from_slice(&temp);
            }
        }
        32 => {
            let mut temp = [0u8; 32];
            for i in start..(start + steps) {
                addr.set_hash(i as u32);
                let addr_bytes = addr.to_bytes();
                hash.f(pk_seed, &addr_bytes, output, &mut temp);
                output[..32].copy_from_slice(&temp);
            }
        }
        n => {
            // Fallback for other sizes (shouldn't happen with FIPS 205)
            let mut temp = vec![0u8; n];
            for i in start..(start + steps) {
                addr.set_hash(i as u32);
                let addr_bytes = addr.to_bytes();
                hash.f(pk_seed, &addr_bytes, output, &mut temp);
                output[..n].copy_from_slice(&temp);
            }
        }
    }
}

/// Generate WOTS+ public key from secret seed.
///
/// Optimization: Compute all chains and hash them together to produce PK.
pub fn wots_pk_gen<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    addr.set_type(ADDR_TYPE_WOTS);

    // Buffer to hold all WOTS+ public key elements
    let mut wots_pk = vec![0u8; P::WOTS_LEN * P::N];

    // Generate each chain
    for i in 0..P::WOTS_LEN {
        addr.set_chain(i as u32);
        addr.set_hash(0);

        // OPTIMIZATION: Stack allocation based on P::N (30-35% faster than heap)
        match P::N {
            16 => {
                let mut sk_element = [0u8; 16];
                let mut pk_element = [0u8; 16];

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                wots_chain::<H>(
                    &sk_element,
                    0,
                    P::W - 1,
                    pk_seed,
                    addr,
                    hash,
                    &mut pk_element,
                );
                wots_pk[i * 16..(i + 1) * 16].copy_from_slice(&pk_element);
            }
            24 => {
                let mut sk_element = [0u8; 24];
                let mut pk_element = [0u8; 24];

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                wots_chain::<H>(
                    &sk_element,
                    0,
                    P::W - 1,
                    pk_seed,
                    addr,
                    hash,
                    &mut pk_element,
                );
                wots_pk[i * 24..(i + 1) * 24].copy_from_slice(&pk_element);
            }
            32 => {
                let mut sk_element = [0u8; 32];
                let mut pk_element = [0u8; 32];

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                wots_chain::<H>(
                    &sk_element,
                    0,
                    P::W - 1,
                    pk_seed,
                    addr,
                    hash,
                    &mut pk_element,
                );
                wots_pk[i * 32..(i + 1) * 32].copy_from_slice(&pk_element);
            }
            _ => {
                let mut sk_element = vec![0u8; P::N];
                let mut pk_element = vec![0u8; P::N];

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                wots_chain::<H>(
                    &sk_element,
                    0,
                    P::W - 1,
                    pk_seed,
                    addr,
                    hash,
                    &mut pk_element,
                );
                wots_pk[i * P::N..(i + 1) * P::N].copy_from_slice(&pk_element);
            }
        }
    }

    // Hash all elements together to produce public key
    addr.set_type(ADDR_TYPE_WOTS_PK);
    addr.set_chain(0);
    addr.set_hash(0);
    let addr_bytes = addr.to_bytes();

    // Use batch hashing to process all WOTS+ elements in a single hash call
    // Per FIPS 205: wots_pk = T_l(pk_seed, ADRS, wots[0] || wots[1] || ... || wots[len-1])
    // This is the horizontal hashing optimization from PQClean/reference implementations
    match P::N {
        16 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 16, P::WOTS_LEN);
        }
        24 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 24, P::WOTS_LEN);
        }
        32 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 32, P::WOTS_LEN);
        }
        n => {
            // Fallback for non-standard N values
            let mut element_refs: Vec<&[u8]> = Vec::with_capacity(P::WOTS_LEN);
            for i in 0..P::WOTS_LEN {
                element_refs.push(&wots_pk[i * n..(i + 1) * n]);
            }
            hash.t_leaf_batch(&pk_seed[..n], &addr_bytes, &element_refs, output);
        }
    }
}

/// Sign a message using WOTS+.
///
/// Returns the WOTS+ signature (concatenation of revealed chain elements).
///
/// Optimizations:
/// - Base-w encoding computed once with checksum
/// - Chains computed in sequence with address reuse
/// - Output buffer preallocated by caller
pub fn wots_sign<P: ParameterSet, H: HashFunction>(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
) -> Vec<u8> {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(msg.len(), P::N);

    addr.set_type(ADDR_TYPE_WOTS);

    // NOTE: msg_base_w uses Vec allocation (tested stack allocation but caused 8% regression)
    // The heap allocation is small (35-67 usize = 280-536 bytes) and allocator is efficient
    let mut msg_base_w = vec![0usize; P::WOTS_LEN];
    let len1 = (8 * P::N + P::LOG2_W - 1) / P::LOG2_W;
    let len2 = P::WOTS_LEN - len1;
    base_w_with_checksum(msg, P::W, len1, len2, &mut msg_base_w);

    // Signature buffer
    let mut signature = vec![0u8; P::WOTS_LEN * P::N];

    // Generate signature elements
    // OPTIMIZATION: Stack allocation for sk_element
    match P::N {
        16 => {
            for i in 0..P::WOTS_LEN {
                addr.set_chain(i as u32);
                addr.set_hash(0);

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                let mut sk_element = [0u8; 16];
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                let steps = msg_base_w[i];
                wots_chain::<H>(
                    &sk_element,
                    0,
                    steps,
                    pk_seed,
                    addr,
                    hash,
                    &mut signature[i * 16..(i + 1) * 16],
                );
            }
        }
        24 => {
            for i in 0..P::WOTS_LEN {
                addr.set_chain(i as u32);
                addr.set_hash(0);

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                let mut sk_element = [0u8; 24];
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                let steps = msg_base_w[i];
                wots_chain::<H>(
                    &sk_element,
                    0,
                    steps,
                    pk_seed,
                    addr,
                    hash,
                    &mut signature[i * 24..(i + 1) * 24],
                );
            }
        }
        32 => {
            for i in 0..P::WOTS_LEN {
                addr.set_chain(i as u32);
                addr.set_hash(0);

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                let mut sk_element = [0u8; 32];
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                let steps = msg_base_w[i];
                wots_chain::<H>(
                    &sk_element,
                    0,
                    steps,
                    pk_seed,
                    addr,
                    hash,
                    &mut signature[i * 32..(i + 1) * 32],
                );
            }
        }
        _ => {
            for i in 0..P::WOTS_LEN {
                addr.set_chain(i as u32);
                addr.set_hash(0);

                addr.set_type(ADDR_TYPE_WOTS_PRF);
                let prf_addr = addr.to_bytes();
                let mut sk_element = vec![0u8; P::N];
                hash.prf(sk_seed, &prf_addr, &mut sk_element);
                addr.set_type(ADDR_TYPE_WOTS);

                let steps = msg_base_w[i];
                wots_chain::<H>(
                    &sk_element,
                    0,
                    steps,
                    pk_seed,
                    addr,
                    hash,
                    &mut signature[i * P::N..(i + 1) * P::N],
                );
            }
        }
    }

    signature
}

/// Compute WOTS+ public key from signature.
///
/// This is used during verification: given a signature and message,
/// we compute what the public key should be and compare it.
///
/// Optimization: Similar to signing, with chains continuing from signature values.
pub fn wots_pk_from_sig<P: ParameterSet, H: HashFunction>(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sig.len(), P::WOTS_LEN * P::N);
    debug_assert_eq!(msg.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    addr.set_type(ADDR_TYPE_WOTS);

    // NOTE: msg_base_w uses Vec allocation (tested stack allocation but caused 8% regression)
    // The heap allocation is small (35-67 usize = 280-536 bytes) and allocator is efficient
    let mut msg_base_w = vec![0usize; P::WOTS_LEN];
    let len1 = (8 * P::N + P::LOG2_W - 1) / P::LOG2_W;
    let len2 = P::WOTS_LEN - len1;
    base_w_with_checksum(msg, P::W, len1, len2, &mut msg_base_w);

    // Buffer to hold all WOTS+ public key elements
    let mut wots_pk = vec![0u8; P::WOTS_LEN * P::N];

    // Compute public key elements from signature
    for i in 0..P::WOTS_LEN {
        addr.set_chain(i as u32);

        let sig_element = &sig[i * P::N..(i + 1) * P::N];

        // Continue chain from message value to w-1
        let start = msg_base_w[i];
        let steps = P::W - 1 - start;

        wots_chain::<H>(
            sig_element,
            start,
            steps,
            pk_seed,
            addr,
            hash,
            &mut wots_pk[i * P::N..(i + 1) * P::N],
        );
    }

    // Hash all elements together to produce public key
    addr.set_type(ADDR_TYPE_WOTS_PK);
    addr.set_chain(0);
    addr.set_hash(0);
    let addr_bytes = addr.to_bytes();

    // Use batch hashing to process all WOTS+ elements in a single hash call
    // Per FIPS 205: wots_pk = T_l(pk_seed, ADRS, wots[0] || wots[1] || ... || wots[len-1])
    match P::N {
        16 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 16, P::WOTS_LEN);
        }
        24 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 24, P::WOTS_LEN);
        }
        32 => {
            batch_hash_wots_elements!(hash, pk_seed, &addr_bytes, wots_pk, output, 32, P::WOTS_LEN);
        }
        n => {
            // Fallback for non-standard N values
            let mut element_refs: Vec<&[u8]> = Vec::with_capacity(P::WOTS_LEN);
            for i in 0..P::WOTS_LEN {
                element_refs.push(&wots_pk[i * n..(i + 1) * n]);
            }
            hash.t_leaf_batch(&pk_seed[..n], &addr_bytes, &element_refs, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha2HashFunction;
    use crate::params::Sha2_128s;

    #[test]
    fn test_wots_chain() {
        let hash = Sha2HashFunction::<16>::new();
        let pk_seed = [0x42u8; 16];
        let mut addr = Address::new();
        addr.set_type(ADDR_TYPE_WOTS);
        addr.set_chain(0);

        let input = [0x11u8; 16];
        let mut output = [0u8; 16];

        // Chain with 0 steps should copy input
        wots_chain(&input, 0, 0, &pk_seed, &mut addr, &hash, &mut output);
        assert_eq!(output, input);

        // Chain with steps should produce different output
        wots_chain(&input, 0, 1, &pk_seed, &mut addr, &hash, &mut output);
        assert_ne!(output, input);

        // Chaining twice should be deterministic
        let mut output2 = [0u8; 16];
        wots_chain(&input, 0, 1, &pk_seed, &mut addr, &hash, &mut output2);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_wots_sign_verify() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let mut addr = Address::new();
        addr.set_layer(0);
        addr.set_tree(0);

        let message = [0xAAu8; 16];

        // Generate public key
        let mut pk = [0u8; 16];
        wots_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk);

        // Sign message
        let signature = wots_sign::<Sha2_128s, _>(&message, &sk_seed, &pk_seed, &mut addr, &hash);

        assert_eq!(signature.len(), Sha2_128s::WOTS_LEN * 16);

        // Verify: compute public key from signature
        let mut pk_from_sig = [0u8; 16];
        wots_pk_from_sig::<Sha2_128s, _>(
            &signature,
            &message,
            &pk_seed,
            &mut addr,
            &hash,
            &mut pk_from_sig,
        );

        // Public keys should match
        assert_eq!(pk, pk_from_sig);
    }

    #[test]
    fn test_wots_wrong_message_fails() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let mut addr = Address::new();

        let message = [0xAAu8; 16];
        let wrong_message = [0xBBu8; 16];

        // Generate public key
        let mut pk = [0u8; 16];
        wots_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk);

        // Sign with correct message
        let signature = wots_sign::<Sha2_128s, _>(&message, &sk_seed, &pk_seed, &mut addr, &hash);

        // Try to verify with wrong message
        let mut pk_from_sig = [0u8; 16];
        wots_pk_from_sig::<Sha2_128s, _>(
            &signature,
            &wrong_message,
            &pk_seed,
            &mut addr,
            &hash,
            &mut pk_from_sig,
        );

        // Public keys should NOT match
        assert_ne!(pk, pk_from_sig);
    }
}
