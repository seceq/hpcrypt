//! FORS (Forest of Random Subsets) implementation.
//!
//! This module implements FORS with optimizations for:
//! - On-demand leaf generation (no full tree storage)
//! - Efficient message-to-indices conversion using bit extraction
//! - Minimal memory footprint
//! - Address update amortization when generating multiple leaves
//! - Batch hashing for FORS root computation

use crate::address::{Address, ADDR_TYPE_FORS_TREE, ADDR_TYPE_FORS_PRF, ADDR_TYPE_FORS_ROOTS};
use crate::hash::traits::HashFunction;
use crate::params::ParameterSet;

/// Macro for batch hashing FORS roots with stack-allocated buffers.
///
/// This macro generates unrolled code for collecting root references
/// and calling the batch hash function, avoiding heap allocations.
///
/// # Usage
/// ```ignore
/// batch_hash_fors_roots!(hash, pk_seed, addr_bytes, roots, pk, 16);
/// ```
macro_rules! batch_hash_fors_roots {
    ($hash:expr, $pk_seed:expr, $addr_bytes:expr, $roots:expr, $pk:expr, $n:expr) => {{
        // Collect references to roots for batch hashing
        let root_refs: Vec<&[u8]> = $roots.iter().map(|r| r.as_slice()).collect();

        // Use batch hash function (horizontal hashing pattern)
        $hash.t_leaf_batch(&$pk_seed[..$n], $addr_bytes, &root_refs, $pk);
    }};
}

/// Generate a FORS secret key element (leaf).
///
/// This uses PRF to derive the secret key element from the seed.
#[inline(always)]
fn fors_sk_gen<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    tree_idx: usize,
    leaf_idx: usize,
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    // Per FIPS 205: Save keypair address before setTypeAndClear (which clears it)
    let keypair = addr.keypair();

    // Per FIPS 205: ADRS.setTypeAndClear(FORS_PRF)
    addr.set_type_and_clear(ADDR_TYPE_FORS_PRF);
    // Restore keypair address (per reference implementation)
    addr.set_keypair(keypair);
    addr.set_tree_index((tree_idx * (1 << P::A) + leaf_idx) as u32);

    let addr_bytes = addr.to_bytes();
    hash.prf(pk_seed, sk_seed, &addr_bytes, output);
}

/// Convert FORS message to tree indices per SPHINCS+/SLH-DSA reference.
///
/// Extracts k indices of A bits each from the message using bit-level extraction.
/// Extract indices from FORS message per FIPS 205 Algorithm 14.
///
/// Per FIPS 205 Section 5.1: "bits(X, s, n)" extracts n consecutive bits starting at
/// index s, where bit index 0 is the MSB of byte 0.
fn message_to_indices<P: ParameterSet>(msg: &[u8]) -> Vec<usize> {
    let mut indices = Vec::with_capacity(P::K);
    let mut offset = 0;

    for _ in 0..P::K {
        let mut idx: usize = 0;
        for j in 0..P::A {
            // Extract bit at position `offset` from message
            // Per FIPS 205 Section 5.1: bit 0 is MSB of byte 0, bit 8 is MSB of byte 1, etc.
            let byte_idx = offset >> 3;
            let bit_pos = offset & 7;
            // MSB-first: bit_pos=0 means bit 7 (MSB), bit_pos=7 means bit 0 (LSB)
            let bit = ((msg[byte_idx] >> (7 - bit_pos)) & 1) as usize;
            // Per FIPS 205: first extracted bit is MSB of result index
            idx |= bit << (P::A - 1 - j);
            offset += 1;
        }
        indices.push(idx);
    }

    indices
}

/// Compute a FORS tree node at given index and height.
///
/// This is the recursive fors_node function per FIPS 205 Algorithm 16.
/// For height 0 (leaves), generates SK and applies F.
/// For height > 0, recursively computes children and applies H.
///
/// Parameters:
/// - tree_idx: which FORS tree (0 to K-1)
/// - node_idx: the node index at the given height
/// - height: node height (0 = leaf, A = root)
#[allow(clippy::too_many_arguments)]
fn fors_node<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    tree_idx: usize,
    node_idx: usize,
    height: usize,
    keypair: u32,
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    // Per FIPS 205 Algorithm 14/16: tree_index = i * 2^(a-z) + node_idx
    // where i is tree_idx (0 to K-1), a is FORS tree height (P::A), z is node height
    // This encodes both which FORS tree and the position within the tree
    let tree_index_base = tree_idx * (1 << (P::A - height));

    if height == 0 {
        // Leaf node: generate SK and apply F
        let leaf_idx = node_idx;
        let mut sk = vec![0u8; P::N];
        fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx, addr, hash, &mut sk);

        addr.set_type_and_clear(ADDR_TYPE_FORS_TREE);
        addr.set_keypair(keypair);
        addr.set_tree_height(0);
        addr.set_tree_index((tree_index_base + leaf_idx) as u32);
        let addr_bytes = addr.to_bytes();
        hash.t_leaf(pk_seed, &addr_bytes, &sk, output);
    } else {
        // Internal node: recursively compute children
        let mut left = vec![0u8; P::N];
        let mut right = vec![0u8; P::N];

        // Left child at index 2*node_idx, height-1
        fors_node::<P, H>(sk_seed, pk_seed, tree_idx, 2 * node_idx, height - 1, keypair, addr, hash, &mut left);
        // Right child at index 2*node_idx + 1, height-1
        fors_node::<P, H>(sk_seed, pk_seed, tree_idx, 2 * node_idx + 1, height - 1, keypair, addr, hash, &mut right);

        addr.set_type_and_clear(ADDR_TYPE_FORS_TREE);
        addr.set_keypair(keypair);
        addr.set_tree_height(height as u32);
        addr.set_tree_index((tree_index_base + node_idx) as u32);
        let addr_bytes = addr.to_bytes();
        hash.t_node(pk_seed, &addr_bytes, &left, &right, output);
    }
}

/// FORS signing implementation per FIPS 205 Algorithm 14.
///
/// Uses the recursive fors_node function for computing authentication paths.
#[inline]
#[allow(clippy::too_many_arguments)]
fn fors_sign_impl<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    indices: &[usize],
    keypair: u32,
    addr: &mut Address,
    hash: &H,
    signature: &mut Vec<u8>,
    roots: &mut Vec<Vec<u8>>,
) {
    for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
        // Step 1: Generate and output SK value for this leaf
        let mut sk = vec![0u8; P::N];
        fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx, addr, hash, &mut sk);
        signature.extend_from_slice(&sk);

        // Step 2: Compute authentication path
        // Per FIPS 205 Algorithm 14:
        // for j from 0 to a-1:
        //   s = (idx / 2^j) XOR 1  (sibling node index at height j)
        //   AUTH[j] = fors_node(SK.seed, s, j, PK.seed, ADRS)
        for j in 0..P::A {
            // s = (leaf_idx >> j) ^ 1 gives the sibling node index at height j
            let s = (leaf_idx >> j) ^ 1;
            let mut auth_node = vec![0u8; P::N];
            fors_node::<P, H>(sk_seed, pk_seed, tree_idx, s, j, keypair, addr, hash, &mut auth_node);
            signature.extend_from_slice(&auth_node);
        }

        // Step 3: Compute tree root for public key computation
        // Root is fors_node at index 0, height A
        let mut root = vec![0u8; P::N];
        fors_node::<P, H>(sk_seed, pk_seed, tree_idx, 0, P::A, keypair, addr, hash, &mut root);
        roots.push(root);
    }
}

/// Sign a message using FORS.
///
/// Returns the FORS signature which consists of:
/// - For each of k trees: the secret key element and its authentication path
///
/// The FORS public key (root of all tree roots) is also computed.
pub fn fors_sign<P: ParameterSet, H: HashFunction>(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
) -> (Vec<u8>, Vec<u8>) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(msg.len(), P::FORS_MSG_BYTES);

    // Convert message to indices
    let indices = message_to_indices::<P>(msg);
    debug_assert_eq!(indices.len(), P::K);

    // Save keypair address before operations that clear it
    let keypair = addr.keypair();

    // Signature buffer
    let mut signature = Vec::with_capacity(P::K * (P::A + 1) * P::N);

    // Roots of all k trees
    let mut roots = Vec::with_capacity(P::K);

    // Use the spec-compliant implementation with fors_node
    fors_sign_impl::<P, H>(sk_seed, pk_seed, &indices, keypair, addr, hash, &mut signature, &mut roots);

    // Compute FORS public key from all roots
    // Per FIPS 205: fors_pk = T_l(pk_seed, ADRS, root[0] || root[1] || ... || root[k-1])
    addr.set_type_and_clear(ADDR_TYPE_FORS_ROOTS);
    addr.set_keypair(keypair);  // Restore keypair
    addr.set_tree_height(0);
    addr.set_tree_index(0);
    let addr_bytes = addr.to_bytes();

    // Use batch hashing to process all FORS roots in a single hash call
    // This is the horizontal hashing optimization from PQClean/reference implementations
    let mut pk = vec![0u8; P::N];
    match P::N {
        16 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, &mut pk, 16);
        }
        24 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, &mut pk, 24);
        }
        32 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, &mut pk, 32);
        }
        n => {
            // Fallback for non-standard N values
            let root_refs: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
            hash.t_leaf_batch(&pk_seed[..n], &addr_bytes, &root_refs, &mut pk);
        }
    }

    (signature, pk)
}

/// Compute FORS public key from signature.
///
/// This is used during verification: given a signature and message,
/// recompute the public key and compare.
///
/// Optimization: Similar to signing, computed on-demand.
pub fn fors_pk_from_sig<P: ParameterSet, H: HashFunction>(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sig.len(), P::K * (P::A + 1) * P::N);
    debug_assert_eq!(msg.len(), P::FORS_MSG_BYTES);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    let indices = message_to_indices::<P>(msg);

    // FORS tree base offset: tree_idx * 2^A (per FIPS 205 Algorithm 15)
    let t = 1 << P::A;

    // Save keypair address before operations that clear it
    let keypair = addr.keypair();

    let mut roots = Vec::with_capacity(P::K);
    let mut sig_offset = 0;

    for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
        // Extract secret key element from signature
        let sk_element = &sig[sig_offset..sig_offset + P::N];
        sig_offset += P::N;

        // Apply T_l to get leaf node
        // Per FIPS 205: tree_index = i * 2^a + idx
        addr.set_type_and_clear(ADDR_TYPE_FORS_TREE);
        addr.set_keypair(keypair);  // Restore keypair (per reference implementation)
        addr.set_tree_height(0);
        addr.set_tree_index((tree_idx * t + leaf_idx) as u32);
        let addr_bytes = addr.to_bytes();

        let mut node = vec![0u8; P::N];
        hash.t_leaf(pk_seed, &addr_bytes, sk_element, &mut node);

        // Process authentication path
        let mut idx = leaf_idx;
        for height in 0..P::A {
            let sibling = &sig[sig_offset..sig_offset + P::N];
            sig_offset += P::N;

            // Per FIPS 205: tree_index = floor((i * 2^a + idx) / 2^(j+1))
            addr.set_tree_height((height + 1) as u32);
            addr.set_tree_index(((tree_idx * t + leaf_idx) >> (height + 1)) as u32);
            let addr_bytes = addr.to_bytes();

            let mut parent = vec![0u8; P::N];
            if idx % 2 == 0 {
                hash.t_node(pk_seed, &addr_bytes, &node, sibling, &mut parent);
            } else {
                hash.t_node(pk_seed, &addr_bytes, sibling, &node, &mut parent);
            }

            node = parent;
            idx >>= 1;
        }

        roots.push(node);
    }

    // Compute FORS public key from all roots
    // Per FIPS 205: fors_pk = T_l(pk_seed, ADRS, root[0] || root[1] || ... || root[k-1])
    addr.set_type_and_clear(ADDR_TYPE_FORS_ROOTS);
    addr.set_keypair(keypair);  // Restore keypair (per reference implementation)
    addr.set_tree_height(0);
    addr.set_tree_index(0);
    let addr_bytes = addr.to_bytes();

    // Use batch hashing to process all FORS roots in a single hash call
    match P::N {
        16 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, output, 16);
        }
        24 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, output, 24);
        }
        32 => {
            batch_hash_fors_roots!(hash, pk_seed, &addr_bytes, roots, output, 32);
        }
        n => {
            // Fallback for non-standard N values
            let root_refs: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
            hash.t_leaf_batch(&pk_seed[..n], &addr_bytes, &root_refs, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha2HashFunction;
    use crate::params::Sha2_128s;

    #[test]
    fn test_message_to_indices() {
        // For Sha2_128s: K=14, A=6 (6 bits per index)
        // FORS_MSG_BYTES = ceil(14*6/8) = ceil(84/8) = 11 bytes
        let msg = [
            0b11010110, 0b10110011, 0b11110000, 0b10101010, 0b11001100,
            0b00110011, 0b11110000, 0b10101010, 0b11001100, 0b00110011,
            0b11110000,
        ];

        let indices = message_to_indices::<Sha2_128s>(&msg);

        assert_eq!(indices.len(), 14);

        // Each index should be less than 2^6 = 64
        for &idx in &indices {
            assert!(idx < 64);
        }
    }

    #[test]
    fn test_fors_sign_verify() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let mut addr = Address::new();
        addr.set_layer(0);
        addr.set_tree(0);

        // Message to sign (FORS_MSG_BYTES for Sha2_128s)
        let message = [0xAAu8; Sha2_128s::FORS_MSG_BYTES];

        // Sign
        let (signature, pk) = fors_sign::<Sha2_128s, _>(&message, &sk_seed, &pk_seed, &mut addr, &hash);

        // Signature should have correct size
        assert_eq!(signature.len(), Sha2_128s::K * (Sha2_128s::A + 1) * 16);
        assert_eq!(pk.len(), 16);

        // Verify: recompute public key from signature
        let mut pk_from_sig = [0u8; 16];
        fors_pk_from_sig::<Sha2_128s, _>(
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
    fn test_fors_wrong_message_fails() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let mut addr = Address::new();

        let message = [0xAAu8; Sha2_128s::FORS_MSG_BYTES];
        let wrong_message = [0xBBu8; Sha2_128s::FORS_MSG_BYTES];

        // Sign with correct message
        let (signature, pk) = fors_sign::<Sha2_128s, _>(&message, &sk_seed, &pk_seed, &mut addr, &hash);

        // Try to verify with wrong message
        let mut pk_from_sig = [0u8; 16];
        fors_pk_from_sig::<Sha2_128s, _>(
            &signature,
            &wrong_message,
            &pk_seed,
            &mut addr,
            &hash,
            &mut pk_from_sig,
        );

        // Public keys should NOT match
        assert_ne!(pk.as_slice(), &pk_from_sig);
    }
}
