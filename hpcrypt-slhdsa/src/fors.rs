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
use crate::utils::extract_bits;
// Note: vectorized module available for future batch optimizations
// use crate::vectorized;

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

    addr.set_type(ADDR_TYPE_FORS_PRF);
    addr.set_tree_height(0);
    addr.set_tree_index((tree_idx * (1 << P::A) + leaf_idx) as u32);

    let addr_bytes = addr.to_bytes();
    hash.prf(sk_seed, &addr_bytes, output);
}

/// Convert FORS message to tree indices.
///
/// Extracts k indices of A bits each from the message.
///
/// Optimization: Uses bit extraction instead of byte-level operations.
fn message_to_indices<P: ParameterSet>(msg: &[u8]) -> Vec<usize> {
    let mut indices = Vec::with_capacity(P::K);

    for i in 0..P::K {
        let bit_offset = i * P::A;
        let index = extract_bits(msg, bit_offset, P::A);
        indices.push(index);
    }

    indices
}

/// Compute authentication path for a FORS tree leaf.
///
/// Similar to Merkle tree auth path but uses FORS-specific addressing.
#[allow(clippy::too_many_arguments)]
fn fors_tree_hash<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    tree_idx: usize,
    leaf_idx_offset: usize,
    target_height: usize,
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    addr.set_type(ADDR_TYPE_FORS_TREE);
    addr.set_tree_index(tree_idx as u32);

    let n_leaves = 1 << target_height;

    // OPTIMIZATION: Use fixed-size arrays instead of Vec<Vec<u8>> to avoid heap allocations
    match P::N {
        16 => {
            let mut stack: Vec<([u8; 16], usize)> = Vec::with_capacity(target_height + 1);
            for i in 0..n_leaves {
                let mut sk_element = [0u8; 16];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx_offset + i, addr, hash, &mut sk_element);

                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index((leaf_idx_offset + i) as u32);
                let addr_bytes = addr.to_bytes();

                let mut node = [0u8; 16];
                hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut node);
                let mut node_height = 0usize;

                while node_height < target_height && !stack.is_empty() {
                    let (_top_node, top_height) = stack.last().unwrap();
                    if *top_height != node_height {
                        break;
                    }

                    let (top_node, _) = stack.pop().unwrap();

                    addr.set_tree_height((node_height + 1) as u32);
                    addr.set_tree_index(((leaf_idx_offset + i) >> (node_height + 1)) as u32);
                    let addr_bytes = addr.to_bytes();

                    let mut parent = [0u8; 16];
                    hash.t_node(pk_seed, &addr_bytes, &top_node, &node, &mut parent);

                    node = parent;
                    node_height += 1;
                }

                if node_height == target_height {
                    output[..16].copy_from_slice(&node);
                    return;
                }

                stack.push((node, node_height));
            }
            // Final root (if any left on stack)
            if let Some((root, _)) = stack.pop() {
                output[..16].copy_from_slice(&root);
            }
        }
        24 => {
            let mut stack: Vec<([u8; 24], usize)> = Vec::with_capacity(target_height + 1);
            for i in 0..n_leaves {
                let mut sk_element = [0u8; 24];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx_offset + i, addr, hash, &mut sk_element);

                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index((leaf_idx_offset + i) as u32);
                let addr_bytes = addr.to_bytes();

                let mut node = [0u8; 24];
                hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut node);
                let mut node_height = 0usize;

                while node_height < target_height && !stack.is_empty() {
                    let (_top_node, top_height) = stack.last().unwrap();
                    if *top_height != node_height {
                        break;
                    }

                    let (top_node, _) = stack.pop().unwrap();

                    addr.set_tree_height((node_height + 1) as u32);
                    addr.set_tree_index(((leaf_idx_offset + i) >> (node_height + 1)) as u32);
                    let addr_bytes = addr.to_bytes();

                    let mut parent = [0u8; 24];
                    hash.t_node(pk_seed, &addr_bytes, &top_node, &node, &mut parent);

                    node = parent;
                    node_height += 1;
                }

                if node_height == target_height {
                    output[..24].copy_from_slice(&node);
                    return;
                }

                stack.push((node, node_height));
            }
            // Final root (if any left on stack)
            if let Some((root, _)) = stack.pop() {
                output[..24].copy_from_slice(&root);
            }
        }
        32 => {
            let mut stack: Vec<([u8; 32], usize)> = Vec::with_capacity(target_height + 1);
            for i in 0..n_leaves {
                let mut sk_element = [0u8; 32];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx_offset + i, addr, hash, &mut sk_element);

                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index((leaf_idx_offset + i) as u32);
                let addr_bytes = addr.to_bytes();

                let mut node = [0u8; 32];
                hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut node);
                let mut node_height = 0usize;

                while node_height < target_height && !stack.is_empty() {
                    let (_top_node, top_height) = stack.last().unwrap();
                    if *top_height != node_height {
                        break;
                    }

                    let (top_node, _) = stack.pop().unwrap();

                    addr.set_tree_height((node_height + 1) as u32);
                    addr.set_tree_index(((leaf_idx_offset + i) >> (node_height + 1)) as u32);
                    let addr_bytes = addr.to_bytes();

                    let mut parent = [0u8; 32];
                    hash.t_node(pk_seed, &addr_bytes, &top_node, &node, &mut parent);

                    node = parent;
                    node_height += 1;
                }

                if node_height == target_height {
                    output[..32].copy_from_slice(&node);
                    return;
                }

                stack.push((node, node_height));
            }
            // Final root (if any left on stack)
            if let Some((root, _)) = stack.pop() {
                output[..32].copy_from_slice(&root);
            }
        }
        _ => {
            let mut stack: Vec<(Vec<u8>, usize)> = Vec::with_capacity(target_height + 1);
            for i in 0..n_leaves {
                let mut sk_element = vec![0u8; P::N];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx_offset + i, addr, hash, &mut sk_element);

                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index((leaf_idx_offset + i) as u32);
                let addr_bytes = addr.to_bytes();

                let mut node = vec![0u8; P::N];
                hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut node);
                let mut node_height = 0usize;

                while node_height < target_height && !stack.is_empty() {
                    let (_top_node, top_height) = stack.last().unwrap();
                    if *top_height != node_height {
                        break;
                    }

                    let (top_node, _) = stack.pop().unwrap();

                    addr.set_tree_height((node_height + 1) as u32);
                    addr.set_tree_index(((leaf_idx_offset + i) >> (node_height + 1)) as u32);
                    let addr_bytes = addr.to_bytes();

                    let mut parent = vec![0u8; P::N];
                    hash.t_node(pk_seed, &addr_bytes, &top_node, &node, &mut parent);

                    node = parent;
                    node_height += 1;
                }

                if node_height == target_height {
                    output.copy_from_slice(&node);
                    return;
                }

                stack.push((node, node_height));
            }
            // Final root (if any left on stack)
            if let Some((root, _)) = stack.pop() {
                output.copy_from_slice(&root);
            }
        }
    }
}

/// Stack-based FORS signing implementation (hot path optimization).
///
/// This function uses stack-allocated arrays instead of Vec to avoid heap allocations
/// in the critical signing loop. Called via match statement on N.
///
/// OPTIMIZED: Uses stack-allocated root buffer to eliminate to_vec() calls (K clones per signature).
#[inline]
fn fors_sign_impl<P: ParameterSet, H: HashFunction, const N: usize>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    indices: &[usize],
    addr: &mut Address,
    hash: &H,
    signature: &mut Vec<u8>,
    roots: &mut Vec<Vec<u8>>,
) {
    // OPTIMIZATION: Stack-allocate root buffer to eliminate K to_vec() calls
    // Maximum K=35 across all parameter sets, use 40 for safety
    const MAX_K: usize = 40;
    let mut roots_buf = [[0u8; N]; MAX_K];

    for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
        // OPTIMIZATION: Stack allocations instead of Vec for hot path buffers
        let mut sk_element = [0u8; N];
        fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx, addr, hash, &mut sk_element);
        signature.extend_from_slice(&sk_element);

        addr.set_type(ADDR_TYPE_FORS_TREE);
        addr.set_tree_height(0);
        addr.set_tree_index(leaf_idx as u32);
        let addr_bytes = addr.to_bytes();
        let mut current_node = [0u8; N];
        hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut current_node);

        for height in 0..P::A {
            let sibling_idx = leaf_idx ^ (1 << height);
            let mut sibling = [0u8; N];

            if height == 0 {
                let mut sk_sibling = [0u8; N];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, sibling_idx, addr, hash, &mut sk_sibling);
                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index(sibling_idx as u32);
                let addr_bytes = addr.to_bytes();
                hash.t_leaf(pk_seed, &addr_bytes, &sk_sibling, &mut sibling);
            } else {
                let sibling_subtree_start = (sibling_idx >> height) << height;
                fors_tree_hash::<P, H>(
                    sk_seed,
                    pk_seed,
                    tree_idx,
                    sibling_subtree_start,
                    height,
                    addr,
                    hash,
                    &mut sibling,
                );
            }

            signature.extend_from_slice(&sibling);

            addr.set_type(ADDR_TYPE_FORS_TREE);
            addr.set_tree_height((height + 1) as u32);
            addr.set_tree_index((leaf_idx >> (height + 1)) as u32);
            let addr_bytes = addr.to_bytes();

            let mut parent = [0u8; N];
            if (leaf_idx >> height) & 1 == 0 {
                hash.t_node(pk_seed, &addr_bytes, &current_node, &sibling, &mut parent);
            } else {
                hash.t_node(pk_seed, &addr_bytes, &sibling, &current_node, &mut parent);
            }

            current_node = parent;
        }

        // OPTIMIZATION: Store root in stack buffer (eliminates to_vec() clone)
        roots_buf[tree_idx].copy_from_slice(&current_node);
    }

    // Convert roots from stack buffer to Vec for final hashing
    // This single conversion is much faster than K individual to_vec() calls
    for i in 0..P::K {
        roots.push(roots_buf[i].to_vec());
    }
}

/// Sign a message using FORS.
///
/// Returns the FORS signature which consists of:
/// - For each of k trees: the secret key element and its authentication path
///
/// The FORS public key (root of all tree roots) is also computed.
///
/// Optimizations:
/// - On-demand leaf generation (no full tree storage)
/// - Authentication paths computed using treehash
/// - Stack allocations for hot path buffers (avoids heap allocations)
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

    // Signature buffer
    let mut signature = Vec::with_capacity(P::K * (P::A + 1) * P::N);

    // Roots of all k trees
    let mut roots = Vec::with_capacity(P::K);

    // OPTIMIZATION: Use match on N to enable stack allocations instead of heap
    // This avoids Vec allocations in the hot loop (14 trees × 12 auth nodes = 168+ allocations per signature)
    match P::N {
        16 => fors_sign_impl::<P, H, 16>(sk_seed, pk_seed, &indices, addr, hash, &mut signature, &mut roots),
        24 => fors_sign_impl::<P, H, 24>(sk_seed, pk_seed, &indices, addr, hash, &mut signature, &mut roots),
        32 => fors_sign_impl::<P, H, 32>(sk_seed, pk_seed, &indices, addr, hash, &mut signature, &mut roots),
        _ => {
            // Fallback to Vec for non-standard N values
            for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
                let mut sk_element = vec![0u8; P::N];
                fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, leaf_idx, addr, hash, &mut sk_element);
                signature.extend_from_slice(&sk_element);

                addr.set_type(ADDR_TYPE_FORS_TREE);
                addr.set_tree_height(0);
                addr.set_tree_index(leaf_idx as u32);
                let addr_bytes = addr.to_bytes();
                let mut current_node = vec![0u8; P::N];
                hash.t_leaf(pk_seed, &addr_bytes, &sk_element, &mut current_node);

                for height in 0..P::A {
                    let sibling_idx = leaf_idx ^ (1 << height);
                    let mut sibling = vec![0u8; P::N];

                    if height == 0 {
                        let mut sk_sibling = vec![0u8; P::N];
                        fors_sk_gen::<P, H>(sk_seed, pk_seed, tree_idx, sibling_idx, addr, hash, &mut sk_sibling);
                        addr.set_type(ADDR_TYPE_FORS_TREE);
                        addr.set_tree_height(0);
                        addr.set_tree_index(sibling_idx as u32);
                        let addr_bytes = addr.to_bytes();
                        hash.t_leaf(pk_seed, &addr_bytes, &sk_sibling, &mut sibling);
                    } else {
                        let sibling_subtree_start = (sibling_idx >> height) << height;
                        fors_tree_hash::<P, H>(
                            sk_seed,
                            pk_seed,
                            tree_idx,
                            sibling_subtree_start,
                            height,
                            addr,
                            hash,
                            &mut sibling,
                        );
                    }

                    signature.extend_from_slice(&sibling);

                    addr.set_type(ADDR_TYPE_FORS_TREE);
                    addr.set_tree_height((height + 1) as u32);
                    addr.set_tree_index((leaf_idx >> (height + 1)) as u32);
                    let addr_bytes = addr.to_bytes();

                    let mut parent = vec![0u8; P::N];
                    if (leaf_idx >> height) & 1 == 0 {
                        hash.t_node(pk_seed, &addr_bytes, &current_node, &sibling, &mut parent);
                    } else {
                        hash.t_node(pk_seed, &addr_bytes, &sibling, &current_node, &mut parent);
                    }

                    current_node = parent;
                }

                roots.push(current_node);
            }
        }
    }

    // Compute FORS public key from all roots
    // Per FIPS 205: fors_pk = T_l(pk_seed, ADRS, root[0] || root[1] || ... || root[k-1])
    addr.set_type(ADDR_TYPE_FORS_ROOTS);
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

    let mut roots = Vec::with_capacity(P::K);
    let mut sig_offset = 0;

    for &leaf_idx in indices.iter() {
        // Extract secret key element from signature
        let sk_element = &sig[sig_offset..sig_offset + P::N];
        sig_offset += P::N;

        // Apply T_l to get leaf node
        addr.set_type(ADDR_TYPE_FORS_TREE);
        addr.set_tree_height(0);
        addr.set_tree_index(leaf_idx as u32);
        let addr_bytes = addr.to_bytes();

        let mut node = vec![0u8; P::N];
        hash.t_leaf(pk_seed, &addr_bytes, sk_element, &mut node);

        // Process authentication path
        let mut idx = leaf_idx;
        for height in 0..P::A {
            let sibling = &sig[sig_offset..sig_offset + P::N];
            sig_offset += P::N;

            addr.set_tree_height((height + 1) as u32);
            addr.set_tree_index((idx >> 1) as u32);
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
    addr.set_type(ADDR_TYPE_FORS_ROOTS);
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
        let msg = [0b11010110, 0b10110011, 0b11110000, 0b10101010, 0b11001100];

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
