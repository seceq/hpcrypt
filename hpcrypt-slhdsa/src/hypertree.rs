//! Hypertree implementation for SLH-DSA.
//!
//! The hypertree consists of D layers of XMSS trees. Each XMSS tree has
//! WOTS+ public keys as leaves. At each layer, a WOTS+ signature authenticates
//! either a message (bottom layer) or the root of the layer below.

use crate::address::Address;
use crate::hash::traits::HashFunction;
use crate::merkle::{xmss_auth_path, xmss_treehash};
use crate::merkle_cache::MerkleCache;
use crate::params::ParameterSet;
use crate::wots::{wots_pk_from_sig, wots_pk_gen, wots_sign};

/// Sign a message using the hypertree with optional Merkle caching.
///
/// This version accepts an optional cache that stores pre-computed authentication
/// paths for the top layers of the hypertree, significantly improving performance
/// when signing multiple messages.
///
/// # Parameters
/// - `cache`: Optional pre-computed Merkle cache (None = no caching)
pub fn ht_sign_cached<P: ParameterSet, H: HashFunction>(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u64,
    addr: &mut Address,
    hash: &H,
    cache: Option<&MerkleCache<P>>,
) -> Vec<u8> {
    debug_assert_eq!(message.len(), P::N);
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);

    // Signature size for D layers: D * (WOTS_SIG + auth_path)
    let sig_capacity = P::D * (P::WOTS_SIG_BYTES + P::TREE_HEIGHT * P::N);
    let mut signature = Vec::with_capacity(sig_capacity);

    let mut node = vec![0u8; P::N];
    node.copy_from_slice(message);

    // Process each layer from bottom to top
    // Per FIPS 205 Algorithm 10
    for layer in 0..P::D {
        addr.set_layer(layer as u32);
        // Per FIPS 205: tree_addr = idx_tree >> (j * h')
        // Handle shift overflow (when shift >= 64, result is 0)
        let tree_shift = layer * P::TREE_HEIGHT;
        addr.set_tree(if tree_shift >= 64 { 0 } else { idx_tree >> tree_shift });

        // Per FIPS 205 Algorithm 10 lines 10-11:
        // At end of each iteration: idx_leaf = idx_tree mod 2^h', idx_tree >>= h'
        // This means at layer j > 0, we use (original_idx_tree >> ((j-1) * h')) mod 2^h'
        // At layer 0, we use the input idx_leaf instead
        let leaf_idx = if layer == 0 {
            idx_leaf as usize
        } else {
            // Extract from LSB end: layer 1 uses bits [h'-1:0], layer 2 uses bits [2h'-1:h'], etc.
            let leaf_shift = (layer - 1) * P::TREE_HEIGHT;
            if leaf_shift >= 64 {
                0
            } else {
                ((idx_tree >> leaf_shift) & ((1 << P::TREE_HEIGHT) - 1)) as usize
            }
        };

        // Set keypair address for WOTS+ operations
        addr.set_keypair(leaf_idx as u32);

        // Sign the node with WOTS+
        let wots_sig = wots_sign::<P, H>(&node, sk_seed, pk_seed, addr, hash);
        signature.extend_from_slice(&wots_sig);

        // Try to get authentication path from cache or compute it
        let auth_path = if let Some(cache) = cache {
            if let Some(cached_path) = cache.get_auth_path(layer, leaf_idx) {
                cached_path.clone()
            } else {
                xmss_auth_path::<P, H>(sk_seed, pk_seed, leaf_idx, P::TREE_HEIGHT, addr, hash)
            }
        } else {
            xmss_auth_path::<P, H>(sk_seed, pk_seed, leaf_idx, P::TREE_HEIGHT, addr, hash)
        };

        // Add authentication path to signature
        for sibling in &auth_path {
            signature.extend_from_slice(sibling);
        }

        // If not the top layer, compute tree root for next layer's message
        if layer < P::D - 1 {
            // Restore address fields (xmss_auth_path may have modified them)
            addr.set_layer(layer as u32);
            addr.set_tree(idx_tree >> (layer * P::TREE_HEIGHT));
            addr.set_keypair(leaf_idx as u32);

            // Compute WOTS+ PK at the signing position
            let mut wots_pk = vec![0u8; P::N];
            wots_pk_gen::<P, H>(sk_seed, pk_seed, addr, hash, &mut wots_pk);

            // Hash up from WOTS+ pk using auth_path to compute tree root
            // Set address type to TREE for internal node computation
            addr.set_type(crate::address::ADDR_TYPE_TREE);
            addr.set_keypair(0); // Must clear keypair (words[4]) for tree addresses

            let mut buffer1 = wots_pk;
            let mut buffer2 = vec![0u8; P::N];
            let mut current_idx = leaf_idx;

            for (height, sibling) in auth_path.iter().enumerate() {
                addr.set_tree_height((height + 1) as u32);
                addr.set_tree_index((current_idx >> 1) as u32);

                if current_idx % 2 == 0 {
                    hash.t_node(pk_seed, &addr.to_bytes(), &buffer1, sibling, &mut buffer2);
                } else {
                    hash.t_node(pk_seed, &addr.to_bytes(), sibling, &buffer1, &mut buffer2);
                }

                core::mem::swap(&mut buffer1, &mut buffer2);
                current_idx >>= 1;
            }

            node = buffer1;
        }
    }

    signature
}

/// Verify a hypertree signature.
///
/// Verifies a signature against the hypertree public root by:
/// 1. At each layer: compute WOTS+ public key from signature
/// 2. Use authentication path to compute tree root
/// 3. At top layer: computed root should match pk_root
pub fn ht_verify<P: ParameterSet, H: HashFunction>(
    message: &[u8],
    signature: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u64,
    pk_root: &[u8],
    addr: &mut Address,
    hash: &H,
) -> bool {
    debug_assert_eq!(message.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(pk_root.len(), P::N);

    // Expected signature size: D layers, each with WOTS_SIG + AUTH
    let expected_sig_len = P::D * (P::WOTS_SIG_BYTES + P::TREE_HEIGHT * P::N);
    if signature.len() < expected_sig_len {
        return false;
    }

    let mut node = vec![0u8; P::N];
    node.copy_from_slice(message);

    let mut sig_offset = 0;

    // Process each layer from bottom to top
    // Per FIPS 205 Algorithm 12
    for layer in 0..P::D {
        addr.set_layer(layer as u32);
        // Per FIPS 205: tree_addr = idx_tree >> (j * h')
        // Handle shift overflow (when shift >= 64, result is 0)
        let tree_shift = layer * P::TREE_HEIGHT;
        addr.set_tree(if tree_shift >= 64 { 0 } else { idx_tree >> tree_shift });

        // Per FIPS 205 Algorithm 10 lines 10-11:
        // At end of each iteration: idx_leaf = idx_tree mod 2^h', idx_tree >>= h'
        // This means at layer j > 0, we use (original_idx_tree >> ((j-1) * h')) mod 2^h'
        // At layer 0, we use the input idx_leaf instead
        let leaf_idx = if layer == 0 {
            idx_leaf as usize
        } else {
            // Extract from LSB end: layer 1 uses bits [h'-1:0], layer 2 uses bits [2h'-1:h'], etc.
            let leaf_shift = (layer - 1) * P::TREE_HEIGHT;
            if leaf_shift >= 64 {
                0
            } else {
                ((idx_tree >> leaf_shift) & ((1 << P::TREE_HEIGHT) - 1)) as usize
            }
        };

        // Set keypair address
        addr.set_keypair(leaf_idx as u32);

        // Extract WOTS+ signature for this layer
        let wots_sig = &signature[sig_offset..sig_offset + P::WOTS_SIG_BYTES];
        sig_offset += P::WOTS_SIG_BYTES;

        // Compute WOTS+ public key from signature
        let mut wots_pk = vec![0u8; P::N];
        wots_pk_from_sig::<P, H>(wots_sig, &node, pk_seed, addr, hash, &mut wots_pk);

        // Extract and use authentication path
        let auth_path_len = P::TREE_HEIGHT * P::N;
        let auth_path_bytes = &signature[sig_offset..sig_offset + auth_path_len];
        sig_offset += auth_path_len;

        // Compute root using WOTS+ PK and authentication path
        // Set address type to TREE for internal node computation
        addr.set_type(crate::address::ADDR_TYPE_TREE);
        addr.set_keypair(0); // Must clear keypair (words[4]) for tree addresses

        let mut buffer1 = wots_pk;
        let mut buffer2 = vec![0u8; P::N];
        let mut current_idx = leaf_idx;

        for height in 0..P::TREE_HEIGHT {
            addr.set_tree_height((height + 1) as u32);
            addr.set_tree_index((current_idx >> 1) as u32);

            let sibling = &auth_path_bytes[height * P::N..(height + 1) * P::N];

            if current_idx % 2 == 0 {
                hash.t_node(pk_seed, &addr.to_bytes(), &buffer1, sibling, &mut buffer2);
            } else {
                hash.t_node(pk_seed, &addr.to_bytes(), sibling, &buffer1, &mut buffer2);
            }

            core::mem::swap(&mut buffer1, &mut buffer2);
            current_idx >>= 1;
        }

        // Computed tree root
        node = buffer1;
    }

    // Final computed root should match pk_root
    node.as_slice() == pk_root
}

/// Compute hypertree public key.
///
/// The public key root is the root of the XMSS tree at layer D-1, tree 0.
/// This is computed by building a Merkle tree where leaves are WOTS+ public keys.
pub fn ht_pk_gen<P: ParameterSet, H: HashFunction>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &mut Address,
    hash: &H,
    output: &mut [u8],
) {
    debug_assert_eq!(sk_seed.len(), P::N);
    debug_assert_eq!(pk_seed.len(), P::N);
    debug_assert_eq!(output.len(), P::N);

    // Set address for top layer, tree 0
    addr.set_layer((P::D - 1) as u32);
    addr.set_tree(0);

    // Compute XMSS tree root at the top layer
    // Leaves are WOTS+ public keys
    xmss_treehash::<P, H>(sk_seed, pk_seed, 0, P::TREE_HEIGHT, addr, hash, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha2HashFunction;
    use crate::params::Sha2_128s;

    #[test]
    fn test_ht_pk_gen() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let mut addr = Address::new();

        let mut pk1 = [0u8; 16];
        ht_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk1);

        // Should be deterministic
        let mut pk2 = [0u8; 16];
        ht_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk2);

        assert_eq!(pk1, pk2);
        assert_ne!(pk1, [0u8; 16]);
    }

    #[test]
    fn test_xmss_tree_root_consistency() {
        // Test that xmss_treehash and manual tree root computation give the same result
        use crate::merkle::{xmss_auth_path, xmss_treehash, xmss_leaf};

        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let leaf_idx = 0usize;
        let tree_height = 3; // Small tree for testing (8 leaves)

        let mut addr = Address::new();
        addr.set_layer(0);
        addr.set_tree(0);

        // Compute tree root directly using xmss_treehash
        let mut expected_root = [0u8; 16];
        xmss_treehash::<Sha2_128s, _>(&sk_seed, &pk_seed, 0, tree_height, &mut addr, &hash, &mut expected_root);

        // Compute leaf and auth path, then manually compute root
        let mut addr2 = Address::new();
        addr2.set_layer(0);
        addr2.set_tree(0);

        // Get the leaf (WOTS+ pk)
        let mut leaf = [0u8; 16];
        xmss_leaf::<Sha2_128s, _>(&sk_seed, &pk_seed, leaf_idx, &mut addr2, &hash, &mut leaf);

        // Reset addr2 for auth path
        addr2.set_layer(0);
        addr2.set_tree(0);

        // Get auth path
        let auth_path = xmss_auth_path::<Sha2_128s, _>(&sk_seed, &pk_seed, leaf_idx, tree_height, &mut addr2, &hash);

        // Manually compute root
        addr2.set_layer(0);
        addr2.set_tree(0);
        addr2.set_type(crate::address::ADDR_TYPE_TREE);
        addr2.set_keypair(0); // Must clear keypair for tree addresses

        let mut buffer1 = leaf.to_vec();
        let mut buffer2 = vec![0u8; 16];
        let mut current_idx = leaf_idx;

        for (height, sibling) in auth_path.iter().enumerate() {
            addr2.set_tree_height((height + 1) as u32);
            addr2.set_tree_index((current_idx >> 1) as u32);

            if current_idx % 2 == 0 {
                hash.t_node(&pk_seed, &addr2.to_bytes(), &buffer1, sibling, &mut buffer2);
            } else {
                hash.t_node(&pk_seed, &addr2.to_bytes(), sibling, &buffer1, &mut buffer2);
            }

            core::mem::swap(&mut buffer1, &mut buffer2);
            current_idx >>= 1;
        }

        let computed_root: [u8; 16] = buffer1.try_into().unwrap();
        assert_eq!(expected_root, computed_root, "Tree root computation mismatch");
    }

    #[test]
    fn test_ht_sign_verify() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let message = [0xAAu8; 16]; // Message to sign
        let idx_tree = 0u64;
        let idx_leaf = 0u64;

        // Generate pk_root
        let mut addr = Address::new();
        let mut pk_root = [0u8; 16];
        ht_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk_root);

        // Sign the message
        let mut sign_addr = Address::new();
        let signature = ht_sign_cached::<Sha2_128s, _>(
            &message,
            &sk_seed,
            &pk_seed,
            idx_tree,
            idx_leaf,
            &mut sign_addr,
            &hash,
            None,
        );

        // Verify the signature
        let mut verify_addr = Address::new();
        let valid = ht_verify::<Sha2_128s, _>(
            &message,
            &signature,
            &pk_seed,
            idx_tree,
            idx_leaf,
            &pk_root,
            &mut verify_addr,
            &hash,
        );

        assert!(valid, "Hypertree signature verification failed");
    }

    #[test]
    fn test_xmss_tree_root_from_different_leaves() {
        // Test that tree root computed from different leaves is the same
        use crate::merkle::{xmss_auth_path, xmss_treehash, xmss_leaf};

        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let tree_height = 3; // Small tree (8 leaves)

        let mut addr = Address::new();
        addr.set_layer(0);
        addr.set_tree(0);

        // Compute expected root directly
        let mut expected_root = [0u8; 16];
        xmss_treehash::<Sha2_128s, _>(&sk_seed, &pk_seed, 0, tree_height, &mut addr, &hash, &mut expected_root);

        // Test computing root from leaf 0
        let mut addr0 = Address::new();
        addr0.set_layer(0);
        addr0.set_tree(0);
        let mut leaf0 = [0u8; 16];
        xmss_leaf::<Sha2_128s, _>(&sk_seed, &pk_seed, 0, &mut addr0, &hash, &mut leaf0);
        addr0.set_layer(0);
        addr0.set_tree(0);
        let auth_path0 = xmss_auth_path::<Sha2_128s, _>(&sk_seed, &pk_seed, 0, tree_height, &mut addr0, &hash);

        addr0.set_layer(0);
        addr0.set_tree(0);
        addr0.set_type(crate::address::ADDR_TYPE_TREE);
        addr0.set_keypair(0);
        let mut buffer1 = leaf0.to_vec();
        let mut buffer2 = vec![0u8; 16];
        let mut current_idx = 0usize;
        for (height, sibling) in auth_path0.iter().enumerate() {
            addr0.set_tree_height((height + 1) as u32);
            addr0.set_tree_index((current_idx >> 1) as u32);
            if current_idx % 2 == 0 {
                hash.t_node(&pk_seed, &addr0.to_bytes(), &buffer1, sibling, &mut buffer2);
            } else {
                hash.t_node(&pk_seed, &addr0.to_bytes(), sibling, &buffer1, &mut buffer2);
            }
            core::mem::swap(&mut buffer1, &mut buffer2);
            current_idx >>= 1;
        }
        let root0: [u8; 16] = buffer1.try_into().unwrap();
        assert_eq!(expected_root, root0, "Root from leaf 0 doesn't match expected");

        // Test computing root from leaf 1
        let mut addr1 = Address::new();
        addr1.set_layer(0);
        addr1.set_tree(0);
        let mut leaf1 = [0u8; 16];
        xmss_leaf::<Sha2_128s, _>(&sk_seed, &pk_seed, 1, &mut addr1, &hash, &mut leaf1);
        addr1.set_layer(0);
        addr1.set_tree(0);
        let auth_path1 = xmss_auth_path::<Sha2_128s, _>(&sk_seed, &pk_seed, 1, tree_height, &mut addr1, &hash);

        addr1.set_layer(0);
        addr1.set_tree(0);
        addr1.set_type(crate::address::ADDR_TYPE_TREE);
        addr1.set_keypair(0);
        let mut buffer1 = leaf1.to_vec();
        let mut buffer2 = vec![0u8; 16];
        let mut current_idx = 1usize;
        for (height, sibling) in auth_path1.iter().enumerate() {
            addr1.set_tree_height((height + 1) as u32);
            addr1.set_tree_index((current_idx >> 1) as u32);
            if current_idx % 2 == 0 {
                hash.t_node(&pk_seed, &addr1.to_bytes(), &buffer1, sibling, &mut buffer2);
            } else {
                hash.t_node(&pk_seed, &addr1.to_bytes(), sibling, &buffer1, &mut buffer2);
            }
            core::mem::swap(&mut buffer1, &mut buffer2);
            current_idx >>= 1;
        }
        let root1: [u8; 16] = buffer1.try_into().unwrap();
        assert_eq!(expected_root, root1, "Root from leaf 1 doesn't match expected");
    }

    #[test]
    fn test_ht_sign_verify_nonzero_tree_index() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];
        let message = [0xAAu8; 16]; // Message to sign
        let idx_tree = 1u64; // Non-zero tree index
        let idx_leaf = 0u64;

        // Generate pk_root
        let mut addr = Address::new();
        let mut pk_root = [0u8; 16];
        ht_pk_gen::<Sha2_128s, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk_root);

        // Sign the message
        let mut sign_addr = Address::new();
        let signature = ht_sign_cached::<Sha2_128s, _>(
            &message,
            &sk_seed,
            &pk_seed,
            idx_tree,
            idx_leaf,
            &mut sign_addr,
            &hash,
            None,
        );

        // Verify the signature
        let mut verify_addr = Address::new();
        let valid = ht_verify::<Sha2_128s, _>(
            &message,
            &signature,
            &pk_seed,
            idx_tree,
            idx_leaf,
            &pk_root,
            &mut verify_addr,
            &hash,
        );

        assert!(valid, "Hypertree signature verification failed for idx_tree=1");
    }
}
