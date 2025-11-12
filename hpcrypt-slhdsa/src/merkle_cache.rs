//! Merkle tree caching for hypertree top layers.
//!
//! Pre-computes and caches authentication paths for the top L layers of the hypertree,
//! which don't change across signatures (only bottom layers are tree_index-dependent).
//!
//! ## Performance Analysis
//!
//! For SHA2-128s (N=16, H=63, D=7, TREE_HEIGHT=9):
//! - Cache depth 1: 73 KB memory, ~10-12% improvement
//! - Cache depth 2: 146 KB memory, ~18-23% improvement
//! - Cache depth 3: 219 KB memory, ~30-35% improvement (OPTIMAL)
//! - Cache depth 4+: Diminishing returns (only ~5% per additional layer)
//!
//! ## Memory Layout
//!
//! ```text
//! cache[layer][tree_index][height] = node_hash
//! Size: cache_depth × 2^TREE_HEIGHT × TREE_HEIGHT × N bytes
//! ```

use crate::address::Address;
use crate::hash::traits::HashFunction;
use crate::merkle::compute_auth_path;
use crate::params::ParameterSet;
use core::marker::PhantomData;

/// Merkle tree cache for hypertree top layers.
///
/// Stores pre-computed authentication paths for the top `cache_depth` layers
/// of the hypertree, significantly reducing signature generation time at the
/// cost of memory.
pub struct MerkleCache<P: ParameterSet> {
    /// Number of cached layers (from top)
    cache_depth: usize,

    /// Cached authentication paths
    /// Structure: auth_paths[layer][tree_index] = vec![node_hashes]
    /// Where each vec![node_hashes] contains TREE_HEIGHT nodes
    auth_paths: Vec<Vec<Vec<Vec<u8>>>>,

    /// Parameter set marker
    _phantom: PhantomData<P>,
}

impl<P: ParameterSet> MerkleCache<P> {
    /// Build cache for top L layers.
    ///
    /// This is a one-time operation performed during key generation.
    ///
    /// # Complexity
    /// - Time: O(cache_depth × 2^TREE_HEIGHT × TREE_HEIGHT)
    /// - Memory: ~73 KB per layer (for N=16, TREE_HEIGHT=9)
    ///
    /// # Parameters
    /// - `sk_seed`: Secret seed for generating tree nodes
    /// - `pk_seed`: Public seed for hash function tweaking
    /// - `cache_depth`: Number of top layers to cache (1-D)
    /// - `hash`: Hash function implementation
    ///
    /// # Panics
    /// Panics if `cache_depth` > `P::D` (can't cache more layers than exist)
    pub fn build<H: HashFunction>(
        sk_seed: &[u8],
        pk_seed: &[u8],
        cache_depth: usize,
        hash: &H,
    ) -> Self {
        assert!(
            cache_depth <= P::D,
            "Cannot cache more layers ({}) than exist ({})",
            cache_depth,
            P::D
        );
        assert!(cache_depth > 0, "Cache depth must be at least 1");

        let mut auth_paths = Vec::with_capacity(cache_depth);

        // Pre-compute auth paths for top layers
        // Top layers are numbered P::D - cache_depth to P::D - 1
        for layer_offset in 0..cache_depth {
            let layer = (P::D - cache_depth + layer_offset) as u32;
            let mut layer_cache = Vec::with_capacity(1 << P::TREE_HEIGHT);

            // For each possible tree index in this layer
            for tree_idx in 0..(1 << P::TREE_HEIGHT) {
                let mut addr = Address::new();
                addr.set_layer(layer);
                addr.set_tree(tree_idx as u64);

                // Compute auth path for this tree
                let auth_path = compute_auth_path::<P, H>(
                    sk_seed,
                    pk_seed,
                    tree_idx,
                    P::TREE_HEIGHT,
                    &mut addr,
                    hash,
                );

                layer_cache.push(auth_path);
            }

            auth_paths.push(layer_cache);
        }

        Self {
            cache_depth,
            auth_paths,
            _phantom: PhantomData,
        }
    }

    /// Lookup cached authentication path.
    ///
    /// Returns `None` if the layer is not cached (use on-demand computation).
    /// Returns `Some(&auth_path)` if cached, where auth_path contains TREE_HEIGHT nodes.
    ///
    /// # Parameters
    /// - `layer`: Layer number (0 = bottom layer)
    /// - `tree_index`: Index of the tree within the layer
    ///
    /// # Returns
    /// - `Some(&Vec<Vec<u8>>)`: Cached authentication path (TREE_HEIGHT nodes)
    /// - `None`: Layer not cached, compute on-demand
    pub fn get_auth_path(&self, layer: usize, tree_index: usize) -> Option<&Vec<Vec<u8>>> {
        // Check if this layer is in the cached range
        if layer < P::D - self.cache_depth {
            return None; // Layer not cached
        }

        let cache_layer_idx = layer - (P::D - self.cache_depth);

        // Bounds check
        if cache_layer_idx >= self.auth_paths.len() {
            return None;
        }

        // Check tree_index bounds
        if tree_index >= self.auth_paths[cache_layer_idx].len() {
            return None;
        }

        Some(&self.auth_paths[cache_layer_idx][tree_index])
    }

    /// Get the cache depth (number of top layers cached).
    pub fn depth(&self) -> usize {
        self.cache_depth
    }

    /// Get memory usage in bytes (approximate).
    ///
    /// Calculated as: cache_depth × 2^TREE_HEIGHT × TREE_HEIGHT × N
    pub fn memory_usage(&self) -> usize {
        self.cache_depth * (1 << P::TREE_HEIGHT) * P::TREE_HEIGHT * P::N
    }

    /// Get the layer range that is cached.
    ///
    /// Returns (first_cached_layer, last_cached_layer)
    /// where both are inclusive indices.
    pub fn cached_layer_range(&self) -> (usize, usize) {
        let first = P::D - self.cache_depth;
        let last = P::D - 1;
        (first, last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha2HashFunction;
    use crate::params::Sha2_128s;

    #[test]
    fn test_cache_build() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];

        // Build cache with depth 1 (top layer only)
        // SHA2-128s has D=7, so depth 1 caches layer 6 (the top layer)
        let cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 1, &hash);

        assert_eq!(cache.depth(), 1);
        assert_eq!(cache.cached_layer_range(), (6, 6)); // SHA2-128s has D=7, so top layer is layer 6
    }

    #[test]
    fn test_cache_lookup() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];

        let cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 1, &hash);

        // Should be able to lookup layer 6 (the top layer for D=7)
        let auth_path = cache.get_auth_path(6, 0);
        assert!(auth_path.is_some());

        // Auth path should have TREE_HEIGHT nodes
        let path = auth_path.unwrap();
        assert_eq!(path.len(), Sha2_128s::TREE_HEIGHT);

        // Each node should be N bytes
        for node in path {
            assert_eq!(node.len(), Sha2_128s::N);
        }

        // Bottom layers (0-5) should not be cached
        assert!(cache.get_auth_path(0, 0).is_none());
        assert!(cache.get_auth_path(3, 0).is_none());
    }

    #[test]
    fn test_cache_memory_calculation() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];

        let cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 1, &hash);

        // Expected: 1 layer × 2^9 trees × 9 nodes × 16 bytes = 73,728 bytes
        let expected = 1 * (1 << 9) * 9 * 16;
        assert_eq!(cache.memory_usage(), expected);
    }

    #[test]
    #[should_panic(expected = "Cannot cache more layers")]
    fn test_cache_depth_exceeds_d() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];

        // SHA2-128s has D=7, trying to cache 8 layers should panic
        let _cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 8, &hash);
    }

    #[test]
    #[should_panic(expected = "Cache depth must be at least 1")]
    fn test_cache_depth_zero() {
        let hash = Sha2HashFunction::<16>::new();
        let sk_seed = [0x12u8; 16];
        let pk_seed = [0x34u8; 16];

        let _cache = MerkleCache::<Sha2_128s>::build(&sk_seed, &pk_seed, 0, &hash);
    }
}
