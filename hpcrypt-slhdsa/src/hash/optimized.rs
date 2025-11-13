//! Optimized hash function wrappers with context pre-initialization.
//!
//! This module provides wrappers around hash functions that pre-initialize
//! contexts with common prefixes (padding + pk_seed), allowing reuse via
//! cloning instead of re-hashing the same data repeatedly.

use hpcrypt_hash::Sha256;

/// Pre-initialized hash contexts for SHA2-based operations.
///
/// This struct holds hash contexts that have already processed common
/// prefixes (padding + pk_seed), allowing us to clone them instead of
/// re-processing the same data for every hash operation.
///
/// Performance improvement: ~5-10% by eliminating redundant hashing of
/// constant prefixes.
pub struct PreInitializedSha2<const N: usize> {
    // Base context for T_leaf/F: [0u8; 32] || pk_seed
    t_leaf_base: Sha256,
    // Base context for T_node: [1u8; 32] || pk_seed
    t_node_base: Sha256,
    // Store pk_seed for operations that need it
    pk_seed: [u8; N],
}

impl<const N: usize> PreInitializedSha2<N> {
    /// Create a new pre-initialized context for the given public seed.
    ///
    /// This should be created once per signing/verification operation and
    /// reused for all hash calls with the same pk_seed.
    #[inline]
    pub fn new(pk_seed: &[u8]) -> Self {
        debug_assert_eq!(pk_seed.len(), N);

        // Pre-initialize T_leaf/F context: padding + pk_seed
        let mut t_leaf_base = Sha256::new();
        t_leaf_base.update(&[0u8; 32]); // T_leaf padding
        t_leaf_base.update(&pk_seed[..N]);

        // Pre-initialize T_node context: padding + pk_seed
        let mut t_node_base = Sha256::new();
        t_node_base.update(&[1u8; 32]); // T_node padding
        t_node_base.update(&pk_seed[..N]);

        let mut pk_seed_array = [0u8; N];
        pk_seed_array.copy_from_slice(&pk_seed[..N]);

        Self {
            t_leaf_base,
            t_node_base,
            pk_seed: pk_seed_array,
        }
    }

    /// T_leaf with pre-initialized context.
    ///
    /// Clones the pre-initialized context instead of rehashing padding + pk_seed.
    #[inline]
    pub fn t_leaf(&self, addr: &[u8; 32], leaf: &[u8], out: &mut [u8]) {
        debug_assert_eq!(leaf.len(), N);
        debug_assert_eq!(out.len(), N);

        // Clone pre-initialized context (faster than creating new + updating prefix)
        let mut hasher = self.t_leaf_base.clone();
        hasher.update(addr);
        hasher.update(&leaf[..N]);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            // For N > 32, we still need MGF1 (rare case)
            Self::mgf1(&result, N, out);
        }
    }

    /// T_node with pre-initialized context.
    ///
    /// Clones the pre-initialized context instead of rehashing padding + pk_seed.
    #[inline]
    pub fn t_node(&self, addr: &[u8; 32], left: &[u8], right: &[u8], out: &mut [u8]) {
        debug_assert_eq!(left.len(), N);
        debug_assert_eq!(right.len(), N);
        debug_assert_eq!(out.len(), N);

        // Clone pre-initialized context
        let mut hasher = self.t_node_base.clone();
        hasher.update(addr);
        hasher.update(&left[..N]);
        hasher.update(&right[..N]);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            Self::mgf1(&result, N, out);
        }
    }

    /// F function (same as T_leaf for SHA2).
    #[inline]
    pub fn f(&self, addr: &[u8; 32], input: &[u8], out: &mut [u8]) {
        self.t_leaf(addr, input, out);
    }

    /// Get the public seed this context was initialized with.
    #[inline]
    pub fn pk_seed(&self) -> &[u8; N] {
        &self.pk_seed
    }

    /// MGF1-SHA256 for variable-length output (rare, only for N > 32).
    #[inline]
    fn mgf1(input: &[u8], outlen: usize, out: &mut [u8]) {
        debug_assert!(out.len() >= outlen);

        let mut counter = 0u32;
        let mut offset = 0;

        while offset < outlen {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.update(&counter.to_be_bytes());

            let hash = hasher.finalize();
            let to_copy = core::cmp::min(32, outlen - offset);
            out[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);

            offset += to_copy;
            counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::Sha2HashFunction;
    use crate::hash::traits::HashFunction;

    #[test]
    fn test_preinit_matches_standard() {
        let pk_seed = [0x42u8; 16];
        let addr = [0x12u8; 32];
        let leaf = [0x34u8; 16];
        let left = [0x56u8; 16];
        let right = [0x78u8; 16];

        let standard = Sha2HashFunction::<16>::new();
        let preinit = PreInitializedSha2::<16>::new(&pk_seed);

        // Test T_leaf
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        standard.t_leaf(&pk_seed, &addr, &leaf, &mut out1);
        preinit.t_leaf(&addr, &leaf, &mut out2);
        assert_eq!(out1, out2, "T_leaf mismatch");

        // Test T_node
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        standard.t_node(&pk_seed, &addr, &left, &right, &mut out1);
        preinit.t_node(&addr, &left, &right, &mut out2);
        assert_eq!(out1, out2, "T_node mismatch");

        // Test F
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        standard.f(&pk_seed, &addr, &leaf, &mut out1);
        preinit.f(&addr, &leaf, &mut out2);
        assert_eq!(out1, out2, "F mismatch");
    }

    #[test]
    fn test_preinit_n24() {
        let pk_seed = [0x42u8; 24];
        let addr = [0x12u8; 32];
        let leaf = [0x34u8; 24];

        let standard = Sha2HashFunction::<24>::new();
        let preinit = PreInitializedSha2::<24>::new(&pk_seed);

        let mut out1 = [0u8; 24];
        let mut out2 = [0u8; 24];
        standard.t_leaf(&pk_seed, &addr, &leaf, &mut out1);
        preinit.t_leaf(&addr, &leaf, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_preinit_n32() {
        let pk_seed = [0x42u8; 32];
        let addr = [0x12u8; 32];
        let leaf = [0x34u8; 32];

        let standard = Sha2HashFunction::<32>::new();
        let preinit = PreInitializedSha2::<32>::new(&pk_seed);

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        standard.t_leaf(&pk_seed, &addr, &leaf, &mut out1);
        preinit.t_leaf(&addr, &leaf, &mut out2);
        assert_eq!(out1, out2);
    }
}
