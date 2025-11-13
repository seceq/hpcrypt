//! SHA2-256 based hash functions for SLH-DSA.
//!
//! This implementation uses hpcrypt-hash with optimizations for context
//! reuse and minimal allocations.

use crate::hash::traits::{HashFunction, HashFunctionContext};
use hpcrypt_hash::Sha256;

/// SHA2-256 hash function implementation for SLH-DSA.
///
/// Uses MGF1-SHA256 for functions that require variable-length output.
#[derive(Clone)]
pub struct Sha2HashFunction<const N: usize>;

impl<const N: usize> Default for Sha2HashFunction<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Sha2HashFunction<N> {
    /// Create a new SHA2 hash function instance.
    pub const fn new() -> Self {
        Self
    }

    /// MGF1-SHA256: Mask generation function for variable-length output.
    ///
    /// This is used when we need more than 32 bytes of output.
    #[inline]
    fn mgf1(&self, input: &[u8], outlen: usize, out: &mut [u8]) {
        debug_assert!(out.len() >= outlen);

        let mut counter = 0u32;
        let mut offset = 0;

        while offset < outlen {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.update(counter.to_be_bytes());

            let hash = hasher.finalize();
            let to_copy = core::cmp::min(32, outlen - offset);
            out[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);

            offset += to_copy;
            counter += 1;
        }
    }
}

impl<const N: usize> HashFunction for Sha2HashFunction<N> {
    const N: usize = N;

    #[inline]
    fn prf(&self, key: &[u8], addr: &[u8; 32], out: &mut [u8]) {
        debug_assert_eq!(key.len(), N);
        debug_assert_eq!(out.len(), N);

        // PRF uses padding: SHA-256(toByte(0, 64) || key || addr)
        let mut hasher = Sha256::new();
        hasher.update(&[0u8; 64]); // Padding
        hasher.update(&key[..N]);
        hasher.update(addr);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            // For N > 32, use MGF1
            self.mgf1(&result, N, out);
        }
    }

    #[inline]
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(sk_prf.len(), N);
        debug_assert_eq!(opt_rand.len(), N);
        debug_assert_eq!(out.len(), N);

        // PRF_msg: SHA-256(toByte(1, 64) || sk_prf || opt_rand || msg)
        let mut hasher = Sha256::new();
        hasher.update(&[1u8; 64]);
        hasher.update(&sk_prf[..N]);
        hasher.update(opt_rand);
        hasher.update(msg);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }

    #[inline]
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(r.len(), N);
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(pk_root.len(), N);

        // H_msg: MGF1-SHA256(r || pk_seed || pk_root || msg)
        let mut hasher = Sha256::new();
        hasher.update(r);
        hasher.update(&pk_seed[..N]);
        hasher.update(&pk_root[..N]);
        hasher.update(msg);

        let result = hasher.finalize();
        self.mgf1(&result, out.len(), out);
    }

    #[inline]
    fn t_leaf(&self, pk_seed: &[u8], addr: &[u8; 32], leaf: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(leaf.len(), N);
        debug_assert_eq!(out.len(), N);

        // T_l: SHA-256(toByte(0, 32) || pk_seed || addr || leaf)
        let mut hasher = Sha256::new();
        hasher.update(&[0u8; 32]);
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);
        hasher.update(&leaf[..N]);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }

    #[inline]
    fn t_node(&self, pk_seed: &[u8], addr: &[u8; 32], left: &[u8], right: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(left.len(), N);
        debug_assert_eq!(right.len(), N);
        debug_assert_eq!(out.len(), N);

        // T_k: SHA-256(toByte(1, 32) || pk_seed || addr || left || right)
        let mut hasher = Sha256::new();
        hasher.update(&[1u8; 32]);
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);
        hasher.update(&left[..N]);
        hasher.update(&right[..N]);

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }

    #[inline]
    fn f(&self, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(input.len(), N);
        debug_assert_eq!(out.len(), N);

        // F: SHA-256(toByte(0, 32) || pk_seed || addr || input)
        // Same as T_l
        self.t_leaf(pk_seed, addr, input, out);
    }

    #[inline]
    fn t_leaf_batch(&self, pk_seed: &[u8], addr: &[u8; 32], inputs: &[&[u8]], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(out.len(), N);

        // Batch hash: T_l(pk_seed, addr, input[0] || input[1] || ... || input[n-1])
        // This is the horizontal hashing pattern from PQClean/reference implementations
        let mut hasher = Sha256::new();
        hasher.update(&[0u8; 32]); // T_l padding
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);

        // Hash all inputs together (batched)
        for input in inputs {
            debug_assert_eq!(input.len(), N);
            hasher.update(&input[..N]);
        }

        let result = hasher.finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }
}

/// Context for SHA2 hash function (allows state reuse).
pub struct Sha2Context {
    hasher: Sha256,
}

impl Clone for Sha2Context {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
        }
    }
}

impl<const N: usize> HashFunctionContext for Sha2HashFunction<N> {
    type Context = Sha2Context;

    fn new_context(&self) -> Self::Context {
        Sha2Context {
            hasher: Sha256::new(),
        }
    }

    fn prf_with_context(
        &self,
        ctx: &mut Self::Context,
        key: &[u8],
        addr: &[u8; 32],
        out: &mut [u8],
    ) {
        // Reset and reuse context
        ctx.hasher = Sha256::new();
        ctx.hasher.update(&[0u8; 64]);
        ctx.hasher.update(&key[..N]);
        ctx.hasher.update(addr);

        let result = ctx.hasher.clone().finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }

    fn f_with_context(
        &self,
        ctx: &mut Self::Context,
        pk_seed: &[u8],
        addr: &[u8; 32],
        input: &[u8],
        out: &mut [u8],
    ) {
        ctx.hasher = Sha256::new();
        ctx.hasher.update(&[0u8; 32]);
        ctx.hasher.update(&pk_seed[..N]);
        ctx.hasher.update(addr);
        ctx.hasher.update(&input[..N]);

        let result = ctx.hasher.clone().finalize();

        if N <= 32 {
            out.copy_from_slice(&result[..N]);
        } else {
            self.mgf1(&result, N, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_basic() {
        let hash_fn = Sha2HashFunction::<16>::new();
        let key = [0u8; 16];
        let addr = [0u8; 32];
        let mut out = [0u8; 16];

        hash_fn.prf(&key, &addr, &mut out);

        // Output should be deterministic
        let mut out2 = [0u8; 16];
        hash_fn.prf(&key, &addr, &mut out2);
        assert_eq!(out, out2);

        // Different address should give different output
        let addr2 = [1u8; 32];
        let mut out3 = [0u8; 16];
        hash_fn.prf(&key, &addr2, &mut out3);
        assert_ne!(out, out3);
    }

    #[test]
    fn test_tree_hashes() {
        let hash_fn = Sha2HashFunction::<32>::new();
        let pk_seed = [0x42u8; 32];
        let addr = [0u8; 32];
        let leaf = [0x12u8; 32];
        let mut out = [0u8; 32];

        hash_fn.t_leaf(&pk_seed, &addr, &leaf, &mut out);

        // Should produce non-zero output
        assert_ne!(out, [0u8; 32]);

        // Test t_node
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        hash_fn.t_node(&pk_seed, &addr, &left, &right, &mut out);
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn test_context_reuse() {
        let hash_fn = Sha2HashFunction::<16>::new();
        let mut ctx = hash_fn.new_context();

        let key = [0u8; 16];
        let addr = [0u8; 32];
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];

        // Using context
        hash_fn.prf_with_context(&mut ctx, &key, &addr, &mut out1);

        // Without context
        hash_fn.prf(&key, &addr, &mut out2);

        assert_eq!(out1, out2);
    }
}
