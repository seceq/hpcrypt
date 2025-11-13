//! SHAKE256 based hash functions for SLH-DSA.
//!
//! This implementation uses hpcrypt-hash with optimizations for state
//! cloning and variable-length output.

use crate::hash::traits::{HashFunction, HashFunctionContext};
use hpcrypt_hash::Shake256;

/// SHAKE256 hash function implementation for SLH-DSA.
#[derive(Clone)]
pub struct ShakeHashFunction<const N: usize>;

impl<const N: usize> Default for ShakeHashFunction<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ShakeHashFunction<N> {
    /// Create a new SHAKE256 hash function instance.
    pub const fn new() -> Self {
        Self
    }

    /// SHAKE256 with variable-length output.
    #[inline]
    #[cfg(test)]
    fn shake256(&self, input: &[u8], outlen: usize, out: &mut [u8]) {
        debug_assert!(out.len() >= outlen);

        let mut hasher = Shake256::new();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..outlen]);
    }
}

impl<const N: usize> HashFunction for ShakeHashFunction<N> {
    const N: usize = N;

    #[inline]
    fn prf(&self, key: &[u8], addr: &[u8; 32], out: &mut [u8]) {
        debug_assert_eq!(key.len(), N);
        debug_assert_eq!(out.len(), N);

        // PRF: SHAKE256(toByte(0, 32) || key || addr)
        let mut hasher = Shake256::new();
        hasher.update(&[0u8; 32]);
        hasher.update(&key[..N]);
        hasher.update(addr);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..N]);
    }

    #[inline]
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(sk_prf.len(), N);
        debug_assert_eq!(opt_rand.len(), N);
        debug_assert_eq!(out.len(), N);

        // PRF_msg: SHAKE256(toByte(2, 32) || sk_prf || opt_rand || msg)
        let mut hasher = Shake256::new();
        hasher.update(&[2u8; 32]);
        hasher.update(&sk_prf[..N]);
        hasher.update(opt_rand);
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..N]);
    }

    #[inline]
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(r.len(), N);
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(pk_root.len(), N);

        // H_msg: SHAKE256(toByte(3, 32) || r || pk_seed || pk_root || msg)
        let mut hasher = Shake256::new();
        hasher.update(&[3u8; 32]);
        hasher.update(r);
        hasher.update(&pk_seed[..N]);
        hasher.update(&pk_root[..N]);
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }

    #[inline]
    fn t_leaf(&self, pk_seed: &[u8], addr: &[u8; 32], leaf: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(leaf.len(), N);
        debug_assert_eq!(out.len(), N);

        // T_l: SHAKE256(toByte(0, 32) || pk_seed || addr || leaf)
        let mut hasher = Shake256::new();
        hasher.update(&[0u8; 32]);
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);
        hasher.update(&leaf[..N]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..N]);
    }

    #[inline]
    fn t_node(&self, pk_seed: &[u8], addr: &[u8; 32], left: &[u8], right: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(left.len(), N);
        debug_assert_eq!(right.len(), N);
        debug_assert_eq!(out.len(), N);

        // T_k: SHAKE256(toByte(1, 32) || pk_seed || addr || left || right)
        let mut hasher = Shake256::new();
        hasher.update(&[1u8; 32]);
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);
        hasher.update(&left[..N]);
        hasher.update(&right[..N]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..N]);
    }

    #[inline]
    fn f(&self, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(input.len(), N);
        debug_assert_eq!(out.len(), N);

        // F: Same as T_l for SHAKE
        self.t_leaf(pk_seed, addr, input, out);
    }

    #[inline]
    fn t_leaf_batch(&self, pk_seed: &[u8], addr: &[u8; 32], inputs: &[&[u8]], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(out.len(), N);

        // Batch hash: T_l(pk_seed, addr, input[0] || input[1] || ... || input[n-1])
        let mut hasher = Shake256::new();
        hasher.update(&[0u8; 32]); // T_l padding
        hasher.update(&pk_seed[..N]);
        hasher.update(addr);

        // Hash all inputs together (batched)
        for input in inputs {
            debug_assert_eq!(input.len(), N);
            hasher.update(&input[..N]);
        }

        let mut reader = hasher.finalize_xof();
        reader.read(&mut out[..N]);
    }
}

/// Context for SHAKE256 hash function (allows state reuse/cloning).
pub struct ShakeContext {
    hasher: Shake256,
}

impl Clone for ShakeContext {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
        }
    }
}

impl<const N: usize> HashFunctionContext for ShakeHashFunction<N> {
    type Context = ShakeContext;

    fn new_context(&self) -> Self::Context {
        ShakeContext {
            hasher: Shake256::new(),
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
        ctx.hasher = Shake256::new();
        ctx.hasher.update(&[0u8; 32]);
        ctx.hasher.update(&key[..N]);
        ctx.hasher.update(addr);
        let mut reader = ctx.hasher.clone().finalize_xof();
        reader.read(&mut out[..N]);
    }

    fn f_with_context(
        &self,
        ctx: &mut Self::Context,
        pk_seed: &[u8],
        addr: &[u8; 32],
        input: &[u8],
        out: &mut [u8],
    ) {
        ctx.hasher = Shake256::new();
        ctx.hasher.update(&[0u8; 32]);
        ctx.hasher.update(&pk_seed[..N]);
        ctx.hasher.update(addr);
        ctx.hasher.update(&input[..N]);
        let mut reader = ctx.hasher.clone().finalize_xof();
        reader.read(&mut out[..N]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_basic() {
        let hash_fn = ShakeHashFunction::<16>::new();
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
    fn test_variable_output() {
        let hash_fn = ShakeHashFunction::<32>::new();
        let input = b"test input";

        let mut out1 = vec![0u8; 64];
        let mut out2 = vec![0u8; 128];

        hash_fn.shake256(input, 64, &mut out1);
        hash_fn.shake256(input, 128, &mut out2);

        // First 64 bytes should match
        assert_eq!(out1[..], out2[..64]);
    }

    #[test]
    fn test_tree_hashes() {
        let hash_fn = ShakeHashFunction::<32>::new();
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
        let hash_fn = ShakeHashFunction::<16>::new();
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

    #[test]
    fn test_prf_msg() {
        let hash_fn = ShakeHashFunction::<24>::new();
        let sk_prf = [0xAAu8; 24];
        let opt_rand = [0xBBu8; 24];
        let msg = b"test message";
        let mut out = [0u8; 24];

        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out);

        // Should be deterministic
        let mut out2 = [0u8; 24];
        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_h_msg() {
        let hash_fn = ShakeHashFunction::<32>::new();
        let r = [0x11u8; 32];
        let pk_seed = [0x22u8; 32];
        let pk_root = [0x33u8; 32];
        let msg = b"test message for h_msg";
        let mut out = vec![0u8; 64]; // Variable length

        hash_fn.h_msg(&r, &pk_seed, &pk_root, msg, &mut out);

        // Should produce non-zero output
        assert_ne!(&out[..], &[0u8; 64]);
    }
}
