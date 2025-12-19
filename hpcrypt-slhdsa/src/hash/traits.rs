//! Hash function traits for SLH-DSA.
//!
//! This module defines the core hash function interfaces that enable
//! zero-cost abstractions through monomorphization.

/// Core hash function trait for SLH-DSA.
///
/// Implementors provide the cryptographic hash operations required by the
/// SLH-DSA algorithm. This trait enables compile-time specialization via
/// monomorphization, ensuring zero runtime overhead.
pub trait HashFunction {
    /// The output size in bytes (N parameter).
    const N: usize;

    /// PRF: Pseudorandom function for secret key generation
    ///
    /// Per FIPS 205 Section 9.3:
    /// PRF(PK.seed, SK.seed, ADRS) returns a pseudorandom n-byte value.
    ///
    /// For SHA2: SHA-256(toByte(0, 64 − n) ∥ PK.seed ∥ ADRS ∥ SK.seed)
    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32], out: &mut [u8]);

    /// PRF_msg: Pseudorandom function for message randomization
    ///
    /// Computes PRF_msg(sk_prf, opt_rand, msg) for message hashing.
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]);

    /// H_msg: Hash function for message compression (external interface with context)
    ///
    /// Hashes the randomized message to produce FORS message and tree index.
    /// Per FIPS 205, incorporates context string for domain separation:
    /// M' = toByte(domain, 1) || toByte(|ctx|, 1) || ctx || M
    /// where domain = 0 for pure mode, 1 for prehash mode.
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], ctx: &[u8], msg: &[u8], out: &mut [u8]);

    /// H_msg for internal interface (no domain separator)
    ///
    /// Uses M directly without the external interface domain separator.
    /// This is used when calling the internal signing/verification algorithms directly.
    fn h_msg_internal(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], out: &mut [u8]);

    /// T_l: Hash function for Merkle tree leaf nodes
    ///
    /// Computes hash of leaf with public seed and address.
    fn t_leaf(&self, pk_seed: &[u8], addr: &[u8; 32], leaf: &[u8], out: &mut [u8]);

    /// T_k: Hash function for intermediate tree nodes
    ///
    /// Computes hash of two child nodes.
    fn t_node(&self, pk_seed: &[u8], addr: &[u8; 32], left: &[u8], right: &[u8], out: &mut [u8]);

    /// F: WOTS+ hash function (chaining function)
    ///
    /// Used in WOTS+ hash chains.
    fn f(&self, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]);

    /// T_l_batch: Batch hash function for multiple leaf nodes
    ///
    /// Computes hash of multiple inputs with the same prefix (pk_seed + addr).
    /// This is an optimization for hashing many blocks together (e.g., FORS roots, WOTS+ elements).
    ///
    /// Default implementation hashes each input sequentially into a single output,
    /// which is the pattern used in SPHINCS+ for computing public keys from
    /// multiple elements (e.g., FORS PK from K tree roots).
    ///
    /// # Arguments
    /// * `pk_seed` - Public seed
    /// * `addr` - Address structure
    /// * `inputs` - Slice of input blocks, each of length N
    /// * `out` - Output buffer of length N
    ///
    /// # Note
    /// This batches multiple inputs into a single hash computation:
    /// `out = T_l(pk_seed, addr, input[0] || input[1] || ... || input[n-1])`
    fn t_leaf_batch(&self, pk_seed: &[u8], addr: &[u8; 32], inputs: &[&[u8]], out: &mut [u8]);
}

/// Extended trait for hash functions that support state reuse.
///
/// This enables optimizations where we can clone a partially initialized
/// hash state instead of reinitializing from scratch.
pub trait HashFunctionContext: HashFunction {
    /// Context type that can be cloned for state reuse.
    type Context: Clone;

    /// Create a new context.
    fn new_context(&self) -> Self::Context;

    /// PRF with context reuse.
    fn prf_with_context(&self, ctx: &mut Self::Context, pk_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32], out: &mut [u8]);

    /// F with context reuse (for WOTS+ chains).
    fn f_with_context(&self, ctx: &mut Self::Context, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]);
}

/// Helper trait for computing multiple hashes with a common prefix.
///
/// This is an optimization for operations where many hash calls share
/// the same prefix (e.g., all using the same public seed).
pub trait PrefixedHash: HashFunction {
    /// Absorb a common prefix that will be reused.
    fn absorb_prefix(&mut self, prefix: &[u8]);

    /// Hash with the previously absorbed prefix.
    fn hash_with_prefix(&mut self, suffix: &[u8], out: &mut [u8]);

    /// Reset to start absorbing a new prefix.
    fn reset_prefix(&mut self);
}
