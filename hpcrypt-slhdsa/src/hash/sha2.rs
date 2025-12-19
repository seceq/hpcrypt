//! SHA2-based hash functions for SLH-DSA.
//!
//! This implementation uses the sha2 crate with optimizations for context
//! reuse and minimal allocations.
//!
//! Per FIPS 205 Section 10.2:
//! - For SHA2-128s/128f/192s/192f (N=16,24): Uses SHA-256 for most functions, HMAC-SHA-256 for PRF_msg
//! - For SHA2-256s/256f (N=32): Uses SHA-256 for Tl/Tk/F/PRF, but SHA-512/HMAC-SHA-512 for H_msg/PRF_msg

use crate::hash::traits::{HashFunction, HashFunctionContext};
use hpcrypt_hash::HashFunction as HpcryptHashFunction;
use hpcrypt_hash::{Sha256, Sha512};
use hpcrypt_mac::{HmacSha256, HmacSha512, Mac, MacContext};

/// SHA2-256 hash function implementation for SLH-DSA.
///
/// Uses MGF1-SHA256 for functions that require variable-length output,
/// except for N=32 where H_msg and PRF_msg use SHA-512 variants.
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

    /// ADRSc: Compress address from 32 bytes to 22 bytes per FIPS 205 Section 10.2.
    ///
    /// ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
    /// - ADRS[3]: 1 byte (layer address LSB)
    /// - ADRS[8:16]: 8 bytes (tree address)
    /// - ADRS[19]: 1 byte (type LSB)
    /// - ADRS[20:32]: 12 bytes (keypair, chain, hash)
    #[inline]
    fn compress_addr(addr: &[u8; 32]) -> [u8; 22] {
        let mut compressed = [0u8; 22];
        compressed[0] = addr[3];           // ADRS[3] - layer LSB
        compressed[1..9].copy_from_slice(&addr[8..16]);   // ADRS[8:16] - tree address (64 bits)
        compressed[9] = addr[19];          // ADRS[19] - type LSB
        compressed[10..22].copy_from_slice(&addr[20..32]); // ADRS[20:32] - keypair, chain, hash
        compressed
    }

    /// MGF1-SHA256: Mask generation function for variable-length output.
    ///
    /// This is used when we need more than 32 bytes of output (N=16, N=24).
    #[inline]
    fn mgf1_sha256(&self, input: &[u8], outlen: usize, out: &mut [u8]) {
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

    /// MGF1-SHA512: Mask generation function for variable-length output.
    ///
    /// This is used for N=32 (SHA2-256s/256f) per FIPS 205 Section 10.2.2.
    #[inline]
    fn mgf1_sha512(&self, input: &[u8], outlen: usize, out: &mut [u8]) {
        debug_assert!(out.len() >= outlen);

        let mut counter = 0u32;
        let mut offset = 0;

        while offset < outlen {
            let mut hasher = Sha512::new();
            hasher.update(input);
            hasher.update(&counter.to_be_bytes());

            let hash = hasher.finalize();
            let to_copy = core::cmp::min(64, outlen - offset);
            out[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);

            offset += to_copy;
            counter += 1;
        }
    }
}

impl<const N: usize> HashFunction for Sha2HashFunction<N> {
    const N: usize = N;

    #[inline]
    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(sk_seed.len(), N);
        debug_assert_eq!(out.len(), N);

        // PRF per FIPS 205 Section 10.2.1:
        // All SHA2 variants use SHA-256 with 22-byte compressed address (ADRSc)
        // SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || SK.seed)
        let padding_len = 64 - N;
        let mut hasher = Sha256::new();

        // pk_seed first, then padding
        hasher.update(&pk_seed[..N]);
        for _ in 0..padding_len {
            hasher.update(&[0u8]);
        }

        // All SHA2 variants use 22-byte compressed address (ADRSc)
        let compressed_addr = Self::compress_addr(addr);
        hasher.update(&compressed_addr);

        hasher.update(&sk_seed[..N]);

        let result = hasher.finalize();
        out.copy_from_slice(&result[..N]);
    }

    #[inline]
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(sk_prf.len(), N);
        debug_assert_eq!(opt_rand.len(), N);
        debug_assert_eq!(out.len(), N);

        // Per FIPS 205 Section 10.2:
        // - For N=16: PRF_msg = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))
        // - For N=24,32: PRF_msg = Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))
        //
        // Note: SHA2-192s/192f (N=24) use HMAC-SHA-512, not HMAC-SHA-256!

        // Use incremental HMAC API for better performance (no allocation needed)
        if N == 16 {
            // Use HMAC-SHA-256 for SHA2-128s/128f only
            let mut ctx = HmacSha256::new_context(sk_prf);
            ctx.update(opt_rand);
            ctx.update(msg);
            let result = ctx.finalize();
            out.copy_from_slice(&result[..N]);
        } else {
            // Use HMAC-SHA-512 for SHA2-192s/192f and SHA2-256s/256f
            let mut ctx = HmacSha512::new_context(sk_prf);
            ctx.update(opt_rand);
            ctx.update(msg);
            let result = ctx.finalize();
            out.copy_from_slice(&result[..N]);
        }
    }

    #[inline]
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], ctx: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(r.len(), N);
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(pk_root.len(), N);
        debug_assert!(ctx.len() <= 255, "Context must be at most 255 bytes");

        // Per FIPS 205 Section 10.2:
        // For external interface (pure mode), M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
        //
        // - For N=16: H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M'), m)
        // - For N=24,32: H_msg = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M'), m)
        //
        // Note: SHA2-192s/192f (N=24) use SHA-512, not SHA-256!

        // Step 1: Build M' (processed message with domain separator and context)
        let mut m_prime = Vec::with_capacity(2 + ctx.len() + msg.len());
        m_prime.push(0u8); // toByte(0, 1) for pure mode
        m_prime.push(ctx.len() as u8); // toByte(|ctx|, 1)
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(msg);

        if N == 16 {
            // Use SHA-256 for SHA2-128s/128f only
            // Step 2: Compute inner_hash = SHA-256(R || PK.seed || PK.root || M')
            let mut inner_hasher = Sha256::new();
            inner_hasher.update(r);
            inner_hasher.update(&pk_seed[..N]);
            inner_hasher.update(&pk_root[..N]);
            inner_hasher.update(&m_prime);
            let inner_hash = inner_hasher.finalize();

            // Step 3: MGF1 seed = R || PK.seed || inner_hash (32 bytes for SHA-256)
            let mut mgf1_seed = Vec::with_capacity(N + N + 32);
            mgf1_seed.extend_from_slice(r);
            mgf1_seed.extend_from_slice(&pk_seed[..N]);
            mgf1_seed.extend_from_slice(&inner_hash);

            // Step 4: Apply MGF1-SHA-256 to produce output
            self.mgf1_sha256(&mgf1_seed, out.len(), out);
        } else {
            // Use SHA-512 for SHA2-192s/192f and SHA2-256s/256f
            // Step 2: Compute inner_hash = SHA-512(R || PK.seed || PK.root || M')
            let mut inner_hasher = Sha512::new();
            inner_hasher.update(r);
            inner_hasher.update(&pk_seed[..N]);
            inner_hasher.update(&pk_root[..N]);
            inner_hasher.update(&m_prime);
            let inner_hash = inner_hasher.finalize();

            // Step 3: MGF1 seed = R || PK.seed || inner_hash (64 bytes for SHA-512)
            let mut mgf1_seed = Vec::with_capacity(N + N + 64);
            mgf1_seed.extend_from_slice(r);
            mgf1_seed.extend_from_slice(&pk_seed[..N]);
            mgf1_seed.extend_from_slice(&inner_hash);

            // Step 4: Apply MGF1-SHA-512 to produce output
            self.mgf1_sha512(&mgf1_seed, out.len(), out);
        }
    }

    #[inline]
    fn h_msg_internal(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], out: &mut [u8]) {
        debug_assert_eq!(r.len(), N);
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(pk_root.len(), N);

        // Internal interface: M used directly without domain separator
        // For N=16: Use SHA-256 and MGF1-SHA-256
        // For N=24,32: Use SHA-512 and MGF1-SHA-512

        if N == 16 {
            // Use SHA-256 for SHA2-128s/128f only
            let mut inner_hasher = Sha256::new();
            inner_hasher.update(r);
            inner_hasher.update(&pk_seed[..N]);
            inner_hasher.update(&pk_root[..N]);
            inner_hasher.update(msg);
            let inner_hash = inner_hasher.finalize();

            let mut mgf1_seed = Vec::with_capacity(N + N + 32);
            mgf1_seed.extend_from_slice(r);
            mgf1_seed.extend_from_slice(&pk_seed[..N]);
            mgf1_seed.extend_from_slice(&inner_hash);

            self.mgf1_sha256(&mgf1_seed, out.len(), out);
        } else {
            // Use SHA-512 for SHA2-192s/192f and SHA2-256s/256f
            let mut inner_hasher = Sha512::new();
            inner_hasher.update(r);
            inner_hasher.update(&pk_seed[..N]);
            inner_hasher.update(&pk_root[..N]);
            inner_hasher.update(msg);
            let inner_hash = inner_hasher.finalize();

            let mut mgf1_seed = Vec::with_capacity(N + N + 64);
            mgf1_seed.extend_from_slice(r);
            mgf1_seed.extend_from_slice(&pk_seed[..N]);
            mgf1_seed.extend_from_slice(&inner_hash);

            self.mgf1_sha512(&mgf1_seed, out.len(), out);
        }
    }

    #[inline]
    fn t_leaf(&self, pk_seed: &[u8], addr: &[u8; 32], leaf: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(leaf.len(), N);
        debug_assert_eq!(out.len(), N);

        // T_l (F function) per FIPS 205 Section 10.2.1:
        // All SHA2 variants use SHA-256 with 22-byte compressed address (ADRSc)
        // SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M1)
        let padding_len = 64 - N;
        let mut hasher = Sha256::new();

        hasher.update(&pk_seed[..N]);
        for _ in 0..padding_len {
            hasher.update(&[0u8]);
        }

        // All SHA2 variants use 22-byte compressed address (ADRSc)
        let compressed_addr = Self::compress_addr(addr);
        hasher.update(&compressed_addr);

        hasher.update(&leaf[..N]);

        let result = hasher.finalize();
        out.copy_from_slice(&result[..N]);
    }

    #[inline]
    fn t_node(&self, pk_seed: &[u8], addr: &[u8; 32], left: &[u8], right: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(left.len(), N);
        debug_assert_eq!(right.len(), N);
        debug_assert_eq!(out.len(), N);

        // H (T_k) per FIPS 205 Section 10.2.1:
        // For N=16: SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M1 || M2)
        // For N=24,32: SHA-512(PK.seed || toByte(0, 128-n) || ADRSc || M1 || M2)

        if N == 16 {
            // Use SHA-256 for SHA2-128s/128f only
            let padding_len = 64 - N;
            let mut hasher = Sha256::new();

            hasher.update(&pk_seed[..N]);
            for _ in 0..padding_len {
                hasher.update(&[0u8]);
            }

            let compressed_addr = Self::compress_addr(addr);
            hasher.update(&compressed_addr);
            hasher.update(&left[..N]);
            hasher.update(&right[..N]);

            let result = hasher.finalize();
            out.copy_from_slice(&result[..N]);
        } else {
            // Use SHA-512 for SHA2-192s/192f and SHA2-256s/256f
            // All SHA2 variants use the 22-byte compressed address (ADRSc)
            let padding_len = 128 - N;
            let mut hasher = Sha512::new();

            hasher.update(&pk_seed[..N]);
            for _ in 0..padding_len {
                hasher.update(&[0u8]);
            }

            let compressed_addr = Self::compress_addr(addr);
            hasher.update(&compressed_addr);

            hasher.update(&left[..N]);
            hasher.update(&right[..N]);

            let result = hasher.finalize();
            out.copy_from_slice(&result[..N]);
        }
    }

    #[inline]
    fn f(&self, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(input.len(), N);
        debug_assert_eq!(out.len(), N);

        // F: SHA-256(toByte(0, 64-n) || PK.seed || ADRS || M)
        // Same as T_l
        self.t_leaf(pk_seed, addr, input, out);
    }

    #[inline]
    fn t_leaf_batch(&self, pk_seed: &[u8], addr: &[u8; 32], inputs: &[&[u8]], out: &mut [u8]) {
        debug_assert_eq!(pk_seed.len(), N);
        debug_assert_eq!(out.len(), N);

        // Batch hash: T_l(pk_seed, padding, ADRSc, input[0] || input[1] || ... || input[n-1])
        // For N=16: SHA-256 with 64-N padding
        // For N=24,32: SHA-512 with 128-N padding

        if N == 16 {
            // Use SHA-256 for SHA2-128s/128f
            let padding_len = 64 - N;
            let mut hasher = Sha256::new();

            hasher.update(&pk_seed[..N]);
            for _ in 0..padding_len {
                hasher.update(&[0u8]);
            }

            let compressed_addr = Self::compress_addr(addr);
            hasher.update(&compressed_addr);

            // Hash all inputs together (batched)
            for input in inputs {
                debug_assert_eq!(input.len(), N);
                hasher.update(&input[..N]);
            }

            let result = hasher.finalize();
            out.copy_from_slice(&result[..N]);
        } else {
            // Use SHA-512 for SHA2-192s/192f and SHA2-256s/256f
            // All SHA2 variants use the 22-byte compressed address (ADRSc)
            let padding_len = 128 - N;
            let mut hasher = Sha512::new();

            hasher.update(&pk_seed[..N]);
            for _ in 0..padding_len {
                hasher.update(&[0u8]);
            }

            let compressed_addr = Self::compress_addr(addr);
            hasher.update(&compressed_addr);

            // Hash all inputs together (batched)
            for input in inputs {
                debug_assert_eq!(input.len(), N);
                hasher.update(&input[..N]);
            }

            let result = hasher.finalize();
            out.copy_from_slice(&result[..N]);
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

    fn prf_with_context(&self, ctx: &mut Self::Context, pk_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32], out: &mut [u8]) {
        // Reset and reuse context
        ctx.hasher = Sha256::new();

        let padding_len = 64 - N;
        ctx.hasher.update(&pk_seed[..N]);
        for _ in 0..padding_len {
            ctx.hasher.update(&[0u8]);
        }

        if N == 32 {
            ctx.hasher.update(addr);
        } else {
            let compressed_addr = Sha2HashFunction::<N>::compress_addr(addr);
            ctx.hasher.update(&compressed_addr);
        }

        ctx.hasher.update(&sk_seed[..N]);

        let result = ctx.hasher.finalize_reset();
        out.copy_from_slice(&result[..N]);
    }

    fn f_with_context(&self, ctx: &mut Self::Context, pk_seed: &[u8], addr: &[u8; 32], input: &[u8], out: &mut [u8]) {
        ctx.hasher = Sha256::new();

        let padding_len = 64 - N;
        ctx.hasher.update(&pk_seed[..N]);
        for _ in 0..padding_len {
            ctx.hasher.update(&[0u8]);
        }

        if N == 32 {
            ctx.hasher.update(addr);
        } else {
            let compressed_addr = Sha2HashFunction::<N>::compress_addr(addr);
            ctx.hasher.update(&compressed_addr);
        }

        ctx.hasher.update(&input[..N]);

        let result = ctx.hasher.finalize_reset();
        out.copy_from_slice(&result[..N]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_basic() {
        let hash_fn = Sha2HashFunction::<16>::new();
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let addr = [0u8; 32];
        let mut out = [0u8; 16];

        hash_fn.prf(&pk_seed, &sk_seed, &addr, &mut out);

        // Output should be deterministic
        let mut out2 = [0u8; 16];
        hash_fn.prf(&pk_seed, &sk_seed, &addr, &mut out2);
        assert_eq!(out, out2);

        // Different address should give different output
        let addr2 = [1u8; 32];
        let mut out3 = [0u8; 16];
        hash_fn.prf(&pk_seed, &sk_seed, &addr2, &mut out3);
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

        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let addr = [0u8; 32];
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];

        // Using context
        hash_fn.prf_with_context(&mut ctx, &pk_seed, &sk_seed, &addr, &mut out1);

        // Without context
        hash_fn.prf(&pk_seed, &sk_seed, &addr, &mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_msg_hmac() {
        // Test that PRF_msg produces valid output for N=16 (HMAC-SHA-256)
        let hash_fn = Sha2HashFunction::<16>::new();
        let sk_prf = [0x01u8; 16];
        let opt_rand = [0x02u8; 16];
        let msg = b"test message";
        let mut out = [0u8; 16];

        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out);
        assert_ne!(out, [0u8; 16]);

        // Test determinism
        let mut out2 = [0u8; 16];
        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_prf_msg_hmac_sha512() {
        // Test that PRF_msg produces valid output for N=32 (HMAC-SHA-512)
        let hash_fn = Sha2HashFunction::<32>::new();
        let sk_prf = [0x01u8; 32];
        let opt_rand = [0x02u8; 32];
        let msg = b"test message";
        let mut out = [0u8; 32];

        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out);
        assert_ne!(out, [0u8; 32]);

        // Test determinism
        let mut out2 = [0u8; 32];
        hash_fn.prf_msg(&sk_prf, &opt_rand, msg, &mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_h_msg_sha512() {
        // Test that H_msg for N=32 uses SHA-512
        let hash_fn = Sha2HashFunction::<32>::new();
        let r = [0x01u8; 32];
        let pk_seed = [0x02u8; 32];
        let pk_root = [0x03u8; 32];
        let ctx: &[u8] = &[];
        let msg = b"test message";
        let mut out = [0u8; 48]; // FORS_MSG_BYTES + 8 for SHA2-256f

        hash_fn.h_msg(&r, &pk_seed, &pk_root, ctx, msg, &mut out);
        assert_ne!(out, [0u8; 48]);

        // Test determinism
        let mut out2 = [0u8; 48];
        hash_fn.h_msg(&r, &pk_seed, &pk_root, ctx, msg, &mut out2);
        assert_eq!(out, out2);
    }
}
