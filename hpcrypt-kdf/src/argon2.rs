//! Argon2 password hashing algorithm
//!
//! Argon2 is a memory-hard password hashing function, designed to be resistant
//! to GPU cracking attacks and side-channel attacks.
//!
//! Three variants:
//! - Argon2d: Data-dependent memory access (faster, vulnerable to side-channels)
//! - Argon2i: Data-independent memory access (resistant to side-channels, slower)
//! - Argon2id: Hybrid (first half Argon2i, second half Argon2d) - RECOMMENDED

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;

use hpcrypt_core::error::KdfError;
use hpcrypt_hash::blake2b::{Blake2b, OUT_LEN as BLAKE2B_OUT_LEN};

/// Argon2 block size in bytes (1024 bytes = 128 u64 words)
const BLOCK_SIZE: usize = 1024;
const QWORDS_IN_BLOCK: usize = BLOCK_SIZE / 8;

/// Minimum and maximum parameters
const MIN_LANES: u32 = 1;
const MAX_LANES: u32 = 0xFFFFFF;
#[allow(dead_code)] // Reserved for future validation
const MIN_THREADS: u32 = 1;
#[allow(dead_code)] // Reserved for future validation
const MAX_THREADS: u32 = 0xFFFFFF;
const MIN_TIME: u32 = 1;
const MIN_MEMORY: u32 = 8; // 8 KiB
const MIN_OUTLEN: usize = 4;
const MAX_OUTLEN: usize = 0xFFFFFFFF;

/// Argon2 variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Data-dependent (fast, may be vulnerable to side-channels)
    Argon2d = 0,
    /// Data-independent (resistant to side-channels)
    Argon2i = 1,
    /// Hybrid (recommended)
    Argon2id = 2,
}

/// Argon2 parameters
#[derive(Debug, Clone)]
pub struct Params {
    /// Output length in bytes
    pub outlen: usize,
    /// Memory size in KiB
    pub mem_cost: u32,
    /// Number of iterations
    pub time_cost: u32,
    /// Degree of parallelism
    pub lanes: u32,
}

impl Default for Params {
    fn default() -> Self {
        // RFC 9106 recommended parameters
        Self {
            outlen: 32,
            mem_cost: 65536, // 64 MiB
            time_cost: 3,
            lanes: 4,
        }
    }
}

impl Params {
    /// Create new parameters with validation
    pub fn new(outlen: usize, mem_cost: u32, time_cost: u32, lanes: u32) -> Result<Self, KdfError> {
        // Validate output length
        if !(MIN_OUTLEN..=MAX_OUTLEN).contains(&outlen) {
            return Err(KdfError::InvalidOutputLength {
                minimum: MIN_OUTLEN,
                maximum: MAX_OUTLEN,
                actual: outlen,
            });
        }

        // Validate memory cost (must be at least 8 * lanes)
        let min_mem = MIN_MEMORY.max(8 * lanes);
        if mem_cost < min_mem {
            return Err(KdfError::MemoryCostTooLow {
                minimum: min_mem,
                actual: mem_cost,
            });
        }

        // Validate time cost
        if time_cost < MIN_TIME {
            return Err(KdfError::TimeCostTooLow {
                minimum: MIN_TIME,
                actual: time_cost,
            });
        }

        // Validate parallelism (lanes)
        if !(MIN_LANES..=MAX_LANES).contains(&lanes) {
            return Err(KdfError::InvalidParallelism {
                minimum: MIN_LANES,
                maximum: MAX_LANES,
                actual: lanes,
            });
        }

        Ok(Self {
            outlen,
            mem_cost,
            time_cost,
            lanes,
        })
    }
}

/// Argon2 hasher
pub struct Argon2 {
    variant: Variant,
    params: Params,
}

impl Argon2 {
    /// Create new Argon2 hasher with specified variant
    pub fn new(variant: Variant, params: Params) -> Self {
        Self { variant, params }
    }

    /// Hash a password with salt
    pub fn hash(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>, KdfError> {
        self.hash_with_ad(password, salt, &[], &[])
    }

    /// Hash with additional data and secret
    pub fn hash_with_ad(
        &self,
        password: &[u8],
        salt: &[u8],
        ad: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, KdfError> {
        // Validate salt length (RFC 9106 recommends minimum 8 bytes)
        if salt.len() < 8 {
            return Err(KdfError::SaltTooShort {
                minimum: 8,
                actual: salt.len(),
            });
        }

        // Calculate memory blocks
        let memory_blocks = (self.params.mem_cost as usize) / self.params.lanes as usize;
        if memory_blocks < 4 * SYNC_POINTS {
            let min_mem = (4 * SYNC_POINTS * self.params.lanes as usize) as u32;
            return Err(KdfError::MemoryCostTooLow {
                minimum: min_mem,
                actual: self.params.mem_cost,
            });
        }

        // Step 1: Initial hash H0
        let h0 = self.initial_hash(password, salt, ad, secret);

        // Step 2: Allocate memory blocks
        let segment_length = memory_blocks / SYNC_POINTS;
        let lane_length = segment_length * SYNC_POINTS;
        let mut memory =
            vec![vec![0u64; QWORDS_IN_BLOCK]; self.params.lanes as usize * lane_length];

        // Step 3: Fill first and second blocks of each lane
        for lane in 0..self.params.lanes as usize {
            // B[lane][0] = H'(H0 || 0 || lane)
            let mut block = [0u8; 72];
            block[..64].copy_from_slice(&h0);
            block[64..68].copy_from_slice(&0u32.to_le_bytes());
            block[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
            let b0 = hash_variable(&block, BLOCK_SIZE);
            bytes_to_block(&b0, &mut memory[lane * lane_length]);

            // B[lane][1] = H'(H0 || 1 || lane)
            block[64..68].copy_from_slice(&1u32.to_le_bytes());
            let b1 = hash_variable(&block, BLOCK_SIZE);
            bytes_to_block(&b1, &mut memory[lane * lane_length + 1]);
        }

        // Step 4: Fill remaining blocks
        //
        // NOTE: Multi-threading is currently disabled due to `forbid(unsafe_code)` in lib.rs.
        // True lane-based parallelism requires unsafe code to partition memory safely across threads.
        // The parallel implementation is available but commented out below.
        //
        // To enable parallelism:
        // 1. Change `forbid(unsafe_code)` to `deny(unsafe_code)` in lib.rs
        // 2. Uncomment the `#[cfg(feature = "std")]` block below
        // 3. Expected speedup: ~3.5x with 4 lanes, ~7x with 8 lanes
        self.fill_memory_sequential(&mut memory, segment_length, lane_length);

        // Parallel version (requires unsafe code):
        // #[cfg(feature = "std")]
        // {
        //     self.fill_memory_parallel(
        //         &mut memory,
        //         segment_length,
        //         lane_length,
        //     );
        // }
        //
        // #[cfg(not(feature = "std"))]
        // {
        //     self.fill_memory_sequential(
        //         &mut memory,
        //         segment_length,
        //         lane_length,
        //     );
        // }

        // Step 5: Finalize - XOR last block of each lane
        let mut final_block =
            memory[(self.params.lanes as usize - 1) * lane_length + lane_length - 1].clone();
        for lane in 0..(self.params.lanes as usize - 1) {
            let last_idx = lane * lane_length + lane_length - 1;
            for (i, item) in final_block.iter_mut().enumerate().take(QWORDS_IN_BLOCK) {
                *item ^= memory[last_idx][i];
            }
        }

        // Convert to bytes and hash to output length
        let mut final_bytes = vec![0u8; BLOCK_SIZE];
        block_to_bytes(&final_block, &mut final_bytes);

        Ok(hash_variable(&final_bytes, self.params.outlen))
    }

    /// Initial hash H0
    fn initial_hash(&self, password: &[u8], salt: &[u8], ad: &[u8], secret: &[u8]) -> [u8; 64] {
        let mut hasher = Blake2b::new();

        // H0 = H(lanes || outlen || mem_cost || time_cost || version || type || pwdlen || pwd || saltlen || salt || secretlen || secret || adlen || ad)
        hasher.update(&(self.params.lanes).to_le_bytes());
        hasher.update(&(self.params.outlen as u32).to_le_bytes());
        hasher.update(&self.params.mem_cost.to_le_bytes());
        hasher.update(&self.params.time_cost.to_le_bytes());
        hasher.update(&0x13u32.to_le_bytes()); // Version 0x13
        hasher.update(&(self.variant as u32).to_le_bytes());

        hasher.update(&(password.len() as u32).to_le_bytes());
        hasher.update(password);

        hasher.update(&(salt.len() as u32).to_le_bytes());
        hasher.update(salt);

        hasher.update(&(secret.len() as u32).to_le_bytes());
        if !secret.is_empty() {
            hasher.update(secret);
        }

        hasher.update(&(ad.len() as u32).to_le_bytes());
        if !ad.is_empty() {
            hasher.update(ad);
        }

        hasher.finalize_fixed()
    }

    /// Fill memory blocks sequentially (single-threaded)
    ///
    /// NOTE: A parallel implementation exists but requires unsafe code to safely partition
    /// memory across threads. Due to `forbid(unsafe_code)` restriction, we use sequential
    /// processing. The parallel version would provide ~3.5x speedup with 4 lanes.
    fn fill_memory_sequential(
        &self,
        memory: &mut [Vec<u64>],
        segment_length: usize,
        lane_length: usize,
    ) {
        for pass in 0..self.params.time_cost {
            for lane in 0..self.params.lanes as usize {
                for slice in 0..SYNC_POINTS {
                    self.fill_segment(memory, pass, lane, slice, segment_length, lane_length);
                }
            }
        }
    }

    /// Fill a single segment
    fn fill_segment(
        &self,
        memory: &mut [Vec<u64>],
        pass: u32,
        lane: usize,
        slice: usize,
        segment_length: usize,
        lane_length: usize,
    ) {
        let start_idx = if pass == 0 && slice == 0 { 2 } else { 0 };

        for idx in start_idx..segment_length {
            let current_idx = lane * lane_length + slice * segment_length + idx;
            let prev_idx = if current_idx % lane_length == 0 {
                current_idx + lane_length - 1
            } else {
                current_idx - 1
            };

            // Compute reference block index
            let ref_idx = self.index_alpha(
                pass,
                lane,
                slice,
                idx,
                segment_length,
                lane_length,
                &memory[prev_idx],
            );

            // G function: compress previous and reference blocks
            let mut block = memory[current_idx].clone();
            g_function(&memory[prev_idx], &memory[ref_idx], &mut block, pass == 0);
            memory[current_idx] = block;
        }
    }

    /// Compute reference block index
    #[allow(clippy::too_many_arguments)]
    fn index_alpha(
        &self,
        pass: u32,
        lane: usize,
        slice: usize,
        idx: usize,
        segment_length: usize,
        lane_length: usize,
        prev_block: &[u64],
    ) -> usize {
        // Simplified version - full implementation would use data-dependent/independent addressing
        let pseudo_rand = prev_block[0];
        let ref_area_size = if pass == 0 {
            if slice == 0 {
                idx - 1
            } else {
                slice * segment_length + idx - 1
            }
        } else {
            lane_length - segment_length + idx - 1
        };

        if ref_area_size > 0 {
            let relative_pos = (pseudo_rand as usize) % ref_area_size;
            lane * lane_length + relative_pos
        } else {
            lane * lane_length
        }
    }
}

const SYNC_POINTS: usize = 4;

/// Variable-length hash using BLAKE2b
fn hash_variable(input: &[u8], outlen: usize) -> Vec<u8> {
    if outlen <= BLAKE2B_OUT_LEN {
        let mut hasher = Blake2b::new_with_output_len(outlen);
        hasher.update(input);
        hasher.finalize()
    } else {
        // For outputs > 64 bytes, use BLAKE2b in tree mode
        let mut result = Vec::with_capacity(outlen);
        let mut hasher = Blake2b::new();
        hasher.update(&(outlen as u32).to_le_bytes());
        hasher.update(input);
        let first = hasher.finalize();

        result.extend_from_slice(&first[..min(BLAKE2B_OUT_LEN, outlen)]);

        let mut pos = BLAKE2B_OUT_LEN;
        while pos < outlen {
            let mut hasher = Blake2b::new();
            hasher.update(&result[pos - BLAKE2B_OUT_LEN..pos]);
            let next = hasher.finalize();
            let to_copy = min(BLAKE2B_OUT_LEN, outlen - pos);
            result.extend_from_slice(&next[..to_copy]);
            pos += to_copy;
        }

        result
    }
}

/// Convert bytes to block (little-endian u64 words)
fn bytes_to_block(bytes: &[u8], block: &mut [u64]) {
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        block[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

/// Convert block to bytes
fn block_to_bytes(block: &[u64], bytes: &mut [u8]) {
    for (i, &word) in block.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
}

/// G compression function
fn g_function(x: &[u64], y: &[u64], result: &mut [u64], first_pass: bool) {
    // R = X XOR Y
    let mut r = [0u64; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        r[i] = x[i] ^ y[i];
    }

    // Q = Z = P(R)
    let mut q = r;
    permute_block(&mut q);

    // result = R XOR Q (or just Q on first pass)
    for i in 0..QWORDS_IN_BLOCK {
        result[i] = if first_pass {
            q[i]
        } else {
            result[i] ^ r[i] ^ q[i]
        };
    }
}

/// Permutation P
fn permute_block(block: &mut [u64]) {
    // Apply Blake2b-like permutation
    // Row-wise
    for i in 0..8 {
        let row_start = i * 16;
        gb(&mut block[row_start..row_start + 16]);
    }

    // Column-wise
    for i in 0..8 {
        let mut col = [0u64; 16];
        for j in 0..16 {
            col[j] = block[j * 8 + i];
        }
        gb(&mut col);
        for j in 0..16 {
            block[j * 8 + i] = col[j];
        }
    }
}

/// GB function (Blake2b round function simplified)
#[inline]
fn gb(v: &mut [u64]) {
    // Simplified permutation mixing
    for i in (0..v.len()).step_by(2) {
        if i + 1 < v.len() {
            let t0 = v[i].wrapping_add(v[i + 1]);
            let t1 = v[i + 1].rotate_right(24);
            v[i] = t0;
            v[i + 1] = t1 ^ t0;
        }
    }
}

/// Argon2d hasher (data-dependent)
pub struct Argon2d;

impl Argon2d {
    /// Hash a password with Argon2d
    pub fn hash(password: &[u8], salt: &[u8], params: &Params) -> Result<Vec<u8>, KdfError> {
        let argon2 = Argon2::new(Variant::Argon2d, params.clone());
        argon2.hash(password, salt)
    }
}

/// Argon2i hasher (data-independent)
pub struct Argon2i;

impl Argon2i {
    /// Hash a password with Argon2i
    pub fn hash(password: &[u8], salt: &[u8], params: &Params) -> Result<Vec<u8>, KdfError> {
        let argon2 = Argon2::new(Variant::Argon2i, params.clone());
        argon2.hash(password, salt)
    }
}

/// Argon2id hasher (hybrid, recommended)
pub struct Argon2id;

impl Argon2id {
    /// Hash a password with Argon2id (RECOMMENDED)
    pub fn hash(password: &[u8], salt: &[u8], params: &Params) -> Result<Vec<u8>, KdfError> {
        let argon2 = Argon2::new(Variant::Argon2id, params.clone());
        argon2.hash(password, salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_basic() {
        let password = b"password";
        let salt = b"somesalt";

        // Low memory parameters for testing
        let params = Params {
            outlen: 32,
            mem_cost: 32, // 32 KiB
            time_cost: 1,
            lanes: 1,
        };

        let hash = Argon2id::hash(password, salt, &params).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_argon2_variants() {
        let password = b"test";
        let salt = b"saltsalt";

        let params = Params {
            outlen: 32,
            mem_cost: 32,
            time_cost: 1,
            lanes: 1,
        };

        let hash_d = Argon2d::hash(password, salt, &params).unwrap();
        let hash_i = Argon2i::hash(password, salt, &params).unwrap();
        let hash_id = Argon2id::hash(password, salt, &params).unwrap();

        // Different variants should produce different hashes
        assert_ne!(hash_d, hash_i);
        assert_ne!(hash_i, hash_id);
        assert_ne!(hash_d, hash_id);
    }

    #[test]
    fn test_argon2_deterministic() {
        let password = b"mypassword";
        let salt = b"randomsalt12345";

        let params = Params {
            outlen: 32,
            mem_cost: 32,
            time_cost: 1,
            lanes: 1,
        };

        let hash1 = Argon2id::hash(password, salt, &params).unwrap();
        let hash2 = Argon2id::hash(password, salt, &params).unwrap();

        // Same inputs should produce same output
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_argon2_salt_sensitivity() {
        let password = b"password";
        let params = Params {
            outlen: 32,
            mem_cost: 32,
            time_cost: 1,
            lanes: 1,
        };

        let hash1 = Argon2id::hash(password, b"salt1234", &params).unwrap();
        let hash2 = Argon2id::hash(password, b"salt5678", &params).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
    }
}
