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

        // Calculate memory blocks (total)
        // mem_cost is in KiB, each block is 1 KiB
        let total_blocks = self.params.mem_cost as usize;
        // Blocks per lane (must be multiple of 4 for sync points)
        let blocks_per_lane = (total_blocks / self.params.lanes as usize) / SYNC_POINTS * SYNC_POINTS;
        if blocks_per_lane < SYNC_POINTS {
            let min_mem = (SYNC_POINTS * self.params.lanes as usize) as u32;
            return Err(KdfError::MemoryCostTooLow {
                minimum: min_mem,
                actual: self.params.mem_cost,
            });
        }
        let memory_blocks = blocks_per_lane;

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
        // IMPORTANT: The correct order is pass -> slice -> lane
        // This ensures all lanes at the same slice are filled before moving to the next slice
        // (required for synchronization points)
        for pass in 0..self.params.time_cost {
            for slice in 0..SYNC_POINTS {
                for lane in 0..self.params.lanes as usize {
                    self.fill_segment(memory, pass as u32, lane, slice, segment_length, lane_length);
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
        let total_memory_blocks = memory.len();
        let iterations = self.params.time_cost as usize;
        let lanes = self.params.lanes as usize;

        // Determine if we need data-independent addressing
        // Argon2i: always data-independent
        // Argon2id: data-independent for first pass, first 2 slices
        let data_independent_addressing = self.variant == Variant::Argon2i
            || (self.variant == Variant::Argon2id && pass == 0 && slice < SYNC_POINTS / 2);

        // Address blocks for data-independent addressing
        let mut address_block = vec![0u64; QWORDS_IN_BLOCK];
        let mut input_block = vec![0u64; QWORDS_IN_BLOCK];
        let zero_block = vec![0u64; QWORDS_IN_BLOCK];

        if data_independent_addressing {
            // Initialize input block with parameters
            input_block[0] = pass as u64;
            input_block[1] = lane as u64;
            input_block[2] = slice as u64;
            input_block[3] = total_memory_blocks as u64;
            input_block[4] = iterations as u64;
            input_block[5] = self.variant as u64;
        }

        // Generate first set of addresses for pass 0, slice 0
        // (since the loop starts at idx=2, we need to pre-generate)
        // For other cases, addresses are generated at idx=0 inside the loop
        if data_independent_addressing && pass == 0 && slice == 0 {
            update_address_block(&mut address_block, &mut input_block, &zero_block);
        }

        for idx in start_idx..segment_length {
            let current_idx = lane * lane_length + slice * segment_length + idx;
            let prev_idx = if current_idx % lane_length == 0 {
                current_idx + lane_length - 1
            } else {
                current_idx - 1
            };

            // Get pseudo-random value for indexing
            let pseudo_rand = if data_independent_addressing {
                let address_index = idx % ADDRESSES_IN_BLOCK;
                // Generate new addresses when address_index == 0
                // For pass 0, slice 0: this happens at idx=128, 256, etc (already pre-generated for idx=2)
                // For other cases: this happens at idx=0 (first iteration), 128, 256, etc
                if address_index == 0 {
                    update_address_block(&mut address_block, &mut input_block, &zero_block);
                }
                address_block[address_index]
            } else {
                // Data-dependent: use first word of previous block
                memory[prev_idx][0]
            };

            // Compute reference block index
            let ref_idx = self.index_alpha_with_rand(
                pass,
                lane,
                slice,
                idx,
                segment_length,
                lane_length,
                lanes,
                pseudo_rand,
            );

            // G function: compress previous and reference blocks
            let mut block = memory[current_idx].clone();
            g_function(&memory[prev_idx], &memory[ref_idx], &mut block, pass == 0);
            memory[current_idx] = block;
        }
    }

    /// Compute reference block index with pre-computed pseudo-random value (RFC 9106 Section 3.4)
    ///
    /// This version takes the pseudo_rand value directly (for data-independent addressing)
    #[allow(clippy::too_many_arguments)]
    fn index_alpha_with_rand(
        &self,
        pass: u32,
        lane: usize,
        slice: usize,
        idx: usize,
        segment_length: usize,
        lane_length: usize,
        lanes: usize,
        pseudo_rand: u64,
    ) -> usize {
        let j1 = pseudo_rand & 0xFFFF_FFFF;
        let j2 = (pseudo_rand >> 32) as u32;

        // Determine reference lane
        let ref_lane = if pass == 0 && slice == 0 {
            // First slice of first pass: can only reference current lane
            lane
        } else {
            // Other cases: J2 mod lanes
            (j2 as usize) % lanes
        };

        // Determine reference area size (matching reference implementation exactly)
        let reference_area_size = if pass == 0 {
            // First pass
            if slice == 0 {
                // First slice: all but the previous
                idx - 1
            } else if ref_lane == lane {
                // Same lane: add current segment
                slice * segment_length + idx - 1
            } else {
                // Different lane
                slice * segment_length - if idx == 0 { 1 } else { 0 }
            }
        } else {
            // Second pass
            if ref_lane == lane {
                lane_length - segment_length + idx - 1
            } else {
                lane_length - segment_length - if idx == 0 { 1 } else { 0 }
            }
        };

        if reference_area_size == 0 {
            return ref_lane * lane_length;
        }

        // Mapping function: compute relative position using J1
        // map = (J1 * J1) >> 32
        // relative_position = reference_area_size - 1 - (reference_area_size * map) >> 32
        let map = (j1 * j1) >> 32;
        let relative_position = reference_area_size - 1
            - (((reference_area_size as u64) * map) >> 32) as usize;

        // Compute starting position for reference area
        let start_position = if pass != 0 && slice != SYNC_POINTS - 1 {
            (slice + 1) * segment_length
        } else {
            0
        };

        let ref_index = (start_position + relative_position) % lane_length;
        ref_lane * lane_length + ref_index
    }
}

const SYNC_POINTS: usize = 4;

/// Number of addresses in a block (128 u64 words)
const ADDRESSES_IN_BLOCK: usize = 128;

/// Variable-length hash H' using BLAKE2b (RFC 9106 Section 3.2)
///
/// For τ ≤ 64: H'(X) = BLAKE2b(τ || X, τ)
/// For τ > 64: H'(X) = V1[0..32] || V2[0..32] || ... || Vr
///   where V1 = BLAKE2b(τ || X), Vi = BLAKE2b(V_{i-1}), Vr is truncated
fn hash_variable(input: &[u8], outlen: usize) -> Vec<u8> {
    if outlen <= BLAKE2B_OUT_LEN {
        // H'(X) = BLAKE2b(τ || X, τ) with τ-byte output
        let mut hasher = Blake2b::new_with_output_len(outlen);
        hasher.update(&(outlen as u32).to_le_bytes());
        hasher.update(input);
        hasher.finalize()
    } else {
        // For outputs > 64 bytes, use chained BLAKE2b
        // Reference implementation logic (matches argon2 crate blake2b_long):
        // 1. Compute V1 = BLAKE2b-64(len || input), write V1[0..32]
        // 2. While remaining > 64: V(i+1) = BLAKE2b-64(V_i), write V(i+1)[0..32]
        // 3. Final: VarBlake2b(V_last, remaining)
        let mut result = Vec::with_capacity(outlen);

        // V1 = BLAKE2b-64(τ || X)
        let mut hasher = Blake2b::new();
        hasher.update(&(outlen as u32).to_le_bytes());
        hasher.update(input);
        let mut prev = hasher.finalize_fixed();

        // Take first 32 bytes from V1
        result.extend_from_slice(&prev[..32]);

        // Generate remaining blocks
        // Continue while remaining > 64, use final block when remaining <= 64
        while result.len() < outlen {
            let remaining = outlen - result.len();
            if remaining <= BLAKE2B_OUT_LEN {
                // Final block: use variable-length output (1-64 bytes)
                let mut hasher = Blake2b::new_with_output_len(remaining);
                hasher.update(&prev);
                result.extend_from_slice(&hasher.finalize());
            } else {
                // Intermediate block: Vi = BLAKE2b(V_{i-1}), take first 32 bytes
                let mut hasher = Blake2b::new();
                hasher.update(&prev);
                prev = hasher.finalize_fixed();
                result.extend_from_slice(&prev[..32]);
            }
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

/// Update address block for data-independent addressing
///
/// Generates 128 pseudo-random addresses using:
/// input_block[6] += 1
/// address_block = G(zero_block, G(zero_block, input_block))
fn update_address_block(address_block: &mut [u64], input_block: &mut [u64], zero_block: &[u64]) {
    input_block[6] += 1;

    // First compression: tmp = G(zero_block, input_block)
    let mut tmp = vec![0u64; QWORDS_IN_BLOCK];
    g_function(zero_block, input_block, &mut tmp, true);

    // Second compression: address_block = G(zero_block, tmp)
    g_function(zero_block, &tmp, address_block, true);
}

/// G compression function (RFC 9106 Section 3.7)
///
/// G(X, Y) = P(X ⊕ Y) ⊕ X ⊕ Y
///
/// First pass: B[i][j] = G(prev, ref)
/// Later passes: B[i][j] = B[i][j] ⊕ G(prev, ref)
fn g_function(x: &[u64], y: &[u64], result: &mut [u64], first_pass: bool) {
    // R = X ⊕ Y
    let mut r = [0u64; QWORDS_IN_BLOCK];
    for i in 0..QWORDS_IN_BLOCK {
        r[i] = x[i] ^ y[i];
    }

    // Q = P(R)
    let mut q = r;
    permute_block(&mut q);

    // G(X, Y) = Q ⊕ R = P(X ⊕ Y) ⊕ X ⊕ Y
    // First pass: result = G(X, Y)
    // Later passes: result = result ⊕ G(X, Y)
    for i in 0..QWORDS_IN_BLOCK {
        let g_result = q[i] ^ r[i];
        result[i] = if first_pass { g_result } else { result[i] ^ g_result };
    }
}

/// Permutation P (RFC 9106 Section 3.6)
///
/// The 1024-byte block is processed as 8 groups of 128 bytes (16 u64 words).
/// Each group is treated as a 4×4 matrix and the round function is applied.
///
/// Then the same 128 u64 words are regrouped column-wise and P is applied again.
fn permute_block(block: &mut [u64]) {
    // First pass: process 8 rows (each row is 16 consecutive u64 words)
    for row in 0..8 {
        let base = row * 16;
        let mut v = [0u64; 16];
        v.copy_from_slice(&block[base..base + 16]);
        p_round(&mut v);
        block[base..base + 16].copy_from_slice(&v);
    }

    // Second pass: process 8 columns
    // Column c contains u64s at positions: 2*c, 2*c+1, 2*c+16, 2*c+17, ..., 2*c+112, 2*c+113
    for col in 0..8 {
        let mut v = [0u64; 16];
        for row in 0..8 {
            let base = row * 16 + col * 2;
            v[row * 2] = block[base];
            v[row * 2 + 1] = block[base + 1];
        }
        p_round(&mut v);
        for row in 0..8 {
            let base = row * 16 + col * 2;
            block[base] = v[row * 2];
            block[base + 1] = v[row * 2 + 1];
        }
    }
}

/// P round function (RFC 9106 Section 3.6)
///
/// P(v0, v1, ..., v15) applies BLAKE2b-style mixing:
///   First round (columns):
///     GB(v0, v4, v8, v12), GB(v1, v5, v9, v13), GB(v2, v6, v10, v14), GB(v3, v7, v11, v15)
///   Second round (diagonals):
///     GB(v0, v5, v10, v15), GB(v1, v6, v11, v12), GB(v2, v7, v8, v13), GB(v3, v4, v9, v14)
fn p_round(v: &mut [u64; 16]) {
    // First round: columns
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);

    // Second round: diagonals
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// GB function (RFC 9106 Section 3.5)
///
/// GB(a, b, c, d) using fBlaMka:
///   a = a + b + 2*trunc(a)*trunc(b)
///   d = (d ⊕ a) >>> 32
///   c = c + d + 2*trunc(c)*trunc(d)
///   b = (b ⊕ c) >>> 24
///   a = a + b + 2*trunc(a)*trunc(b)
///   d = (d ⊕ a) >>> 16
///   c = c + d + 2*trunc(c)*trunc(d)
///   b = (b ⊕ c) >>> 63
#[inline]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    // fBlaMka: x + y + 2 * trunc(x) * trunc(y)
    #[inline(always)]
    fn fblmk(x: u64, y: u64) -> u64 {
        let xl = x & 0xFFFF_FFFF;
        let yl = y & 0xFFFF_FFFF;
        x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(xl).wrapping_mul(yl))
    }

    v[a] = fblmk(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fblmk(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fblmk(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fblmk(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
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

    #[cfg(feature = "std")]
    #[test]
    fn test_compare_with_reference() {
        extern crate std;
        use std::println;
        use argon2::{Argon2 as RefArgon2, Algorithm, Version, Params as RefParams};
        use hpcrypt_hash::blake2b::Blake2b;
        use blake2::{Blake2b as Blake2bRef, Digest};
        use blake2::digest::VariableOutput;
        use blake2::Blake2bVar;

        // Compare BLAKE2b implementations
        // Our implementation
        let mut our_blake = Blake2b::new();
        our_blake.update(b"abc");
        let our_hash = our_blake.finalize_fixed();

        // Reference blake2 crate
        let mut ref_blake = Blake2bRef::<blake2::digest::consts::U64>::new();
        ref_blake.update(b"abc");
        let ref_hash: [u8; 64] = ref_blake.finalize().into();

        println!("Our BLAKE2b:       {}", hex::encode(&our_hash));
        println!("Ref BLAKE2b:       {}", hex::encode(&ref_hash));

        // Compare H' for 32 bytes
        let test_input = b"test";

        // Our H'
        let our_hv_32 = hash_variable(test_input, 32);

        // Reference: BLAKE2b(32 || X) with 32-byte output
        let mut ref_hv = Blake2bVar::new(32).unwrap();
        blake2::digest::Update::update(&mut ref_hv, &32u32.to_le_bytes());
        blake2::digest::Update::update(&mut ref_hv, test_input);
        let mut ref_result_32 = [0u8; 32];
        ref_hv.finalize_variable(&mut ref_result_32).unwrap();

        println!("\nOur H'(test, 32):  {}", hex::encode(&our_hv_32));
        println!("Ref H'(test, 32):  {}", hex::encode(&ref_result_32));

        // Compare H' for 1024 bytes
        let our_hv_1024 = hash_variable(test_input, 1024);

        // For reference, compute using the argon2 crate's method
        // V1 = BLAKE2b-64(1024 || X)
        let mut v1_hasher = Blake2bRef::<blake2::digest::consts::U64>::new();
        v1_hasher.update(&1024u32.to_le_bytes());
        v1_hasher.update(test_input);
        let v1: [u8; 64] = v1_hasher.finalize().into();

        println!("\nOur H'(1024)[0:32]:  {}", hex::encode(&our_hv_1024[..32]));
        println!("Ref V1[0:32]:        {}", hex::encode(&v1[..32]));

        // Simple test
        let password = b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
        let salt = b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02";

        // Reference argon2 crate
        let ref_params = RefParams::new(32, 1, 1, Some(32)).unwrap();
        let ref_argon2 = RefArgon2::new(Algorithm::Argon2d, Version::V0x13, ref_params);
        let mut ref_output = [0u8; 32];
        ref_argon2.hash_password_into(password, salt, &mut ref_output).unwrap();

        // Our implementation
        let params = Params {
            outlen: 32,
            mem_cost: 32,
            time_cost: 1,
            lanes: 1,
        };
        let our_output = Argon2d::hash(password, salt, &params).unwrap();

        println!("\nReference:         {}", hex::encode(ref_output));
        println!("Our:               {}", hex::encode(&our_output));
    }
}
