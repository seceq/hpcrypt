//! BLAKE3 cryptographic hash function
//!
//! High-performance implementation of BLAKE3, a fast and secure hash function.
//! BLAKE3 is designed for maximum parallelism and achieves exceptional performance
//! through a tree structure and optimized permutation function.
//!
//! Target performance: 3 GB/s single-thread, 15.8 GB/s with multi-threading
//!
//! Key features:
//! - Single-pass Merkle tree construction
//! - Unlimited output length (XOF mode)
//! - Keyed hash and key derivation modes
//! - Highly parallelizable

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_core::utils::{read_u32_le, write_u32_le};

/// BLAKE3 output size in bytes (256 bits)
pub const OUT_LEN: usize = 32;

/// BLAKE3 key size in bytes (256 bits)
pub const KEY_LEN: usize = 32;

/// BLAKE3 block size in bytes
pub const BLOCK_LEN: usize = 64;

/// BLAKE3 chunk size in bytes
pub const CHUNK_LEN: usize = 1024;

/// BLAKE3 initialization vector (first 8 words of SHA-256 IV)
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Domain separation flags
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

/// Message schedule permutation for BLAKE3
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// BLAKE3 compression function output
#[derive(Clone, Copy)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u8,
}

impl Output {
    /// Generate chaining value (first 8 words of output)
    fn chaining_value(&self) -> [u32; 8] {
        let mut cv = self.input_chaining_value;
        self.compress(&mut cv);
        [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7]]
    }

    /// Generate root output bytes
    fn root_output_bytes(&self, out: &mut [u8]) {
        let mut offset = 0;
        let mut output_block_counter = 0u64;

        while offset < out.len() {
            let words = self.compress_full(output_block_counter);

            // Convert 16 words to bytes
            let mut block = [0u8; 64];
            for i in 0..16 {
                write_u32_le(&mut block[i * 4..(i + 1) * 4], words[i]);
            }

            let take = (out.len() - offset).min(64);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
            output_block_counter += 1;
        }
    }

    /// Perform full compression returning all 16 words
    fn compress_full(&self, counter: u64) -> [u32; 16] {
        // Initialize state
        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&self.input_chaining_value);
        v[8..16].copy_from_slice(&IV);
        v[12] = counter as u32;
        v[13] = (counter >> 32) as u32;
        v[14] = self.block_len;
        let flags_with_root = self.flags | ROOT;
        v[15] = flags_with_root as u32;

        // 7 rounds of mixing with in-place block permutation
        // Python reference permutes the message block IN-PLACE between rounds
        let mut block = self.block_words;

        for _round in 0..7 {
            // Column step
            Self::g(&mut v, 0, 4, 8, 12, block[0], block[1]);
            Self::g(&mut v, 1, 5, 9, 13, block[2], block[3]);
            Self::g(&mut v, 2, 6, 10, 14, block[4], block[5]);
            Self::g(&mut v, 3, 7, 11, 15, block[6], block[7]);

            // Diagonal step
            Self::g(&mut v, 0, 5, 10, 15, block[8], block[9]);
            Self::g(&mut v, 1, 6, 11, 12, block[10], block[11]);
            Self::g(&mut v, 2, 7, 8, 13, block[12], block[13]);
            Self::g(&mut v, 3, 4, 9, 14, block[14], block[15]);

            // Permute block for next round (MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8])
            let original = block;
            block = [
                original[2], original[6], original[3], original[10],
                original[7], original[0], original[4], original[13],
                original[1], original[11], original[12], original[5],
                original[9], original[14], original[15], original[8],
            ];
        }

        // XOR the two halves for full output
        // Need to save v[8..16] before modifying for correct XOR
        let v_high = [v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]];

        for i in 0..8 {
            v[i] ^= v_high[i];
            v[i + 8] = v_high[i] ^ self.input_chaining_value[i];
        }

        v
    }

    /// Perform BLAKE3 compression
    #[inline(always)]
    fn compress(&self, state: &mut [u32; 8]) {
        self.compress_with_counter(state, 0);
    }

    /// Perform BLAKE3 compression with output block counter
    fn compress_with_counter(&self, state: &mut [u32; 8], output_block_counter: u64) {
        let counter = if self.flags & ROOT != 0 {
            output_block_counter
        } else {
            self.counter
        };

        // Initialize state
        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(state);
        v[8..16].copy_from_slice(&IV);
        v[12] = counter as u32;
        v[13] = (counter >> 32) as u32;
        v[14] = self.block_len;
        v[15] = self.flags as u32;

        // 7 rounds of mixing
        for round in 0..7 {
            let schedule = &MSG_SCHEDULE[round];

            // Column step
            Self::g(&mut v, 0, 4, 8, 12, self.block_words[schedule[0]], self.block_words[schedule[1]]);
            Self::g(&mut v, 1, 5, 9, 13, self.block_words[schedule[2]], self.block_words[schedule[3]]);
            Self::g(&mut v, 2, 6, 10, 14, self.block_words[schedule[4]], self.block_words[schedule[5]]);
            Self::g(&mut v, 3, 7, 11, 15, self.block_words[schedule[6]], self.block_words[schedule[7]]);

            // Diagonal step
            Self::g(&mut v, 0, 5, 10, 15, self.block_words[schedule[8]], self.block_words[schedule[9]]);
            Self::g(&mut v, 1, 6, 11, 12, self.block_words[schedule[10]], self.block_words[schedule[11]]);
            Self::g(&mut v, 2, 7, 8, 13, self.block_words[schedule[12]], self.block_words[schedule[13]]);
            Self::g(&mut v, 3, 4, 9, 14, self.block_words[schedule[14]], self.block_words[schedule[15]]);
        }

        // XOR state with compressed output (first 8 words only for chaining_value)
        for i in 0..8 {
            state[i] = v[i] ^ v[i + 8];
            // Note: we don't need v[i+8] ^ input_cv[i] for chaining_value(),
            // only for full 16-word output in compress_full()
        }
    }

    /// BLAKE3 mixing function G
    #[inline(always)]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
}

/// BLAKE3 chunk state
#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u8) -> Self {
        Self {
            chaining_value: *key,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [0u32; 16];
                for i in 0..16 {
                    block_words[i] = read_u32_le(&self.block[i * 4..(i + 1) * 4]);
                }

                let output = Output {
                    input_chaining_value: self.chaining_value,
                    block_words,
                    counter: self.chunk_counter,
                    block_len: BLOCK_LEN as u32,
                    flags: self.flags | self.start_flag(),
                };

                self.chaining_value = output.chaining_value();
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        for i in 0..16 {
            if i * 4 < self.block_len as usize {
                let end = ((i + 1) * 4).min(self.block_len as usize);
                let mut word_bytes = [0u8; 4];
                word_bytes[..end - i * 4].copy_from_slice(&self.block[i * 4..end]);
                block_words[i] = read_u32_le(&word_bytes);
            }
        }

        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/// BLAKE3 hasher state
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; 54], // log2(2^64 / 1024) = 54 max depth
    cv_stack_len: usize,
    flags: u8,
}

impl Blake3 {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(&IV, 0, 0),
            key: IV,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags: 0,
        }
    }

    /// Create a new BLAKE3 hasher with a key (for MAC)
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = read_u32_le(&key[i * 4..(i + 1) * 4]);
        }

        Self {
            chunk_state: ChunkState::new(&key_words, 0, KEYED_HASH),
            key: key_words,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags: KEYED_HASH,
        }
    }

    /// Create a new BLAKE3 key derivation context
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self {
            chunk_state: ChunkState::new(&IV, 0, DERIVE_KEY_CONTEXT),
            key: IV,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags: DERIVE_KEY_CONTEXT,
        };
        context_hasher.update(context.as_bytes());
        let context_key = context_hasher.finalize_words();

        Self {
            chunk_state: ChunkState::new(&context_key, 0, DERIVE_KEY_MATERIAL),
            key: context_key,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags: DERIVE_KEY_MATERIAL,
        }
    }

    /// Update the hasher with input data
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Add a chunk chaining value to the tree
    fn add_chunk_chaining_value(&mut self, cv: [u32; 8], total_chunks: u64) {
        // Merge subtrees from the stack
        let mut new_cv = cv;
        let mut total = total_chunks;

        while total & 1 == 0 {
            self.cv_stack_len -= 1;
            new_cv = self.parent_cv(self.cv_stack[self.cv_stack_len], new_cv);
            total >>= 1;
        }

        self.cv_stack[self.cv_stack_len] = new_cv;
        self.cv_stack_len += 1;
    }

    /// Compute parent chaining value
    fn parent_cv(&self, left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
        self.parent_output(left, right).chaining_value()
    }

    /// Create parent output node
    fn parent_output(&self, left: [u32; 8], right: [u32; 8]) -> Output {
        let mut block_words = [0u32; 16];
        block_words[0..8].copy_from_slice(&left);
        block_words[8..16].copy_from_slice(&right);

        Output {
            input_chaining_value: self.key,
            block_words,
            counter: 0,
            block_len: BLOCK_LEN as u32,
            flags: self.flags | PARENT,
        }
    }

    /// Finalize and return the hash as words
    fn finalize_words(&self) -> [u32; 8] {
        let mut cv = self.chunk_state.output().chaining_value();

        // Merge remaining stack from right to left
        for i in (0..self.cv_stack_len).rev() {
            cv = self.parent_cv(self.cv_stack[i], cv);
        }

        cv
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> [u8; OUT_LEN] {
        // Starting with the Output from the current chunk, compute all the
        // parent outputs along the right edge of the tree, until we have the root Output.
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len;

        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = self.parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
            );
        }

        let mut out = [0u8; OUT_LEN];
        output.root_output_bytes(&mut out);
        out
    }

    /// Finalize and return arbitrary-length output (XOF mode)
    pub fn finalize_xof(self, length: usize) -> Vec<u8> {
        // Same tree-merging logic as finalize()
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len;

        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = self.parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
            );
        }

        let mut out = vec![0u8; length];
        output.root_output_bytes(&mut out);
        out
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot BLAKE3 hash
pub fn blake3(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake3::new();
    hasher.update(data);
    hasher.finalize()
}

/// One-shot BLAKE3 keyed hash
pub fn blake3_keyed(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake3::new_keyed(key);
    hasher.update(data);
    hasher.finalize()
}

/// One-shot BLAKE3 key derivation
pub fn blake3_derive_key(context: &str, key_material: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Blake3::new_derive_key(context);
    hasher.update(key_material);
    hasher.finalize_xof(output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_empty() {
        let hash = blake3(b"");
        let expected = hex_literal::hex!(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_hello() {
        let hash = blake3(b"hello world");
        let expected = hex_literal::hex!(
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let hash1 = blake3(data);

        // Incremental
        let mut hasher = Blake3::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_xof() {
        let data = b"test";
        let mut hasher = Blake3::new();
        hasher.update(data);

        let xof_64 = hasher.clone().finalize_xof(64);
        let xof_32 = hasher.finalize_xof(32);

        // First 32 bytes should match
        assert_eq!(&xof_64[..32], &xof_32[..]);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; KEY_LEN];
        let data = b"keyed hash test";

        let hash = blake3_keyed(&key, data);

        // Should differ from unkeyed hash
        let unkeyed = blake3(data);
        assert_ne!(hash, unkeyed);
    }

    #[test]
    fn test_blake3_multi_chunk_2k() {
        // Test with 2KB input (2 chunks)
        let data = vec![0xABu8; 2048];

        // One-shot
        let hash1 = blake3(&data);

        // Incremental
        let mut hasher = Blake3::new();
        hasher.update(&data[..1024]);
        hasher.update(&data[1024..]);
        let hash2 = hasher.finalize();

        // One-shot and incremental should match
        assert_eq!(hash1, hash2);

        // Expected hash for 2KB of 0xAB bytes (verified against official BLAKE3)
        let expected = hex_literal::hex!(
            "5ce2bb471d0c7dddfa641ef980c1bb11dfda024dd5a5e647cf9eb150f9684f5c"
        );
        assert_eq!(hash1, expected);
    }

    #[test]
    fn test_blake3_multi_chunk_5k() {
        // Test with 5KB input (5 chunks) - creates deeper tree
        let data = vec![0x42u8; 5120];

        let hash = blake3(&data);

        // Expected hash for 5KB of 0x42 bytes (verified against official BLAKE3)
        let expected = hex_literal::hex!(
            "0633d9f3a4a212819dd3bd6b257241e141362101838e1d83a88bdafee45c1f0f"
        );
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_multi_chunk_incremental() {
        // Test incremental hashing with varying chunk boundaries
        let data = vec![0x55u8; 3000];

        // One-shot
        let hash1 = blake3(&data);

        // Incremental with different boundaries
        let mut hasher = Blake3::new();
        hasher.update(&data[..500]);
        hasher.update(&data[500..1500]);
        hasher.update(&data[1500..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_multi_chunk_xof() {
        // Test XOF mode with multi-chunk input
        let data = vec![0x77u8; 2048];

        let mut hasher = Blake3::new();
        hasher.update(&data);

        let xof_128 = hasher.clone().finalize_xof(128);
        let xof_64 = hasher.finalize_xof(64);

        // First 64 bytes should match
        assert_eq!(&xof_128[..64], &xof_64[..]);
        assert_eq!(xof_128.len(), 128);
        assert_eq!(xof_64.len(), 64);
    }

    #[test]
    fn test_blake3_exact_chunk_boundary() {
        // Test exactly 1024 bytes (boundary case)
        let data = vec![0x99u8; 1024];

        let hash1 = blake3(&data);

        let mut hasher = Blake3::new();
        hasher.update(&data);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_multi_chunk_keyed() {
        // Test keyed hash with multi-chunk input
        let key = [0xCDu8; KEY_LEN];
        let data = vec![0xEFu8; 3072]; // 3 chunks

        let hash = blake3_keyed(&key, &data);

        // Should differ from unkeyed
        let unkeyed = blake3(&data);
        assert_ne!(hash, unkeyed);
    }
}
