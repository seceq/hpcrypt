//! BLAKE3 cryptographic hash function
//!
//! High-performance implementation of BLAKE3, a fast and secure hash function
//! based on a tree structure and optimized permutation function.
//!
//! # Features
//!
//! - Single-pass Merkle tree construction
//! - Unlimited output length (XOF mode)
//! - Keyed hash and key derivation modes
//! - Highly parallelizable
//!
//! # Examples
//!
//! ```
//! use hpcrypt_hash::blake3::{Blake3, blake3};
//!
//! // One-shot hashing
//! let hash = blake3(b"hello world");
//!
//! // Incremental hashing
//! let mut hasher = Blake3::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let hash = hasher.finalize();
//! ```

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

/// Optimal buffer size for streaming operations (16 KiB)
///
/// This size provides high throughput with efficient chunk batching
/// and good CPU cache utilization.
///
/// # Example
///
/// ```no_run
/// use hpcrypt_hash::blake3::{Blake3, OPTIMAL_BUF_SIZE};
/// use std::fs::File;
/// use std::io::{BufReader, Read};
///
/// fn hash_file(path: &str) -> std::io::Result<[u8; 32]> {
///     let file = File::open(path)?;
///     let mut reader = BufReader::with_capacity(OPTIMAL_BUF_SIZE, file);
///     let mut hasher = Blake3::new();
///     let mut buffer = vec![0u8; OPTIMAL_BUF_SIZE];
///
///     loop {
///         let n = reader.read(&mut buffer)?;
///         if n == 0 { break; }
///         hasher.update(&buffer[..n]);
///     }
///
///     Ok(hasher.finalize())
/// }
/// ```
pub const OPTIMAL_BUF_SIZE: usize = 16 * 1024;

/// Minimum recommended buffer size for streaming operations (4 KiB)
///
/// Suitable when memory is constrained but reasonable performance is still desired.
pub const MIN_BUF_SIZE: usize = 4 * 1024;

/// Maximum useful buffer size for single-threaded hashing (64 KiB)
///
/// Buffers larger than this provide no additional performance benefit
/// for single-threaded operations.
pub const MAX_USEFUL_BUF_SIZE: usize = 64 * 1024;

/// BLAKE3 initialization vector
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Domain separation flags
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

/// Message schedule permutation
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Perform one BLAKE3 round (column step + diagonal step)
macro_rules! blake3_round {
    ($v:expr, $m0:expr, $m1:expr, $m2:expr, $m3:expr, $m4:expr, $m5:expr, $m6:expr, $m7:expr,
             $m8:expr, $m9:expr, $m10:expr, $m11:expr, $m12:expr, $m13:expr, $m14:expr, $m15:expr) => {
        // Column step
        Output::g(&mut $v, 0, 4, 8, 12, $m0, $m1);
        Output::g(&mut $v, 1, 5, 9, 13, $m2, $m3);
        Output::g(&mut $v, 2, 6, 10, 14, $m4, $m5);
        Output::g(&mut $v, 3, 7, 11, 15, $m6, $m7);

        // Diagonal step
        Output::g(&mut $v, 0, 5, 10, 15, $m8, $m9);
        Output::g(&mut $v, 1, 6, 11, 12, $m10, $m11);
        Output::g(&mut $v, 2, 7, 8, 13, $m12, $m13);
        Output::g(&mut $v, 3, 4, 9, 14, $m14, $m15);
    };
}

/// Convert 16 u32 words from byte slice
macro_rules! words_from_bytes {
    ($block:expr) => {{
        [
            read_u32_le(&$block[0..4]),
            read_u32_le(&$block[4..8]),
            read_u32_le(&$block[8..12]),
            read_u32_le(&$block[12..16]),
            read_u32_le(&$block[16..20]),
            read_u32_le(&$block[20..24]),
            read_u32_le(&$block[24..28]),
            read_u32_le(&$block[28..32]),
            read_u32_le(&$block[32..36]),
            read_u32_le(&$block[36..40]),
            read_u32_le(&$block[40..44]),
            read_u32_le(&$block[44..48]),
            read_u32_le(&$block[48..52]),
            read_u32_le(&$block[52..56]),
            read_u32_le(&$block[56..60]),
            read_u32_le(&$block[60..64]),
        ]
    }};
}

/// Convert 16 u32 words to bytes
macro_rules! words_to_bytes {
    ($words:expr, $block:expr) => {{
        write_u32_le(&mut $block[0..4], $words[0]);
        write_u32_le(&mut $block[4..8], $words[1]);
        write_u32_le(&mut $block[8..12], $words[2]);
        write_u32_le(&mut $block[12..16], $words[3]);
        write_u32_le(&mut $block[16..20], $words[4]);
        write_u32_le(&mut $block[20..24], $words[5]);
        write_u32_le(&mut $block[24..28], $words[6]);
        write_u32_le(&mut $block[28..32], $words[7]);
        write_u32_le(&mut $block[32..36], $words[8]);
        write_u32_le(&mut $block[36..40], $words[9]);
        write_u32_le(&mut $block[40..44], $words[10]);
        write_u32_le(&mut $block[44..48], $words[11]);
        write_u32_le(&mut $block[48..52], $words[12]);
        write_u32_le(&mut $block[52..56], $words[13]);
        write_u32_le(&mut $block[56..60], $words[14]);
        write_u32_le(&mut $block[60..64], $words[15]);
    }};
}

/// Write first 32 bytes (8 words) directly to output
macro_rules! write_first_32_bytes {
    ($words:expr, $out:expr) => {{
        write_u32_le(&mut $out[0..4], $words[0]);
        write_u32_le(&mut $out[4..8], $words[1]);
        write_u32_le(&mut $out[8..12], $words[2]);
        write_u32_le(&mut $out[12..16], $words[3]);
        write_u32_le(&mut $out[16..20], $words[4]);
        write_u32_le(&mut $out[20..24], $words[5]);
        write_u32_le(&mut $out[24..28], $words[6]);
        write_u32_le(&mut $out[28..32], $words[7]);
    }};
}

/// Construct parent block words from two chaining values
macro_rules! parent_block_words {
    ($left:expr, $right:expr) => {
        [
            $left[0], $left[1], $left[2], $left[3],
            $left[4], $left[5], $left[6], $left[7],
            $right[0], $right[1], $right[2], $right[3],
            $right[4], $right[5], $right[6], $right[7],
        ]
    };
}

/// Merge with one parent from stack
macro_rules! merge_parent {
    ($self:expr, $cv:expr) => {{
        $self.cv_stack_len -= 1;
        $self.parent_output(
            $self.cv_stack[$self.cv_stack_len],
            $cv
        ).chaining_value()
    }};
}

/// Push chaining value to stack
macro_rules! push_cv {
    ($self:expr, $cv:expr) => {{
        $self.cv_stack[$self.cv_stack_len] = $cv;
        $self.cv_stack_len += 1;
    }};
}

#[inline(always)]
const fn counter_low(counter: u64) -> u32 {
    counter as u32
}

#[inline(always)]
const fn counter_high(counter: u64) -> u32 {
    (counter >> 32) as u32
}

/// BLAKE3 compression function output
#[derive(Clone, Copy)]
#[repr(C)]
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u8,
}

impl Output {
    #[inline(always)]
    const fn flags_as_u32(&self) -> u32 {
        self.flags as u32
    }

    #[inline(always)]
    const fn flags_with_root(&self) -> u32 {
        (self.flags | ROOT) as u32
    }

    #[inline(always)]
    fn select_counter(&self, output_block_counter: u64) -> u64 {
        let is_root = ((self.flags & ROOT) != 0) as u64;
        let mask = is_root.wrapping_neg();
        (output_block_counter & mask) | (self.counter & !mask)
    }

    #[inline(always)]
    fn xor_finalize_chaining(state: &[u32; 16], out: &mut [u32; 8]) {
        out[0] = state[0] ^ state[8];
        out[1] = state[1] ^ state[9];
        out[2] = state[2] ^ state[10];
        out[3] = state[3] ^ state[11];
        out[4] = state[4] ^ state[12];
        out[5] = state[5] ^ state[13];
        out[6] = state[6] ^ state[14];
        out[7] = state[7] ^ state[15];
    }

    #[inline(always)]
    fn xor_finalize_full(state: &mut [u32; 16], input_cv: &[u32; 8]) {
        state[0] ^= state[8];
        state[1] ^= state[9];
        state[2] ^= state[10];
        state[3] ^= state[11];
        state[4] ^= state[12];
        state[5] ^= state[13];
        state[6] ^= state[14];
        state[7] ^= state[15];

        state[8] ^= input_cv[0];
        state[9] ^= input_cv[1];
        state[10] ^= input_cv[2];
        state[11] ^= input_cv[3];
        state[12] ^= input_cv[4];
        state[13] ^= input_cv[5];
        state[14] ^= input_cv[6];
        state[15] ^= input_cv[7];
    }

    #[inline(always)]
    fn chaining_value(&self) -> [u32; 8] {
        let mut cv = self.input_chaining_value;
        self.compress(&mut cv);
        cv
    }

    #[inline]
    fn root_output_bytes(&self, out: &mut [u8]) {
        let len = out.len();

        match len {
            32 => {
                let words = self.compress_full(0);
                write_first_32_bytes!(words, out);
            }
            64 => {
                let words = self.compress_full(0);
                words_to_bytes!(words, out);
            }
            128 => {
                let words1 = self.compress_full(0);
                words_to_bytes!(words1, out[0..64]);
                let words2 = self.compress_full(1);
                words_to_bytes!(words2, out[64..128]);
            }
            256 => {
                let words1 = self.compress_full(0);
                words_to_bytes!(words1, out[0..64]);
                let words2 = self.compress_full(1);
                words_to_bytes!(words2, out[64..128]);
                let words3 = self.compress_full(2);
                words_to_bytes!(words3, out[128..192]);
                let words4 = self.compress_full(3);
                words_to_bytes!(words4, out[192..256]);
            }
            _ => {
                self.root_output_bytes_general(out);
            }
        }
    }

    #[inline(never)]
    fn root_output_bytes_general(&self, out: &mut [u8]) {
        let len = out.len();
        let mut offset = 0;
        let mut output_block_counter = 0u64;

        while offset + 64 <= len {
            let words = self.compress_full(output_block_counter);
            words_to_bytes!(words, out[offset..offset + 64]);
            offset += 64;
            output_block_counter += 1;
        }

        if offset < len {
            let words = self.compress_full(output_block_counter);
            let mut block = [0u8; 64];
            words_to_bytes!(words, block);
            let remaining = len - offset;
            out[offset..].copy_from_slice(&block[..remaining]);
        }
    }

    fn compress_full(&self, counter: u64) -> [u32; 16] {
        let cv = &self.input_chaining_value;
        let mut v = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
            IV[0], IV[1], IV[2], IV[3],
            counter_low(counter),
            counter_high(counter),
            self.block_len,
            self.flags_with_root(),
        ];

        let m = self.block_words;

        blake3_round!(v, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7],
                         m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);

        blake3_round!(v, m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
                         m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8]);

        blake3_round!(v, m[3], m[4], m[10], m[12], m[13], m[2], m[7], m[14],
                         m[6], m[5], m[9], m[0], m[11], m[15], m[8], m[1]);

        blake3_round!(v, m[10], m[7], m[12], m[9], m[14], m[3], m[13], m[15],
                         m[4], m[0], m[11], m[2], m[5], m[8], m[1], m[6]);

        blake3_round!(v, m[12], m[13], m[9], m[11], m[15], m[10], m[14], m[8],
                         m[7], m[2], m[5], m[3], m[0], m[1], m[6], m[4]);

        blake3_round!(v, m[9], m[14], m[11], m[5], m[8], m[12], m[15], m[1],
                         m[13], m[3], m[0], m[10], m[2], m[6], m[4], m[7]);

        blake3_round!(v, m[11], m[15], m[5], m[0], m[1], m[9], m[8], m[6],
                         m[14], m[10], m[2], m[12], m[3], m[4], m[7], m[13]);

        Self::xor_finalize_full(&mut v, &self.input_chaining_value);

        v
    }

    #[inline(always)]
    fn compress(&self, state: &mut [u32; 8]) {
        self.compress_with_counter(state, 0);
    }

    fn compress_with_counter(&self, state: &mut [u32; 8], output_block_counter: u64) {
        let counter = self.select_counter(output_block_counter);

        let mut v = [
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            IV[0], IV[1], IV[2], IV[3],
            counter_low(counter),
            counter_high(counter),
            self.block_len,
            self.flags_as_u32(),
        ];

        let m = self.block_words;

        blake3_round!(v, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7],
                         m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);

        blake3_round!(v, m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13],
                         m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8]);

        blake3_round!(v, m[3], m[4], m[10], m[12], m[13], m[2], m[7], m[14],
                         m[6], m[5], m[9], m[0], m[11], m[15], m[8], m[1]);

        blake3_round!(v, m[10], m[7], m[12], m[9], m[14], m[3], m[13], m[15],
                         m[4], m[0], m[11], m[2], m[5], m[8], m[1], m[6]);

        blake3_round!(v, m[12], m[13], m[9], m[11], m[15], m[10], m[14], m[8],
                         m[7], m[2], m[5], m[3], m[0], m[1], m[6], m[4]);

        blake3_round!(v, m[9], m[14], m[11], m[5], m[8], m[12], m[15], m[1],
                         m[13], m[3], m[0], m[10], m[2], m[6], m[4], m[7]);

        blake3_round!(v, m[11], m[15], m[5], m[0], m[1], m[9], m[8], m[6],
                         m[14], m[10], m[2], m[12], m[3], m[4], m[7], m[13]);

        Self::xor_finalize_chaining(&v, state);
    }

    /// BLAKE3 mixing function G
    #[inline(always)]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        let mut va = v[a];
        let mut vb = v[b];
        let mut vc = v[c];
        let mut vd = v[d];

        va = va.wrapping_add(vb).wrapping_add(mx);
        vd = (vd ^ va).rotate_right(16);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(12);

        va = va.wrapping_add(vb).wrapping_add(my);
        vd = (vd ^ va).rotate_right(8);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(7);

        v[a] = va;
        v[b] = vb;
        v[c] = vc;
        v[d] = vd;
    }
}

/// BLAKE3 chunk state
#[derive(Clone)]
#[repr(C)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block_len: u8,
    blocks_compressed: u8,
    flags: u8,
    block: [u8; BLOCK_LEN],
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u8) -> Self {
        Self {
            chaining_value: *key,
            chunk_counter,
            block_len: 0,
            blocks_compressed: 0,
            flags,
            block: [0; BLOCK_LEN],
        }
    }

    #[inline(always)]
    fn reset(&mut self, key: &[u32; 8], chunk_counter: u64, flags: u8) {
        self.chaining_value = *key;
        self.chunk_counter = chunk_counter;
        self.block_len = 0;
        self.blocks_compressed = 0;
        self.flags = flags;
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

    #[inline]
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_bytes!(self.block);

                let output = Output {
                    input_chaining_value: self.chaining_value,
                    block_words,
                    counter: self.chunk_counter,
                    block_len: BLOCK_LEN as u32,
                    flags: self.flags | self.start_flag(),
                };

                self.chaining_value = output.chaining_value();
                self.blocks_compressed += 1;
                self.block_len = 0;
            }

            let block_offset = self.block_len as usize;
            let want = BLOCK_LEN - block_offset;
            let take = want.min(input.len());

            self.block[block_offset..block_offset + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        let block_len = self.block_len as usize;

        let full_words = block_len / 4;

        for i in 0..full_words {
            block_words[i] = read_u32_le(&self.block[i * 4..(i + 1) * 4]);
        }

        if block_len % 4 != 0 {
            let mut word_bytes = [0u8; 4];
            let start = full_words * 4;
            let remaining = block_len - start;
            word_bytes[..remaining].copy_from_slice(&self.block[start..block_len]);
            block_words[full_words] = read_u32_le(&word_bytes);
        }

        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/// BLAKE3 hasher state
#[derive(Clone)]
#[repr(C)]
pub struct Blake3 {
    cv_stack_len: usize,
    flags: u8,
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; 54],
}

impl Blake3 {
    /// Internal method: create a new BLAKE3 hasher
    fn new_internal() -> Self {
        Self {
            cv_stack_len: 0,
            flags: 0,
            chunk_state: ChunkState::new(&IV, 0, 0),
            key: IV,
            cv_stack: [[0u32; 8]; 54],
        }
    }

    /// Create a new BLAKE3 hasher with a key for MAC mode
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = read_u32_le(&key[i * 4..(i + 1) * 4]);
        }

        Self {
            cv_stack_len: 0,
            flags: KEYED_HASH,
            chunk_state: ChunkState::new(&key_words, 0, KEYED_HASH),
            key: key_words,
            cv_stack: [[0u32; 8]; 54],
        }
    }

    /// Create a new BLAKE3 key derivation context
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_hasher = Self {
            cv_stack_len: 0,
            flags: DERIVE_KEY_CONTEXT,
            chunk_state: ChunkState::new(&IV, 0, DERIVE_KEY_CONTEXT),
            key: IV,
            cv_stack: [[0u32; 8]; 54],
        };
        context_hasher.update_internal(context.as_bytes());

        // Get the root hash output (32 bytes) and convert to words
        let context_hash = context_hasher.finalize_internal();
        let mut context_key = [0u32; 8];
        for i in 0..8 {
            context_key[i] = read_u32_le(&context_hash[i * 4..(i + 1) * 4]);
        }

        Self {
            cv_stack_len: 0,
            flags: DERIVE_KEY_MATERIAL,
            chunk_state: ChunkState::new(&context_key, 0, DERIVE_KEY_MATERIAL),
            key: context_key,
            cv_stack: [[0u32; 8]; 54],
        }
    }

    /// Internal method: update the hasher with input data
    #[inline]
    fn update_internal(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state.reset(&self.key, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    #[inline(always)]
    fn add_chunk_chaining_value(&mut self, cv: [u32; 8], total_chunks: u64) {
        let merge_count = total_chunks.trailing_zeros() as usize;

        match merge_count {
            0 => {
                push_cv!(self, cv);
            }
            1 => {
                let merged = merge_parent!(self, cv);
                push_cv!(self, merged);
            }
            2 => {
                self.cv_stack_len -= 1;
                let merged1 = self.parent_output(
                    self.cv_stack[self.cv_stack_len],
                    cv
                ).chaining_value();
                self.cv_stack_len -= 1;
                let merged2 = self.parent_output(
                    self.cv_stack[self.cv_stack_len],
                    merged1
                ).chaining_value();
                push_cv!(self, merged2);
            }
            _ => {
                let mut new_cv = cv;
                for _ in 0..merge_count {
                    new_cv = merge_parent!(self, new_cv);
                }
                push_cv!(self, new_cv);
            }
        }
    }

    fn parent_cv(&self, left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
        self.parent_output(left, right).chaining_value()
    }

    #[inline]
    fn parent_output(&self, left: [u32; 8], right: [u32; 8]) -> Output {
        Output {
            input_chaining_value: self.key,
            block_words: parent_block_words!(left, right),
            counter: 0,
            block_len: BLOCK_LEN as u32,
            flags: self.flags | PARENT,
        }
    }

    #[inline]
    fn finalize_to_output(&self) -> Output {
        let mut output = self.chunk_state.output();

        match self.cv_stack_len {
            0 => {
                output
            }
            1 => {
                self.parent_output(self.cv_stack[0], output.chaining_value())
            }
            2 => {
                // Two parent merges (unrolled) - process in reverse order
                output = self.parent_output(self.cv_stack[1], output.chaining_value());
                self.parent_output(self.cv_stack[0], output.chaining_value())
            }
            _ => {
                for i in (0..self.cv_stack_len).rev() {
                    output = self.parent_output(self.cv_stack[i], output.chaining_value());
                }
                output
            }
        }
    }

    #[inline]
    fn finalize_words(&self) -> [u32; 8] {
        self.finalize_to_output().chaining_value()
    }

    /// Internal method: finalize and return the hash
    #[inline]
    fn finalize_internal(self) -> [u8; OUT_LEN] {
        let output = self.finalize_to_output();
        let mut out = [0u8; OUT_LEN];
        output.root_output_bytes(&mut out);
        out
    }

    /// Finalize and return arbitrary-length output (XOF mode)
    pub fn finalize_xof(self, length: usize) -> Vec<u8> {
        let output = self.finalize_to_output();
        let mut out = vec![0u8; length];
        output.root_output_bytes(&mut out);
        out
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new_internal()
    }
}

impl crate::traits::HashFunction for Blake3 {
    type Output = [u8; OUT_LEN];
    const OUTPUT_SIZE: usize = OUT_LEN;
    const BLOCK_SIZE: usize = BLOCK_LEN;

    #[inline]
    fn new() -> Self {
        Self::new_internal()
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.update_internal(data)
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        self.finalize_internal()
    }

    #[inline]
    fn finalize_reset(&mut self) -> Self::Output {
        let clone = self.clone();
        *self = Self::new();
        clone.finalize_internal()
    }
}

/// One-shot BLAKE3 hash
pub fn blake3(data: &[u8]) -> [u8; OUT_LEN] {
    use crate::traits::HashFunction;
    Blake3::hash(data)
}

/// One-shot BLAKE3 keyed hash
pub fn blake3_keyed(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Blake3::new_keyed(key);
    hasher.update_internal(data);
    hasher.finalize_internal()
}

/// One-shot BLAKE3 key derivation
pub fn blake3_derive_key(context: &str, key_material: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Blake3::new_derive_key(context);
    hasher.update_internal(key_material);
    hasher.finalize_xof(output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_empty() {
        let hash = blake3(b"");
        let expected =
            hex_literal::hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_hello() {
        let hash = blake3(b"hello world");
        let expected =
            hex_literal::hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_incremental() {
        use crate::traits::HashFunction;
        let data = b"The quick brown fox jumps over the lazy dog";

        let hash1 = blake3(data);

        let mut hasher = Blake3::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_xof() {
        use crate::traits::HashFunction;
        let data = b"test";
        let mut hasher = Blake3::new();
        hasher.update(data);

        let xof_64 = hasher.clone().finalize_xof(64);
        let xof_32 = hasher.finalize_xof(32);

        assert_eq!(&xof_64[..32], &xof_32[..]);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; KEY_LEN];
        let data = b"keyed hash test";

        let hash = blake3_keyed(&key, data);

        let unkeyed = blake3(data);
        assert_ne!(hash, unkeyed);
    }

    #[test]
    fn test_blake3_multi_chunk_2k() {
        use crate::traits::HashFunction;
        let data = vec![0xABu8; 2048];

        let hash1 = blake3(&data);

        let mut hasher = Blake3::new();
        hasher.update(&data[..1024]);
        hasher.update(&data[1024..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);

        let expected =
            hex_literal::hex!("5ce2bb471d0c7dddfa641ef980c1bb11dfda024dd5a5e647cf9eb150f9684f5c");
        assert_eq!(hash1, expected);
    }

    #[test]
    fn test_blake3_multi_chunk_5k() {
        let data = vec![0x42u8; 5120];

        let hash = blake3(&data);

        let expected =
            hex_literal::hex!("0633d9f3a4a212819dd3bd6b257241e141362101838e1d83a88bdafee45c1f0f");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_multi_chunk_incremental() {
        use crate::traits::HashFunction;
        let data = vec![0x55u8; 3000];

        let hash1 = blake3(&data);

        let mut hasher = Blake3::new();
        hasher.update(&data[..500]);
        hasher.update(&data[500..1500]);
        hasher.update(&data[1500..]);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_multi_chunk_xof() {
        use crate::traits::HashFunction;
        let data = vec![0x77u8; 2048];

        let mut hasher = Blake3::new();
        hasher.update(&data);

        let xof_128 = hasher.clone().finalize_xof(128);
        let xof_64 = hasher.finalize_xof(64);

        assert_eq!(&xof_128[..64], &xof_64[..]);
        assert_eq!(xof_128.len(), 128);
        assert_eq!(xof_64.len(), 64);
    }

    #[test]
    fn test_blake3_exact_chunk_boundary() {
        use crate::traits::HashFunction;
        let data = vec![0x99u8; 1024];

        let hash1 = blake3(&data);

        let mut hasher = Blake3::new();
        hasher.update(&data);
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_multi_chunk_keyed() {
        let key = [0xCDu8; KEY_LEN];
        let data = vec![0xEFu8; 3072];

        let hash = blake3_keyed(&key, &data);

        let unkeyed = blake3(&data);
        assert_ne!(hash, unkeyed);
    }
}
