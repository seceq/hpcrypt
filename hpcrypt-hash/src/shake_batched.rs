//! Batched 4-way SHAKE-128 and SHAKE-256 implementations.
//!
//! Provides parallel processing of 4 independent SHAKE instances for improved
//! throughput in applications like ML-DSA that require many XOF evaluations.
//!
//! # Example
//!
//! ```
//! use hpcrypt_hash::shake_batched::{Shake128x4, Shake256x4};
//!
//! let inputs: [&[u8]; 4] = [b"input0", b"input1", b"input2", b"input3"];
//! let outputs: [[u8; 64]; 4] = Shake128x4::hash_x4(&inputs);
//! ```

use crate::sha3::STATE_SIZE;

/// Keccak-f[1600] round constants.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// SHAKE-128 rate in bytes (1344 bits).
pub const SHAKE128_RATE: usize = 168;

/// SHAKE-256 rate in bytes (1088 bits).
pub const SHAKE256_RATE: usize = 136;

/// SHAKE domain separation byte (0x1F per FIPS 202).
const SHAKE_DOMAIN_SEP: u8 = 0x1F;

/// 4-way parallel Keccak state.
///
/// Contains 4 independent 1600-bit Keccak states for parallel processing.
#[derive(Clone)]
#[repr(C, align(64))]
pub struct KeccakState4 {
    /// Four independent Keccak states.
    pub states: [[u64; STATE_SIZE]; 4],
}

impl Default for KeccakState4 {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakState4 {
    /// Creates a new zeroed 4-way Keccak state.
    #[inline]
    pub fn new() -> Self {
        Self {
            states: [[0u64; STATE_SIZE]; 4],
        }
    }

    /// Resets all 4 states to zero.
    #[inline]
    pub fn reset(&mut self) {
        for state in &mut self.states {
            *state = [0u64; STATE_SIZE];
        }
    }

    /// Applies Keccak-f[1600] permutation to all 4 states in parallel.
    #[inline]
    pub fn permute_x4(&mut self) {
        keccak_f_x4(&mut self.states);
    }

    /// Applies Keccak-f[1600] to a single state.
    #[inline]
    pub fn permute_single(&mut self, idx: usize) {
        debug_assert!(idx < 4);
        keccak_f_single(&mut self.states[idx]);
    }

    /// XORs a block of data into one state.
    #[inline]
    pub fn xor_block(&mut self, idx: usize, block: &[u8], rate_words: usize) {
        debug_assert!(idx < 4);
        for (i, chunk) in block.chunks_exact(8).take(rate_words).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.states[idx][i] ^= word;
        }
    }

    /// Extracts bytes from one state.
    #[inline]
    pub fn extract(&self, idx: usize, output: &mut [u8], rate_bytes: usize) {
        debug_assert!(idx < 4);
        let to_copy = core::cmp::min(output.len(), rate_bytes);

        let complete_words = to_copy / 8;
        for i in 0..complete_words {
            let bytes = self.states[idx][i].to_le_bytes();
            output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        let remainder_offset = complete_words * 8;
        if to_copy > remainder_offset {
            let bytes = self.states[idx][complete_words].to_le_bytes();
            let remainder = to_copy - remainder_offset;
            output[remainder_offset..to_copy].copy_from_slice(&bytes[..remainder]);
        }
    }
}

/// Keccak-f[1600] permutation for a single state.
#[inline]
fn keccak_f_single(state: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];
    let mut b = [0u64; 25];

    for round in 0..24 {
        // Theta
        c[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        c[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        c[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        c[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        c[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        d[0] = c[4] ^ c[1].rotate_left(1);
        d[1] = c[0] ^ c[2].rotate_left(1);
        d[2] = c[1] ^ c[3].rotate_left(1);
        d[3] = c[2] ^ c[4].rotate_left(1);
        d[4] = c[3] ^ c[0].rotate_left(1);

        for i in 0..25 {
            state[i] ^= d[i % 5];
        }

        // Rho and Pi
        b[0] = state[0];
        b[10] = state[1].rotate_left(1);
        b[7] = state[10].rotate_left(3);
        b[11] = state[7].rotate_left(6);
        b[17] = state[11].rotate_left(10);
        b[18] = state[17].rotate_left(15);
        b[3] = state[18].rotate_left(21);
        b[5] = state[3].rotate_left(28);
        b[16] = state[5].rotate_left(36);
        b[8] = state[16].rotate_left(45);
        b[21] = state[8].rotate_left(55);
        b[24] = state[21].rotate_left(2);
        b[4] = state[24].rotate_left(14);
        b[15] = state[4].rotate_left(27);
        b[23] = state[15].rotate_left(41);
        b[19] = state[23].rotate_left(56);
        b[13] = state[19].rotate_left(8);
        b[12] = state[13].rotate_left(25);
        b[2] = state[12].rotate_left(43);
        b[20] = state[2].rotate_left(62);
        b[14] = state[20].rotate_left(18);
        b[22] = state[14].rotate_left(39);
        b[9] = state[22].rotate_left(61);
        b[6] = state[9].rotate_left(20);
        b[1] = state[6].rotate_left(44);

        // Chi
        for y in 0..5 {
            let base = y * 5;
            let t0 = b[base];
            let t1 = b[base + 1];
            let t2 = b[base + 2];
            let t3 = b[base + 3];
            let t4 = b[base + 4];
            state[base] = t0 ^ ((!t1) & t2);
            state[base + 1] = t1 ^ ((!t2) & t3);
            state[base + 2] = t2 ^ ((!t3) & t4);
            state[base + 3] = t3 ^ ((!t4) & t0);
            state[base + 4] = t4 ^ ((!t0) & t1);
        }

        // Iota
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Keccak-f[1600] permutation for 4 states in parallel.
#[inline]
fn keccak_f_x4(states: &mut [[u64; 25]; 4]) {
    let mut c = [[0u64; 5]; 4];
    let mut d = [[0u64; 5]; 4];
    let mut b = [[0u64; 25]; 4];

    for round in 0..24 {
        // Theta
        for s in 0..4 {
            c[s][0] = states[s][0] ^ states[s][5] ^ states[s][10] ^ states[s][15] ^ states[s][20];
            c[s][1] = states[s][1] ^ states[s][6] ^ states[s][11] ^ states[s][16] ^ states[s][21];
            c[s][2] = states[s][2] ^ states[s][7] ^ states[s][12] ^ states[s][17] ^ states[s][22];
            c[s][3] = states[s][3] ^ states[s][8] ^ states[s][13] ^ states[s][18] ^ states[s][23];
            c[s][4] = states[s][4] ^ states[s][9] ^ states[s][14] ^ states[s][19] ^ states[s][24];
        }

        for s in 0..4 {
            d[s][0] = c[s][4] ^ c[s][1].rotate_left(1);
            d[s][1] = c[s][0] ^ c[s][2].rotate_left(1);
            d[s][2] = c[s][1] ^ c[s][3].rotate_left(1);
            d[s][3] = c[s][2] ^ c[s][4].rotate_left(1);
            d[s][4] = c[s][3] ^ c[s][0].rotate_left(1);
        }

        for s in 0..4 {
            for i in 0..25 {
                states[s][i] ^= d[s][i % 5];
            }
        }

        // Rho and Pi
        for s in 0..4 {
            b[s][0] = states[s][0];
            b[s][10] = states[s][1].rotate_left(1);
            b[s][7] = states[s][10].rotate_left(3);
            b[s][11] = states[s][7].rotate_left(6);
            b[s][17] = states[s][11].rotate_left(10);
            b[s][18] = states[s][17].rotate_left(15);
            b[s][3] = states[s][18].rotate_left(21);
            b[s][5] = states[s][3].rotate_left(28);
            b[s][16] = states[s][5].rotate_left(36);
            b[s][8] = states[s][16].rotate_left(45);
            b[s][21] = states[s][8].rotate_left(55);
            b[s][24] = states[s][21].rotate_left(2);
            b[s][4] = states[s][24].rotate_left(14);
            b[s][15] = states[s][4].rotate_left(27);
            b[s][23] = states[s][15].rotate_left(41);
            b[s][19] = states[s][23].rotate_left(56);
            b[s][13] = states[s][19].rotate_left(8);
            b[s][12] = states[s][13].rotate_left(25);
            b[s][2] = states[s][12].rotate_left(43);
            b[s][20] = states[s][2].rotate_left(62);
            b[s][14] = states[s][20].rotate_left(18);
            b[s][22] = states[s][14].rotate_left(39);
            b[s][9] = states[s][22].rotate_left(61);
            b[s][6] = states[s][9].rotate_left(20);
            b[s][1] = states[s][6].rotate_left(44);
        }

        // Chi
        for s in 0..4 {
            for y in 0..5 {
                let base = y * 5;
                let t0 = b[s][base];
                let t1 = b[s][base + 1];
                let t2 = b[s][base + 2];
                let t3 = b[s][base + 3];
                let t4 = b[s][base + 4];
                states[s][base] = t0 ^ ((!t1) & t2);
                states[s][base + 1] = t1 ^ ((!t2) & t3);
                states[s][base + 2] = t2 ^ ((!t3) & t4);
                states[s][base + 3] = t3 ^ ((!t4) & t0);
                states[s][base + 4] = t4 ^ ((!t0) & t1);
            }
        }

        // Iota
        for s in 0..4 {
            states[s][0] ^= ROUND_CONSTANTS[round];
        }
    }
}

/// 4-way parallel SHAKE-128 XOF.
///
/// Processes 4 independent SHAKE-128 instances simultaneously.
#[derive(Clone)]
pub struct Shake128x4 {
    state: KeccakState4,
    buffers: [[u8; SHAKE128_RATE]; 4],
    buffer_lens: [usize; 4],
    finalized: bool,
}

impl Default for Shake128x4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake128x4 {
    /// Creates a new 4-way SHAKE-128 instance.
    pub fn new() -> Self {
        Self {
            state: KeccakState4::new(),
            buffers: [[0u8; SHAKE128_RATE]; 4],
            buffer_lens: [0; 4],
            finalized: false,
        }
    }

    /// Resets the instance to its initial state.
    pub fn reset(&mut self) {
        self.state.reset();
        self.buffers = [[0u8; SHAKE128_RATE]; 4];
        self.buffer_lens = [0; 4];
        self.finalized = false;
    }

    /// Absorbs data into all 4 instances.
    ///
    /// Each input is processed independently into its corresponding state.
    pub fn absorb_x4(&mut self, inputs: &[&[u8]; 4]) {
        const RATE: usize = SHAKE128_RATE;
        const RATE_WORDS: usize = RATE / 8;

        for i in 0..4 {
            let input = inputs[i];
            let mut offset = 0;

            if self.buffer_lens[i] > 0 {
                let space = RATE - self.buffer_lens[i];
                let to_copy = core::cmp::min(space, input.len());
                self.buffers[i][self.buffer_lens[i]..self.buffer_lens[i] + to_copy]
                    .copy_from_slice(&input[..to_copy]);
                self.buffer_lens[i] += to_copy;
                offset = to_copy;

                if self.buffer_lens[i] == RATE {
                    self.state.xor_block(i, &self.buffers[i], RATE_WORDS);
                    self.state.permute_single(i);
                    self.buffer_lens[i] = 0;
                }
            }

            while offset + RATE <= input.len() {
                self.state.xor_block(i, &input[offset..offset + RATE], RATE_WORDS);
                self.state.permute_single(i);
                offset += RATE;
            }

            if offset < input.len() {
                let remaining = input.len() - offset;
                self.buffers[i][..remaining].copy_from_slice(&input[offset..]);
                self.buffer_lens[i] = remaining;
            }
        }
    }

    /// Finalizes all instances and prepares for squeezing.
    fn finalize_all(&mut self) {
        if self.finalized {
            return;
        }

        const RATE: usize = SHAKE128_RATE;
        const RATE_WORDS: usize = RATE / 8;

        for i in 0..4 {
            self.buffers[i][self.buffer_lens[i]] = SHAKE_DOMAIN_SEP;
            for j in self.buffer_lens[i] + 1..RATE {
                self.buffers[i][j] = 0;
            }
            self.buffers[i][RATE - 1] |= 0x80;
            self.state.xor_block(i, &self.buffers[i], RATE_WORDS);
        }

        self.state.permute_x4();
        self.finalized = true;
    }

    /// Squeezes fixed-size output from all 4 instances.
    pub fn squeeze_x4<const N: usize>(&mut self, outputs: &mut [[u8; N]; 4]) {
        self.finalize_all();

        const RATE: usize = SHAKE128_RATE;
        let mut offset = 0;

        while offset < N {
            let to_copy = core::cmp::min(RATE, N - offset);

            for i in 0..4 {
                self.state.extract(i, &mut outputs[i][offset..offset + to_copy], to_copy);
            }

            offset += to_copy;

            if offset < N {
                self.state.permute_x4();
            }
        }
    }

    /// Squeezes variable-length output from all 4 instances.
    pub fn squeeze_x4_var(&mut self, outputs: &mut [&mut [u8]; 4]) {
        self.finalize_all();

        const RATE: usize = SHAKE128_RATE;
        let max_len = outputs.iter().map(|o| o.len()).max().unwrap_or(0);
        let mut offset = 0;

        while offset < max_len {
            let chunk_size = core::cmp::min(RATE, max_len - offset);

            for i in 0..4 {
                if offset < outputs[i].len() {
                    let to_copy = core::cmp::min(chunk_size, outputs[i].len() - offset);
                    self.state.extract(i, &mut outputs[i][offset..offset + to_copy], to_copy);
                }
            }

            offset += chunk_size;

            if offset < max_len {
                self.state.permute_x4();
            }
        }
    }

    /// Absorbs 4 inputs and squeezes fixed-size outputs in one call.
    pub fn hash_x4<const N: usize>(inputs: &[&[u8]; 4]) -> [[u8; N]; 4] {
        let mut hasher = Self::new();
        hasher.absorb_x4(inputs);
        let mut outputs = [[0u8; N]; 4];
        hasher.squeeze_x4(&mut outputs);
        outputs
    }
}

/// 4-way parallel SHAKE-256 XOF.
///
/// Processes 4 independent SHAKE-256 instances simultaneously.
#[derive(Clone)]
pub struct Shake256x4 {
    state: KeccakState4,
    buffers: [[u8; SHAKE256_RATE]; 4],
    buffer_lens: [usize; 4],
    finalized: bool,
}

impl Default for Shake256x4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256x4 {
    /// Creates a new 4-way SHAKE-256 instance.
    pub fn new() -> Self {
        Self {
            state: KeccakState4::new(),
            buffers: [[0u8; SHAKE256_RATE]; 4],
            buffer_lens: [0; 4],
            finalized: false,
        }
    }

    /// Resets the instance to its initial state.
    pub fn reset(&mut self) {
        self.state.reset();
        self.buffers = [[0u8; SHAKE256_RATE]; 4];
        self.buffer_lens = [0; 4];
        self.finalized = false;
    }

    /// Absorbs data into all 4 instances.
    ///
    /// Each input is processed independently into its corresponding state.
    pub fn absorb_x4(&mut self, inputs: &[&[u8]; 4]) {
        const RATE: usize = SHAKE256_RATE;
        const RATE_WORDS: usize = RATE / 8;

        for i in 0..4 {
            let input = inputs[i];
            let mut offset = 0;

            if self.buffer_lens[i] > 0 {
                let space = RATE - self.buffer_lens[i];
                let to_copy = core::cmp::min(space, input.len());
                self.buffers[i][self.buffer_lens[i]..self.buffer_lens[i] + to_copy]
                    .copy_from_slice(&input[..to_copy]);
                self.buffer_lens[i] += to_copy;
                offset = to_copy;

                if self.buffer_lens[i] == RATE {
                    self.state.xor_block(i, &self.buffers[i], RATE_WORDS);
                    self.state.permute_single(i);
                    self.buffer_lens[i] = 0;
                }
            }

            while offset + RATE <= input.len() {
                self.state.xor_block(i, &input[offset..offset + RATE], RATE_WORDS);
                self.state.permute_single(i);
                offset += RATE;
            }

            if offset < input.len() {
                let remaining = input.len() - offset;
                self.buffers[i][..remaining].copy_from_slice(&input[offset..]);
                self.buffer_lens[i] = remaining;
            }
        }
    }

    /// Finalizes all instances and prepares for squeezing.
    fn finalize_all(&mut self) {
        if self.finalized {
            return;
        }

        const RATE: usize = SHAKE256_RATE;
        const RATE_WORDS: usize = RATE / 8;

        for i in 0..4 {
            self.buffers[i][self.buffer_lens[i]] = SHAKE_DOMAIN_SEP;
            for j in self.buffer_lens[i] + 1..RATE {
                self.buffers[i][j] = 0;
            }
            self.buffers[i][RATE - 1] |= 0x80;
            self.state.xor_block(i, &self.buffers[i], RATE_WORDS);
        }

        self.state.permute_x4();
        self.finalized = true;
    }

    /// Squeezes fixed-size output from all 4 instances.
    pub fn squeeze_x4<const N: usize>(&mut self, outputs: &mut [[u8; N]; 4]) {
        self.finalize_all();

        const RATE: usize = SHAKE256_RATE;
        let mut offset = 0;

        while offset < N {
            let to_copy = core::cmp::min(RATE, N - offset);

            for i in 0..4 {
                self.state.extract(i, &mut outputs[i][offset..offset + to_copy], to_copy);
            }

            offset += to_copy;

            if offset < N {
                self.state.permute_x4();
            }
        }
    }

    /// Squeezes variable-length output from all 4 instances.
    pub fn squeeze_x4_var(&mut self, outputs: &mut [&mut [u8]; 4]) {
        self.finalize_all();

        const RATE: usize = SHAKE256_RATE;
        let max_len = outputs.iter().map(|o| o.len()).max().unwrap_or(0);
        let mut offset = 0;

        while offset < max_len {
            let chunk_size = core::cmp::min(RATE, max_len - offset);

            for i in 0..4 {
                if offset < outputs[i].len() {
                    let to_copy = core::cmp::min(chunk_size, outputs[i].len() - offset);
                    self.state.extract(i, &mut outputs[i][offset..offset + to_copy], to_copy);
                }
            }

            offset += chunk_size;

            if offset < max_len {
                self.state.permute_x4();
            }
        }
    }

    /// Absorbs 4 inputs and squeezes fixed-size outputs in one call.
    pub fn hash_x4<const N: usize>(inputs: &[&[u8]; 4]) -> [[u8; N]; 4] {
        let mut hasher = Self::new();
        hasher.absorb_x4(inputs);
        let mut outputs = [[0u8; N]; 4];
        hasher.squeeze_x4(&mut outputs);
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::{Shake128, Shake256};
    use crate::traits::XofFunction;

    #[test]
    fn test_shake128x4_matches_sequential() {
        let inputs: [&[u8]; 4] = [b"input0", b"input1", b"input2", b"input3"];
        let outputs: [[u8; 64]; 4] = Shake128x4::hash_x4(&inputs);

        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake128::new();
            hasher.update(input);
            let mut expected = [0u8; 64];
            hasher.finalize(&mut expected);
            assert_eq!(outputs[i], expected);
        }
    }

    #[test]
    fn test_shake256x4_matches_sequential() {
        let inputs: [&[u8]; 4] = [b"input0", b"input1", b"input2", b"input3"];
        let outputs: [[u8; 128]; 4] = Shake256x4::hash_x4(&inputs);

        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake256::new();
            hasher.update(input);
            let mut expected = [0u8; 128];
            hasher.finalize(&mut expected);
            assert_eq!(outputs[i], expected);
        }
    }

    #[test]
    fn test_shake128x4_empty() {
        let inputs: [&[u8]; 4] = [b"", b"", b"", b""];
        let outputs: [[u8; 32]; 4] = Shake128x4::hash_x4(&inputs);

        let hasher = Shake128::new();
        let mut expected = [0u8; 32];
        hasher.finalize(&mut expected);

        for output in &outputs {
            assert_eq!(output, &expected);
        }
    }

    #[test]
    fn test_shake256x4_empty() {
        let inputs: [&[u8]; 4] = [b"", b"", b"", b""];
        let outputs: [[u8; 32]; 4] = Shake256x4::hash_x4(&inputs);

        let hasher = Shake256::new();
        let mut expected = [0u8; 32];
        hasher.finalize(&mut expected);

        for output in &outputs {
            assert_eq!(output, &expected);
        }
    }

    #[test]
    fn test_shake128x4_large_output() {
        let inputs: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        let outputs: [[u8; 512]; 4] = Shake128x4::hash_x4(&inputs);

        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake128::new();
            hasher.update(input);
            let mut expected = [0u8; 512];
            hasher.finalize(&mut expected);
            assert_eq!(outputs[i], expected);
        }
    }

    #[test]
    fn test_shake128x4_multi_block() {
        let long_input = [0xABu8; 500];
        let inputs: [&[u8]; 4] = [&long_input, &long_input[..300], &long_input[..100], &long_input];
        let outputs: [[u8; 64]; 4] = Shake128x4::hash_x4(&inputs);

        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake128::new();
            hasher.update(input);
            let mut expected = [0u8; 64];
            hasher.finalize(&mut expected);
            assert_eq!(outputs[i], expected);
        }
    }

    #[test]
    fn test_batched_hash_x4() {
        // Test hash_x4 convenience method for Shake128x4
        let inputs: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        let outputs: [[u8; 32]; 4] = Shake128x4::hash_x4(&inputs);

        // Verify against sequential SHAKE128
        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake128::new();
            hasher.update(input);
            let mut expected = [0u8; 32];
            hasher.finalize(&mut expected);
            assert_eq!(outputs[i], expected);
        }

        // Test hash_x4 convenience method for Shake256x4
        let outputs256: [[u8; 64]; 4] = Shake256x4::hash_x4(&inputs);

        // Verify against sequential SHAKE256
        for (i, input) in inputs.iter().enumerate() {
            let mut hasher = Shake256::new();
            hasher.update(input);
            let mut expected = [0u8; 64];
            hasher.finalize(&mut expected);
            assert_eq!(outputs256[i], expected);
        }
    }
}
