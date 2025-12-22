//! Batched 4-way SHAKE-128 and SHAKE-256 implementations.
//!
//! Provides parallel processing of 4 independent SHAKE instances for improved
//! throughput in applications like ML-DSA that require many XOF evaluations.
//!
//! # Example
//!
//! ```
//! use hpcrypt_hash::shake_x4::{Shake128x4, Shake256x4};
//!
//! let inputs: [&[u8]; 4] = [b"input0", b"input1", b"input2", b"input3"];
//! let outputs: [[u8; 64]; 4] = Shake128x4::hash_x4(&inputs);
//! ```

use crate::sha3::STATE_SIZE;

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
        crate::sha3::keccak_f(&mut self.states[idx]);
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

/// Keccak-f[1600] permutation for 4 states in parallel.
/// Uses SIMD x4 when available (AVX2 on x86_64, NEON on aarch64),
/// otherwise falls back to sequential single-state permutations.
#[inline]
fn keccak_f_x4(states: &mut [[u64; 25]; 4]) {
    // Try AVX2 x4 on x86_64/x86
    #[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "std", feature = "avx2"))]
    {
        if crate::intrinsics::has_avx2() {
            unsafe { crate::intrinsics::keccak_f1600_x4_states(states) };
            return;
        }
    }

    // Try NEON x4 on AArch64
    #[cfg(all(target_arch = "aarch64", feature = "std", feature = "neon"))]
    {
        if crate::intrinsics::has_neon() {
            unsafe { crate::intrinsics::keccak_f1600_x4_states_neon(states) };
            return;
        }
    }

    // Fallback: process each state sequentially using sha3::keccak_f
    for state in states.iter_mut() {
        crate::sha3::keccak_f(state);
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
