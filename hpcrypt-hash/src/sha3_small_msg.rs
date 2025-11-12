//! Small Message Fast Path for SHA-3 and SHAKE
//!
//! This module provides optimized implementations for messages that fit in a single block.
//! For small messages (< RATE - 2 bytes), we can skip buffering overhead entirely.
//!
//! **Performance Target**: 30-40% improvement for messages < 100 bytes
//!
//! **Optimization Strategy**:
//! - Detect messages that fit in single block: len + 2 < RATE (2 bytes = domain_sep + 0x80)
//! - Build padded block directly without buffer management
//! - Single absorb_block() call
//! - Skip buffer_len tracking overhead
//!
//! **Safety**: This is a pure optimization - output is identical to the baseline implementation.

#![forbid(unsafe_code)]

use crate::sha3::ShakeCore;

impl<const RATE: usize, const ROUNDS: usize> ShakeCore<RATE, ROUNDS> {
    /// Fast path for small messages that fit in a single block
    ///
    /// This method is called from the public API when:
    /// - `buffer_len == 0` (no prior buffered data)
    /// - `data.len() + 2 < RATE` (message + padding fits in one block)
    ///
    /// # Performance
    /// - Eliminates buffer management overhead
    /// - Single absorb_block() call
    /// - Direct squeeze without intermediate buffer operations
    ///
    /// # Arguments
    /// * `data` - Input message (must fit in single block)
    /// * `output` - Output buffer to fill
    #[inline(always)]
    pub fn finalize_small_message(&mut self, data: &[u8], output: &mut [u8]) {
        debug_assert!(self.buffer_len == 0, "Small message fast path requires empty buffer");
        debug_assert!(data.len() + 2 <= RATE, "Message too large for single block");

        // Build padded block directly
        let mut block = [0u8; RATE];

        // Copy message
        block[..data.len()].copy_from_slice(data);

        // Apply padding: domain_sep || 0* || 0x80
        block[data.len()] = self.domain_sep;
        // zeros already present from initialization
        block[RATE - 1] |= 0x80;

        // Single absorption
        self.absorb_block(&block);

        // Squeeze output
        self.squeeze_output(output);
    }

    /// Squeeze output after absorption (shared between fast path and normal path)
    ///
    /// Extracted from finalize_internal to avoid code duplication.
    #[inline(always)]
    fn squeeze_output(&mut self, output: &mut [u8]) {
        let mut offset = 0;
        while offset < output.len() {
            let to_copy = core::cmp::min(RATE, output.len() - offset);

            #[cfg(not(feature = "lane-complement"))]
            {
                // Extract by u64 words for better performance
                let full_words = to_copy / 8;
                for i in 0..full_words {
                    let word_bytes = self.state[i].to_le_bytes();
                    output[offset + i * 8..offset + (i + 1) * 8].copy_from_slice(&word_bytes);
                }

                // Handle remaining bytes
                let remainder_offset = full_words * 8;
                if to_copy > remainder_offset {
                    let word_bytes = self.state[full_words].to_le_bytes();
                    let remainder = to_copy - remainder_offset;
                    output[offset + remainder_offset..offset + to_copy]
                        .copy_from_slice(&word_bytes[..remainder]);
                }
            }

            #[cfg(feature = "lane-complement")]
            {
                // Lane complement feature: handle complemented lanes
                const COMPLEMENTED: [bool; 25] = [
                    false, true, true, false, false,
                    false, false, false, true, false,
                    false, false, true, false, false,
                    false, false, true, false, false,
                    true, false, false, false, false,
                ];

                let full_words = to_copy / 8;
                for i in 0..full_words {
                    let word = if COMPLEMENTED[i] { !self.state[i] } else { self.state[i] };
                    let word_bytes = word.to_le_bytes();
                    output[offset + i * 8..offset + (i + 1) * 8].copy_from_slice(&word_bytes);
                }

                // Handle remaining bytes
                let remainder_offset = full_words * 8;
                if to_copy > remainder_offset {
                    let word = if COMPLEMENTED[full_words] {
                        !self.state[full_words]
                    } else {
                        self.state[full_words]
                    };
                    let word_bytes = word.to_le_bytes();
                    let remainder = to_copy - remainder_offset;
                    output[offset + remainder_offset..offset + to_copy]
                        .copy_from_slice(&word_bytes[..remainder]);
                }
            }

            offset += to_copy;

            // Need more output? Perform another permutation
            if offset < output.len() {
                Self::permute(&mut self.state);
            }
        }
    }
}

/// Public API wrappers for small message fast path
///
/// These implementations are added to the Shake128/Shake256 types via extension trait.
impl crate::sha3::Shake128 {
    /// One-shot hash for small messages (< 166 bytes)
    ///
    /// This is a convenience method that automatically uses the fast path.
    ///
    /// # Example
    /// ```
    /// use hpcrypt_hash::Shake128;
    ///
    /// let mut output = [0u8; 32];
    /// Shake128::hash_small(b"small message", &mut output);
    /// ```
    #[inline]
    pub fn hash_small(data: &[u8], output: &mut [u8]) {
        if data.len() + 2 <= 168 {
            let mut shake = Self::new();
            shake.finalize_small_message(data, output);
        } else {
            // Fall back to normal path for larger messages
            let mut shake = Self::new();
            shake.update(data);
            shake.finalize(output);
        }
    }
}

impl crate::sha3::Shake256 {
    /// One-shot hash for small messages (< 134 bytes)
    ///
    /// This is a convenience method that automatically uses the fast path.
    ///
    /// # Example
    /// ```
    /// use hpcrypt_hash::Shake256;
    ///
    /// let mut output = [0u8; 64];
    /// Shake256::hash_small(b"small message", &mut output);
    /// ```
    #[inline]
    pub fn hash_small(data: &[u8], output: &mut [u8]) {
        if data.len() + 2 <= 136 {
            let mut shake = Self::new();
            shake.finalize_small_message(data, output);
        } else {
            // Fall back to normal path for larger messages
            let mut shake = Self::new();
            shake.update(data);
            shake.finalize(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sha3::{Shake128, Shake256};

    #[cfg(feature = "alloc")]
    extern crate alloc;
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    #[test]
    #[cfg(feature = "alloc")]
    fn test_shake128_small_message_vs_baseline() {
        let inputs: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            &[0u8; 100],  // 100 bytes of zeros
            &[0xFFu8; 100],  // 100 bytes of ones
        ];

        for input in inputs.iter() {
            let mut expected = [0u8; 64];
            let mut actual = [0u8; 64];

            // Baseline
            let mut shake1 = Shake128::new();
            shake1.update(input);
            shake1.finalize(&mut expected);

            // Fast path
            let mut shake2 = Shake128::new();
            shake2.finalize_small_message(input, &mut actual);

            assert_eq!(
                expected, actual,
                "Small message fast path mismatch for input length {}",
                input.len()
            );
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_shake256_small_message_vs_baseline() {
        let inputs: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            &[0u8; 100],
            &[0xFFu8; 100],
        ];

        for input in inputs.iter() {
            let mut expected = [0u8; 64];
            let mut actual = [0u8; 64];

            // Baseline
            let mut shake1 = Shake256::new();
            shake1.update(input);
            shake1.finalize(&mut expected);

            // Fast path
            let mut shake2 = Shake256::new();
            shake2.finalize_small_message(input, &mut actual);

            assert_eq!(
                expected, actual,
                "Small message fast path mismatch for input length {}",
                input.len()
            );
        }
    }

    #[test]
    fn test_shake128_hash_small_convenience() {
        let input = b"test message";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        // Using convenience method
        Shake128::hash_small(input, &mut output1);

        // Using baseline
        let mut shake = Shake128::new();
        shake.update(input);
        shake.finalize(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_shake256_hash_small_convenience() {
        let input = b"test message";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        // Using convenience method
        Shake256::hash_small(input, &mut output1);

        // Using baseline
        let mut shake = Shake256::new();
        shake.update(input);
        shake.finalize(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_different_output_sizes() {
        let input = b"test";
        let sizes = [16, 32, 64, 128, 200];  // Test various output sizes including > RATE

        for &size in sizes.iter() {
            let mut expected = vec![0u8; size];
            let mut actual = vec![0u8; size];

            // Baseline
            let mut shake1 = Shake128::new();
            shake1.update(input);
            shake1.finalize(&mut expected);

            // Fast path
            let mut shake2 = Shake128::new();
            shake2.finalize_small_message(input, &mut actual);

            assert_eq!(
                expected, actual,
                "Mismatch for output size {}",
                size
            );
        }
    }
}
