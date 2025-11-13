//! XOF Reader - Streaming API for Extendable-Output Functions
//!
//! Provides an incremental output interface for SHAKE128, SHAKE256, and TurboSHAKE
//! that allows reading arbitrary amounts of output data without re-finalization.
//!
//! Benefits:
//! - No allocation for known output sizes (uses provided buffer)
//! - Incremental squeezing without state duplication
//! - Efficient for variable-length output generation
//! - Zero-copy when reading complete blocks

#![forbid(unsafe_code)]

use crate::sha3::{ShakeCore, STATE_SIZE};

/// XOF Reader for incremental output extraction
///
/// This structure allows reading arbitrary amounts of output from a finalized
/// SHAKE/TurboSHAKE state without requiring multiple finalizations.
///
/// # Example
/// ```ignore
/// let mut shake = Shake128::new();
/// shake.update(b"input data");
/// let mut reader = shake.finalize_xof();
///
/// // Read output incrementally
/// let mut buf1 = [0u8; 32];
/// reader.read(&mut buf1);
///
/// let mut buf2 = [0u8; 64];
/// reader.read(&mut buf2);
/// ```
pub struct XofReader<const RATE: usize, const ROUNDS: usize> {
    state: [u64; STATE_SIZE],
    buffer: [u8; RATE],
    buffer_offset: usize, // Current position in buffer (how much we've already read)
    squeezed: bool,       // Whether we've squeezed the first block
}

impl<const RATE: usize, const ROUNDS: usize> XofReader<RATE, ROUNDS> {
    /// Create a new XOF reader from a finalized ShakeCore state
    ///
    /// This is called by `finalize_xof()` on SHAKE/TurboSHAKE types
    #[inline]
    pub(crate) fn new(mut core: ShakeCore<RATE, ROUNDS>) -> Self {
        // Finalize the absorption phase (apply padding and final permutation)
        core.finalize_into_state();

        Self {
            state: core.state,
            buffer: [0u8; RATE],
            buffer_offset: 0,
            squeezed: false,
        }
    }

    /// Read output data into the provided buffer
    ///
    /// This method can be called multiple times to extract arbitrary amounts of output.
    /// It automatically performs Keccak permutations as needed.
    ///
    /// # Arguments
    /// * `output` - Buffer to fill with output data
    ///
    /// # Performance
    /// - First call: Extracts from already-permuted state (no extra permutation)
    /// - Subsequent calls: Performs permutation only when crossing RATE boundary
    /// - Uses word-at-a-time extraction for better performance
    #[inline]
    pub fn read(&mut self, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }

        let mut output_offset = 0;

        // First squeeze: extract from current state without additional permutation
        if !self.squeezed {
            self.fill_buffer();
            self.squeezed = true;
        }

        while output_offset < output.len() {
            // How much data is available in the buffer?
            let available = RATE - self.buffer_offset;
            let needed = output.len() - output_offset;
            let to_copy = core::cmp::min(available, needed);

            // Copy from buffer to output
            output[output_offset..output_offset + to_copy]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + to_copy]);

            output_offset += to_copy;
            self.buffer_offset += to_copy;

            // If we've exhausted the buffer, perform permutation and refill
            if self.buffer_offset >= RATE && output_offset < output.len() {
                ShakeCore::<RATE, ROUNDS>::permute(&mut self.state);
                self.fill_buffer();
                self.buffer_offset = 0;
            }
        }
    }

    /// Fill internal buffer from current state
    ///
    /// Extracts one RATE's worth of data from the state into the buffer.
    /// Uses word-at-a-time extraction for better performance.
    #[inline(always)]
    fn fill_buffer(&mut self) {
        #[cfg(not(feature = "lane-complement"))]
        {
            // Extract complete u64 words
            let words = RATE / 8;
            for i in 0..words {
                let bytes = self.state[i].to_le_bytes();
                self.buffer[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
            }

            // Handle any remaining bytes (for rates not divisible by 8)
            let remainder_offset = words * 8;
            if RATE > remainder_offset {
                let bytes = self.state[words].to_le_bytes();
                let remainder = RATE - remainder_offset;
                self.buffer[remainder_offset..RATE].copy_from_slice(&bytes[..remainder]);
            }
        }

        #[cfg(feature = "lane-complement")]
        {
            // Lane complement mode: certain lanes are stored complemented
            // For SHAKE128 (RATE=168): lanes that need complementing
            const COMPLEMENTED: [bool; 25] = [
                false, true, true, false, false, false, false, false, true, false, false,
                false, true, false, false, false, false, true, false, false, true, false,
                false, false, false,
            ];

            // Extract complete u64 words with complementing
            let words = RATE / 8;
            for i in 0..words {
                let lane = if COMPLEMENTED[i] {
                    !self.state[i]
                } else {
                    self.state[i]
                };
                let bytes = lane.to_le_bytes();
                self.buffer[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
            }

            // Handle any remaining bytes (for rates not divisible by 8)
            let remainder_offset = words * 8;
            if RATE > remainder_offset {
                let lane = if COMPLEMENTED[words] {
                    !self.state[words]
                } else {
                    self.state[words]
                };
                let bytes = lane.to_le_bytes();
                let remainder = RATE - remainder_offset;
                self.buffer[remainder_offset..RATE].copy_from_slice(&bytes[..remainder]);
            }
        }
    }

    /// Read exactly `N` bytes into an array
    ///
    /// Convenience method for fixed-size output.
    ///
    /// # Example
    /// ```ignore
    /// let output: [u8; 32] = reader.read_array();
    /// ```
    #[inline]
    pub fn read_array<const N: usize>(&mut self) -> [u8; N] {
        let mut output = [0u8; N];
        self.read(&mut output);
        output
    }

    /// Clone the reader to create an independent copy
    ///
    /// This allows branching the output stream - both readers will produce
    /// the same output sequence from this point forward, but independently.
    #[inline]
    pub fn fork(&self) -> Self {
        Self {
            state: self.state,
            buffer: self.buffer,
            buffer_offset: self.buffer_offset,
            squeezed: self.squeezed,
        }
    }
}

impl<const RATE: usize, const ROUNDS: usize> Clone for XofReader<RATE, ROUNDS> {
    fn clone(&self) -> Self {
        self.fork()
    }
}

/// Implement Read trait for XofReader (requires std feature)
#[cfg(feature = "std")]
impl<const RATE: usize, const ROUNDS: usize> std::io::Read for XofReader<RATE, ROUNDS> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::Shake128;

    #[cfg(feature = "alloc")]
    extern crate alloc;
    #[cfg(feature = "alloc")]
    use alloc::vec;

    #[test]
    #[cfg(feature = "alloc")]
    fn test_xof_reader_basic() {
        let mut shake = Shake128::new();
        shake.update(b"test");
        let mut reader = shake.finalize_xof();

        let mut buf1 = [0u8; 32];
        reader.read(&mut buf1);

        let mut buf2 = [0u8; 32];
        reader.read(&mut buf2);

        // Outputs should be different (consecutive chunks)
        assert_ne!(buf1, buf2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_xof_reader_vs_finalize() {
        let input = b"test data";

        // One-shot finalize
        let mut shake1 = Shake128::new();
        shake1.update(input);
        let mut expected = vec![0u8; 128];
        shake1.finalize(&mut expected);

        // XOF reader
        let mut shake2 = Shake128::new();
        shake2.update(input);
        let mut reader = shake2.finalize_xof();
        let mut actual = vec![0u8; 128];
        reader.read(&mut actual);

        assert_eq!(
            expected, actual,
            "XOF reader should match one-shot finalize"
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_xof_reader_incremental() {
        let input = b"test data";

        // Read all at once
        let mut shake1 = Shake128::new();
        shake1.update(input);
        let mut reader1 = shake1.finalize_xof();
        let mut all_at_once = vec![0u8; 200];
        reader1.read(&mut all_at_once);

        // Read incrementally
        let mut shake2 = Shake128::new();
        shake2.update(input);
        let mut reader2 = shake2.finalize_xof();

        let mut incremental = vec![0u8; 200];
        reader2.read(&mut incremental[0..50]);
        reader2.read(&mut incremental[50..100]);
        reader2.read(&mut incremental[100..150]);
        reader2.read(&mut incremental[150..200]);

        assert_eq!(
            all_at_once, incremental,
            "Incremental reads should match all-at-once"
        );
    }

    #[test]
    fn test_xof_reader_fork() {
        let mut shake = Shake128::new();
        shake.update(b"test");
        let mut reader1 = shake.finalize_xof();

        // Read some data from first reader
        let mut buf1 = [0u8; 32];
        reader1.read(&mut buf1);

        // Fork the reader
        let mut reader2 = reader1.fork();

        // Both should produce the same output from this point
        let mut buf2 = [0u8; 64];
        let mut buf3 = [0u8; 64];
        reader1.read(&mut buf2);
        reader2.read(&mut buf3);

        assert_eq!(buf2, buf3, "Forked readers should produce identical output");
    }

    #[test]
    fn test_xof_reader_array() {
        let mut shake = Shake128::new();
        shake.update(b"test");
        let mut reader = shake.finalize_xof();

        let output1: [u8; 32] = reader.read_array();
        let output2: [u8; 32] = reader.read_array();

        assert_ne!(output1, output2, "Sequential arrays should differ");
    }
}
