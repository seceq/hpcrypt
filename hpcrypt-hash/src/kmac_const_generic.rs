//! Const Generic Rate Specialization for KMAC/CShake
//!
//! Optimizations:
//! 1. Const generic RATE parameter - eliminates runtime rate checks
//! 2. Compile-time buffer size - optimal stack allocation
//! 3. Monomorphization benefits - separate optimized code paths for each rate
//!
//! Expected improvement: 3-5% on KMAC operations
//!
//! Strategy: Use const generics to specialize CShake/KMAC implementations by rate,
//! enabling the compiler to eliminate all rate-related branches and optimize
//! buffer operations at compile time.

#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::kmac::{bytepad, encode_string, right_encode_fast, ROUND_CONSTANTS};

/// Keccak state size in 64-bit words
const STATE_SIZE: usize = 25;

/// Keccak-f[1600] permutation (reuse from baseline for fair comparison)
#[inline(always)]
fn keccak_f_baseline(state: &mut [u64; 25]) {
    #[allow(clippy::needless_range_loop)]
    for round in 0..24 {
        // θ (theta) step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ (rho) and π (pi) steps
        const ROTATION_OFFSETS: [u32; 24] = [
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20,
            44,
        ];
        const PI_LANE: [usize; 24] = [
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
        ];

        let mut current = state[1];
        for i in 0..24 {
            let (x, y) = (PI_LANE[i] % 5, PI_LANE[i] / 5);
            let temp = state[x + 5 * y];
            state[x + 5 * y] = current.rotate_left(ROTATION_OFFSETS[i]);
            current = temp;
        }

        // χ (chi) step
        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι (iota) step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Generic cSHAKE implementation with const RATE parameter
///
/// This eliminates all runtime rate checks and enables compile-time optimizations:
/// - Buffer size is known at compile time
/// - Rate comparisons are eliminated
/// - Monomorphization creates specialized code for each rate
///
/// Type parameter:
/// - `RATE`: Rate in bytes (168 for cSHAKE128, 136 for cSHAKE256)
#[derive(Clone)]
pub struct CShakeGeneric<const RATE: usize> {
    state: [u64; STATE_SIZE],
    buffer: [u8; RATE], // Compile-time sized buffer!
    buffer_len: usize,
    is_custom: bool,
}

impl<const RATE: usize> CShakeGeneric<RATE> {
    /// Create a new cSHAKE instance
    ///
    /// # Arguments
    /// * `function_name` - Function name (N) for domain separation
    /// * `customization` - Customization string (S)
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
        let mut hasher = Self {
            state: [0u64; STATE_SIZE],
            buffer: [0u8; RATE],
            buffer_len: 0,
            is_custom: !function_name.is_empty() || !customization.is_empty(),
        };

        // If customized, absorb the prefix
        if hasher.is_custom {
            let mut prefix = encode_string(function_name);
            prefix.extend_from_slice(&encode_string(customization));
            let padded = bytepad(&prefix, RATE); // RATE is const!
            hasher.update(&padded);
        }

        hasher
    }

    /// Update with input data
    ///
    /// All rate checks are compile-time constants, enabling better optimization
    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer if partial
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(RATE - self.buffer_len, data.len()); // RATE is const!
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == RATE {
                // RATE comparison is const!
                let buffer = self.buffer; // Copy before mutable borrow
                self.absorb_block(&buffer);
                self.buffer_len = 0;
            }
        }

        // Process complete blocks - loop condition uses const RATE
        while offset + RATE <= data.len() {
            self.absorb_block(&data[offset..offset + RATE]);
            offset += RATE;
        }

        // Buffer remaining data
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and squeeze output of arbitrary length
    #[inline(always)]
    pub fn finalize(mut self, output: &mut [u8]) {
        // cSHAKE padding (or SHAKE if not customized)
        let pad_byte = if self.is_custom { 0x04 } else { 0x1F };

        self.buffer[self.buffer_len] = pad_byte;
        for i in self.buffer_len + 1..RATE {
            // RATE is const!
            self.buffer[i] = 0;
        }
        self.buffer[RATE - 1] |= 0x80; // RATE - 1 is const!

        let buffer = self.buffer; // Copy before mutable borrow
        self.absorb_block(&buffer);

        // Squeeze - all rate operations are const
        let mut offset = 0;
        while offset < output.len() {
            let to_copy = core::cmp::min(RATE, output.len() - offset); // RATE is const!
            for i in 0..to_copy {
                let word_idx = i / 8;
                let byte_idx = i % 8;
                output[offset + i] = self.state[word_idx].to_le_bytes()[byte_idx];
            }
            offset += to_copy;
            if offset < output.len() {
                keccak_f_baseline(&mut self.state);
            }
        }
    }

    /// Absorb a block into the state
    ///
    /// RATE determines loop iterations at compile time
    #[inline(always)]
    fn absorb_block(&mut self, block: &[u8]) {
        // chunk_exact(8) iterator over exactly RATE bytes
        // Compiler knows RATE at compile time
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        keccak_f_baseline(&mut self.state);
    }
}

/// Type alias for cSHAKE128 with const generic rate
pub type CShake128Generic = CShakeGeneric<168>; // 1344 bits = 168 bytes

/// Type alias for cSHAKE256 with const generic rate
pub type CShake256Generic = CShakeGeneric<136>; // 1088 bits = 136 bytes

/// KMAC128 with const generic rate specialization
#[derive(Clone)]
pub struct Kmac128Generic {
    cshake: CShake128Generic,
}

impl Kmac128Generic {
    /// Create a new KMAC128 instance
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `customization` - Optional customization string for domain separation
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        let mut kmac = Self {
            cshake: CShake128Generic::new(b"KMAC", customization),
        };

        // Absorb key: bytepad(encode_string(K), rate) || X || right_encode(L)
        // Rate is compile-time constant 168
        let encoded_key = bytepad(&encode_string(key), 168);
        kmac.cshake.update(&encoded_key);

        kmac
    }

    /// Update with message data
    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }

    /// Finalize and produce MAC of specified output length
    ///
    /// # Arguments
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        // Append right_encode(output_len in bits)
        let suffix = right_encode_fast(output_len * 8);
        self.cshake.update(suffix.as_slice());

        // Squeeze output
        let mut output = vec![0u8; output_len];
        self.cshake.finalize(&mut output);
        output
    }

    /// Compute KMAC128 in one call
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `message` - The message to authenticate
    /// * `customization` - Optional customization string
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn mac(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
        let mut kmac = Self::new(key, customization);
        kmac.update(message);
        kmac.finalize(output_len)
    }
}

/// KMAC256 with const generic rate specialization
#[derive(Clone)]
pub struct Kmac256Generic {
    cshake: CShake256Generic,
}

impl Kmac256Generic {
    /// Create a new KMAC256 instance
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `customization` - Optional customization string for domain separation
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        let mut kmac = Self {
            cshake: CShake256Generic::new(b"KMAC", customization),
        };

        // Absorb key: bytepad(encode_string(K), rate) || X || right_encode(L)
        // Rate is compile-time constant 136
        let encoded_key = bytepad(&encode_string(key), 136);
        kmac.cshake.update(&encoded_key);

        kmac
    }

    /// Update with message data
    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        self.cshake.update(data);
    }

    /// Finalize and produce MAC of specified output length
    ///
    /// # Arguments
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        // Append right_encode(output_len in bits)
        let suffix = right_encode_fast(output_len * 8);
        self.cshake.update(suffix.as_slice());

        // Squeeze output
        let mut output = vec![0u8; output_len];
        self.cshake.finalize(&mut output);
        output
    }

    /// Compute KMAC256 in one call
    ///
    /// # Arguments
    /// * `key` - The MAC key
    /// * `message` - The message to authenticate
    /// * `customization` - Optional customization string
    /// * `output_len` - Desired MAC length in bytes
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn mac(key: &[u8], message: &[u8], customization: &[u8], output_len: usize) -> Vec<u8> {
        let mut kmac = Self::new(key, customization);
        kmac.update(message);
        kmac.finalize(output_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kmac128_generic_matches_baseline() {
        let key = b"test key";
        let message = b"test message";
        let customization = b"";

        let mac_baseline = crate::kmac::Kmac128::mac(key, message, customization, 32);
        let mac_generic = Kmac128Generic::mac(key, message, customization, 32);

        assert_eq!(
            mac_baseline, mac_generic,
            "Generic KMAC128 should match baseline"
        );
    }

    #[test]
    fn test_kmac256_generic_matches_baseline() {
        let key = b"test key";
        let message = b"test message";
        let customization = b"";

        let mac_baseline = crate::kmac::Kmac256::mac(key, message, customization, 64);
        let mac_generic = Kmac256Generic::mac(key, message, customization, 64);

        assert_eq!(
            mac_baseline, mac_generic,
            "Generic KMAC256 should match baseline"
        );
    }

    #[test]
    fn test_kmac128_generic_incremental() {
        let key = b"test key";
        let customization = b"test";

        // One-shot
        let mac1 = Kmac128Generic::mac(key, b"abcdef", customization, 32);

        // Incremental
        let mut kmac = Kmac128Generic::new(key, customization);
        kmac.update(b"abc");
        kmac.update(b"def");
        let mac2 = kmac.finalize(32);

        assert_eq!(mac1, mac2, "Incremental should match one-shot");
    }

    #[test]
    fn test_kmac256_generic_incremental() {
        let key = b"test key";
        let customization = b"test";

        // One-shot
        let mac1 = Kmac256Generic::mac(key, b"abcdef", customization, 64);

        // Incremental
        let mut kmac = Kmac256Generic::new(key, customization);
        kmac.update(b"abc");
        kmac.update(b"def");
        let mac2 = kmac.finalize(64);

        assert_eq!(mac1, mac2, "Incremental should match one-shot");
    }

    #[test]
    fn test_cshake128_generic_empty() {
        let mut cshake_baseline = crate::kmac::CShake128::new(b"", b"");
        let mut output_baseline = vec![0u8; 32];
        cshake_baseline.finalize(&mut output_baseline);

        let cshake_generic = CShake128Generic::new(b"", b"");
        let mut output_generic = vec![0u8; 32];
        cshake_generic.finalize(&mut output_generic);

        assert_eq!(
            output_baseline, output_generic,
            "Generic cSHAKE128 should match baseline"
        );
    }

    #[test]
    fn test_cshake256_generic_custom() {
        let mut cshake_baseline = crate::kmac::CShake256::new(b"Test", b"Custom");
        cshake_baseline.update(b"message");
        let mut output_baseline = vec![0u8; 64];
        cshake_baseline.finalize(&mut output_baseline);

        let mut cshake_generic = CShake256Generic::new(b"Test", b"Custom");
        cshake_generic.update(b"message");
        let mut output_generic = vec![0u8; 64];
        cshake_generic.finalize(&mut output_generic);

        assert_eq!(
            output_baseline, output_generic,
            "Generic cSHAKE256 should match baseline"
        );
    }
}
