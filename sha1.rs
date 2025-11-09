//! SHA-1 Hash Function Implementation
//!
//! This module provides a high-performance implementation of the SHA-1 cryptographic hash function
//! as specified in FIPS 180-4.
//!
//! # Security Warning
//!
//! **SHA-1 is cryptographically broken and MUST NOT be used for security-critical applications.**
//!
//! SHA-1 has known collision vulnerabilities and is no longer considered secure. This implementation
//! is provided solely for compatibility with legacy protocols that still require SHA-1, such as:
//! - SRP-6a authentication (RFC 5054)
//! - Legacy TLS handshakes
//! - Git (for non-security purposes)
//!
//! For new applications, use SHA-256, SHA-384, or SHA-512 instead.
//!
//! # Performance Characteristics
//!
//! This implementation has been optimized for performance with the following features:
//! - Circular buffer technique (16 words instead of 80)
//! - Rolling macro pattern for round functions
//! - Cache-line alignment for hash state
//! - Branch prediction optimization
//! - Specialized fast paths for common cases
//!
//! # Example
//!
//! ```rust
//! use sha1::sha1;
//!
//! let hash = sha1(b"hello world");
//! assert_eq!(hash.len(), 20);
//! ```

#![no_std]

/// SHA-1 round constants (K values) as defined in FIPS 180-4
const K: [u32; 4] = [
    0x5A827999, // K₀ for rounds 0-19
    0x6ED9EBA1, // K₁ for rounds 20-39
    0x8F1BBCDC, // K₂ for rounds 40-59
    0xCA62C1D6, // K₃ for rounds 60-79
];

/// SHA-1 initial hash values (H₀) as specified in FIPS 180-4
const H_INIT: [u32; 5] = [
    0x67452301, // H₀
    0xEFCDAB89, // H₁
    0x98BADCFE, // H₂
    0x10325476, // H₃
    0xC3D2E1F0, // H₄
];

/// Round function for SHA-1 choice operation (Ch) used in rounds 0-19
///
/// Implements: Ch(x,y,z) = (x AND y) XOR (NOT x AND z)
/// Optimized as: z XOR (x AND (y XOR z))
///
/// Uses rolling pattern where variables rotate (a,b,c,d,e) → (e,a,b,c,d)
macro_rules! round_ch {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr) => {
        $e = $e.wrapping_add($a.rotate_left(5))
            .wrapping_add($d ^ ($b & ($c ^ $d)))
            .wrapping_add(K[0])
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Round function for SHA-1 parity operation (Parity) used in rounds 20-39 and 60-79
///
/// Implements: Parity(x,y,z) = x XOR y XOR z
///
/// Uses rolling pattern where variables rotate (a,b,c,d,e) → (e,a,b,c,d)
macro_rules! round_parity {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $k:expr) => {
        $e = $e.wrapping_add($a.rotate_left(5))
            .wrapping_add($b ^ $c ^ $d)
            .wrapping_add($k)
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Round function for SHA-1 majority operation (Maj) used in rounds 40-59
///
/// Implements: Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
/// Optimized as: (x AND y) OR ((x OR y) AND z)
///
/// Uses rolling pattern where variables rotate (a,b,c,d,e) → (e,a,b,c,d)
macro_rules! round_maj {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr) => {
        $e = $e.wrapping_add($a.rotate_left(5))
            .wrapping_add(($b & $c) | (($b | $c) & $d))
            .wrapping_add(K[2])
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Computes the next message schedule word in the circular buffer
///
/// Implements: W[t] = ROTL¹(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
///
/// Uses circular buffer indexing with mask 0xF (16 words instead of 80)
macro_rules! schedule {
    ($w:expr, $t:expr) => {
        $w[($t) & 0xF] = ($w[($t - 3) & 0xF] ^ $w[($t - 8) & 0xF] ^
                          $w[($t - 14) & 0xF] ^ $w[($t - 16) & 0xF])
                         .rotate_left(1)
    };
}

/// Reads a big-endian u32 from a byte slice at the specified offset
///
/// # Arguments
/// * `bytes` - Source byte slice
/// * `offset` - Byte offset to read from
///
/// # Returns
/// A u32 value in native endianness converted from big-endian bytes
#[inline(always)]
const fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// 64-byte aligned block for optimized SHA-1 processing
///
/// This struct guarantees 64-byte alignment matching typical CPU cache line size,
/// enabling:
/// - Aligned load instructions (faster on most CPUs)
/// - Better memory access patterns
/// - Reduced cache line splits
///
/// The `#[repr(C)]` ensures predictable layout with data field at offset 0.
#[repr(C, align(64))]
#[derive(Copy, Clone)]
pub struct AlignedBlock {
    /// 64-byte data block
    pub data: [u8; 64],
}

impl AlignedBlock {
    /// Creates a new aligned block from a byte array
    ///
    /// # Arguments
    /// * `data` - Exactly 64 bytes of input data
    ///
    /// # Returns
    /// An aligned block containing the input data
    #[inline]
    pub const fn new(data: [u8; 64]) -> Self {
        Self { data }
    }

    /// Creates a new zeroed aligned block
    ///
    /// # Returns
    /// An aligned block filled with zeros
    #[inline]
    pub const fn zeroed() -> Self {
        Self { data: [0u8; 64] }
    }
}

/// SHA-1 hasher state
///
/// Maintains the hash state across incremental updates. The struct is aligned to
/// 64 bytes (cache line) for optimal performance.
///
/// # Fields
/// - `h`: Current hash value (5 × 32-bit words)
/// - `buffer`: Pending input data (up to 64 bytes)
/// - `buffer_len`: Number of bytes currently in buffer
/// - `total_len`: Total bits processed (excluding current buffer)
#[repr(align(64))]
pub struct Sha1 {
    h: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    /// Creates a new SHA-1 hasher initialized with standard IV
    ///
    /// Initializes the hash state with the values specified in FIPS 180-4.
    ///
    /// # Returns
    /// A new SHA-1 hasher ready to process data
    ///
    /// # Example
    /// ```rust
    /// let mut hasher = Sha1::new();
    /// hasher.update(b"hello");
    /// hasher.update(b" world");
    /// let hash = hasher.finalize();
    /// ```
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Updates the hasher with input data
    ///
    /// Can be called multiple times to hash data incrementally.
    /// Processes complete 512-bit (64-byte) blocks immediately and buffers
    /// any remaining bytes.
    ///
    /// # Arguments
    /// * `data` - Input bytes to hash
    ///
    /// # Example
    /// ```rust
    /// let mut hasher = Sha1::new();
    /// hasher.update(b"part1");
    /// hasher.update(b"part2");
    /// ```
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        while !remaining.is_empty() {
            let to_copy = core::cmp::min(64 - self.buffer_len, remaining.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&remaining[..to_copy]);
            self.buffer_len += to_copy;
            remaining = &remaining[to_copy..];

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
                self.total_len += 512;
            }
        }
    }

    /// Processes final padding when extra block is needed (cold path)
    ///
    /// This method handles the rare case (~12.5% probability) where the message
    /// length plus padding doesn't fit in the current block. Marked with
    /// `#[cold]` and `#[inline(never)]` to optimize the common path.
    ///
    /// # Arguments
    /// * `bit_len` - Total message length in bits
    #[inline(never)]
    #[cold]
    fn finalize_with_extra_block(&mut self, bit_len: u64) {
        // Pad current block to 64 bytes
        while self.buffer_len < 64 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        let block = self.buffer;
        self.process_block(&block);
        self.buffer_len = 0;

        // Process final block with length
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buffer;
        self.process_block(&final_block);
    }

    /// Finalizes the hash and returns the 160-bit digest
    ///
    /// Consumes the hasher, applies SHA-1 padding, and returns the final hash value.
    ///
    /// # Returns
    /// A 20-byte array containing the SHA-1 hash
    ///
    /// # Padding Scheme
    /// SHA-1 padding consists of:
    /// 1. A single '1' bit (0x80 byte)
    /// 2. Zero bits to fill to 448 bits mod 512
    /// 3. 64-bit big-endian message length
    ///
    /// # Example
    /// ```rust
    /// let mut hasher = Sha1::new();
    /// hasher.update(b"hello world");
    /// let hash = hasher.finalize();
    /// assert_eq!(hash.len(), 20);
    /// ```
    #[inline]
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len + (self.buffer_len as u64 * 8);

        // Append padding bit
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Branch optimization: common path first (87.5% probability)
        if self.buffer_len <= 56 {
            // Common case: padding fits in current block
            while self.buffer_len < 56 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let final_block = self.buffer;
            self.process_block(&final_block);
        } else {
            // Rare case: need extra block for padding
            self.finalize_with_extra_block(bit_len);
        }

        // Convert hash state to bytes
        let mut output = [0u8; 20];
        for (i, &h) in self.h.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        output
    }

    /// Processes a single 512-bit (64-byte) SHA-1 block
    ///
    /// Implements the SHA-1 compression function with 80 rounds using:
    /// - Rounds 0-19: Choice function
    /// - Rounds 20-39: Parity function
    /// - Rounds 40-59: Majority function
    /// - Rounds 60-79: Parity function
    ///
    /// Uses circular buffer optimization (16 words vs 80) to reduce memory usage.
    ///
    /// # Arguments
    /// * `block` - Exactly 64 bytes of input data
    #[inline(always)]
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 16];

        // Load initial 16 message schedule words
        w[0] = read_be_u32(block, 0);
        w[1] = read_be_u32(block, 4);
        w[2] = read_be_u32(block, 8);
        w[3] = read_be_u32(block, 12);
        w[4] = read_be_u32(block, 16);
        w[5] = read_be_u32(block, 20);
        w[6] = read_be_u32(block, 24);
        w[7] = read_be_u32(block, 28);
        w[8] = read_be_u32(block, 32);
        w[9] = read_be_u32(block, 36);
        w[10] = read_be_u32(block, 40);
        w[11] = read_be_u32(block, 44);
        w[12] = read_be_u32(block, 48);
        w[13] = read_be_u32(block, 52);
        w[14] = read_be_u32(block, 56);
        w[15] = read_be_u32(block, 60);

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Rounds 0-19: Choice function
        round_ch!(a, b, c, d, e, w[0]);
        round_ch!(e, a, b, c, d, w[1]);
        round_ch!(d, e, a, b, c, w[2]);
        round_ch!(c, d, e, a, b, w[3]);
        round_ch!(b, c, d, e, a, w[4]);

        round_ch!(a, b, c, d, e, w[5]);
        round_ch!(e, a, b, c, d, w[6]);
        round_ch!(d, e, a, b, c, w[7]);
        round_ch!(c, d, e, a, b, w[8]);
        round_ch!(b, c, d, e, a, w[9]);

        round_ch!(a, b, c, d, e, w[10]);
        round_ch!(e, a, b, c, d, w[11]);
        round_ch!(d, e, a, b, c, w[12]);
        round_ch!(c, d, e, a, b, w[13]);
        round_ch!(b, c, d, e, a, w[14]);

        round_ch!(a, b, c, d, e, w[15]);
        schedule!(w, 16); round_ch!(e, a, b, c, d, w[16 & 0xF]);
        schedule!(w, 17); round_ch!(d, e, a, b, c, w[17 & 0xF]);
        schedule!(w, 18); round_ch!(c, d, e, a, b, w[18 & 0xF]);
        schedule!(w, 19); round_ch!(b, c, d, e, a, w[19 & 0xF]);

        // Rounds 20-39: Parity function
        schedule!(w, 20); round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
        schedule!(w, 21); round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
        schedule!(w, 22); round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
        schedule!(w, 23); round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
        schedule!(w, 24); round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);

        schedule!(w, 25); round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
        schedule!(w, 26); round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
        schedule!(w, 27); round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
        schedule!(w, 28); round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
        schedule!(w, 29); round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);

        schedule!(w, 30); round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
        schedule!(w, 31); round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
        schedule!(w, 32); round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
        schedule!(w, 33); round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
        schedule!(w, 34); round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);

        schedule!(w, 35); round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
        schedule!(w, 36); round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
        schedule!(w, 37); round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
        schedule!(w, 38); round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
        schedule!(w, 39); round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

        // Rounds 40-59: Majority function
        schedule!(w, 40); round_maj!(a, b, c, d, e, w[40 & 0xF]);
        schedule!(w, 41); round_maj!(e, a, b, c, d, w[41 & 0xF]);
        schedule!(w, 42); round_maj!(d, e, a, b, c, w[42 & 0xF]);
        schedule!(w, 43); round_maj!(c, d, e, a, b, w[43 & 0xF]);
        schedule!(w, 44); round_maj!(b, c, d, e, a, w[44 & 0xF]);

        schedule!(w, 45); round_maj!(a, b, c, d, e, w[45 & 0xF]);
        schedule!(w, 46); round_maj!(e, a, b, c, d, w[46 & 0xF]);
        schedule!(w, 47); round_maj!(d, e, a, b, c, w[47 & 0xF]);
        schedule!(w, 48); round_maj!(c, d, e, a, b, w[48 & 0xF]);
        schedule!(w, 49); round_maj!(b, c, d, e, a, w[49 & 0xF]);

        schedule!(w, 50); round_maj!(a, b, c, d, e, w[50 & 0xF]);
        schedule!(w, 51); round_maj!(e, a, b, c, d, w[51 & 0xF]);
        schedule!(w, 52); round_maj!(d, e, a, b, c, w[52 & 0xF]);
        schedule!(w, 53); round_maj!(c, d, e, a, b, w[53 & 0xF]);
        schedule!(w, 54); round_maj!(b, c, d, e, a, w[54 & 0xF]);

        schedule!(w, 55); round_maj!(a, b, c, d, e, w[55 & 0xF]);
        schedule!(w, 56); round_maj!(e, a, b, c, d, w[56 & 0xF]);
        schedule!(w, 57); round_maj!(d, e, a, b, c, w[57 & 0xF]);
        schedule!(w, 58); round_maj!(c, d, e, a, b, w[58 & 0xF]);
        schedule!(w, 59); round_maj!(b, c, d, e, a, w[59 & 0xF]);

        // Rounds 60-79: Parity function
        schedule!(w, 60); round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
        schedule!(w, 61); round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
        schedule!(w, 62); round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
        schedule!(w, 63); round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
        schedule!(w, 64); round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);

        schedule!(w, 65); round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
        schedule!(w, 66); round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
        schedule!(w, 67); round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
        schedule!(w, 68); round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
        schedule!(w, 69); round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);

        schedule!(w, 70); round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
        schedule!(w, 71); round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
        schedule!(w, 72); round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
        schedule!(w, 73); round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
        schedule!(w, 74); round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);

        schedule!(w, 75); round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
        schedule!(w, 76); round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
        schedule!(w, 77); round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
        schedule!(w, 78); round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
        schedule!(w, 79); round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

        // Update hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    /// Processes a single 512-bit block with guaranteed 64-byte alignment
    ///
    /// Optimized variant of `process_block` for aligned input data.
    /// The compiler can generate more efficient code knowing the alignment.
    ///
    /// # Arguments
    /// * `block` - 64-byte aligned input block
    ///
    /// # Performance
    /// Alignment enables:
    /// - Aligned load instructions (faster on most CPUs)
    /// - Better auto-vectorization opportunities
    /// - Reduced cache line splits
    #[inline(always)]
    #[allow(dead_code)]
    fn process_aligned_block(&mut self, block: &AlignedBlock) {
        let mut w = [0u32; 16];

        // Load initial 16 message schedule words from aligned data
        w[0] = read_be_u32(&block.data, 0);
        w[1] = read_be_u32(&block.data, 4);
        w[2] = read_be_u32(&block.data, 8);
        w[3] = read_be_u32(&block.data, 12);
        w[4] = read_be_u32(&block.data, 16);
        w[5] = read_be_u32(&block.data, 20);
        w[6] = read_be_u32(&block.data, 24);
        w[7] = read_be_u32(&block.data, 28);
        w[8] = read_be_u32(&block.data, 32);
        w[9] = read_be_u32(&block.data, 36);
        w[10] = read_be_u32(&block.data, 40);
        w[11] = read_be_u32(&block.data, 44);
        w[12] = read_be_u32(&block.data, 48);
        w[13] = read_be_u32(&block.data, 52);
        w[14] = read_be_u32(&block.data, 56);
        w[15] = read_be_u32(&block.data, 60);

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Rounds 0-19: Choice
        round_ch!(a, b, c, d, e, w[0]);
        round_ch!(e, a, b, c, d, w[1]);
        round_ch!(d, e, a, b, c, w[2]);
        round_ch!(c, d, e, a, b, w[3]);
        round_ch!(b, c, d, e, a, w[4]);
        round_ch!(a, b, c, d, e, w[5]);
        round_ch!(e, a, b, c, d, w[6]);
        round_ch!(d, e, a, b, c, w[7]);
        round_ch!(c, d, e, a, b, w[8]);
        round_ch!(b, c, d, e, a, w[9]);
        round_ch!(a, b, c, d, e, w[10]);
        round_ch!(e, a, b, c, d, w[11]);
        round_ch!(d, e, a, b, c, w[12]);
        round_ch!(c, d, e, a, b, w[13]);
        round_ch!(b, c, d, e, a, w[14]);
        round_ch!(a, b, c, d, e, w[15]);
        schedule!(w, 16); round_ch!(e, a, b, c, d, w[16 & 0xF]);
        schedule!(w, 17); round_ch!(d, e, a, b, c, w[17 & 0xF]);
        schedule!(w, 18); round_ch!(c, d, e, a, b, w[18 & 0xF]);
        schedule!(w, 19); round_ch!(b, c, d, e, a, w[19 & 0xF]);

        // Rounds 20-39: Parity
        schedule!(w, 20); round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
        schedule!(w, 21); round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
        schedule!(w, 22); round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
        schedule!(w, 23); round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
        schedule!(w, 24); round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);
        schedule!(w, 25); round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
        schedule!(w, 26); round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
        schedule!(w, 27); round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
        schedule!(w, 28); round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
        schedule!(w, 29); round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);
        schedule!(w, 30); round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
        schedule!(w, 31); round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
        schedule!(w, 32); round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
        schedule!(w, 33); round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
        schedule!(w, 34); round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);
        schedule!(w, 35); round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
        schedule!(w, 36); round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
        schedule!(w, 37); round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
        schedule!(w, 38); round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
        schedule!(w, 39); round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

        // Rounds 40-59: Majority
        schedule!(w, 40); round_maj!(a, b, c, d, e, w[40 & 0xF]);
        schedule!(w, 41); round_maj!(e, a, b, c, d, w[41 & 0xF]);
        schedule!(w, 42); round_maj!(d, e, a, b, c, w[42 & 0xF]);
        schedule!(w, 43); round_maj!(c, d, e, a, b, w[43 & 0xF]);
        schedule!(w, 44); round_maj!(b, c, d, e, a, w[44 & 0xF]);
        schedule!(w, 45); round_maj!(a, b, c, d, e, w[45 & 0xF]);
        schedule!(w, 46); round_maj!(e, a, b, c, d, w[46 & 0xF]);
        schedule!(w, 47); round_maj!(d, e, a, b, c, w[47 & 0xF]);
        schedule!(w, 48); round_maj!(c, d, e, a, b, w[48 & 0xF]);
        schedule!(w, 49); round_maj!(b, c, d, e, a, w[49 & 0xF]);
        schedule!(w, 50); round_maj!(a, b, c, d, e, w[50 & 0xF]);
        schedule!(w, 51); round_maj!(e, a, b, c, d, w[51 & 0xF]);
        schedule!(w, 52); round_maj!(d, e, a, b, c, w[52 & 0xF]);
        schedule!(w, 53); round_maj!(c, d, e, a, b, w[53 & 0xF]);
        schedule!(w, 54); round_maj!(b, c, d, e, a, w[54 & 0xF]);
        schedule!(w, 55); round_maj!(a, b, c, d, e, w[55 & 0xF]);
        schedule!(w, 56); round_maj!(e, a, b, c, d, w[56 & 0xF]);
        schedule!(w, 57); round_maj!(d, e, a, b, c, w[57 & 0xF]);
        schedule!(w, 58); round_maj!(c, d, e, a, b, w[58 & 0xF]);
        schedule!(w, 59); round_maj!(b, c, d, e, a, w[59 & 0xF]);

        // Rounds 60-79: Parity
        schedule!(w, 60); round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
        schedule!(w, 61); round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
        schedule!(w, 62); round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
        schedule!(w, 63); round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
        schedule!(w, 64); round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);
        schedule!(w, 65); round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
        schedule!(w, 66); round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
        schedule!(w, 67); round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
        schedule!(w, 68); round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
        schedule!(w, 69); round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);
        schedule!(w, 70); round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
        schedule!(w, 71); round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
        schedule!(w, 72); round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
        schedule!(w, 73); round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
        schedule!(w, 74); round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);
        schedule!(w, 75); round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
        schedule!(w, 76); round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
        schedule!(w, 77); round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
        schedule!(w, 78); round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
        schedule!(w, 79); round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

        // Update hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Optimized fast path for small single-block messages (≤ 55 bytes)
///
/// This specialized function eliminates buffer management overhead for messages
/// that fit entirely in a single SHA-1 block with padding.
///
/// # Arguments
/// * `data` - Input data (must be ≤ 55 bytes)
///
/// # Returns
/// A 20-byte SHA-1 hash
///
/// # Performance
/// Approximately 10-20% faster than the general-purpose path for small inputs.
///
/// # Panics
/// Debug builds will panic if `data.len() > 55`
///
/// # Security Warning
/// SHA-1 is broken! Only use for legacy compatibility.
#[inline]
pub fn sha1_single_block_small(data: &[u8]) -> [u8; 20] {
    debug_assert!(data.len() <= 55, "Data must be <= 55 bytes for single-block fast path");

    // Initialize working variables with standard IVs
    let mut h0 = H_INIT[0];
    let mut h1 = H_INIT[1];
    let mut h2 = H_INIT[2];
    let mut h3 = H_INIT[3];
    let mut h4 = H_INIT[4];

    // Build padded block inline
    let mut block = [0u8; 64];
    block[..data.len()].copy_from_slice(data);
    block[data.len()] = 0x80;
    let bit_len = (data.len() as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());

    // Message schedule (circular buffer)
    let mut w = [0u32; 16];
    w[0] = read_be_u32(&block, 0);
    w[1] = read_be_u32(&block, 4);
    w[2] = read_be_u32(&block, 8);
    w[3] = read_be_u32(&block, 12);
    w[4] = read_be_u32(&block, 16);
    w[5] = read_be_u32(&block, 20);
    w[6] = read_be_u32(&block, 24);
    w[7] = read_be_u32(&block, 28);
    w[8] = read_be_u32(&block, 32);
    w[9] = read_be_u32(&block, 36);
    w[10] = read_be_u32(&block, 40);
    w[11] = read_be_u32(&block, 44);
    w[12] = read_be_u32(&block, 48);
    w[13] = read_be_u32(&block, 52);
    w[14] = read_be_u32(&block, 56);
    w[15] = read_be_u32(&block, 60);

    let mut a = h0;
    let mut b = h1;
    let mut c = h2;
    let mut d = h3;
    let mut e = h4;

    // 80 rounds of SHA-1 compression

    // Rounds 0-19: Choice
    round_ch!(a, b, c, d, e, w[0]);
    round_ch!(e, a, b, c, d, w[1]);
    round_ch!(d, e, a, b, c, w[2]);
    round_ch!(c, d, e, a, b, w[3]);
    round_ch!(b, c, d, e, a, w[4]);
    round_ch!(a, b, c, d, e, w[5]);
    round_ch!(e, a, b, c, d, w[6]);
    round_ch!(d, e, a, b, c, w[7]);
    round_ch!(c, d, e, a, b, w[8]);
    round_ch!(b, c, d, e, a, w[9]);
    round_ch!(a, b, c, d, e, w[10]);
    round_ch!(e, a, b, c, d, w[11]);
    round_ch!(d, e, a, b, c, w[12]);
    round_ch!(c, d, e, a, b, w[13]);
    round_ch!(b, c, d, e, a, w[14]);
    round_ch!(a, b, c, d, e, w[15]);
    schedule!(w, 16); round_ch!(e, a, b, c, d, w[16 & 0xF]);
    schedule!(w, 17); round_ch!(d, e, a, b, c, w[17 & 0xF]);
    schedule!(w, 18); round_ch!(c, d, e, a, b, w[18 & 0xF]);
    schedule!(w, 19); round_ch!(b, c, d, e, a, w[19 & 0xF]);

    // Rounds 20-39: Parity
    schedule!(w, 20); round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
    schedule!(w, 21); round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
    schedule!(w, 22); round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
    schedule!(w, 23); round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
    schedule!(w, 24); round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);
    schedule!(w, 25); round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
    schedule!(w, 26); round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
    schedule!(w, 27); round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
    schedule!(w, 28); round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
    schedule!(w, 29); round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);
    schedule!(w, 30); round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
    schedule!(w, 31); round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
    schedule!(w, 32); round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
    schedule!(w, 33); round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
    schedule!(w, 34); round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);
    schedule!(w, 35); round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
    schedule!(w, 36); round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
    schedule!(w, 37); round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
    schedule!(w, 38); round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
    schedule!(w, 39); round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

    // Rounds 40-59: Majority
    schedule!(w, 40); round_maj!(a, b, c, d, e, w[40 & 0xF]);
    schedule!(w, 41); round_maj!(e, a, b, c, d, w[41 & 0xF]);
    schedule!(w, 42); round_maj!(d, e, a, b, c, w[42 & 0xF]);
    schedule!(w, 43); round_maj!(c, d, e, a, b, w[43 & 0xF]);
    schedule!(w, 44); round_maj!(b, c, d, e, a, w[44 & 0xF]);
    schedule!(w, 45); round_maj!(a, b, c, d, e, w[45 & 0xF]);
    schedule!(w, 46); round_maj!(e, a, b, c, d, w[46 & 0xF]);
    schedule!(w, 47); round_maj!(d, e, a, b, c, w[47 & 0xF]);
    schedule!(w, 48); round_maj!(c, d, e, a, b, w[48 & 0xF]);
    schedule!(w, 49); round_maj!(b, c, d, e, a, w[49 & 0xF]);
    schedule!(w, 50); round_maj!(a, b, c, d, e, w[50 & 0xF]);
    schedule!(w, 51); round_maj!(e, a, b, c, d, w[51 & 0xF]);
    schedule!(w, 52); round_maj!(d, e, a, b, c, w[52 & 0xF]);
    schedule!(w, 53); round_maj!(c, d, e, a, b, w[53 & 0xF]);
    schedule!(w, 54); round_maj!(b, c, d, e, a, w[54 & 0xF]);
    schedule!(w, 55); round_maj!(a, b, c, d, e, w[55 & 0xF]);
    schedule!(w, 56); round_maj!(e, a, b, c, d, w[56 & 0xF]);
    schedule!(w, 57); round_maj!(d, e, a, b, c, w[57 & 0xF]);
    schedule!(w, 58); round_maj!(c, d, e, a, b, w[58 & 0xF]);
    schedule!(w, 59); round_maj!(b, c, d, e, a, w[59 & 0xF]);

    // Rounds 60-79: Parity
    schedule!(w, 60); round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
    schedule!(w, 61); round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
    schedule!(w, 62); round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
    schedule!(w, 63); round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
    schedule!(w, 64); round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);
    schedule!(w, 65); round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
    schedule!(w, 66); round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
    schedule!(w, 67); round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
    schedule!(w, 68); round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
    schedule!(w, 69); round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);
    schedule!(w, 70); round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
    schedule!(w, 71); round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
    schedule!(w, 72); round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
    schedule!(w, 73); round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
    schedule!(w, 74); round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);
    schedule!(w, 75); round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
    schedule!(w, 76); round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
    schedule!(w, 77); round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
    schedule!(w, 78); round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
    schedule!(w, 79); round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

    // Finalize hash
    h0 = h0.wrapping_add(a);
    h1 = h1.wrapping_add(b);
    h2 = h2.wrapping_add(c);
    h3 = h3.wrapping_add(d);
    h4 = h4.wrapping_add(e);

    // Convert to bytes
    let mut output = [0u8; 20];
    output[0..4].copy_from_slice(&h0.to_be_bytes());
    output[4..8].copy_from_slice(&h1.to_be_bytes());
    output[8..12].copy_from_slice(&h2.to_be_bytes());
    output[12..16].copy_from_slice(&h3.to_be_bytes());
    output[16..20].copy_from_slice(&h4.to_be_bytes());
    output
}

/// Precomputed SHA-1 hash of empty input for fast-path optimization
///
/// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
const SHA1_EMPTY: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
    0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
];

/// Computes SHA-1 hash of input data (one-shot interface)
///
/// This is a convenience function that automatically selects the optimal
/// code path based on input size:
/// - Empty input: Returns precomputed constant
/// - ≤ 55 bytes: Uses specialized single-block function
/// - > 55 bytes: Uses general incremental hasher
///
/// # Arguments
/// * `data` - Input bytes to hash
///
/// # Returns
/// A 20-byte SHA-1 hash
///
/// # Security Warning
/// **SHA-1 is cryptographically broken!** Only use for:
/// - Legacy protocol compatibility
/// - Non-security applications (e.g., checksums)
/// - Where collision resistance is not required
///
/// For security-critical applications, use SHA-256 or stronger.
///
/// # Example
/// ```rust
/// use sha1::sha1;
///
/// let hash = sha1(b"hello world");
/// assert_eq!(hash.len(), 20);
/// ```
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    if data.is_empty() {
        return SHA1_EMPTY;
    }

    if data.len() <= 55 {
        return sha1_single_block_small(data);
    }

    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}
