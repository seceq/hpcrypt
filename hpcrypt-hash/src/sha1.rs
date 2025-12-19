//! SHA-1 hash function implementation
//!
//! **WARNING**: SHA-1 is cryptographically broken and should not be used for
//! security-critical applications. It is provided here for compatibility with
//! legacy protocols (like SRP-6a which uses SHA-1 per RFC 5054).
//!
//! Consider using SHA-256, SHA-384, or SHA-512 for new applications.

/// SHA-1 output length in bytes (160 bits)
pub const OUT_LEN: usize = 20;

/// SHA-1 block length in bytes (512 bits)
pub const BLOCK_LEN: usize = 64;

const K: [u32; 4] = [
    0x5A827999, // 0  <= t <= 19
    0x6ED9EBA1, // 20 <= t <= 39
    0x8F1BBCDC, // 40 <= t <= 59
    0xCA62C1D6, // 60 <= t <= 79
];

/// SHA-1 initial hash values (as per FIPS 180-4)
const H_INIT: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

// Rolling macro for SHA-1 rounds
// This uses a "rolling" pattern where variables rotate: (a,b,c,d,e) -> (e,a,b,c,d)
// This eliminates the need for temporary variables and makes the code more readable

/// Round macro for choice function (rounds 0-19)
macro_rules! round_ch {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr) => {
        $e = $e
            .wrapping_add($a.rotate_left(5))
            .wrapping_add($d ^ ($b & ($c ^ $d)))
            .wrapping_add(K[0])
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Round macro for parity function (rounds 20-39, 60-79)
macro_rules! round_parity {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr, $k:expr) => {
        $e = $e
            .wrapping_add($a.rotate_left(5))
            .wrapping_add($b ^ $c ^ $d)
            .wrapping_add($k)
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Round macro for majority function (rounds 40-59)
macro_rules! round_maj {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $w:expr) => {
        $e = $e
            .wrapping_add($a.rotate_left(5))
            .wrapping_add(($b & $c) | (($b | $c) & $d))
            .wrapping_add(K[2])
            .wrapping_add($w);
        $b = $b.rotate_left(30);
    };
}

/// Macro to compute next message schedule word in circular buffer
macro_rules! schedule {
    ($w:expr, $t:expr) => {
        $w[($t) & 0xF] =
            ($w[($t - 3) & 0xF] ^ $w[($t - 8) & 0xF] ^ $w[($t - 14) & 0xF] ^ $w[($t - 16) & 0xF])
                .rotate_left(1)
    };
}

/// Helper to read big-endian u32 from byte slice
#[inline(always)]
const fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Aligned 64-byte block for SHA-1 processing
///
/// This type guarantees 64-byte alignment, which allows the compiler to:
/// - Use aligned load instructions (faster on most CPUs)
/// - Better optimize memory access patterns
/// - Potentially enable auto-vectorization
///
/// The `#[repr(C)]` ensures the layout is predictable and the data field
/// is at offset 0 (same as the struct address).
#[repr(C, align(64))]
#[derive(Copy, Clone)]
pub struct AlignedBlock {
    pub data: [u8; 64],
}

impl AlignedBlock {
    /// Create a new aligned block from a byte array
    #[inline]
    pub const fn new(data: [u8; 64]) -> Self {
        Self { data }
    }

    /// Create a new zeroed aligned block
    #[inline]
    pub const fn zeroed() -> Self {
        Self { data: [0u8; 64] }
    }
}

/// SHA-1 hasher
#[repr(align(64))] // Cache line alignment for better performance
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    // No public methods - use HashFunction trait methods instead

    /// Internal: Create a new SHA-1 hasher
    #[inline]
    fn new_internal() -> Self {
        Self {
            h: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Internal: Update the hasher with input data
    #[inline]
    fn update_internal(&mut self, data: &[u8]) {
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
                self.total_len += 512; // 64 bytes * 8 bits
            }
        }
    }

    /// Cold path: Process padding when buffer doesn't have enough space
    #[inline(never)]
    #[cold]
    fn finalize_with_extra_block(&mut self, bit_len: u64) {
        // Pad to end of current block
        while self.buffer_len < 64 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        let block = self.buffer;
        self.process_block(&block);
        self.buffer_len = 0;

        // Now continue with normal padding in empty buffer
        while self.buffer_len < 56 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buffer;
        self.process_block(&final_block);
    }

    /// Internal: Finalize the hash and return the digest
    #[inline]
    fn finalize_internal(mut self) -> [u8; 20] {
        let bit_len = self.total_len + (self.buffer_len as u64 * 8);

        // Append padding
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Branch prediction: Common path first (buffer_len <= 56 happens ~87.5% of the time)
        // This helps the CPU branch predictor learn the pattern faster
        if self.buffer_len <= 56 {
            // Hot path - inline padding (common case: ~87.5%)
            while self.buffer_len < 56 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let final_block = self.buffer;
            self.process_block(&final_block);
        } else {
            // Cold path - need extra block (rare case: ~12.5%)
            self.finalize_with_extra_block(bit_len);
        }

        // Convert hash to bytes (using loop for better optimization)
        let mut output = [0u8; 20];
        for (i, &h) in self.h.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        output
    }

    /// Process a single SHA-1 block
    ///
    /// This is marked `#[inline(always)]` to enable better optimization and
    /// auto-vectorization opportunities when processing multiple blocks.
    #[inline(always)]
    fn process_block(&mut self, block: &[u8; 64]) {
        // Use circular buffer: only 16 words instead of 80
        let mut w = [0u32; 16];

        // Load message schedule words 0-15 (unrolled for performance)
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

        // Rounds 0-19: Choice function with rolling pattern
        // Pattern: round_ch!(a, b, c, d, e, w) rotates to (e, a, b, c, d) for next round
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
        schedule!(w, 16);
        round_ch!(e, a, b, c, d, w[16 & 0xF]);
        schedule!(w, 17);
        round_ch!(d, e, a, b, c, w[17 & 0xF]);
        schedule!(w, 18);
        round_ch!(c, d, e, a, b, w[18 & 0xF]);
        schedule!(w, 19);
        round_ch!(b, c, d, e, a, w[19 & 0xF]);

        // Rounds 20-39: Parity function
        schedule!(w, 20);
        round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
        schedule!(w, 21);
        round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
        schedule!(w, 22);
        round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
        schedule!(w, 23);
        round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
        schedule!(w, 24);
        round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);

        schedule!(w, 25);
        round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
        schedule!(w, 26);
        round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
        schedule!(w, 27);
        round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
        schedule!(w, 28);
        round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
        schedule!(w, 29);
        round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);

        schedule!(w, 30);
        round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
        schedule!(w, 31);
        round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
        schedule!(w, 32);
        round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
        schedule!(w, 33);
        round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
        schedule!(w, 34);
        round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);

        schedule!(w, 35);
        round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
        schedule!(w, 36);
        round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
        schedule!(w, 37);
        round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
        schedule!(w, 38);
        round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
        schedule!(w, 39);
        round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

        // Rounds 40-59: Majority function
        schedule!(w, 40);
        round_maj!(a, b, c, d, e, w[40 & 0xF]);
        schedule!(w, 41);
        round_maj!(e, a, b, c, d, w[41 & 0xF]);
        schedule!(w, 42);
        round_maj!(d, e, a, b, c, w[42 & 0xF]);
        schedule!(w, 43);
        round_maj!(c, d, e, a, b, w[43 & 0xF]);
        schedule!(w, 44);
        round_maj!(b, c, d, e, a, w[44 & 0xF]);

        schedule!(w, 45);
        round_maj!(a, b, c, d, e, w[45 & 0xF]);
        schedule!(w, 46);
        round_maj!(e, a, b, c, d, w[46 & 0xF]);
        schedule!(w, 47);
        round_maj!(d, e, a, b, c, w[47 & 0xF]);
        schedule!(w, 48);
        round_maj!(c, d, e, a, b, w[48 & 0xF]);
        schedule!(w, 49);
        round_maj!(b, c, d, e, a, w[49 & 0xF]);

        schedule!(w, 50);
        round_maj!(a, b, c, d, e, w[50 & 0xF]);
        schedule!(w, 51);
        round_maj!(e, a, b, c, d, w[51 & 0xF]);
        schedule!(w, 52);
        round_maj!(d, e, a, b, c, w[52 & 0xF]);
        schedule!(w, 53);
        round_maj!(c, d, e, a, b, w[53 & 0xF]);
        schedule!(w, 54);
        round_maj!(b, c, d, e, a, w[54 & 0xF]);

        schedule!(w, 55);
        round_maj!(a, b, c, d, e, w[55 & 0xF]);
        schedule!(w, 56);
        round_maj!(e, a, b, c, d, w[56 & 0xF]);
        schedule!(w, 57);
        round_maj!(d, e, a, b, c, w[57 & 0xF]);
        schedule!(w, 58);
        round_maj!(c, d, e, a, b, w[58 & 0xF]);
        schedule!(w, 59);
        round_maj!(b, c, d, e, a, w[59 & 0xF]);

        // Rounds 60-79: Parity function again
        schedule!(w, 60);
        round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
        schedule!(w, 61);
        round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
        schedule!(w, 62);
        round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
        schedule!(w, 63);
        round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
        schedule!(w, 64);
        round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);

        schedule!(w, 65);
        round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
        schedule!(w, 66);
        round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
        schedule!(w, 67);
        round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
        schedule!(w, 68);
        round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
        schedule!(w, 69);
        round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);

        schedule!(w, 70);
        round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
        schedule!(w, 71);
        round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
        schedule!(w, 72);
        round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
        schedule!(w, 73);
        round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
        schedule!(w, 74);
        round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);

        schedule!(w, 75);
        round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
        schedule!(w, 76);
        round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
        schedule!(w, 77);
        round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
        schedule!(w, 78);
        round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
        schedule!(w, 79);
        round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

        // Add to hash - note the final rotation state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    /// Process a single SHA-1 block with guaranteed 64-byte alignment
    ///
    /// This method is optimized for aligned input data. The compiler knows
    /// the block is 64-byte aligned and can:
    /// - Use aligned load instructions (faster on most CPUs)
    /// - Optimize memory access patterns
    /// - Potentially enable better auto-vectorization
    ///
    /// This is marked `#[inline(always)]` to enable maximum optimization.
    #[inline(always)]
    #[allow(dead_code)]
    fn process_aligned_block(&mut self, block: &AlignedBlock) {
        // Use circular buffer: only 16 words instead of 80
        let mut w = [0u32; 16];

        // Load message schedule words 0-15 (unrolled for performance)
        // The compiler knows block.data is 64-byte aligned
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

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Rounds 0-19: Choice function with rolling pattern
        // Pattern: round_ch!(a, b, c, d, e, w) rotates to (e, a, b, c, d) for next round
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
        schedule!(w, 16);
        round_ch!(e, a, b, c, d, w[16 & 0xF]);
        schedule!(w, 17);
        round_ch!(d, e, a, b, c, w[17 & 0xF]);
        schedule!(w, 18);
        round_ch!(c, d, e, a, b, w[18 & 0xF]);
        schedule!(w, 19);
        round_ch!(b, c, d, e, a, w[19 & 0xF]);

        // Rounds 20-39: Parity function
        schedule!(w, 20);
        round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
        schedule!(w, 21);
        round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
        schedule!(w, 22);
        round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
        schedule!(w, 23);
        round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
        schedule!(w, 24);
        round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);

        schedule!(w, 25);
        round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
        schedule!(w, 26);
        round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
        schedule!(w, 27);
        round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
        schedule!(w, 28);
        round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
        schedule!(w, 29);
        round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);

        schedule!(w, 30);
        round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
        schedule!(w, 31);
        round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
        schedule!(w, 32);
        round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
        schedule!(w, 33);
        round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
        schedule!(w, 34);
        round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);

        schedule!(w, 35);
        round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
        schedule!(w, 36);
        round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
        schedule!(w, 37);
        round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
        schedule!(w, 38);
        round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
        schedule!(w, 39);
        round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

        // Rounds 40-59: Majority function
        schedule!(w, 40);
        round_maj!(a, b, c, d, e, w[40 & 0xF]);
        schedule!(w, 41);
        round_maj!(e, a, b, c, d, w[41 & 0xF]);
        schedule!(w, 42);
        round_maj!(d, e, a, b, c, w[42 & 0xF]);
        schedule!(w, 43);
        round_maj!(c, d, e, a, b, w[43 & 0xF]);
        schedule!(w, 44);
        round_maj!(b, c, d, e, a, w[44 & 0xF]);

        schedule!(w, 45);
        round_maj!(a, b, c, d, e, w[45 & 0xF]);
        schedule!(w, 46);
        round_maj!(e, a, b, c, d, w[46 & 0xF]);
        schedule!(w, 47);
        round_maj!(d, e, a, b, c, w[47 & 0xF]);
        schedule!(w, 48);
        round_maj!(c, d, e, a, b, w[48 & 0xF]);
        schedule!(w, 49);
        round_maj!(b, c, d, e, a, w[49 & 0xF]);

        schedule!(w, 50);
        round_maj!(a, b, c, d, e, w[50 & 0xF]);
        schedule!(w, 51);
        round_maj!(e, a, b, c, d, w[51 & 0xF]);
        schedule!(w, 52);
        round_maj!(d, e, a, b, c, w[52 & 0xF]);
        schedule!(w, 53);
        round_maj!(c, d, e, a, b, w[53 & 0xF]);
        schedule!(w, 54);
        round_maj!(b, c, d, e, a, w[54 & 0xF]);

        schedule!(w, 55);
        round_maj!(a, b, c, d, e, w[55 & 0xF]);
        schedule!(w, 56);
        round_maj!(e, a, b, c, d, w[56 & 0xF]);
        schedule!(w, 57);
        round_maj!(d, e, a, b, c, w[57 & 0xF]);
        schedule!(w, 58);
        round_maj!(c, d, e, a, b, w[58 & 0xF]);
        schedule!(w, 59);
        round_maj!(b, c, d, e, a, w[59 & 0xF]);

        // Rounds 60-79: Parity function again
        schedule!(w, 60);
        round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
        schedule!(w, 61);
        round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
        schedule!(w, 62);
        round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
        schedule!(w, 63);
        round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
        schedule!(w, 64);
        round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);

        schedule!(w, 65);
        round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
        schedule!(w, 66);
        round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
        schedule!(w, 67);
        round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
        schedule!(w, 68);
        round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
        schedule!(w, 69);
        round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);

        schedule!(w, 70);
        round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
        schedule!(w, 71);
        round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
        schedule!(w, 72);
        round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
        schedule!(w, 73);
        round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
        schedule!(w, 74);
        round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);

        schedule!(w, 75);
        round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
        schedule!(w, 76);
        round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
        schedule!(w, 77);
        round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
        schedule!(w, 78);
        round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
        schedule!(w, 79);
        round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

        // Add to hash - note the final rotation state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new_internal()
    }
}

// ===== HashFunction Trait Implementation =====

impl crate::traits::HashFunction for Sha1 {
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
        *self = Self::new_internal();
        clone.finalize_internal()
    }

    #[inline]
    fn hash(data: &[u8]) -> Self::Output {
        sha1(data)
    }
}

/// Specialized fast path for single-block messages (<= 55 bytes)
///
/// This optimized path eliminates buffer management overhead for small messages
/// that fit in a single SHA-1 block without needing padding in a second block.
///
/// **Performance**: ~10-20% faster than general-purpose path for small data
///
/// **WARNING**: SHA-1 is broken! Only use for legacy compatibility.
#[inline]
pub fn sha1_single_block_small(data: &[u8]) -> [u8; 20] {
    debug_assert!(
        data.len() <= 55,
        "Data must be <= 55 bytes for single-block fast path"
    );

    // Initialize hash state from const
    let mut h0 = H_INIT[0];
    let mut h1 = H_INIT[1];
    let mut h2 = H_INIT[2];
    let mut h3 = H_INIT[3];
    let mut h4 = H_INIT[4];

    // Build the single block with padding inline
    let mut block = [0u8; 64];
    block[..data.len()].copy_from_slice(data);
    block[data.len()] = 0x80;
    // Length in bits (data.len() * 8) in big-endian at bytes 56-63
    let bit_len = (data.len() as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());

    // Use circular buffer: only 16 words instead of 80
    let mut w = [0u32; 16];

    // Load message schedule words 0-15 (unrolled for performance)
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

    // Initialize working variables
    let mut a = h0;
    let mut b = h1;
    let mut c = h2;
    let mut d = h3;
    let mut e = h4;

    // Rounds 0-19: Choice function with rolling pattern
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
    schedule!(w, 16);
    round_ch!(e, a, b, c, d, w[16 & 0xF]);
    schedule!(w, 17);
    round_ch!(d, e, a, b, c, w[17 & 0xF]);
    schedule!(w, 18);
    round_ch!(c, d, e, a, b, w[18 & 0xF]);
    schedule!(w, 19);
    round_ch!(b, c, d, e, a, w[19 & 0xF]);

    // Rounds 20-39: Parity function
    schedule!(w, 20);
    round_parity!(a, b, c, d, e, w[20 & 0xF], K[1]);
    schedule!(w, 21);
    round_parity!(e, a, b, c, d, w[21 & 0xF], K[1]);
    schedule!(w, 22);
    round_parity!(d, e, a, b, c, w[22 & 0xF], K[1]);
    schedule!(w, 23);
    round_parity!(c, d, e, a, b, w[23 & 0xF], K[1]);
    schedule!(w, 24);
    round_parity!(b, c, d, e, a, w[24 & 0xF], K[1]);

    schedule!(w, 25);
    round_parity!(a, b, c, d, e, w[25 & 0xF], K[1]);
    schedule!(w, 26);
    round_parity!(e, a, b, c, d, w[26 & 0xF], K[1]);
    schedule!(w, 27);
    round_parity!(d, e, a, b, c, w[27 & 0xF], K[1]);
    schedule!(w, 28);
    round_parity!(c, d, e, a, b, w[28 & 0xF], K[1]);
    schedule!(w, 29);
    round_parity!(b, c, d, e, a, w[29 & 0xF], K[1]);

    schedule!(w, 30);
    round_parity!(a, b, c, d, e, w[30 & 0xF], K[1]);
    schedule!(w, 31);
    round_parity!(e, a, b, c, d, w[31 & 0xF], K[1]);
    schedule!(w, 32);
    round_parity!(d, e, a, b, c, w[32 & 0xF], K[1]);
    schedule!(w, 33);
    round_parity!(c, d, e, a, b, w[33 & 0xF], K[1]);
    schedule!(w, 34);
    round_parity!(b, c, d, e, a, w[34 & 0xF], K[1]);

    schedule!(w, 35);
    round_parity!(a, b, c, d, e, w[35 & 0xF], K[1]);
    schedule!(w, 36);
    round_parity!(e, a, b, c, d, w[36 & 0xF], K[1]);
    schedule!(w, 37);
    round_parity!(d, e, a, b, c, w[37 & 0xF], K[1]);
    schedule!(w, 38);
    round_parity!(c, d, e, a, b, w[38 & 0xF], K[1]);
    schedule!(w, 39);
    round_parity!(b, c, d, e, a, w[39 & 0xF], K[1]);

    // Rounds 40-59: Majority function
    schedule!(w, 40);
    round_maj!(a, b, c, d, e, w[40 & 0xF]);
    schedule!(w, 41);
    round_maj!(e, a, b, c, d, w[41 & 0xF]);
    schedule!(w, 42);
    round_maj!(d, e, a, b, c, w[42 & 0xF]);
    schedule!(w, 43);
    round_maj!(c, d, e, a, b, w[43 & 0xF]);
    schedule!(w, 44);
    round_maj!(b, c, d, e, a, w[44 & 0xF]);

    schedule!(w, 45);
    round_maj!(a, b, c, d, e, w[45 & 0xF]);
    schedule!(w, 46);
    round_maj!(e, a, b, c, d, w[46 & 0xF]);
    schedule!(w, 47);
    round_maj!(d, e, a, b, c, w[47 & 0xF]);
    schedule!(w, 48);
    round_maj!(c, d, e, a, b, w[48 & 0xF]);
    schedule!(w, 49);
    round_maj!(b, c, d, e, a, w[49 & 0xF]);

    schedule!(w, 50);
    round_maj!(a, b, c, d, e, w[50 & 0xF]);
    schedule!(w, 51);
    round_maj!(e, a, b, c, d, w[51 & 0xF]);
    schedule!(w, 52);
    round_maj!(d, e, a, b, c, w[52 & 0xF]);
    schedule!(w, 53);
    round_maj!(c, d, e, a, b, w[53 & 0xF]);
    schedule!(w, 54);
    round_maj!(b, c, d, e, a, w[54 & 0xF]);

    schedule!(w, 55);
    round_maj!(a, b, c, d, e, w[55 & 0xF]);
    schedule!(w, 56);
    round_maj!(e, a, b, c, d, w[56 & 0xF]);
    schedule!(w, 57);
    round_maj!(d, e, a, b, c, w[57 & 0xF]);
    schedule!(w, 58);
    round_maj!(c, d, e, a, b, w[58 & 0xF]);
    schedule!(w, 59);
    round_maj!(b, c, d, e, a, w[59 & 0xF]);

    // Rounds 60-79: Parity function again
    schedule!(w, 60);
    round_parity!(a, b, c, d, e, w[60 & 0xF], K[3]);
    schedule!(w, 61);
    round_parity!(e, a, b, c, d, w[61 & 0xF], K[3]);
    schedule!(w, 62);
    round_parity!(d, e, a, b, c, w[62 & 0xF], K[3]);
    schedule!(w, 63);
    round_parity!(c, d, e, a, b, w[63 & 0xF], K[3]);
    schedule!(w, 64);
    round_parity!(b, c, d, e, a, w[64 & 0xF], K[3]);

    schedule!(w, 65);
    round_parity!(a, b, c, d, e, w[65 & 0xF], K[3]);
    schedule!(w, 66);
    round_parity!(e, a, b, c, d, w[66 & 0xF], K[3]);
    schedule!(w, 67);
    round_parity!(d, e, a, b, c, w[67 & 0xF], K[3]);
    schedule!(w, 68);
    round_parity!(c, d, e, a, b, w[68 & 0xF], K[3]);
    schedule!(w, 69);
    round_parity!(b, c, d, e, a, w[69 & 0xF], K[3]);

    schedule!(w, 70);
    round_parity!(a, b, c, d, e, w[70 & 0xF], K[3]);
    schedule!(w, 71);
    round_parity!(e, a, b, c, d, w[71 & 0xF], K[3]);
    schedule!(w, 72);
    round_parity!(d, e, a, b, c, w[72 & 0xF], K[3]);
    schedule!(w, 73);
    round_parity!(c, d, e, a, b, w[73 & 0xF], K[3]);
    schedule!(w, 74);
    round_parity!(b, c, d, e, a, w[74 & 0xF], K[3]);

    schedule!(w, 75);
    round_parity!(a, b, c, d, e, w[75 & 0xF], K[3]);
    schedule!(w, 76);
    round_parity!(e, a, b, c, d, w[76 & 0xF], K[3]);
    schedule!(w, 77);
    round_parity!(d, e, a, b, c, w[77 & 0xF], K[3]);
    schedule!(w, 78);
    round_parity!(c, d, e, a, b, w[78 & 0xF], K[3]);
    schedule!(w, 79);
    round_parity!(b, c, d, e, a, w[79 & 0xF], K[3]);

    // Add to hash - note the final rotation state
    h0 = h0.wrapping_add(a);
    h1 = h1.wrapping_add(b);
    h2 = h2.wrapping_add(c);
    h3 = h3.wrapping_add(d);
    h4 = h4.wrapping_add(e);

    // Convert hash to bytes (inline for performance)
    let mut output = [0u8; 20];
    output[0..4].copy_from_slice(&h0.to_be_bytes());
    output[4..8].copy_from_slice(&h1.to_be_bytes());
    output[8..12].copy_from_slice(&h2.to_be_bytes());
    output[12..16].copy_from_slice(&h3.to_be_bytes());
    output[16..20].copy_from_slice(&h4.to_be_bytes());
    output
}

/// Precomputed SHA-1 hash of empty input
///
/// This is the result of hashing zero bytes, precomputed at compile time.
/// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
const SHA1_EMPTY: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
];

/// Convenience function to compute SHA-1 hash
///
/// **WARNING**: SHA-1 is broken! Only use for legacy compatibility.
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    // Fast path: empty input (common in some protocols)
    if data.is_empty() {
        return SHA1_EMPTY;
    }

    // Fast path: small single-block messages (<= 55 bytes)
    if data.len() <= 55 {
        return sha1_single_block_small(data);
    }

    // General-purpose path for larger data
    let mut hasher = Sha1::new_internal();
    hasher.update_internal(data);
    hasher.finalize_internal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::HashFunction;

    #[test]
    fn test_sha1_empty() {
        let hash = sha1(b"");
        let expected = hex_literal::hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        let expected = hex_literal::hex!("a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_long() {
        let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected = hex_literal::hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_incremental() {
        let mut hasher = Sha1::new();
        hasher.update(b"abc");
        hasher.update(b"def");
        let hash = hasher.finalize();

        let hash_direct = sha1(b"abcdef");
        assert_eq!(hash, hash_direct);
    }
}
