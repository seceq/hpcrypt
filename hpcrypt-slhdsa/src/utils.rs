//! Utility functions for SLH-DSA including base-w encoding and buffer management.

/// Cold path for unsupported Winternitz parameter error.
///
/// Marked cold to keep error handling out of hot paths, improving
/// instruction cache utilization.
#[cold]
#[inline(never)]
fn unsupported_winternitz_parameter(w: usize) -> ! {
    panic!("Unsupported Winternitz parameter: {}", w)
}

// OPTIMIZATION: Precompute (W-1) - digit for W=16 at compile time
// This eliminates subtraction in the hot checksum computation path
const fn compute_w_minus_1_table_w16() -> [u8; 16] {
    let mut table = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        table[i] = (15 - i) as u8;
        i += 1;
    }
    table
}

static W_MINUS_1_W16: [u8; 16] = compute_w_minus_1_table_w16();

/// Base-w encoding for W=16 (optimized using nibble extraction).
///
/// Extracts 4-bit nibbles from bytes, which is much faster than
/// general division-based encoding.
#[inline]
pub fn base16_encode(input: &[u8], output: &mut [u8]) {
    let mut out_idx = 0;
    for &byte in input.iter() {
        if out_idx >= output.len() {
            break;
        }
        output[out_idx] = byte >> 4; // High nibble
        out_idx += 1;

        if out_idx >= output.len() {
            break;
        }
        output[out_idx] = byte & 0x0F; // Low nibble
        out_idx += 1;
    }
}

/// Base-w encoding with checksum for WOTS+.
///
/// Encodes the message in base-w and appends a checksum to detect errors.
/// For W=16, uses optimized nibble extraction.
pub fn base_w_with_checksum(msg: &[u8], w: usize, len1: usize, len2: usize, output: &mut [usize]) {
    debug_assert_eq!(output.len(), len1 + len2);

    match w {
        16 => {
            // Optimized path for W=16
            let mut csum = 0usize;
            let mut out_idx = 0;

            // Encode message and compute checksum
            for &byte in msg.iter() {
                if out_idx >= len1 {
                    break;
                }

                let high = (byte >> 4) as usize;
                let low = (byte & 0x0F) as usize;

                output[out_idx] = high;
                // OPTIMIZATION: Use precomputed table instead of subtraction
                csum += W_MINUS_1_W16[high] as usize;
                out_idx += 1;

                if out_idx < len1 {
                    output[out_idx] = low;
                    // OPTIMIZATION: Use precomputed table instead of subtraction
                    csum += W_MINUS_1_W16[low] as usize;
                    out_idx += 1;
                }
            }

            // Encode checksum in base-16
            // Shift checksum left to align it properly
            let shift_bits = (8 - ((len2 * 4) % 8)) % 8;
            csum <<= shift_bits;

            for i in 0..len2 {
                output[len1 + i] = (csum >> ((len2 - 1 - i) * 4)) & 0x0F;
            }
        }
        256 => {
            // For W=256, bytes are already base-256 digits
            let mut csum = 0usize;

            for i in 0..len1 {
                if i < msg.len() {
                    output[i] = msg[i] as usize;
                    csum += 255 - (msg[i] as usize);
                } else {
                    output[i] = 0;
                    csum += 255;
                }
            }

            // Encode checksum
            for i in 0..len2 {
                output[len1 + i] = (csum >> ((len2 - 1 - i) * 8)) & 0xFF;
            }
        }
        _ => unsupported_winternitz_parameter(w),
    }
}

/// Extract bits from a byte array to form an index.
///
/// Used in FORS to convert message bits to tree indices.
#[inline(always)]
pub fn extract_bits(input: &[u8], bit_offset: usize, num_bits: usize) -> usize {
    let byte_offset = bit_offset / 8;
    let bit_in_byte = bit_offset % 8;
    let mut result = 0usize;
    let mut bits_remaining = num_bits;
    let mut current_byte = byte_offset;
    let mut shift = bit_in_byte;

    while bits_remaining > 0 && current_byte < input.len() {
        let bits_from_this_byte = (8 - shift).min(bits_remaining);
        // Use wrapping_sub to handle edge case: when bits_from_this_byte==8,
        // (1u16 << 8) - 1 = 255, cast to u8 gives 0xFF
        let mask = ((1u16 << bits_from_this_byte).wrapping_sub(1)) as u8;
        let bits = (input[current_byte] >> shift) & mask;

        result |= (bits as usize) << (num_bits - bits_remaining);
        bits_remaining -= bits_from_this_byte;
        current_byte += 1;
        shift = 0;
    }

    result
}

/// Arena-style scratch space for temporary allocations.
///
/// Provides a simple bump allocator for temporary data that can be
/// reset after use, avoiding heap allocations.
pub struct ScratchSpace {
    buffer: Vec<u8>,
    position: usize,
}

impl ScratchSpace {
    /// Create a new scratch space with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0u8; capacity],
            position: 0,
        }
    }

    /// Allocate a slice from the scratch space.
    ///
    /// Returns None if there's not enough space remaining.
    pub fn alloc(&mut self, size: usize) -> Option<&mut [u8]> {
        if self.position + size > self.buffer.len() {
            return None;
        }

        let start = self.position;
        self.position += size;
        Some(&mut self.buffer[start..self.position])
    }

    /// Reset the scratch space for reuse.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Get the amount of space used.
    pub fn used(&self) -> usize {
        self.position
    }

    /// Get the total capacity.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base16_encode() {
        let input = [0xAB, 0xCD, 0xEF];
        let mut output = [0u8; 6];
        base16_encode(&input, &mut output);

        assert_eq!(output, [0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    }

    #[test]
    fn test_base_w_with_checksum_w16() {
        let msg = [0x12, 0x34];
        let mut output = [0usize; 8];

        // len1=4 (message), len2=4 (checksum)
        base_w_with_checksum(&msg, 16, 4, 4, &mut output);

        // First 4 elements are message encoding
        assert_eq!(output[0], 1); // high nibble of 0x12
        assert_eq!(output[1], 2); // low nibble of 0x12
        assert_eq!(output[2], 3); // high nibble of 0x34
        assert_eq!(output[3], 4); // low nibble of 0x34

        // Remaining elements are checksum (non-zero)
        let checksum_sum: usize = output[4..8].iter().sum();
        assert!(checksum_sum > 0);
    }

    #[test]
    fn test_base_w_with_checksum_w256() {
        let msg = [0xAB, 0xCD];
        let mut output = [0usize; 4];

        // len1=2 (message), len2=2 (checksum)
        base_w_with_checksum(&msg, 256, 2, 2, &mut output);

        assert_eq!(output[0], 0xAB);
        assert_eq!(output[1], 0xCD);

        // Checksum elements should be non-zero
        assert!(output[2] > 0 || output[3] > 0);
    }

    #[test]
    fn test_extract_bits() {
        let data = [0b11010110, 0b10110011];
        //          76543210   FEDCBA98  (bit positions)

        // Extract 4 bits starting at bit 0 (bits 0-3)
        // data[0] bits 0-3: 0110
        assert_eq!(extract_bits(&data, 0, 4), 0b0110);

        // Extract 4 bits starting at bit 4 (bits 4-7)
        // data[0] bits 4-7: 1101
        assert_eq!(extract_bits(&data, 4, 4), 0b1101);

        // Extract 8 bits starting at bit 4 (cross byte boundary)
        // data[0] bits 4-7: 1101 (lower 4 bits of result)
        // data[1] bits 0-3: 0011 (upper 4 bits of result)
        // Combined: 0011_1101 = 0x3D = 61
        assert_eq!(extract_bits(&data, 4, 8), 0b00111101);

        // Extract 3 bits starting at bit 10
        // Bit 10 is in data[1], bit position 2
        // data[1] = 10110011, bits 2-4: 100
        assert_eq!(extract_bits(&data, 10, 3), 0b100);
    }

    #[test]
    fn test_scratch_space() {
        let mut scratch = ScratchSpace::new(100);

        let slice1 = scratch.alloc(32).unwrap();
        assert_eq!(slice1.len(), 32);
        assert_eq!(scratch.used(), 32);

        let slice2 = scratch.alloc(40).unwrap();
        assert_eq!(slice2.len(), 40);
        assert_eq!(scratch.used(), 72);

        // Not enough space
        assert!(scratch.alloc(50).is_none());

        // Reset
        scratch.reset();
        assert_eq!(scratch.used(), 0);

        let slice3 = scratch.alloc(50).unwrap();
        assert_eq!(slice3.len(), 50);
    }
}
