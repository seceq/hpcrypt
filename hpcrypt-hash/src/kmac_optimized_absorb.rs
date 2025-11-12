//! KMAC Absorb Block Optimization
//!
//! Optimizations:
//! 1. Manual loop unrolling (3-5% gain) - Unroll XOR operations
//!
//! Expected improvement: 3-5% on absorb operations
//!
//! Note: Unsafe pointer-based optimization was considered but rejected
//! due to library policy forbidding unsafe code.

#![forbid(unsafe_code)]

/// Rolling macro for unrolled XOR operations
/// Generates clean, readable unrolled code
macro_rules! unroll_xor {
    ($state:expr, $block:expr, $($i:expr),+) => {
        $(
            let word = u64::from_le_bytes([
                $block[$i * 8],
                $block[$i * 8 + 1],
                $block[$i * 8 + 2],
                $block[$i * 8 + 3],
                $block[$i * 8 + 4],
                $block[$i * 8 + 5],
                $block[$i * 8 + 6],
                $block[$i * 8 + 7],
            ]);
            $state[$i] ^= word;
        )+
    };
}

/// Baseline absorb_block for comparison (identical to kmac.rs)
#[inline(never)]
pub fn absorb_block_baseline(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        state[i] ^= word;
    }
}

/// Optimized absorb_block with manual loop unrolling for KMAC128 (rate=168, 21 words)
#[inline]
pub fn absorb_block_unrolled_168(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), 168);

    // Unroll 21 words (168 bytes / 8 = 21 words)
    unroll_xor!(state, block,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20
    );
}

/// Optimized absorb_block with manual loop unrolling for KMAC256 (rate=136, 17 words)
#[inline]
pub fn absorb_block_unrolled_136(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), 136);

    // Unroll 17 words (136 bytes / 8 = 17 words)
    unroll_xor!(state, block,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16
    );
}


#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_state() -> [u64; 25] {
        let mut state = [0u64; 25];
        for i in 0..25 {
            state[i] = i as u64 * 0x0123456789ABCDEF;
        }
        state
    }

    fn init_test_block_168() -> [u8; 168] {
        let mut block = [0u8; 168];
        for i in 0..168 {
            block[i] = (i % 256) as u8;
        }
        block
    }

    fn init_test_block_136() -> [u8; 136] {
        let mut block = [0u8; 136];
        for i in 0..136 {
            block[i] = (i % 256) as u8;
        }
        block
    }

    #[test]
    fn test_unrolled_168_matches_baseline() {
        let mut state1 = init_test_state();
        let mut state2 = state1;
        let block = init_test_block_168();

        absorb_block_baseline(&mut state1, &block);
        absorb_block_unrolled_168(&mut state2, &block);

        assert_eq!(state1, state2, "Unrolled 168 should match baseline");
    }

    #[test]
    fn test_unrolled_136_matches_baseline() {
        let mut state1 = init_test_state();
        let mut state2 = state1;
        let block = init_test_block_136();

        absorb_block_baseline(&mut state1, &block);
        absorb_block_unrolled_136(&mut state2, &block);

        assert_eq!(state1, state2, "Unrolled 136 should match baseline");
    }

}
