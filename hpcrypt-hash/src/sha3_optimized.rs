//! Optimized SHAKE implementations - Phase 1 optimizations
//!
//! This module contains optimized versions of SHAKE128/256 with:
//! 1. Squeezing optimization (extract by u64 words)
//! 2. Cache alignment
//! 3. Direct block processing
//!
//! Uses macros for code readability and organization.

use super::{keccak_f, STATE_SIZE};

/// Macro to extract squeezing logic by u64 words (without lane-complement)
///
/// This replaces the slow byte-at-a-time extraction with word-at-a-time extraction.
/// Expected improvement: 40-50% for small outputs
macro_rules! squeeze_words_no_complement {
    ($state:expr, $output:expr, $offset:expr, $to_copy:expr) => {
        {
            // Extract complete u64 words
            let complete_words = $to_copy / 8;
            for i in 0..complete_words {
                let bytes = $state[i].to_le_bytes();
                $output[$offset + i * 8..$offset + (i + 1) * 8].copy_from_slice(&bytes);
            }

            // Handle remaining 0-7 bytes
            let remainder_offset = complete_words * 8;
            if $to_copy > remainder_offset {
                let bytes = $state[complete_words].to_le_bytes();
                let remainder = $to_copy - remainder_offset;
                $output[$offset + remainder_offset..$offset + $to_copy]
                    .copy_from_slice(&bytes[..remainder]);
            }
        }
    };
}

/// Macro to extract squeezing logic by u64 words (with lane-complement)
///
/// Same as above but handles complemented lanes correctly
macro_rules! squeeze_words_with_complement {
    ($state:expr, $output:expr, $offset:expr, $to_copy:expr, $complemented:expr) => {
        {
            // Extract complete u64 words
            let complete_words = $to_copy / 8;
            for i in 0..complete_words {
                let lane = if $complemented[i] {
                    !$state[i]
                } else {
                    $state[i]
                };
                let bytes = lane.to_le_bytes();
                $output[$offset + i * 8..$offset + (i + 1) * 8].copy_from_slice(&bytes);
            }

            // Handle remaining bytes
            let remainder_offset = complete_words * 8;
            if $to_copy > remainder_offset {
                let lane = if $complemented[complete_words] {
                    !$state[complete_words]
                } else {
                    $state[complete_words]
                };
                let bytes = lane.to_le_bytes();
                let remainder = $to_copy - remainder_offset;
                $output[$offset + remainder_offset..$offset + $to_copy]
                    .copy_from_slice(&bytes[..remainder]);
            }
        }
    };
}

/// Macro to extract u64 word from byte slice at offset
///
/// Used in absorption optimization for better readability
macro_rules! word_from_bytes {
    ($block:expr, $offset:expr) => {
        u64::from_le_bytes([
            $block[$offset],
            $block[$offset + 1],
            $block[$offset + 2],
            $block[$offset + 3],
            $block[$offset + 4],
            $block[$offset + 5],
            $block[$offset + 6],
            $block[$offset + 7],
        ])
    };
}

/// Macro for unrolled absorption (SHAKE128 - 21 words)
///
/// Unrolls the absorption loop for better performance
/// Expected improvement: 10-15% in absorption phase
macro_rules! absorb_shake128_unrolled {
    ($state:expr, $block:expr) => {
        {
            debug_assert_eq!($block.len(), 168);

            $state[0] ^= word_from_bytes!($block, 0);
            $state[1] ^= word_from_bytes!($block, 8);
            $state[2] ^= word_from_bytes!($block, 16);
            $state[3] ^= word_from_bytes!($block, 24);
            $state[4] ^= word_from_bytes!($block, 32);
            $state[5] ^= word_from_bytes!($block, 40);
            $state[6] ^= word_from_bytes!($block, 48);
            $state[7] ^= word_from_bytes!($block, 56);
            $state[8] ^= word_from_bytes!($block, 64);
            $state[9] ^= word_from_bytes!($block, 72);
            $state[10] ^= word_from_bytes!($block, 80);
            $state[11] ^= word_from_bytes!($block, 88);
            $state[12] ^= word_from_bytes!($block, 96);
            $state[13] ^= word_from_bytes!($block, 104);
            $state[14] ^= word_from_bytes!($block, 112);
            $state[15] ^= word_from_bytes!($block, 120);
            $state[16] ^= word_from_bytes!($block, 128);
            $state[17] ^= word_from_bytes!($block, 136);
            $state[18] ^= word_from_bytes!($block, 144);
            $state[19] ^= word_from_bytes!($block, 152);
            $state[20] ^= word_from_bytes!($block, 160);
        }
    };
}

/// Macro for unrolled absorption (SHAKE256 - 17 words)
macro_rules! absorb_shake256_unrolled {
    ($state:expr, $block:expr) => {
        {
            debug_assert_eq!($block.len(), 136);

            $state[0] ^= word_from_bytes!($block, 0);
            $state[1] ^= word_from_bytes!($block, 8);
            $state[2] ^= word_from_bytes!($block, 16);
            $state[3] ^= word_from_bytes!($block, 24);
            $state[4] ^= word_from_bytes!($block, 32);
            $state[5] ^= word_from_bytes!($block, 40);
            $state[6] ^= word_from_bytes!($block, 48);
            $state[7] ^= word_from_bytes!($block, 56);
            $state[8] ^= word_from_bytes!($block, 64);
            $state[9] ^= word_from_bytes!($block, 72);
            $state[10] ^= word_from_bytes!($block, 80);
            $state[11] ^= word_from_bytes!($block, 88);
            $state[12] ^= word_from_bytes!($block, 96);
            $state[13] ^= word_from_bytes!($block, 104);
            $state[14] ^= word_from_bytes!($block, 112);
            $state[15] ^= word_from_bytes!($block, 120);
            $state[16] ^= word_from_bytes!($block, 128);
        }
    };
}

/// Macro for unrolled absorption with lane-complement handling (SHAKE128)
macro_rules! absorb_shake128_unrolled_complement {
    ($state:expr, $block:expr) => {
        {
            debug_assert_eq!($block.len(), 168);

            const COMPLEMENTED: [bool; 25] = [
                false, true, true, false, false,
                false, false, false, true, false,
                false, false, true, false, false,
                false, false, true, false, false,
                true, false, false, false, false,
            ];

            // Unroll all 21 words for SHAKE128 rate
            // For each word, check if complemented and handle accordingly

            // Words 0-20 (21 total for rate=168)
            macro_rules! absorb_word {
                ($idx:expr, $offset:expr) => {
                    {
                        let word = word_from_bytes!($block, $offset);
                        if COMPLEMENTED[$idx] {
                            let logical = !$state[$idx];
                            let new_logical = logical ^ word;
                            $state[$idx] = !new_logical;
                        } else {
                            $state[$idx] ^= word;
                        }
                    }
                };
            }

            absorb_word!(0, 0);
            absorb_word!(1, 8);
            absorb_word!(2, 16);
            absorb_word!(3, 24);
            absorb_word!(4, 32);
            absorb_word!(5, 40);
            absorb_word!(6, 48);
            absorb_word!(7, 56);
            absorb_word!(8, 64);
            absorb_word!(9, 72);
            absorb_word!(10, 80);
            absorb_word!(11, 88);
            absorb_word!(12, 96);
            absorb_word!(13, 104);
            absorb_word!(14, 112);
            absorb_word!(15, 120);
            absorb_word!(16, 128);
            absorb_word!(17, 136);
            absorb_word!(18, 144);
            absorb_word!(19, 152);
            absorb_word!(20, 160);
        }
    };
}

/// Macro for unrolled absorption with lane-complement handling (SHAKE256)
macro_rules! absorb_shake256_unrolled_complement {
    ($state:expr, $block:expr) => {
        {
            debug_assert_eq!($block.len(), 136);

            const COMPLEMENTED: [bool; 25] = [
                false, true, true, false, false,
                false, false, false, true, false,
                false, false, true, false, false,
                false, false, true, false, false,
                true, false, false, false, false,
            ];

            macro_rules! absorb_word {
                ($idx:expr, $offset:expr) => {
                    {
                        let word = word_from_bytes!($block, $offset);
                        if COMPLEMENTED[$idx] {
                            let logical = !$state[$idx];
                            let new_logical = logical ^ word;
                            $state[$idx] = !new_logical;
                        } else {
                            $state[$idx] ^= word;
                        }
                    }
                };
            }

            absorb_word!(0, 0);
            absorb_word!(1, 8);
            absorb_word!(2, 16);
            absorb_word!(3, 24);
            absorb_word!(4, 32);
            absorb_word!(5, 40);
            absorb_word!(6, 48);
            absorb_word!(7, 56);
            absorb_word!(8, 64);
            absorb_word!(9, 72);
            absorb_word!(10, 80);
            absorb_word!(11, 88);
            absorb_word!(12, 96);
            absorb_word!(13, 104);
            absorb_word!(14, 112);
            absorb_word!(15, 120);
            absorb_word!(16, 128);
        }
    };
}

// Export macros for use in parent module
pub(crate) use squeeze_words_no_complement;
pub(crate) use squeeze_words_with_complement;
pub(crate) use absorb_shake128_unrolled;
pub(crate) use absorb_shake256_unrolled;
pub(crate) use absorb_shake128_unrolled_complement;
pub(crate) use absorb_shake256_unrolled_complement;
