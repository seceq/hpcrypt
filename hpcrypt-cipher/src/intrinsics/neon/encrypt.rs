//! ARM NEON AES encryption with 4-block parallel processing.
//!
//! ARM's AES instructions work differently from x86 AES-NI:
//! - vaeseq_u8(state, key) performs: SubBytes(ShiftRows(state XOR key))
//! - vaesmcq_u8(state) performs: MixColumns(state)
//!
//! Standard AES round is: MixColumns(SubBytes(ShiftRows(AddRoundKey(state))))
//! With ARM we do: vaesmcq_u8(vaeseq_u8(state, rk[i])) then XOR with rk[i+1] next round
//!
//! The round keys are stored such that rk[0] is used in vaeseq_u8 for round 0,
//! and the final round key is XORed at the end.

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use super::keysched::{AesNeon128, AesNeon192, AesNeon256};

impl AesNeon128 {
    /// Encrypts a single block in place.
    ///
    /// # Safety
    ///
    /// Caller must ensure ARM Cryptographic Extensions are available.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.enc_keys();
        let mut state = vld1q_u8(block.as_ptr());

        // Rounds 0-8: vaeseq_u8 does SubBytes(ShiftRows(state XOR rk))
        // then vaesmcq_u8 does MixColumns
        state = vaeseq_u8(state, rk[0]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[1]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[2]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[3]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[4]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[5]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[6]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[7]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[8]);
        state = vaesmcq_u8(state);
        // Final round: no MixColumns, just SubBytes(ShiftRows(state XOR rk[9])) XOR rk[10]
        state = vaeseq_u8(state, rk[9]);
        state = veorq_u8(state, rk[10]);

        vst1q_u8(block.as_mut_ptr(), state);
    }

    /// Encrypts 4 blocks in parallel.
    ///
    /// # Safety
    ///
    /// Caller must ensure ARM Cryptographic Extensions are available.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_4_blocks(&self, blocks: &mut [[u8; 16]; 4]) {
        let rk = self.enc_keys();
        let mut b0 = vld1q_u8(blocks[0].as_ptr());
        let mut b1 = vld1q_u8(blocks[1].as_ptr());
        let mut b2 = vld1q_u8(blocks[2].as_ptr());
        let mut b3 = vld1q_u8(blocks[3].as_ptr());

        // Round 0
        b0 = vaeseq_u8(b0, rk[0]);
        b1 = vaeseq_u8(b1, rk[0]);
        b2 = vaeseq_u8(b2, rk[0]);
        b3 = vaeseq_u8(b3, rk[0]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 1
        b0 = vaeseq_u8(b0, rk[1]);
        b1 = vaeseq_u8(b1, rk[1]);
        b2 = vaeseq_u8(b2, rk[1]);
        b3 = vaeseq_u8(b3, rk[1]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 2
        b0 = vaeseq_u8(b0, rk[2]);
        b1 = vaeseq_u8(b1, rk[2]);
        b2 = vaeseq_u8(b2, rk[2]);
        b3 = vaeseq_u8(b3, rk[2]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 3
        b0 = vaeseq_u8(b0, rk[3]);
        b1 = vaeseq_u8(b1, rk[3]);
        b2 = vaeseq_u8(b2, rk[3]);
        b3 = vaeseq_u8(b3, rk[3]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 4
        b0 = vaeseq_u8(b0, rk[4]);
        b1 = vaeseq_u8(b1, rk[4]);
        b2 = vaeseq_u8(b2, rk[4]);
        b3 = vaeseq_u8(b3, rk[4]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 5
        b0 = vaeseq_u8(b0, rk[5]);
        b1 = vaeseq_u8(b1, rk[5]);
        b2 = vaeseq_u8(b2, rk[5]);
        b3 = vaeseq_u8(b3, rk[5]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 6
        b0 = vaeseq_u8(b0, rk[6]);
        b1 = vaeseq_u8(b1, rk[6]);
        b2 = vaeseq_u8(b2, rk[6]);
        b3 = vaeseq_u8(b3, rk[6]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 7
        b0 = vaeseq_u8(b0, rk[7]);
        b1 = vaeseq_u8(b1, rk[7]);
        b2 = vaeseq_u8(b2, rk[7]);
        b3 = vaeseq_u8(b3, rk[7]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Round 8
        b0 = vaeseq_u8(b0, rk[8]);
        b1 = vaeseq_u8(b1, rk[8]);
        b2 = vaeseq_u8(b2, rk[8]);
        b3 = vaeseq_u8(b3, rk[8]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Final round (no MixColumns)
        b0 = vaeseq_u8(b0, rk[9]);
        b1 = vaeseq_u8(b1, rk[9]);
        b2 = vaeseq_u8(b2, rk[9]);
        b3 = vaeseq_u8(b3, rk[9]);
        b0 = veorq_u8(b0, rk[10]);
        b1 = veorq_u8(b1, rk[10]);
        b2 = veorq_u8(b2, rk[10]);
        b3 = veorq_u8(b3, rk[10]);

        vst1q_u8(blocks[0].as_mut_ptr(), b0);
        vst1q_u8(blocks[1].as_mut_ptr(), b1);
        vst1q_u8(blocks[2].as_mut_ptr(), b2);
        vst1q_u8(blocks[3].as_mut_ptr(), b3);
    }
}

impl AesNeon192 {
    /// Encrypts a single block in place.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.enc_keys();
        let mut state = vld1q_u8(block.as_ptr());

        // Rounds 0-10
        state = vaeseq_u8(state, rk[0]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[1]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[2]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[3]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[4]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[5]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[6]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[7]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[8]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[9]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[10]);
        state = vaesmcq_u8(state);
        // Final round
        state = vaeseq_u8(state, rk[11]);
        state = veorq_u8(state, rk[12]);

        vst1q_u8(block.as_mut_ptr(), state);
    }

    /// Encrypts 4 blocks in parallel.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_4_blocks(&self, blocks: &mut [[u8; 16]; 4]) {
        let rk = self.enc_keys();
        let mut b0 = vld1q_u8(blocks[0].as_ptr());
        let mut b1 = vld1q_u8(blocks[1].as_ptr());
        let mut b2 = vld1q_u8(blocks[2].as_ptr());
        let mut b3 = vld1q_u8(blocks[3].as_ptr());

        // Rounds 0-10
        b0 = vaeseq_u8(b0, rk[0]);
        b1 = vaeseq_u8(b1, rk[0]);
        b2 = vaeseq_u8(b2, rk[0]);
        b3 = vaeseq_u8(b3, rk[0]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[1]);
        b1 = vaeseq_u8(b1, rk[1]);
        b2 = vaeseq_u8(b2, rk[1]);
        b3 = vaeseq_u8(b3, rk[1]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[2]);
        b1 = vaeseq_u8(b1, rk[2]);
        b2 = vaeseq_u8(b2, rk[2]);
        b3 = vaeseq_u8(b3, rk[2]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[3]);
        b1 = vaeseq_u8(b1, rk[3]);
        b2 = vaeseq_u8(b2, rk[3]);
        b3 = vaeseq_u8(b3, rk[3]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[4]);
        b1 = vaeseq_u8(b1, rk[4]);
        b2 = vaeseq_u8(b2, rk[4]);
        b3 = vaeseq_u8(b3, rk[4]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[5]);
        b1 = vaeseq_u8(b1, rk[5]);
        b2 = vaeseq_u8(b2, rk[5]);
        b3 = vaeseq_u8(b3, rk[5]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[6]);
        b1 = vaeseq_u8(b1, rk[6]);
        b2 = vaeseq_u8(b2, rk[6]);
        b3 = vaeseq_u8(b3, rk[6]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[7]);
        b1 = vaeseq_u8(b1, rk[7]);
        b2 = vaeseq_u8(b2, rk[7]);
        b3 = vaeseq_u8(b3, rk[7]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[8]);
        b1 = vaeseq_u8(b1, rk[8]);
        b2 = vaeseq_u8(b2, rk[8]);
        b3 = vaeseq_u8(b3, rk[8]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[9]);
        b1 = vaeseq_u8(b1, rk[9]);
        b2 = vaeseq_u8(b2, rk[9]);
        b3 = vaeseq_u8(b3, rk[9]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[10]);
        b1 = vaeseq_u8(b1, rk[10]);
        b2 = vaeseq_u8(b2, rk[10]);
        b3 = vaeseq_u8(b3, rk[10]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Final round
        b0 = vaeseq_u8(b0, rk[11]);
        b1 = vaeseq_u8(b1, rk[11]);
        b2 = vaeseq_u8(b2, rk[11]);
        b3 = vaeseq_u8(b3, rk[11]);
        b0 = veorq_u8(b0, rk[12]);
        b1 = veorq_u8(b1, rk[12]);
        b2 = veorq_u8(b2, rk[12]);
        b3 = veorq_u8(b3, rk[12]);

        vst1q_u8(blocks[0].as_mut_ptr(), b0);
        vst1q_u8(blocks[1].as_mut_ptr(), b1);
        vst1q_u8(blocks[2].as_mut_ptr(), b2);
        vst1q_u8(blocks[3].as_mut_ptr(), b3);
    }
}

impl AesNeon256 {
    /// Encrypts a single block in place.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.enc_keys();
        let mut state = vld1q_u8(block.as_ptr());

        // Rounds 0-12
        state = vaeseq_u8(state, rk[0]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[1]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[2]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[3]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[4]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[5]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[6]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[7]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[8]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[9]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[10]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[11]);
        state = vaesmcq_u8(state);
        state = vaeseq_u8(state, rk[12]);
        state = vaesmcq_u8(state);
        // Final round
        state = vaeseq_u8(state, rk[13]);
        state = veorq_u8(state, rk[14]);

        vst1q_u8(block.as_mut_ptr(), state);
    }

    /// Encrypts 4 blocks in parallel.
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "neon")]
    #[inline]
    pub unsafe fn encrypt_4_blocks(&self, blocks: &mut [[u8; 16]; 4]) {
        let rk = self.enc_keys();
        let mut b0 = vld1q_u8(blocks[0].as_ptr());
        let mut b1 = vld1q_u8(blocks[1].as_ptr());
        let mut b2 = vld1q_u8(blocks[2].as_ptr());
        let mut b3 = vld1q_u8(blocks[3].as_ptr());

        // Rounds 0-12
        b0 = vaeseq_u8(b0, rk[0]);
        b1 = vaeseq_u8(b1, rk[0]);
        b2 = vaeseq_u8(b2, rk[0]);
        b3 = vaeseq_u8(b3, rk[0]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[1]);
        b1 = vaeseq_u8(b1, rk[1]);
        b2 = vaeseq_u8(b2, rk[1]);
        b3 = vaeseq_u8(b3, rk[1]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[2]);
        b1 = vaeseq_u8(b1, rk[2]);
        b2 = vaeseq_u8(b2, rk[2]);
        b3 = vaeseq_u8(b3, rk[2]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[3]);
        b1 = vaeseq_u8(b1, rk[3]);
        b2 = vaeseq_u8(b2, rk[3]);
        b3 = vaeseq_u8(b3, rk[3]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[4]);
        b1 = vaeseq_u8(b1, rk[4]);
        b2 = vaeseq_u8(b2, rk[4]);
        b3 = vaeseq_u8(b3, rk[4]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[5]);
        b1 = vaeseq_u8(b1, rk[5]);
        b2 = vaeseq_u8(b2, rk[5]);
        b3 = vaeseq_u8(b3, rk[5]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[6]);
        b1 = vaeseq_u8(b1, rk[6]);
        b2 = vaeseq_u8(b2, rk[6]);
        b3 = vaeseq_u8(b3, rk[6]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[7]);
        b1 = vaeseq_u8(b1, rk[7]);
        b2 = vaeseq_u8(b2, rk[7]);
        b3 = vaeseq_u8(b3, rk[7]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[8]);
        b1 = vaeseq_u8(b1, rk[8]);
        b2 = vaeseq_u8(b2, rk[8]);
        b3 = vaeseq_u8(b3, rk[8]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[9]);
        b1 = vaeseq_u8(b1, rk[9]);
        b2 = vaeseq_u8(b2, rk[9]);
        b3 = vaeseq_u8(b3, rk[9]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[10]);
        b1 = vaeseq_u8(b1, rk[10]);
        b2 = vaeseq_u8(b2, rk[10]);
        b3 = vaeseq_u8(b3, rk[10]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[11]);
        b1 = vaeseq_u8(b1, rk[11]);
        b2 = vaeseq_u8(b2, rk[11]);
        b3 = vaeseq_u8(b3, rk[11]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        b0 = vaeseq_u8(b0, rk[12]);
        b1 = vaeseq_u8(b1, rk[12]);
        b2 = vaeseq_u8(b2, rk[12]);
        b3 = vaeseq_u8(b3, rk[12]);
        b0 = vaesmcq_u8(b0);
        b1 = vaesmcq_u8(b1);
        b2 = vaesmcq_u8(b2);
        b3 = vaesmcq_u8(b3);

        // Final round
        b0 = vaeseq_u8(b0, rk[13]);
        b1 = vaeseq_u8(b1, rk[13]);
        b2 = vaeseq_u8(b2, rk[13]);
        b3 = vaeseq_u8(b3, rk[13]);
        b0 = veorq_u8(b0, rk[14]);
        b1 = veorq_u8(b1, rk[14]);
        b2 = veorq_u8(b2, rk[14]);
        b3 = veorq_u8(b3, rk[14]);

        vst1q_u8(blocks[0].as_mut_ptr(), b0);
        vst1q_u8(blocks[1].as_mut_ptr(), b1);
        vst1q_u8(blocks[2].as_mut_ptr(), b2);
        vst1q_u8(blocks[3].as_mut_ptr(), b3);
    }
}
