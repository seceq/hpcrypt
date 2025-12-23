//! AES-NI decryption with 8-block parallel processing.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::keysched::{AesNi128, AesNi192, AesNi256};

macro_rules! aesdec_8x {
    ($b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident, $rk:expr) => {
        $b0 = _mm_aesdec_si128($b0, $rk);
        $b1 = _mm_aesdec_si128($b1, $rk);
        $b2 = _mm_aesdec_si128($b2, $rk);
        $b3 = _mm_aesdec_si128($b3, $rk);
        $b4 = _mm_aesdec_si128($b4, $rk);
        $b5 = _mm_aesdec_si128($b5, $rk);
        $b6 = _mm_aesdec_si128($b6, $rk);
        $b7 = _mm_aesdec_si128($b7, $rk);
    };
}

macro_rules! aesdeclast_8x {
    ($b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident, $rk:expr) => {
        $b0 = _mm_aesdeclast_si128($b0, $rk);
        $b1 = _mm_aesdeclast_si128($b1, $rk);
        $b2 = _mm_aesdeclast_si128($b2, $rk);
        $b3 = _mm_aesdeclast_si128($b3, $rk);
        $b4 = _mm_aesdeclast_si128($b4, $rk);
        $b5 = _mm_aesdeclast_si128($b5, $rk);
        $b6 = _mm_aesdeclast_si128($b6, $rk);
        $b7 = _mm_aesdeclast_si128($b7, $rk);
    };
}

macro_rules! xor_8x {
    ($b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident, $rk:expr) => {
        $b0 = _mm_xor_si128($b0, $rk);
        $b1 = _mm_xor_si128($b1, $rk);
        $b2 = _mm_xor_si128($b2, $rk);
        $b3 = _mm_xor_si128($b3, $rk);
        $b4 = _mm_xor_si128($b4, $rk);
        $b5 = _mm_xor_si128($b5, $rk);
        $b6 = _mm_xor_si128($b6, $rk);
        $b7 = _mm_xor_si128($b7, $rk);
    };
}

macro_rules! load_8x {
    ($blocks:expr) => {{
        let b0 = _mm_loadu_si128($blocks[0].as_ptr() as *const __m128i);
        let b1 = _mm_loadu_si128($blocks[1].as_ptr() as *const __m128i);
        let b2 = _mm_loadu_si128($blocks[2].as_ptr() as *const __m128i);
        let b3 = _mm_loadu_si128($blocks[3].as_ptr() as *const __m128i);
        let b4 = _mm_loadu_si128($blocks[4].as_ptr() as *const __m128i);
        let b5 = _mm_loadu_si128($blocks[5].as_ptr() as *const __m128i);
        let b6 = _mm_loadu_si128($blocks[6].as_ptr() as *const __m128i);
        let b7 = _mm_loadu_si128($blocks[7].as_ptr() as *const __m128i);
        (b0, b1, b2, b3, b4, b5, b6, b7)
    }};
}

macro_rules! store_8x {
    ($blocks:expr, $b0:ident, $b1:ident, $b2:ident, $b3:ident, $b4:ident, $b5:ident, $b6:ident, $b7:ident) => {
        _mm_storeu_si128($blocks[0].as_mut_ptr() as *mut __m128i, $b0);
        _mm_storeu_si128($blocks[1].as_mut_ptr() as *mut __m128i, $b1);
        _mm_storeu_si128($blocks[2].as_mut_ptr() as *mut __m128i, $b2);
        _mm_storeu_si128($blocks[3].as_mut_ptr() as *mut __m128i, $b3);
        _mm_storeu_si128($blocks[4].as_mut_ptr() as *mut __m128i, $b4);
        _mm_storeu_si128($blocks[5].as_mut_ptr() as *mut __m128i, $b5);
        _mm_storeu_si128($blocks[6].as_mut_ptr() as *mut __m128i, $b6);
        _mm_storeu_si128($blocks[7].as_mut_ptr() as *mut __m128i, $b7);
    };
}

impl AesNi128 {
    /// Decrypts a single block in place.
    ///
    /// # Safety
    ///
    /// Caller must ensure AES-NI is available.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.dec_keys();
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        state = _mm_xor_si128(state, rk[0]);
        state = _mm_aesdec_si128(state, rk[1]);
        state = _mm_aesdec_si128(state, rk[2]);
        state = _mm_aesdec_si128(state, rk[3]);
        state = _mm_aesdec_si128(state, rk[4]);
        state = _mm_aesdec_si128(state, rk[5]);
        state = _mm_aesdec_si128(state, rk[6]);
        state = _mm_aesdec_si128(state, rk[7]);
        state = _mm_aesdec_si128(state, rk[8]);
        state = _mm_aesdec_si128(state, rk[9]);
        state = _mm_aesdeclast_si128(state, rk[10]);

        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }

    /// Decrypts 8 blocks in parallel.
    ///
    /// # Safety
    ///
    /// Caller must ensure AES-NI is available.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_8_blocks(&self, blocks: &mut [[u8; 16]; 8]) {
        let rk = self.dec_keys();
        let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5, mut b6, mut b7) = load_8x!(blocks);

        xor_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[0]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[1]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[2]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[3]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[4]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[5]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[6]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[7]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[8]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[9]);
        aesdeclast_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[10]);

        store_8x!(blocks, b0, b1, b2, b3, b4, b5, b6, b7);
    }

    /// Decrypts 8 blocks from XMM registers directly.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_8_xmm(
        &self,
        b0: __m128i,
        b1: __m128i,
        b2: __m128i,
        b3: __m128i,
        b4: __m128i,
        b5: __m128i,
        b6: __m128i,
        b7: __m128i,
    ) -> (__m128i, __m128i, __m128i, __m128i, __m128i, __m128i, __m128i, __m128i) {
        let rk = self.dec_keys();

        let mut b0 = _mm_xor_si128(b0, rk[0]);
        let mut b1 = _mm_xor_si128(b1, rk[0]);
        let mut b2 = _mm_xor_si128(b2, rk[0]);
        let mut b3 = _mm_xor_si128(b3, rk[0]);
        let mut b4 = _mm_xor_si128(b4, rk[0]);
        let mut b5 = _mm_xor_si128(b5, rk[0]);
        let mut b6 = _mm_xor_si128(b6, rk[0]);
        let mut b7 = _mm_xor_si128(b7, rk[0]);

        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[1]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[2]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[3]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[4]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[5]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[6]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[7]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[8]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[9]);
        aesdeclast_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[10]);

        (b0, b1, b2, b3, b4, b5, b6, b7)
    }
}

impl AesNi192 {
    /// Decrypts a single block in place.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.dec_keys();
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        state = _mm_xor_si128(state, rk[0]);
        state = _mm_aesdec_si128(state, rk[1]);
        state = _mm_aesdec_si128(state, rk[2]);
        state = _mm_aesdec_si128(state, rk[3]);
        state = _mm_aesdec_si128(state, rk[4]);
        state = _mm_aesdec_si128(state, rk[5]);
        state = _mm_aesdec_si128(state, rk[6]);
        state = _mm_aesdec_si128(state, rk[7]);
        state = _mm_aesdec_si128(state, rk[8]);
        state = _mm_aesdec_si128(state, rk[9]);
        state = _mm_aesdec_si128(state, rk[10]);
        state = _mm_aesdec_si128(state, rk[11]);
        state = _mm_aesdeclast_si128(state, rk[12]);

        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }

    /// Decrypts 8 blocks in parallel.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_8_blocks(&self, blocks: &mut [[u8; 16]; 8]) {
        let rk = self.dec_keys();
        let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5, mut b6, mut b7) = load_8x!(blocks);

        xor_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[0]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[1]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[2]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[3]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[4]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[5]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[6]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[7]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[8]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[9]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[10]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[11]);
        aesdeclast_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[12]);

        store_8x!(blocks, b0, b1, b2, b3, b4, b5, b6, b7);
    }
}

impl AesNi256 {
    /// Decrypts a single block in place.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_block(&self, block: &mut [u8; 16]) {
        let rk = self.dec_keys();
        let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);

        state = _mm_xor_si128(state, rk[0]);
        state = _mm_aesdec_si128(state, rk[1]);
        state = _mm_aesdec_si128(state, rk[2]);
        state = _mm_aesdec_si128(state, rk[3]);
        state = _mm_aesdec_si128(state, rk[4]);
        state = _mm_aesdec_si128(state, rk[5]);
        state = _mm_aesdec_si128(state, rk[6]);
        state = _mm_aesdec_si128(state, rk[7]);
        state = _mm_aesdec_si128(state, rk[8]);
        state = _mm_aesdec_si128(state, rk[9]);
        state = _mm_aesdec_si128(state, rk[10]);
        state = _mm_aesdec_si128(state, rk[11]);
        state = _mm_aesdec_si128(state, rk[12]);
        state = _mm_aesdec_si128(state, rk[13]);
        state = _mm_aesdeclast_si128(state, rk[14]);

        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }

    /// Decrypts 8 blocks in parallel.
    #[target_feature(enable = "aes")]
    #[inline]
    pub unsafe fn decrypt_8_blocks(&self, blocks: &mut [[u8; 16]; 8]) {
        let rk = self.dec_keys();
        let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5, mut b6, mut b7) = load_8x!(blocks);

        xor_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[0]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[1]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[2]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[3]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[4]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[5]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[6]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[7]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[8]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[9]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[10]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[11]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[12]);
        aesdec_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[13]);
        aesdeclast_8x!(b0, b1, b2, b3, b4, b5, b6, b7, rk[14]);

        store_8x!(blocks, b0, b1, b2, b3, b4, b5, b6, b7);
    }
}
