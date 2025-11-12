//! SHA-256 with 8-way partial loop unrolling
//!
//! This version uses 8-way unrolling with rolling macros to test if it provides
//! better performance than 4-way unrolling while maintaining code readability.

use hpcrypt_core::utils::{read_u32_be, rotr32, write_u32_be};

pub const OUT_LEN: usize = 32;
pub const BLOCK_LEN: usize = 64;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; BLOCK_LEN],
    buflen: usize,
    len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK_LEN],
            buflen: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64);

        while !input.is_empty() {
            if self.buflen == BLOCK_LEN {
                self.process_block();
                self.buflen = 0;
            }

            let take = (BLOCK_LEN - self.buflen).min(input.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
            self.buflen += take;
            input = &input[take..];
        }
    }

    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        if self.buflen == BLOCK_LEN {
            self.process_block();
            self.buflen = 0;
        }

        self.buf[self.buflen] = 0x80;
        self.buflen += 1;

        if self.buflen > 56 {
            self.buf[self.buflen..BLOCK_LEN].fill(0);
            self.process_block();
            self.buflen = 0;
        }

        self.buf[self.buflen..56].fill(0);

        let bit_len = self.len.wrapping_mul(8);
        write_u32_be(&mut self.buf[56..60], (bit_len >> 32) as u32);
        write_u32_be(&mut self.buf[60..64], bit_len as u32);

        self.process_block();

        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            write_u32_be(&mut out[i * 4..(i + 1) * 4], self.h[i]);
        }

        out
    }

    /// Process a single 512-bit block with 8-way partial unrolling
    #[inline(always)]
    fn process_block(&mut self) {
        // Define rolling macros locally for organization
        macro_rules! update_w {
            ($w:expr, $i:expr) => {{
                let w_i_minus_15 = $w[($i - 15) & 15];
                let w_i_minus_2 = $w[($i - 2) & 15];

                let s0 = rotr32(w_i_minus_15, 7) ^ rotr32(w_i_minus_15, 18) ^ (w_i_minus_15 >> 3);
                let s1 = rotr32(w_i_minus_2, 17) ^ rotr32(w_i_minus_2, 19) ^ (w_i_minus_2 >> 10);

                $w[$i & 15] = $w[($i - 16) & 15]
                    .wrapping_add(s0)
                    .wrapping_add($w[($i - 7) & 15])
                    .wrapping_add(s1);
            }};
        }

        macro_rules! sha256_round {
            ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $ki:expr, $wi:expr) => {{
                let s1 = rotr32($e, 6) ^ rotr32($e, 11) ^ rotr32($e, 25);
                let ch = $g ^ ($e & ($f ^ $g));
                let temp1 = $h.wrapping_add(s1).wrapping_add(ch).wrapping_add($ki).wrapping_add($wi);

                let s0 = rotr32($a, 2) ^ rotr32($a, 13) ^ rotr32($a, 22);
                let maj = ($a & $b) | ($c & ($a | $b));
                let temp2 = s0.wrapping_add(maj);

                $h = $g;
                $g = $f;
                $f = $e;
                $e = $d.wrapping_add(temp1);
                $d = $c;
                $c = $b;
                $b = $a;
                $a = temp1.wrapping_add(temp2);
            }};
        }

        let mut w = [0u32; 16];

        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            w[i] = read_u32_be(&self.buf[i * 4..(i + 1) * 4]);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // First 16 rounds (no message schedule update needed) - grouped by 8 for visual consistency
        sha256_round!(a, b, c, d, e, f, g, h, K[0], w[0]);
        sha256_round!(a, b, c, d, e, f, g, h, K[1], w[1]);
        sha256_round!(a, b, c, d, e, f, g, h, K[2], w[2]);
        sha256_round!(a, b, c, d, e, f, g, h, K[3], w[3]);
        sha256_round!(a, b, c, d, e, f, g, h, K[4], w[4]);
        sha256_round!(a, b, c, d, e, f, g, h, K[5], w[5]);
        sha256_round!(a, b, c, d, e, f, g, h, K[6], w[6]);
        sha256_round!(a, b, c, d, e, f, g, h, K[7], w[7]);

        sha256_round!(a, b, c, d, e, f, g, h, K[8], w[8]);
        sha256_round!(a, b, c, d, e, f, g, h, K[9], w[9]);
        sha256_round!(a, b, c, d, e, f, g, h, K[10], w[10]);
        sha256_round!(a, b, c, d, e, f, g, h, K[11], w[11]);
        sha256_round!(a, b, c, d, e, f, g, h, K[12], w[12]);
        sha256_round!(a, b, c, d, e, f, g, h, K[13], w[13]);
        sha256_round!(a, b, c, d, e, f, g, h, K[14], w[14]);
        sha256_round!(a, b, c, d, e, f, g, h, K[15], w[15]);

        // Remaining 48 rounds with 8-way unrolling (6 groups of 8)
        // Rounds 16-23
        update_w!(w, 16); sha256_round!(a, b, c, d, e, f, g, h, K[16], w[16 & 15]);
        update_w!(w, 17); sha256_round!(a, b, c, d, e, f, g, h, K[17], w[17 & 15]);
        update_w!(w, 18); sha256_round!(a, b, c, d, e, f, g, h, K[18], w[18 & 15]);
        update_w!(w, 19); sha256_round!(a, b, c, d, e, f, g, h, K[19], w[19 & 15]);
        update_w!(w, 20); sha256_round!(a, b, c, d, e, f, g, h, K[20], w[20 & 15]);
        update_w!(w, 21); sha256_round!(a, b, c, d, e, f, g, h, K[21], w[21 & 15]);
        update_w!(w, 22); sha256_round!(a, b, c, d, e, f, g, h, K[22], w[22 & 15]);
        update_w!(w, 23); sha256_round!(a, b, c, d, e, f, g, h, K[23], w[23 & 15]);

        // Rounds 24-31
        update_w!(w, 24); sha256_round!(a, b, c, d, e, f, g, h, K[24], w[24 & 15]);
        update_w!(w, 25); sha256_round!(a, b, c, d, e, f, g, h, K[25], w[25 & 15]);
        update_w!(w, 26); sha256_round!(a, b, c, d, e, f, g, h, K[26], w[26 & 15]);
        update_w!(w, 27); sha256_round!(a, b, c, d, e, f, g, h, K[27], w[27 & 15]);
        update_w!(w, 28); sha256_round!(a, b, c, d, e, f, g, h, K[28], w[28 & 15]);
        update_w!(w, 29); sha256_round!(a, b, c, d, e, f, g, h, K[29], w[29 & 15]);
        update_w!(w, 30); sha256_round!(a, b, c, d, e, f, g, h, K[30], w[30 & 15]);
        update_w!(w, 31); sha256_round!(a, b, c, d, e, f, g, h, K[31], w[31 & 15]);

        // Rounds 32-39
        update_w!(w, 32); sha256_round!(a, b, c, d, e, f, g, h, K[32], w[32 & 15]);
        update_w!(w, 33); sha256_round!(a, b, c, d, e, f, g, h, K[33], w[33 & 15]);
        update_w!(w, 34); sha256_round!(a, b, c, d, e, f, g, h, K[34], w[34 & 15]);
        update_w!(w, 35); sha256_round!(a, b, c, d, e, f, g, h, K[35], w[35 & 15]);
        update_w!(w, 36); sha256_round!(a, b, c, d, e, f, g, h, K[36], w[36 & 15]);
        update_w!(w, 37); sha256_round!(a, b, c, d, e, f, g, h, K[37], w[37 & 15]);
        update_w!(w, 38); sha256_round!(a, b, c, d, e, f, g, h, K[38], w[38 & 15]);
        update_w!(w, 39); sha256_round!(a, b, c, d, e, f, g, h, K[39], w[39 & 15]);

        // Rounds 40-47
        update_w!(w, 40); sha256_round!(a, b, c, d, e, f, g, h, K[40], w[40 & 15]);
        update_w!(w, 41); sha256_round!(a, b, c, d, e, f, g, h, K[41], w[41 & 15]);
        update_w!(w, 42); sha256_round!(a, b, c, d, e, f, g, h, K[42], w[42 & 15]);
        update_w!(w, 43); sha256_round!(a, b, c, d, e, f, g, h, K[43], w[43 & 15]);
        update_w!(w, 44); sha256_round!(a, b, c, d, e, f, g, h, K[44], w[44 & 15]);
        update_w!(w, 45); sha256_round!(a, b, c, d, e, f, g, h, K[45], w[45 & 15]);
        update_w!(w, 46); sha256_round!(a, b, c, d, e, f, g, h, K[46], w[46 & 15]);
        update_w!(w, 47); sha256_round!(a, b, c, d, e, f, g, h, K[47], w[47 & 15]);

        // Rounds 48-55
        update_w!(w, 48); sha256_round!(a, b, c, d, e, f, g, h, K[48], w[48 & 15]);
        update_w!(w, 49); sha256_round!(a, b, c, d, e, f, g, h, K[49], w[49 & 15]);
        update_w!(w, 50); sha256_round!(a, b, c, d, e, f, g, h, K[50], w[50 & 15]);
        update_w!(w, 51); sha256_round!(a, b, c, d, e, f, g, h, K[51], w[51 & 15]);
        update_w!(w, 52); sha256_round!(a, b, c, d, e, f, g, h, K[52], w[52 & 15]);
        update_w!(w, 53); sha256_round!(a, b, c, d, e, f, g, h, K[53], w[53 & 15]);
        update_w!(w, 54); sha256_round!(a, b, c, d, e, f, g, h, K[54], w[54 & 15]);
        update_w!(w, 55); sha256_round!(a, b, c, d, e, f, g, h, K[55], w[55 & 15]);

        // Rounds 56-63
        update_w!(w, 56); sha256_round!(a, b, c, d, e, f, g, h, K[56], w[56 & 15]);
        update_w!(w, 57); sha256_round!(a, b, c, d, e, f, g, h, K[57], w[57 & 15]);
        update_w!(w, 58); sha256_round!(a, b, c, d, e, f, g, h, K[58], w[58 & 15]);
        update_w!(w, 59); sha256_round!(a, b, c, d, e, f, g, h, K[59], w[59 & 15]);
        update_w!(w, 60); sha256_round!(a, b, c, d, e, f, g, h, K[60], w[60 & 15]);
        update_w!(w, 61); sha256_round!(a, b, c, d, e, f, g, h, K[61], w[61 & 15]);
        update_w!(w, 62); sha256_round!(a, b, c, d, e, f, g, h, K[62], w[62 & 15]);
        update_w!(w, 63); sha256_round!(a, b, c, d, e, f, g, h, K[63], w[63 & 15]);

        // Add to hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}
