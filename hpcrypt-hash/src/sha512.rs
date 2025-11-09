//! SHA-512 with 4-way partial loop unrolling
//!
//! This version uses 4-way unrolling with rolling macros for better performance
//! on multi-block workloads while maintaining code readability.

use hpcrypt_core::utils::{read_u64_be, rotr64, write_u64_be};

pub const OUT_LEN: usize = 64;
pub const BLOCK_LEN: usize = 128;

const H0_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buflen: usize,
    len: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            h: H0_512,
            buf: [0; BLOCK_LEN],
            buflen: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u128);

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

        if self.buflen > 112 {
            self.buf[self.buflen..BLOCK_LEN].fill(0);
            self.process_block();
            self.buflen = 0;
        }

        self.buf[self.buflen..112].fill(0);

        let bit_len = self.len.wrapping_mul(8);
        write_u64_be(&mut self.buf[112..120], (bit_len >> 64) as u64);
        write_u64_be(&mut self.buf[120..128], bit_len as u64);

        self.process_block();

        let mut out = [0u8; OUT_LEN];
        for i in 0..8 {
            write_u64_be(&mut out[i * 8..(i + 1) * 8], self.h[i]);
        }

        out
    }

    /// Process a single 1024-bit block with 4-way partial unrolling
    #[inline(always)]
    fn process_block(&mut self) {
        // Define rolling macros locally for organization
        macro_rules! update_w {
            ($w:expr, $i:expr) => {{
                let w_i_minus_15 = $w[($i - 15) & 15];
                let w_i_minus_2 = $w[($i - 2) & 15];

                let s0 = rotr64(w_i_minus_15, 1) ^ rotr64(w_i_minus_15, 8) ^ (w_i_minus_15 >> 7);
                let s1 = rotr64(w_i_minus_2, 19) ^ rotr64(w_i_minus_2, 61) ^ (w_i_minus_2 >> 6);

                $w[$i & 15] = $w[($i - 16) & 15]
                    .wrapping_add(s0)
                    .wrapping_add($w[($i - 7) & 15])
                    .wrapping_add(s1);
            }};
        }

        macro_rules! sha512_round {
            ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $ki:expr, $wi:expr) => {{
                let s1 = rotr64($e, 14) ^ rotr64($e, 18) ^ rotr64($e, 41);
                let ch = $g ^ ($e & ($f ^ $g));
                let temp1 = $h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add($ki)
                    .wrapping_add($wi);

                let s0 = rotr64($a, 28) ^ rotr64($a, 34) ^ rotr64($a, 39);
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

        let mut w = [0u64; 16];

        // Load first 16 words
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            w[i] = read_u64_be(&self.buf[i * 8..(i + 1) * 8]);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // First 16 rounds (no message schedule update needed)
        sha512_round!(a, b, c, d, e, f, g, h, K[0], w[0]);
        sha512_round!(a, b, c, d, e, f, g, h, K[1], w[1]);
        sha512_round!(a, b, c, d, e, f, g, h, K[2], w[2]);
        sha512_round!(a, b, c, d, e, f, g, h, K[3], w[3]);
        sha512_round!(a, b, c, d, e, f, g, h, K[4], w[4]);
        sha512_round!(a, b, c, d, e, f, g, h, K[5], w[5]);
        sha512_round!(a, b, c, d, e, f, g, h, K[6], w[6]);
        sha512_round!(a, b, c, d, e, f, g, h, K[7], w[7]);
        sha512_round!(a, b, c, d, e, f, g, h, K[8], w[8]);
        sha512_round!(a, b, c, d, e, f, g, h, K[9], w[9]);
        sha512_round!(a, b, c, d, e, f, g, h, K[10], w[10]);
        sha512_round!(a, b, c, d, e, f, g, h, K[11], w[11]);
        sha512_round!(a, b, c, d, e, f, g, h, K[12], w[12]);
        sha512_round!(a, b, c, d, e, f, g, h, K[13], w[13]);
        sha512_round!(a, b, c, d, e, f, g, h, K[14], w[14]);
        sha512_round!(a, b, c, d, e, f, g, h, K[15], w[15]);

        // Remaining 64 rounds in groups of 4 (4-way unrolling)
        // Rounds 16-19
        update_w!(w, 16);
        sha512_round!(a, b, c, d, e, f, g, h, K[16], w[16 & 15]);
        update_w!(w, 17);
        sha512_round!(a, b, c, d, e, f, g, h, K[17], w[17 & 15]);
        update_w!(w, 18);
        sha512_round!(a, b, c, d, e, f, g, h, K[18], w[18 & 15]);
        update_w!(w, 19);
        sha512_round!(a, b, c, d, e, f, g, h, K[19], w[19 & 15]);

        // Rounds 20-23
        update_w!(w, 20);
        sha512_round!(a, b, c, d, e, f, g, h, K[20], w[20 & 15]);
        update_w!(w, 21);
        sha512_round!(a, b, c, d, e, f, g, h, K[21], w[21 & 15]);
        update_w!(w, 22);
        sha512_round!(a, b, c, d, e, f, g, h, K[22], w[22 & 15]);
        update_w!(w, 23);
        sha512_round!(a, b, c, d, e, f, g, h, K[23], w[23 & 15]);

        // Rounds 24-27
        update_w!(w, 24);
        sha512_round!(a, b, c, d, e, f, g, h, K[24], w[24 & 15]);
        update_w!(w, 25);
        sha512_round!(a, b, c, d, e, f, g, h, K[25], w[25 & 15]);
        update_w!(w, 26);
        sha512_round!(a, b, c, d, e, f, g, h, K[26], w[26 & 15]);
        update_w!(w, 27);
        sha512_round!(a, b, c, d, e, f, g, h, K[27], w[27 & 15]);

        // Rounds 28-31
        update_w!(w, 28);
        sha512_round!(a, b, c, d, e, f, g, h, K[28], w[28 & 15]);
        update_w!(w, 29);
        sha512_round!(a, b, c, d, e, f, g, h, K[29], w[29 & 15]);
        update_w!(w, 30);
        sha512_round!(a, b, c, d, e, f, g, h, K[30], w[30 & 15]);
        update_w!(w, 31);
        sha512_round!(a, b, c, d, e, f, g, h, K[31], w[31 & 15]);

        // Rounds 32-35
        update_w!(w, 32);
        sha512_round!(a, b, c, d, e, f, g, h, K[32], w[32 & 15]);
        update_w!(w, 33);
        sha512_round!(a, b, c, d, e, f, g, h, K[33], w[33 & 15]);
        update_w!(w, 34);
        sha512_round!(a, b, c, d, e, f, g, h, K[34], w[34 & 15]);
        update_w!(w, 35);
        sha512_round!(a, b, c, d, e, f, g, h, K[35], w[35 & 15]);

        // Rounds 36-39
        update_w!(w, 36);
        sha512_round!(a, b, c, d, e, f, g, h, K[36], w[36 & 15]);
        update_w!(w, 37);
        sha512_round!(a, b, c, d, e, f, g, h, K[37], w[37 & 15]);
        update_w!(w, 38);
        sha512_round!(a, b, c, d, e, f, g, h, K[38], w[38 & 15]);
        update_w!(w, 39);
        sha512_round!(a, b, c, d, e, f, g, h, K[39], w[39 & 15]);

        // Rounds 40-43
        update_w!(w, 40);
        sha512_round!(a, b, c, d, e, f, g, h, K[40], w[40 & 15]);
        update_w!(w, 41);
        sha512_round!(a, b, c, d, e, f, g, h, K[41], w[41 & 15]);
        update_w!(w, 42);
        sha512_round!(a, b, c, d, e, f, g, h, K[42], w[42 & 15]);
        update_w!(w, 43);
        sha512_round!(a, b, c, d, e, f, g, h, K[43], w[43 & 15]);

        // Rounds 44-47
        update_w!(w, 44);
        sha512_round!(a, b, c, d, e, f, g, h, K[44], w[44 & 15]);
        update_w!(w, 45);
        sha512_round!(a, b, c, d, e, f, g, h, K[45], w[45 & 15]);
        update_w!(w, 46);
        sha512_round!(a, b, c, d, e, f, g, h, K[46], w[46 & 15]);
        update_w!(w, 47);
        sha512_round!(a, b, c, d, e, f, g, h, K[47], w[47 & 15]);

        // Rounds 48-51
        update_w!(w, 48);
        sha512_round!(a, b, c, d, e, f, g, h, K[48], w[48 & 15]);
        update_w!(w, 49);
        sha512_round!(a, b, c, d, e, f, g, h, K[49], w[49 & 15]);
        update_w!(w, 50);
        sha512_round!(a, b, c, d, e, f, g, h, K[50], w[50 & 15]);
        update_w!(w, 51);
        sha512_round!(a, b, c, d, e, f, g, h, K[51], w[51 & 15]);

        // Rounds 52-55
        update_w!(w, 52);
        sha512_round!(a, b, c, d, e, f, g, h, K[52], w[52 & 15]);
        update_w!(w, 53);
        sha512_round!(a, b, c, d, e, f, g, h, K[53], w[53 & 15]);
        update_w!(w, 54);
        sha512_round!(a, b, c, d, e, f, g, h, K[54], w[54 & 15]);
        update_w!(w, 55);
        sha512_round!(a, b, c, d, e, f, g, h, K[55], w[55 & 15]);

        // Rounds 56-59
        update_w!(w, 56);
        sha512_round!(a, b, c, d, e, f, g, h, K[56], w[56 & 15]);
        update_w!(w, 57);
        sha512_round!(a, b, c, d, e, f, g, h, K[57], w[57 & 15]);
        update_w!(w, 58);
        sha512_round!(a, b, c, d, e, f, g, h, K[58], w[58 & 15]);
        update_w!(w, 59);
        sha512_round!(a, b, c, d, e, f, g, h, K[59], w[59 & 15]);

        // Rounds 60-63
        update_w!(w, 60);
        sha512_round!(a, b, c, d, e, f, g, h, K[60], w[60 & 15]);
        update_w!(w, 61);
        sha512_round!(a, b, c, d, e, f, g, h, K[61], w[61 & 15]);
        update_w!(w, 62);
        sha512_round!(a, b, c, d, e, f, g, h, K[62], w[62 & 15]);
        update_w!(w, 63);
        sha512_round!(a, b, c, d, e, f, g, h, K[63], w[63 & 15]);

        // Rounds 64-67
        update_w!(w, 64);
        sha512_round!(a, b, c, d, e, f, g, h, K[64], w[64 & 15]);
        update_w!(w, 65);
        sha512_round!(a, b, c, d, e, f, g, h, K[65], w[65 & 15]);
        update_w!(w, 66);
        sha512_round!(a, b, c, d, e, f, g, h, K[66], w[66 & 15]);
        update_w!(w, 67);
        sha512_round!(a, b, c, d, e, f, g, h, K[67], w[67 & 15]);

        // Rounds 68-71
        update_w!(w, 68);
        sha512_round!(a, b, c, d, e, f, g, h, K[68], w[68 & 15]);
        update_w!(w, 69);
        sha512_round!(a, b, c, d, e, f, g, h, K[69], w[69 & 15]);
        update_w!(w, 70);
        sha512_round!(a, b, c, d, e, f, g, h, K[70], w[70 & 15]);
        update_w!(w, 71);
        sha512_round!(a, b, c, d, e, f, g, h, K[71], w[71 & 15]);

        // Rounds 72-75
        update_w!(w, 72);
        sha512_round!(a, b, c, d, e, f, g, h, K[72], w[72 & 15]);
        update_w!(w, 73);
        sha512_round!(a, b, c, d, e, f, g, h, K[73], w[73 & 15]);
        update_w!(w, 74);
        sha512_round!(a, b, c, d, e, f, g, h, K[74], w[74 & 15]);
        update_w!(w, 75);
        sha512_round!(a, b, c, d, e, f, g, h, K[75], w[75 & 15]);

        // Rounds 76-79
        update_w!(w, 76);
        sha512_round!(a, b, c, d, e, f, g, h, K[76], w[76 & 15]);
        update_w!(w, 77);
        sha512_round!(a, b, c, d, e, f, g, h, K[77], w[77 & 15]);
        update_w!(w, 78);
        sha512_round!(a, b, c, d, e, f, g, h, K[78], w[78 & 15]);
        update_w!(w, 79);
        sha512_round!(a, b, c, d, e, f, g, h, K[79], w[79 & 15]);

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

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha512(data: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}
