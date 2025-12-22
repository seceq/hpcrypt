//! GHASH universal hash function for GCM mode.
//!
//! Implementation based on 64-bit Karatsuba decomposition with precomputed
//! bit-reversed values. Uses deferred reduction for 4-block parallel processing.
//!
//! The polynomial field is GF(2^128) with the GHASH polynomial.
//! GHASH uses big-endian byte ordering (bit-reflected compared to POLYVAL).

use core::{convert::TryInto, num::Wrapping};

const BLOCK_SIZE: usize = 16;

/// Precomputed GHASH key material.
///
/// Stores powers H through H^4 with precomputed bit-reversed values
/// for efficient Karatsuba multiplication.
#[derive(Clone, Debug)]
pub struct GhashKey {
    /// Powers of H: each entry is (h0, h1, h0r, h1r, h2, h2r)
    powers: [(u64, u64, u64, u64, u64, u64); 4],
}

/// GHASH authenticator state.
#[derive(Clone, Debug)]
pub struct Ghash {
    key: GhashKey,
    acc: (u64, u64),
}

/// 64x64 -> 64-bit carry-less multiplication (lower bits only).
/// Uses nibble-based masking for constant-time operation.
#[inline(always)]
fn bmul64(x: u64, y: u64) -> u64 {
    let x0 = Wrapping(x & 0x1111_1111_1111_1111);
    let x1 = Wrapping(x & 0x2222_2222_2222_2222);
    let x2 = Wrapping(x & 0x4444_4444_4444_4444);
    let x3 = Wrapping(x & 0x8888_8888_8888_8888);
    let y0 = Wrapping(y & 0x1111_1111_1111_1111);
    let y1 = Wrapping(y & 0x2222_2222_2222_2222);
    let y2 = Wrapping(y & 0x4444_4444_4444_4444);
    let y3 = Wrapping(y & 0x8888_8888_8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111_1111_1111;
    z1 &= 0x2222_2222_2222_2222;
    z2 &= 0x4444_4444_4444_4444;
    z3 &= 0x8888_8888_8888_8888;

    z0 | z1 | z2 | z3
}

/// Bit-reverse a 64-bit value.
#[inline(always)]
fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
    x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
    x.rotate_right(32)
}

/// Unreduced 256-bit GF(2^128) product using Karatsuba.
#[inline(always)]
fn gf128_mul_unreduced(
    h0: u64, h1: u64, h0r: u64, h1r: u64, h2: u64, h2r: u64,
    y0: u64, y1: u64,
) -> (u64, u64, u64, u64) {
    let y0r = rev64(y0);
    let y1r = rev64(y1);
    let y2 = y0 ^ y1;
    let y2r = y0r ^ y1r;

    let z0 = bmul64(y0, h0);
    let z1 = bmul64(y1, h1);
    let mut z2 = bmul64(y2, h2);
    let mut z0h = bmul64(y0r, h0r);
    let mut z1h = bmul64(y1r, h1r);
    let mut z2h = bmul64(y2r, h2r);

    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;

    (z0, z0h ^ z2, z1 ^ z2h, z1h)
}

/// Reduce 256-bit value modulo the field polynomial using shifts.
#[inline(always)]
fn reduce_256(v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> (u64, u64) {
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    (v2, v3)
}

/// GF(2^128) multiplication with reduction.
#[inline(always)]
fn gf128_mul(
    h0: u64, h1: u64, h0r: u64, h1r: u64, h2: u64, h2r: u64,
    y0: u64, y1: u64,
) -> (u64, u64) {
    let (v0, v1, v2, v3) = gf128_mul_unreduced(h0, h1, h0r, h1r, h2, h2r, y0, y1);
    reduce_256(v0, v1, v2, v3)
}

/// Multiply by x in GF(2^128) for GHASH-to-POLYVAL conversion.
#[inline]
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

impl GhashKey {
    /// Creates a new GHASH key from the hash subkey H.
    pub fn new(h: &[u8; 16]) -> Self {
        // Convert GHASH H to internal representation via byte reversal + mulx
        let mut h_reversed = *h;
        h_reversed.reverse();
        let h_polyval = mulx(&h_reversed);

        let h0 = u64::from_le_bytes(h_polyval[0..8].try_into().unwrap());
        let h1 = u64::from_le_bytes(h_polyval[8..16].try_into().unwrap());

        let power1 = Self::compute_power_tuple(h0, h1);

        let (h2_0, h2_1) = gf128_mul(
            power1.0, power1.1, power1.2, power1.3, power1.4, power1.5,
            h0, h1,
        );
        let power2 = Self::compute_power_tuple(h2_0, h2_1);

        let (h3_0, h3_1) = gf128_mul(
            power2.0, power2.1, power2.2, power2.3, power2.4, power2.5,
            h0, h1,
        );
        let power3 = Self::compute_power_tuple(h3_0, h3_1);

        let (h4_0, h4_1) = gf128_mul(
            power2.0, power2.1, power2.2, power2.3, power2.4, power2.5,
            h2_0, h2_1,
        );
        let power4 = Self::compute_power_tuple(h4_0, h4_1);

        Self {
            powers: [power1, power2, power3, power4],
        }
    }

    #[inline]
    fn compute_power_tuple(h0: u64, h1: u64) -> (u64, u64, u64, u64, u64, u64) {
        let h0r = rev64(h0);
        let h1r = rev64(h1);
        let h2 = h0 ^ h1;
        let h2r = h0r ^ h1r;
        (h0, h1, h0r, h1r, h2, h2r)
    }
}

impl Ghash {
    /// Creates a new GHASH instance from the hash subkey H.
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            key: GhashKey::new(h),
            acc: (0, 0),
        }
    }

    /// Creates from a pre-computed key.
    pub fn from_key(key: GhashKey) -> Self {
        Self {
            key,
            acc: (0, 0),
        }
    }

    /// Processes a single 16-byte block.
    #[inline]
    pub fn update(&mut self, block: &[u8; 16]) {
        let x1 = u64::from_be_bytes(block[0..8].try_into().unwrap());
        let x0 = u64::from_be_bytes(block[8..16].try_into().unwrap());

        let m0 = self.acc.0 ^ x0;
        let m1 = self.acc.1 ^ x1;

        let (h0, h1, h0r, h1r, h2, h2r) = self.key.powers[0];
        self.acc = gf128_mul(h0, h1, h0r, h1r, h2, h2r, m0, m1);
    }

    /// Processes multiple blocks of data.
    pub fn update_blocks(&mut self, data: &[u8]) {
        let num_full_blocks = data.len() / BLOCK_SIZE;
        let full_block_bytes = num_full_blocks * BLOCK_SIZE;

        let mut offset = 0;
        while offset + 64 <= full_block_bytes {
            self.process_4_blocks(&data[offset..offset + 64]);
            offset += 64;
        }

        while offset + 16 <= full_block_bytes {
            let block: &[u8; 16] = data[offset..offset + 16].try_into().unwrap();
            self.update(block);
            offset += 16;
        }

        if offset < data.len() {
            let mut padded = [0u8; 16];
            padded[..data.len() - offset].copy_from_slice(&data[offset..]);
            self.update(&padded);
        }
    }

    /// Processes 4 blocks with deferred reduction.
    #[inline]
    fn process_4_blocks(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);

        macro_rules! load_block {
            ($offset:expr) => {{
                let lo = u64::from_be_bytes(data[$offset + 8..$offset + 16].try_into().unwrap());
                let hi = u64::from_be_bytes(data[$offset..$offset + 8].try_into().unwrap());
                (lo, hi)
            }};
        }

        macro_rules! prepare_input {
            ($y0:expr, $y1:expr) => {{
                let y0r = rev64($y0);
                let y1r = rev64($y1);
                let y2 = $y0 ^ $y1;
                let y2r = y0r ^ y1r;
                ($y0, $y1, y0r, y1r, y2, y2r)
            }};
        }

        macro_rules! compute_products {
            ($y0:expr, $y1:expr, $y0r:expr, $y1r:expr, $y2:expr, $y2r:expr,
             $h0:expr, $h1:expr, $h0r:expr, $h1r:expr, $h2:expr, $h2r:expr) => {{
                let z0 = bmul64($y0, $h0);
                let z1 = bmul64($y1, $h1);
                let z2 = bmul64($y2, $h2);
                let z0h = bmul64($y0r, $h0r);
                let z1h = bmul64($y1r, $h1r);
                let z2h = bmul64($y2r, $h2r);
                (z0, z1, z2, z0h, z1h, z2h)
            }};
        }

        macro_rules! karatsuba_combine {
            ($z0:expr, $z1:expr, $z2:expr, $z0h:expr, $z1h:expr, $z2h:expr) => {{
                let k2 = $z2 ^ $z0 ^ $z1;
                let k2h = $z2h ^ $z0h ^ $z1h;
                let v0 = $z0;
                let v1 = (rev64($z0h) >> 1) ^ k2;
                let v2 = $z1 ^ (rev64(k2h) >> 1);
                let v3 = rev64($z1h) >> 1;
                (v0, v1, v2, v3)
            }};
        }

        let (mut y0_0, mut y0_1) = load_block!(0);
        y0_0 ^= self.acc.0;
        y0_1 ^= self.acc.1;
        let (y1_0, y1_1) = load_block!(16);
        let (y2_0, y2_1) = load_block!(32);
        let (y3_0, y3_1) = load_block!(48);

        let (y0_0, y0_1, y0_0r, y0_1r, y0_2, y0_2r) = prepare_input!(y0_0, y0_1);
        let (y1_0, y1_1, y1_0r, y1_1r, y1_2, y1_2r) = prepare_input!(y1_0, y1_1);
        let (y2_0, y2_1, y2_0r, y2_1r, y2_2, y2_2r) = prepare_input!(y2_0, y2_1);
        let (y3_0, y3_1, y3_0r, y3_1r, y3_2, y3_2r) = prepare_input!(y3_0, y3_1);

        let (h4_0, h4_1, h4_0r, h4_1r, h4_2, h4_2r) = self.key.powers[3];
        let (h3_0, h3_1, h3_0r, h3_1r, h3_2, h3_2r) = self.key.powers[2];
        let (h2_0, h2_1, h2_0r, h2_1r, h2_2, h2_2r) = self.key.powers[1];
        let (h1_0, h1_1, h1_0r, h1_1r, h1_2, h1_2r) = self.key.powers[0];

        let (z0_0, z1_0, z2_0, z0h_0, z1h_0, z2h_0) =
            compute_products!(y0_0, y0_1, y0_0r, y0_1r, y0_2, y0_2r, h4_0, h4_1, h4_0r, h4_1r, h4_2, h4_2r);
        let (z0_1, z1_1, z2_1, z0h_1, z1h_1, z2h_1) =
            compute_products!(y1_0, y1_1, y1_0r, y1_1r, y1_2, y1_2r, h3_0, h3_1, h3_0r, h3_1r, h3_2, h3_2r);
        let (z0_2, z1_2, z2_2, z0h_2, z1h_2, z2h_2) =
            compute_products!(y2_0, y2_1, y2_0r, y2_1r, y2_2, y2_2r, h2_0, h2_1, h2_0r, h2_1r, h2_2, h2_2r);
        let (z0_3, z1_3, z2_3, z0h_3, z1h_3, z2h_3) =
            compute_products!(y3_0, y3_1, y3_0r, y3_1r, y3_2, y3_2r, h1_0, h1_1, h1_0r, h1_1r, h1_2, h1_2r);

        let (v0_0, v1_0, v2_0, v3_0) = karatsuba_combine!(z0_0, z1_0, z2_0, z0h_0, z1h_0, z2h_0);
        let (v0_1, v1_1, v2_1, v3_1) = karatsuba_combine!(z0_1, z1_1, z2_1, z0h_1, z1h_1, z2h_1);
        let (v0_2, v1_2, v2_2, v3_2) = karatsuba_combine!(z0_2, z1_2, z2_2, z0h_2, z1h_2, z2h_2);
        let (v0_3, v1_3, v2_3, v3_3) = karatsuba_combine!(z0_3, z1_3, z2_3, z0h_3, z1h_3, z2h_3);

        let v0 = v0_0 ^ v0_1 ^ v0_2 ^ v0_3;
        let v1 = v1_0 ^ v1_1 ^ v1_2 ^ v1_3;
        let v2 = v2_0 ^ v2_1 ^ v2_2 ^ v2_3;
        let v3 = v3_0 ^ v3_1 ^ v3_2 ^ v3_3;

        self.acc = reduce_256(v0, v1, v2, v3);
    }

    /// Finalizes and returns the authentication tag.
    pub fn finalize(self) -> [u8; 16] {
        let mut result = [0u8; 16];
        result[0..8].copy_from_slice(&self.acc.1.to_be_bytes());
        result[8..16].copy_from_slice(&self.acc.0.to_be_bytes());
        result
    }

    /// Resets to process a new message with the same key.
    pub fn reset(&mut self) {
        self.acc = (0, 0);
    }
}

/// Computes GHASH over the given data in one call.
///
/// Automatically uses hardware acceleration when available:
/// - AVX2 + PCLMULQDQ on x86/x86_64
/// - NEON + PMULL on AArch64
#[allow(unsafe_code)]
pub fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    // Try AVX2 + PCLMULQDQ on x86/x86_64
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if hpcrypt_core::cpufeatures::has_avx2_pclmulqdq() {
            // SAFETY: We verified AVX2 + PCLMULQDQ are available
            return unsafe { crate::intrinsics::avx2::ghash_avx2(h, data) };
        }
    }

    // Try NEON + AES/PMULL on AArch64
    #[cfg(target_arch = "aarch64")]
    {
        if hpcrypt_core::cpufeatures::has_neon_aes() {
            // SAFETY: We verified NEON + AES/PMULL are available
            return unsafe { crate::intrinsics::neon::ghash_neon(h, data) };
        }
    }

    // Portable fallback
    ghash_portable(h, data)
}

/// Portable GHASH implementation (always available).
#[inline]
fn ghash_portable(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut hasher = Ghash::new(h);
    hasher.update_blocks(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmul64_identity() {
        assert_eq!(bmul64(0, 0x1234567890ABCDEF), 0);
        assert_eq!(bmul64(0x1234567890ABCDEF, 0), 0);
        let x = 0x0123456789ABCDEF;
        assert_eq!(bmul64(x, 1), x);
        assert_eq!(bmul64(1, x), x);
    }

    #[test]
    fn test_rev64() {
        assert_eq!(rev64(0), 0);
        assert_eq!(rev64(1), 0x8000000000000000);
        assert_eq!(rev64(0x8000000000000000), 1);
    }

    #[test]
    fn test_ghash_empty() {
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let tag = ghash(&h, &[]);
        assert_eq!(tag, [0u8; 16]);
    }

    #[test]
    fn test_ghash_deterministic() {
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let data = [0x42u8; 64];
        assert_eq!(ghash(&h, &data), ghash(&h, &data));
    }

    #[test]
    fn test_ghash_single_block() {
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let data = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];
        let tag = ghash(&h, &data);
        assert_ne!(tag, [0u8; 16]);
    }

    #[test]
    fn test_ghash_multiple_blocks() {
        let h = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
        let data = [0x42u8; 80];
        let tag = ghash(&h, &data);
        assert_ne!(tag, [0u8; 16]);
    }
}
