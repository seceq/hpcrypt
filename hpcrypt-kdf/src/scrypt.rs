//! Scrypt - Memory-hard Key Derivation Function
//!
//! Scrypt is a password-based key derivation function designed to be more secure against
//! hardware brute-force attacks than alternatives like PBKDF2 by being memory-hard.
//!
//! # Security
//!
//! The security of scrypt relies on three parameters:
//! - **N**: CPU/memory cost parameter (must be power of 2, recommended: 16384 or higher)
//! - **r**: Block size parameter (recommended: 8)
//! - **p**: Parallelization parameter (recommended: 1)
//!
//! # References
//!
//! - [RFC 7914: The scrypt Password-Based Key Derivation Function](https://tools.ietf.org/html/rfc7914)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_hash::HmacSha256;

/// Scrypt parameters
#[derive(Debug, Clone, Copy)]
pub struct ScryptParams {
    /// CPU/Memory cost parameter (must be power of 2)
    pub n: usize,
    /// Block size parameter
    pub r: usize,
    /// Parallelization parameter
    pub p: usize,
}

impl ScryptParams {
    /// Create new scrypt parameters
    ///
    /// # Arguments
    ///
    /// * `log_n` - log2 of the CPU/memory cost (N = 2^log_n)
    /// * `r` - Block size parameter
    /// * `p` - Parallelization parameter
    ///
    /// # Recommended Values
    ///
    /// - **Interactive**: log_n=14 (N=16384), r=8, p=1 - Fast, ~16MB memory
    /// - **Moderate**: log_n=16 (N=65536), r=8, p=1 - Medium, ~64MB memory
    /// - **Sensitive**: log_n=18 (N=262144), r=8, p=1 - Slow, ~256MB memory
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_kdf::scrypt::ScryptParams;
    ///
    /// // Interactive (fast)
    /// let params = ScryptParams::new(14, 8, 1).unwrap();
    ///
    /// // Sensitive data (slow, more secure)
    /// let params = ScryptParams::new(18, 8, 1).unwrap();
    /// ```
    pub fn new(log_n: u8, r: usize, p: usize) -> Result<Self, &'static str> {
        if log_n >= 64 {
            return Err("log_n too large");
        }

        let n = 1usize << log_n;

        if r == 0 || p == 0 {
            return Err("r and p must be greater than 0");
        }

        // Check for overflow: n * r * p * 128 must fit in usize
        let memory_required = n
            .checked_mul(r)
            .and_then(|nr| nr.checked_mul(p))
            .and_then(|nrp| nrp.checked_mul(128))
            .ok_or("parameters too large (would cause overflow)")?;

        // Reasonable limit: 1GB
        if memory_required > 1024 * 1024 * 1024 {
            return Err("parameters too large (would require >1GB memory)");
        }

        Ok(Self { n, r, p })
    }

    /// Recommended parameters for interactive logins (fast)
    ///
    /// N=16384, r=8, p=1 (~16MB memory, ~100ms on modern CPU)
    pub fn interactive() -> Self {
        Self {
            n: 16384,
            r: 8,
            p: 1,
        }
    }

    /// Recommended parameters for moderate security (medium)
    ///
    /// N=65536, r=8, p=1 (~64MB memory, ~400ms on modern CPU)
    pub fn moderate() -> Self {
        Self {
            n: 65536,
            r: 8,
            p: 1,
        }
    }

    /// Recommended parameters for sensitive data (slow, more secure)
    ///
    /// N=262144, r=8, p=1 (~256MB memory, ~1.6s on modern CPU)
    pub fn sensitive() -> Self {
        Self {
            n: 262144,
            r: 8,
            p: 1,
        }
    }
}

/// Derive a key using scrypt
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - Salt value (recommended: 16+ bytes of random data)
/// * `params` - Scrypt parameters (N, r, p)
/// * `output_len` - Desired output length in bytes
///
/// # Example
///
/// ```
/// use hpcrypt_kdf::scrypt::{scrypt, ScryptParams};
///
/// let password = b"my secure password";
/// let salt = b"random salt 1234"; // Use crypto-random salt in production
/// let params = ScryptParams::interactive();
///
/// let key = scrypt(password, salt, &params, 32);
/// ```
pub fn scrypt(password: &[u8], salt: &[u8], params: &ScryptParams, output_len: usize) -> Vec<u8> {
    let ScryptParams { n, r, p } = *params;

    // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
    let b_len = p * 128 * r;
    let mut b = vec![0u8; b_len];
    pbkdf2_hmac_sha256(password, salt, 1, &mut b);

    // Step 2: For each block, apply ROMix
    for i in 0..p {
        let block_start = i * 128 * r;
        let block_end = block_start + 128 * r;
        romix(&mut b[block_start..block_end], n, r);
    }

    // Step 3: DK = PBKDF2-HMAC-SHA256(password, B, 1, output_len)
    let mut output = vec![0u8; output_len];
    pbkdf2_hmac_sha256(password, &b, 1, &mut output);

    output
}

/// ROMix function from scrypt specification
fn romix(block: &mut [u8], n: usize, r: usize) {
    let block_size = 128 * r;
    let mut v = vec![0u8; n * block_size];
    let mut x = block.to_vec();

    // Step 1: X = B
    // (already copied above)

    // Step 2: for i = 0 to N-1 do
    //           V[i] = X
    //           X = scryptBlockMix(X)
    for i in 0..n {
        v[i * block_size..(i + 1) * block_size].copy_from_slice(&x);
        block_mix(&mut x, r);
    }

    // Step 3: for i = 0 to N-1 do
    //           j = Integerify(X) mod N
    //           X = X xor V[j]
    //           X = scryptBlockMix(X)
    for _ in 0..n {
        let j = integerify(&x, r) % n;
        for k in 0..block_size {
            x[k] ^= v[j * block_size + k];
        }
        block_mix(&mut x, r);
    }

    // Step 4: B' = X
    block.copy_from_slice(&x);
}

/// BlockMix function from scrypt specification
fn block_mix(b: &mut [u8], r: usize) {
    let mut x = [0u8; 64];
    let mut y = vec![0u8; 128 * r];

    // X = B[2r - 1]
    x.copy_from_slice(&b[(2 * r - 1) * 64..(2 * r) * 64]);

    // for i = 0 to 2r - 1 do
    //   X = Salsa20/8(X xor B[i])
    //   Y[i] = X
    for i in 0..(2 * r) {
        // X = X xor B[i]
        for j in 0..64 {
            x[j] ^= b[i * 64 + j];
        }

        // X = Salsa20/8(X)
        salsa20_8(&mut x);

        // Y[i] = X
        y[i * 64..(i + 1) * 64].copy_from_slice(&x);
    }

    // B = (Y[0], Y[2], ..., Y[2r-2], Y[1], Y[3], ..., Y[2r-1])
    for i in 0..r {
        b[i * 64..(i + 1) * 64].copy_from_slice(&y[2 * i * 64..(2 * i + 1) * 64]);
        b[(r + i) * 64..(r + i + 1) * 64].copy_from_slice(&y[(2 * i + 1) * 64..(2 * i + 2) * 64]);
    }
}

/// Salsa20/8 core function (8 rounds)
fn salsa20_8(input: &mut [u8; 64]) {
    // Convert bytes to u32 little-endian
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            input[i * 4],
            input[i * 4 + 1],
            input[i * 4 + 2],
            input[i * 4 + 3],
        ]);
    }

    let mut z = x;

    // 8 rounds (4 double-rounds)
    for _ in 0..4 {
        // Column round
        quarter_round(&mut z, 0, 4, 8, 12);
        quarter_round(&mut z, 5, 9, 13, 1);
        quarter_round(&mut z, 10, 14, 2, 6);
        quarter_round(&mut z, 15, 3, 7, 11);

        // Row round
        quarter_round(&mut z, 0, 1, 2, 3);
        quarter_round(&mut z, 5, 6, 7, 4);
        quarter_round(&mut z, 10, 11, 8, 9);
        quarter_round(&mut z, 15, 12, 13, 14);
    }

    // Add original values
    for i in 0..16 {
        z[i] = z[i].wrapping_add(x[i]);
    }

    // Convert back to bytes
    for i in 0..16 {
        let bytes = z[i].to_le_bytes();
        input[i * 4] = bytes[0];
        input[i * 4 + 1] = bytes[1];
        input[i * 4 + 2] = bytes[2];
        input[i * 4 + 3] = bytes[3];
    }
}

/// Quarter round function for Salsa20
#[inline]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// Integerify function from scrypt specification
fn integerify(b: &[u8], r: usize) -> usize {
    // Return the last 64-byte block as a little-endian integer
    let offset = (2 * r - 1) * 64;
    usize::from_le_bytes([
        b[offset],
        b[offset + 1],
        b[offset + 2],
        b[offset + 3],
        b[offset + 4],
        b[offset + 5],
        b[offset + 6],
        b[offset + 7],
    ])
}

/// Simple PBKDF2-HMAC-SHA256 implementation for scrypt
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8]) {
    let hlen = 32; // SHA-256 output length
    let blocks_needed = (output.len() + hlen - 1) / hlen;

    for block_index in 1..=blocks_needed {
        let mut block = [0u8; 32];

        // U1 = PRF(password, salt || block_index)
        let mut salt_with_index = salt.to_vec();
        salt_with_index.extend_from_slice(&(block_index as u32).to_be_bytes());

        let mut u = HmacSha256::new(password).compute(&salt_with_index);
        block.copy_from_slice(&u);

        // U2, U3, ... = PRF(password, U_prev)
        for _ in 1..iterations {
            u = HmacSha256::new(password).compute(&u);
            for (b, &u_byte) in block.iter_mut().zip(u.iter()) {
                *b ^= u_byte;
            }
        }

        // Copy to output
        let start = (block_index - 1) * hlen;
        let end = core::cmp::min(start + hlen, output.len());
        output[start..end].copy_from_slice(&block[..end - start]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrypt_rfc7914_test_vector_1() {
        // RFC 7914 Test Vector 1
        let password = b"";
        let salt = b"";
        let params = ScryptParams { n: 16, r: 1, p: 1 };

        let output = scrypt(password, salt, &params, 64);

        let expected = hex_literal::hex!(
            "77d6576238657b203b19ca42c18a0497\
             f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17\
             e8d3e0fb2e0d3628cf35e20c38d18906"
        );

        assert_eq!(output.as_slice(), &expected[..]);
    }

    #[test]
    fn test_scrypt_rfc7914_test_vector_2() {
        // RFC 7914 Test Vector 2
        let password = b"password";
        let salt = b"NaCl";
        let params = ScryptParams {
            n: 1024,
            r: 8,
            p: 16,
        };

        let output = scrypt(password, salt, &params, 64);

        let expected = hex_literal::hex!(
            "fdbabe1c9d3472007856e7190d01e9fe\
             7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830da\
             c727afb94a83ee6d8360cbdfa2cc0640"
        );

        assert_eq!(output.as_slice(), &expected[..]);
    }

    #[test]
    fn test_scrypt_params_interactive() {
        let params = ScryptParams::interactive();
        assert_eq!(params.n, 16384);
        assert_eq!(params.r, 8);
        assert_eq!(params.p, 1);
    }

    #[test]
    fn test_scrypt_params_new() {
        let params = ScryptParams::new(14, 8, 1).unwrap();
        assert_eq!(params.n, 16384);
        assert_eq!(params.r, 8);
        assert_eq!(params.p, 1);
    }

    #[test]
    fn test_scrypt_basic() {
        let password = b"my password";
        let salt = b"random salt";
        let params = ScryptParams::interactive();

        let key1 = scrypt(password, salt, &params, 32);
        let key2 = scrypt(password, salt, &params, 32);

        // Same inputs should produce same output
        assert_eq!(key1, key2);

        // Different password should produce different output
        let key3 = scrypt(b"different password", salt, &params, 32);
        assert_ne!(key1, key3);
    }
}
