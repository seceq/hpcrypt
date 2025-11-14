//! PBKDF2 - Password-Based Key Derivation Function 2 (RFC 2898)

#![allow(clippy::manual_div_ceil)] // MSRV 1.70 compatibility - div_ceil stabilized in 1.73

extern crate alloc;
use alloc::vec::Vec;

use hpcrypt_mac::{HmacSha256, HmacSha512};

/// PBKDF2 with HMAC-SHA256
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2_inner::<32>(password, salt, iterations, output, |key, data| {
        HmacSha256::new(key).compute(data)
    });
}

/// PBKDF2 with HMAC-SHA512
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2_inner::<64>(password, salt, iterations, output, |key, data| {
        HmacSha512::new(key).compute(data)
    });
}

fn pbkdf2_inner<const N: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
    prf: impl Fn(&[u8], &[u8]) -> [u8; N],
) {
    let h_len = N;
    let blocks = (output.len() + h_len - 1) / h_len;

    for block_index in 1..=blocks {
        // U_1 = PRF(password, salt || INT(i))
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&(block_index as u32).to_be_bytes());

        let mut u = prf(password, &salt_block);
        let mut result = u;

        // U_j = PRF(password, U_{j-1})
        for _ in 1..iterations {
            u = prf(password, &u);
            for i in 0..h_len {
                result[i] ^= u[i];
            }
        }

        // Copy result to output
        let offset = (block_index - 1) * h_len;
        let to_copy = core::cmp::min(h_len, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&result[..to_copy]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_hmac_sha256_rfc() {
        // RFC 6070 Test Vector 1
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;

        let mut output = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut output);

        let expected =
            hex_literal::hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

        assert_eq!(output, expected);
    }

    #[test]
    fn test_pbkdf2_hmac_sha256_2_iterations() {
        // RFC 6070 Test Vector 2
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;

        let mut output = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut output);

        let expected =
            hex_literal::hex!("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

        assert_eq!(output, expected);
    }

    #[test]
    fn test_pbkdf2_hmac_sha256_4096_iterations() {
        // RFC 6070 Test Vector 3
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;

        let mut output = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut output);

        let expected =
            hex_literal::hex!("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");

        assert_eq!(output, expected);
    }

    #[test]
    fn test_pbkdf2_hmac_sha512_basic() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;

        let mut output = [0u8; 64];
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output);

        // Just verify it produces non-zero output
        assert_ne!(output, [0u8; 64]);
    }
}
