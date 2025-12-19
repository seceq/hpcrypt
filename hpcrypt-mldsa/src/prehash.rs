//! HashML-DSA - Pre-hashing mode as specified in FIPS 204 Section 5.4
//!
//! This module implements HashML-DSA, the pre-hash variant of ML-DSA.
//!
//! # FIPS 204 Specification
//!
//! HashML-DSA uses a different message encoding than pure ML-DSA:
//! - ML-DSA:     M' = 0x00 || len(ctx) || ctx || M
//! - HashML-DSA: M' = 0x01 || len(ctx) || ctx || OID || PH(M)
//!
//! Where:
//! - 0x01 is the pre-hash flag (vs 0x00 for pure ML-DSA)
//! - len(ctx) is the context length (1 byte, max 255)
//! - ctx is the context string
//! - OID is the DER-encoded object identifier for the hash function
//! - PH(M) is the pre-hash of the message
//!
//! # Security Requirements (FIPS 204 Section 5.4)
//!
//! The hash function must be an approved hash function or XOF providing at least
//! λ bits of classical security strength against collision attacks:
//! - ML-DSA-44: ≥256-bit digest (SHA-256 or stronger)
//! - ML-DSA-65: ≥384-bit digest (SHA-384 or stronger)
//! - ML-DSA-87: ≥512-bit digest (SHA-512)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_hash::{HashFunction, XofFunction};
use hpcrypt_hash::{
    Sha256, Sha384, Sha512,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Shake128, Shake256,
};

use crate::keygen::{PublicKey, SecretKey};
use crate::params::DsaParams;
use crate::sign::{Signature, sign_deterministic_fips};
use crate::verify::verify;

/// Maximum context string length as per FIPS 204
pub const MAX_CONTEXT_LENGTH: usize = 255;

// ============================================================================
// DER-encoded OIDs for hash algorithms
// Format: 0x06 (OID tag) || length || OID bytes
// OID base: 2.16.840.1.101.3.4.2.X (nistAlgorithm.hashAlgs.X)
// ============================================================================

/// SHA2-224: 2.16.840.1.101.3.4.2.4
const OID_SHA2_224: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];

/// SHA2-256: 2.16.840.1.101.3.4.2.1
const OID_SHA2_256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// SHA2-384: 2.16.840.1.101.3.4.2.2
const OID_SHA2_384: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// SHA2-512: 2.16.840.1.101.3.4.2.3
const OID_SHA2_512: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// SHA2-512/224: 2.16.840.1.101.3.4.2.5
const OID_SHA2_512_224: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05];

/// SHA2-512/256: 2.16.840.1.101.3.4.2.6
const OID_SHA2_512_256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06];

/// SHA3-224: 2.16.840.1.101.3.4.2.7
const OID_SHA3_224: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07];

/// SHA3-256: 2.16.840.1.101.3.4.2.8
const OID_SHA3_256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];

/// SHA3-384: 2.16.840.1.101.3.4.2.9
const OID_SHA3_384: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];

/// SHA3-512: 2.16.840.1.101.3.4.2.10
const OID_SHA3_512: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A];

/// SHAKE128: 2.16.840.1.101.3.4.2.11
const OID_SHAKE128: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B];

/// SHAKE256: 2.16.840.1.101.3.4.2.12
const OID_SHAKE256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];

// ============================================================================
// SHA-224 Implementation (FIPS 180-4)
// SHA-224 uses the same algorithm as SHA-256 but with different initial values
// and outputs only 224 bits (28 bytes)
// ============================================================================

/// SHA-224 Initial Hash Values (FIPS 180-4)
/// These are the second 32 bits of the fractional parts of the square roots
/// of the 9th through 16th primes (23, 29, 31, 37, 41, 43, 47, 53)
const SHA224_H0: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// SHA-256 round constants
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-224 hash of a message
fn sha224_hash(message: &[u8]) -> Vec<u8> {
    let mut h = SHA224_H0;
    let mut buf = [0u8; 64];
    let mut buflen = 0usize;
    let total_len = message.len();
    let mut processed = 0;

    // Process complete blocks
    while processed + 64 <= total_len {
        sha256_compress(&mut h, &message[processed..processed + 64]);
        processed += 64;
    }

    // Copy remaining bytes to buffer
    buflen = total_len - processed;
    buf[..buflen].copy_from_slice(&message[processed..]);

    // Padding
    buf[buflen] = 0x80;
    buflen += 1;

    if buflen > 56 {
        buf[buflen..64].fill(0);
        sha256_compress(&mut h, &buf);
        buf.fill(0);
    } else {
        buf[buflen..56].fill(0);
    }

    // Length in bits (big-endian)
    let bit_len = (total_len as u64).wrapping_mul(8);
    buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress(&mut h, &buf);

    // Output only first 28 bytes (224 bits)
    let mut output = Vec::with_capacity(28);
    for i in 0..7 {
        output.extend_from_slice(&h[i].to_be_bytes());
    }
    output
}

/// SHA-256 compression function
fn sha256_compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];

    // Parse block into 16 32-bit words
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // Extend to 64 words
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

// ============================================================================
// SHA-512/224 and SHA-512/256 Implementation (FIPS 180-4)
// These use the same algorithm as SHA-512 but with different initial values
// ============================================================================

/// SHA-512/224 Initial Hash Values (FIPS 180-4)
const SHA512_224_H0: [u64; 8] = [
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
    0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
];

/// SHA-512/256 Initial Hash Values (FIPS 180-4)
const SHA512_256_H0: [u64; 8] = [
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2,
    0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
];

/// SHA-512 round constants
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Compute SHA-512/224 hash of a message
fn sha512_224_hash(message: &[u8]) -> Vec<u8> {
    sha512_variant_hash(message, &SHA512_224_H0, 28)
}

/// Compute SHA-512/256 hash of a message
fn sha512_256_hash(message: &[u8]) -> Vec<u8> {
    sha512_variant_hash(message, &SHA512_256_H0, 32)
}

/// Generic SHA-512 variant hash with custom initial values
fn sha512_variant_hash(message: &[u8], h0: &[u64; 8], output_len: usize) -> Vec<u8> {
    let mut h = *h0;
    let mut buf = [0u8; 128];
    let total_len = message.len();
    let mut processed = 0;

    // Process complete blocks
    while processed + 128 <= total_len {
        sha512_compress(&mut h, &message[processed..processed + 128]);
        processed += 128;
    }

    // Copy remaining bytes to buffer
    let buflen = total_len - processed;
    buf[..buflen].copy_from_slice(&message[processed..]);

    // Padding
    buf[buflen] = 0x80;
    let pad_start = buflen + 1;

    if pad_start > 112 {
        buf[pad_start..128].fill(0);
        sha512_compress(&mut h, &buf);
        buf.fill(0);
    } else {
        buf[pad_start..112].fill(0);
    }

    // Length in bits (128-bit big-endian, we use lower 64 bits)
    let bit_len = (total_len as u128).wrapping_mul(8);
    buf[112..120].copy_from_slice(&((bit_len >> 64) as u64).to_be_bytes());
    buf[120..128].copy_from_slice(&(bit_len as u64).to_be_bytes());
    sha512_compress(&mut h, &buf);

    // Output the requested number of bytes
    let mut output = Vec::with_capacity(output_len);
    let mut remaining = output_len;
    for i in 0..8 {
        if remaining == 0 {
            break;
        }
        let bytes = h[i].to_be_bytes();
        let take = remaining.min(8);
        output.extend_from_slice(&bytes[..take]);
        remaining -= take;
    }
    output
}

/// SHA-512 compression function
fn sha512_compress(h: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];

    // Parse block into 16 64-bit words
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
    }

    // Extend to 80 words
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

// ============================================================================
// Hash Algorithm Enum
// ============================================================================

/// Supported pre-hash algorithms for HashML-DSA
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA2-224 (28 bytes)
    Sha2_224,
    /// SHA2-256 (32 bytes)
    Sha2_256,
    /// SHA2-384 (48 bytes)
    Sha2_384,
    /// SHA2-512 (64 bytes)
    Sha2_512,
    /// SHA2-512/224 (28 bytes)
    Sha2_512_224,
    /// SHA2-512/256 (32 bytes)
    Sha2_512_256,
    /// SHA3-224 (28 bytes)
    Sha3_224,
    /// SHA3-256 (32 bytes)
    Sha3_256,
    /// SHA3-384 (48 bytes)
    Sha3_384,
    /// SHA3-512 (64 bytes)
    Sha3_512,
    /// SHAKE128 (configurable output, typically 32 bytes for ACVP)
    Shake128,
    /// SHAKE256 (configurable output, typically 64 bytes for ACVP)
    Shake256,
}

impl HashAlgorithm {
    /// Get the DER-encoded OID for this hash algorithm
    pub fn oid(&self) -> &'static [u8] {
        match self {
            HashAlgorithm::Sha2_224 => OID_SHA2_224,
            HashAlgorithm::Sha2_256 => OID_SHA2_256,
            HashAlgorithm::Sha2_384 => OID_SHA2_384,
            HashAlgorithm::Sha2_512 => OID_SHA2_512,
            HashAlgorithm::Sha2_512_224 => OID_SHA2_512_224,
            HashAlgorithm::Sha2_512_256 => OID_SHA2_512_256,
            HashAlgorithm::Sha3_224 => OID_SHA3_224,
            HashAlgorithm::Sha3_256 => OID_SHA3_256,
            HashAlgorithm::Sha3_384 => OID_SHA3_384,
            HashAlgorithm::Sha3_512 => OID_SHA3_512,
            HashAlgorithm::Shake128 => OID_SHAKE128,
            HashAlgorithm::Shake256 => OID_SHAKE256,
        }
    }

    /// Get the default output length for this hash algorithm
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Sha2_224 => 28,
            HashAlgorithm::Sha2_256 => 32,
            HashAlgorithm::Sha2_384 => 48,
            HashAlgorithm::Sha2_512 => 64,
            HashAlgorithm::Sha2_512_224 => 28,
            HashAlgorithm::Sha2_512_256 => 32,
            HashAlgorithm::Sha3_224 => 28,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha3_512 => 64,
            // For XOFs, use parameter-appropriate lengths
            HashAlgorithm::Shake128 => 32,  // 256-bit for ML-DSA-44
            HashAlgorithm::Shake256 => 64,  // 512-bit for ML-DSA-87
        }
    }

    /// Parse hash algorithm from ACVP test vector string
    pub fn from_acvp_name(name: &str) -> Option<Self> {
        match name {
            "SHA2-224" => Some(HashAlgorithm::Sha2_224),
            "SHA2-256" => Some(HashAlgorithm::Sha2_256),
            "SHA2-384" => Some(HashAlgorithm::Sha2_384),
            "SHA2-512" => Some(HashAlgorithm::Sha2_512),
            "SHA2-512/224" => Some(HashAlgorithm::Sha2_512_224),
            "SHA2-512/256" => Some(HashAlgorithm::Sha2_512_256),
            "SHA3-224" => Some(HashAlgorithm::Sha3_224),
            "SHA3-256" => Some(HashAlgorithm::Sha3_256),
            "SHA3-384" => Some(HashAlgorithm::Sha3_384),
            "SHA3-512" => Some(HashAlgorithm::Sha3_512),
            "SHAKE-128" | "SHAKE128" => Some(HashAlgorithm::Shake128),
            "SHAKE-256" | "SHAKE256" => Some(HashAlgorithm::Shake256),
            _ => None,
        }
    }

    /// Hash a message using this algorithm
    pub fn hash(&self, message: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha2_224 => {
                // SHA-224: FIPS 180-4 compliant implementation with correct IV
                sha224_hash(message)
            }
            HashAlgorithm::Sha2_256 => {
                let mut hasher = Sha256::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha2_384 => {
                let mut hasher = Sha384::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha2_512 => {
                let mut hasher = Sha512::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha2_512_224 => {
                // SHA-512/224: FIPS 180-4 compliant implementation with correct IV
                sha512_224_hash(message)
            }
            HashAlgorithm::Sha2_512_256 => {
                // SHA-512/256: FIPS 180-4 compliant implementation with correct IV
                sha512_256_hash(message)
            }
            HashAlgorithm::Sha3_224 => {
                let mut hasher = Sha3_224::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Shake128 => {
                let mut hasher = Shake128::new();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; 32]; // 256-bit output
                reader.read(&mut output);
                output
            }
            HashAlgorithm::Shake256 => {
                let mut hasher = Shake256::new();
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; 64]; // 512-bit output
                reader.read(&mut output);
                output
            }
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Error type for HashML-DSA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashMlDsaError {
    /// Context string exceeds maximum length of 255 bytes
    ContextTooLong,
    /// Signing failed after max rejection attempts
    SigningFailed,
    /// Unsupported hash algorithm
    UnsupportedHashAlgorithm,
}

// ============================================================================
// FIPS 204 HashML-DSA Message Encoding
// ============================================================================

/// Encode message for HashML-DSA as per FIPS 204 Section 5.4
///
/// Format: 0x01 || len(ctx) || ctx || OID || PH(M)
///
/// # Arguments
/// * `message` - Original message to be pre-hashed
/// * `context` - Context string (max 255 bytes)
/// * `hash_alg` - Hash algorithm to use for pre-hashing
///
/// # Returns
/// * Encoded message M' for signing, or error if context is too long
pub fn encode_hash_ml_dsa_message(
    message: &[u8],
    context: &[u8],
    hash_alg: HashAlgorithm,
) -> Result<Vec<u8>, HashMlDsaError> {
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err(HashMlDsaError::ContextTooLong);
    }

    // Compute pre-hash of message
    let ph_m = hash_alg.hash(message);
    let oid = hash_alg.oid();

    // Allocate: 1 byte (0x01) + 1 byte (len) + context + OID + hash
    let mut encoded = Vec::with_capacity(2 + context.len() + oid.len() + ph_m.len());

    // FIPS 204 HashML-DSA encoding: 0x01 || len(ctx) || ctx || OID || PH(M)
    encoded.push(0x01);  // Pre-hash flag
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    encoded.extend_from_slice(oid);
    encoded.extend_from_slice(&ph_m);

    Ok(encoded)
}

// ============================================================================
// HashML-DSA Sign Functions
// ============================================================================

/// Sign a message using HashML-DSA (FIPS 204 compliant)
///
/// This implements Algorithm 4 from FIPS 204 Section 5.4.
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message to sign (will be pre-hashed)
/// * `context` - Context string (max 255 bytes)
/// * `hash_alg` - Hash algorithm for pre-hashing
/// * `rnd` - 32-byte randomness (use zeros for deterministic)
///
/// # Returns
/// * Signature or error
pub fn sign_hash_ml_dsa<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    context: &[u8],
    hash_alg: HashAlgorithm,
    rnd: &[u8; 32],
) -> Result<Signature<P>, HashMlDsaError> {
    // Encode message: 0x01 || len(ctx) || ctx || OID || PH(M)
    let encoded = encode_hash_ml_dsa_message(message, context, hash_alg)?;

    // Sign the encoded message using standard ML-DSA internal signing
    sign_deterministic_fips(sk, &encoded, rnd)
        .ok_or(HashMlDsaError::SigningFailed)
}

/// Verify a HashML-DSA signature (FIPS 204 compliant)
///
/// This implements Algorithm 5 from FIPS 204 Section 5.4.
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message (will be pre-hashed)
/// * `context` - Context string (must match signing context)
/// * `hash_alg` - Hash algorithm for pre-hashing
/// * `signature` - Signature to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn verify_hash_ml_dsa<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    context: &[u8],
    hash_alg: HashAlgorithm,
    signature: &Signature<P>,
) -> bool {
    // Encode message: 0x01 || len(ctx) || ctx || OID || PH(M)
    let Ok(encoded) = encode_hash_ml_dsa_message(message, context, hash_alg) else {
        return false;
    };

    // Verify using standard ML-DSA verification
    verify(pk, &encoded, signature)
}

// ============================================================================
// Convenience Functions for Common Hash Algorithms
// ============================================================================

/// Sign a message using HashML-DSA with SHA3-512 pre-hashing
///
/// Suitable for all ML-DSA security levels.
pub fn sign_prehashed_sha3_512<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    context: &[u8],
    rnd: &[u8; 32],
) -> Option<Signature<P>> {
    sign_hash_ml_dsa(sk, message, context, HashAlgorithm::Sha3_512, rnd).ok()
}

/// Verify a HashML-DSA signature with SHA3-512 pre-hashing
pub fn verify_prehashed_sha3_512<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    context: &[u8],
    signature: &Signature<P>,
) -> bool {
    verify_hash_ml_dsa(pk, message, context, HashAlgorithm::Sha3_512, signature)
}

/// Sign a message using HashML-DSA with SHA2-512 pre-hashing
///
/// This is the variant with standardized OIDs (id-Hash-ML-DSA-XX-with-sha512).
pub fn sign_prehashed_sha512<P: DsaParams>(
    sk: &SecretKey<P>,
    message: &[u8],
    context: &[u8],
    rnd: &[u8; 32],
) -> Option<Signature<P>> {
    sign_hash_ml_dsa(sk, message, context, HashAlgorithm::Sha2_512, rnd).ok()
}

/// Verify a HashML-DSA signature with SHA2-512 pre-hashing
pub fn verify_prehashed_sha512<P: DsaParams>(
    pk: &PublicKey<P>,
    message: &[u8],
    context: &[u8],
    signature: &Signature<P>,
) -> bool {
    verify_hash_ml_dsa(pk, message, context, HashAlgorithm::Sha2_512, signature)
}

// ============================================================================
// Legacy API (for backwards compatibility)
// These use empty context and non-FIPS encoding - deprecated
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MlDsa65;
    use crate::keygen::keygen;

    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_hash_ml_dsa_sha3_512() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test message for HashML-DSA";
        let context = b"test-context";
        let rnd = [0u8; 32];

        let sig = sign_hash_ml_dsa(&sk, message, context, HashAlgorithm::Sha3_512, &rnd)
            .expect("Signing failed");

        let valid = verify_hash_ml_dsa(&pk, message, context, HashAlgorithm::Sha3_512, &sig);
        assert!(valid, "Valid HashML-DSA signature should verify");
    }

    #[test]
    fn test_hash_ml_dsa_sha2_256() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test message for SHA2-256";
        let context = b"";
        let rnd = [0u8; 32];

        let sig = sign_hash_ml_dsa(&sk, message, context, HashAlgorithm::Sha2_256, &rnd)
            .expect("Signing failed");

        let valid = verify_hash_ml_dsa(&pk, message, context, HashAlgorithm::Sha2_256, &sig);
        assert!(valid, "Valid HashML-DSA-SHA256 signature should verify");
    }

    #[test]
    fn test_hash_ml_dsa_different_hash_no_verify() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test message";
        let context = b"";
        let rnd = [0u8; 32];

        // Sign with SHA3-256
        let sig = sign_hash_ml_dsa(&sk, message, context, HashAlgorithm::Sha3_256, &rnd)
            .expect("Signing failed");

        // Verify with SHA3-512 should fail (different OID and hash)
        let valid = verify_hash_ml_dsa(&pk, message, context, HashAlgorithm::Sha3_512, &sig);
        assert!(!valid, "Signature with different hash algorithm should not verify");
    }

    #[test]
    fn test_hash_ml_dsa_different_context_no_verify() {
        let (pk, sk) = keygen::<MlDsa65>();

        let message = b"Test message";
        let context1 = b"context-1";
        let context2 = b"context-2";
        let rnd = [0u8; 32];

        let sig = sign_hash_ml_dsa(&sk, message, context1, HashAlgorithm::Sha3_512, &rnd)
            .expect("Signing failed");

        let valid = verify_hash_ml_dsa(&pk, message, context2, HashAlgorithm::Sha3_512, &sig);
        assert!(!valid, "Signature with different context should not verify");
    }

    #[test]
    fn test_message_encoding_format() {
        let message = b"Hello";
        let context = b"test";
        let hash_alg = HashAlgorithm::Sha2_256;

        let encoded = encode_hash_ml_dsa_message(message, context, hash_alg).unwrap();

        // Check format: 0x01 || len(ctx) || ctx || OID || PH(M)
        assert_eq!(encoded[0], 0x01, "First byte should be 0x01 (pre-hash flag)");
        assert_eq!(encoded[1], context.len() as u8, "Second byte should be context length");
        assert_eq!(&encoded[2..2+context.len()], context, "Context should follow");

        let oid = hash_alg.oid();
        let oid_start = 2 + context.len();
        assert_eq!(&encoded[oid_start..oid_start+oid.len()], oid, "OID should follow context");

        // The rest should be the hash of the message
        let hash_start = oid_start + oid.len();
        let expected_hash = hash_alg.hash(message);
        assert_eq!(&encoded[hash_start..], expected_hash.as_slice(), "Hash should be at end");
    }

    #[test]
    fn test_context_too_long() {
        let message = b"Test";
        let too_long_context = vec![0x42u8; MAX_CONTEXT_LENGTH + 1];

        let result = encode_hash_ml_dsa_message(message, &too_long_context, HashAlgorithm::Sha2_256);
        assert!(result.is_err(), "Encoding with too-long context should fail");
    }

    #[test]
    fn test_hash_algorithm_oids() {
        // Verify OID format: tag (0x06) + length + OID bytes
        for alg in [
            HashAlgorithm::Sha2_256,
            HashAlgorithm::Sha2_384,
            HashAlgorithm::Sha2_512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512,
        ] {
            let oid = alg.oid();
            assert_eq!(oid[0], 0x06, "OID tag should be 0x06");
            assert_eq!(oid[1], 0x09, "OID length should be 9 bytes");
            assert_eq!(oid.len(), 11, "Full OID should be 11 bytes (tag + length + 9)");
        }
    }

    #[test]
    fn test_acvp_name_parsing() {
        assert_eq!(HashAlgorithm::from_acvp_name("SHA2-256"), Some(HashAlgorithm::Sha2_256));
        assert_eq!(HashAlgorithm::from_acvp_name("SHA3-512"), Some(HashAlgorithm::Sha3_512));
        assert_eq!(HashAlgorithm::from_acvp_name("SHAKE-128"), Some(HashAlgorithm::Shake128));
        assert_eq!(HashAlgorithm::from_acvp_name("SHAKE256"), Some(HashAlgorithm::Shake256));
        assert_eq!(HashAlgorithm::from_acvp_name("UNKNOWN"), None);
    }
}
