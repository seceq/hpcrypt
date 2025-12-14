//! Symmetric cryptographic primitives for ML-DSA
//!
//! This module implements the symmetric primitive functions specified in FIPS 204:
//! - XOF: Extendable Output Function (SHAKE-128)
//! - PRF: Pseudorandom Function (SHAKE-256)
//! - H: Hash function (SHAKE-256, 512 bits for ML-DSA)
//!
//! These primitives are used throughout ML-DSA for:
//! - Matrix expansion (SHAKE-128)
//! - Challenge polynomial generation (SHAKE-256)
//! - Key hashing (SHAKE-256)
//! - Mask expansion (SHAKE-256)

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use hpcrypt_hash::{Shake128, Shake256};

/// Extendable Output Function (XOF)
///
/// XOF(seed) = SHAKE-128(seed)
///
/// Used for generating pseudorandom bytes from a seed.
/// In ML-DSA, primarily used for expanding the matrix A.
pub struct Xof {
    reader: hpcrypt_hash::xof_reader::XofReader<168, 24>,
}

impl Xof {
    /// Create a new XOF instance with the given seed
    ///
    /// # Arguments
    /// * `seed` - Input seed bytes
    ///
    /// # Returns
    /// A new XOF instance ready to produce output
    pub fn new(seed: &[u8]) -> Self {
        let mut state = Shake128::new();
        state.update(seed);
        Self {
            reader: state.finalize_xof(),
        }
    }

    /// Read output bytes from the XOF
    ///
    /// # Arguments
    /// * `output` - Buffer to fill with pseudorandom bytes
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }

    /// Create a new reader for this XOF
    pub fn reader(&self) -> hpcrypt_hash::xof_reader::XofReader<168, 24> {
        self.reader.clone()
    }
}

/// SHAKE-256 extendable output function (zero-allocation)
///
/// Used for various purposes in ML-DSA including:
/// - Challenge polynomial generation
/// - Mask expansion (ExpandMask)
/// - Message hashing
///
/// This implementation uses a concrete type instead of `Box<dyn XofReader>`,
/// eliminating heap allocation and dynamic dispatch overhead.
pub struct Shake256Xof {
    reader: hpcrypt_hash::xof_reader::XofReader<136, 24>,
}

impl Shake256Xof {
    /// Create a new SHAKE-256 XOF instance with the given input
    #[inline]
    pub fn new(input: &[u8]) -> Self {
        let mut state = Shake256::new();
        state.update(input);
        Self {
            reader: state.finalize_xof(),
        }
    }

    /// Read output bytes from the XOF
    /// This advances the internal reader state, so each call returns NEW data
    #[inline]
    pub fn read(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// Alias for backward compatibility (deprecated, use Shake256Xof directly)
pub type Shake256Direct = Shake256Xof;

/// H function for ML-DSA: SHAKE-256 with 512-bit output
///
/// H(input) = SHAKE-256(input, 512 bits)
///
/// Used for hashing public keys and computing tr (public key hash).
///
/// # Arguments
/// * `input` - Input bytes to hash
///
/// # Returns
/// 64-byte (512-bit) hash output
pub fn h(input: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let mut hasher = Shake256::new();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// H function with 256-bit output
///
/// H(input) = SHAKE-256(input, 256 bits)
///
/// # Used for challenge generation in signing/verification.
///
/// # Arguments
/// * `input` - Input bytes to hash
///
/// # Returns
/// 32-byte (256-bit) hash output
pub fn h256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Shake256::new();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// H function with variable-length output
///
/// H(input, len) = SHAKE-256(input, len*8 bits)
///
/// Used for challenge hash c~ generation where len = CTILDEBYTES (32/48/64 bytes).
///
/// # Arguments
/// * `input` - Input bytes to hash
/// * `len` - Number of bytes to output
///
/// # Returns
/// Vector of `len` bytes
pub fn h_var(input: &[u8], len: usize) -> Vec<u8> {
    let mut output = vec![0u8; len];
    let mut hasher = Shake256::new();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// H function with 1024-bit (128-byte) output
///
/// H(input, 128) = SHAKE-256(input, 1024 bits)
///
/// Used for seed expansion in key generation (Algorithm 6).
/// Expands ξ into (ρ, ρ', K) = (32 bytes, 64 bytes, 32 bytes) = 128 bytes total
///
/// # Arguments
/// * `input` - Input bytes to hash
///
/// # Returns
/// 128-byte (1024-bit) hash output
pub fn h128(input: &[u8]) -> [u8; 128] {
    let mut output = [0u8; 128];
    let mut hasher = Shake256::new();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// ExpandA: Expand matrix A from seed ρ
///
/// Uses SHAKE-128 to expand the public matrix A from a seed.
/// Each element A[i][j] is expanded from SHAKE-128(ρ || j || i).
///
/// # Arguments
/// * `rho` - 32-byte seed
/// * `i` - Row index
/// * `j` - Column index
///
/// # Returns
/// XOF instance ready to sample polynomial coefficients
pub fn expand_a(rho: &[u8; 32], i: u8, j: u8) -> Xof {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    seed[32] = j;
    seed[33] = i;
    Xof::new(&seed)
}

/// Batched ExpandA (4-way parallel SHAKE-128)
///
/// Expands 4 matrix elements using SHAKE-128.
///
/// # Arguments
/// * `rho` - 32-byte seed
/// * `indices` - Array of 4 (i, j) index pairs
///
/// # Returns
/// Array of 4 SHAKE-128 XOF outputs (840 bytes each for uniform sampling)
#[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
pub fn expand_a_x4_avx2(rho: &[u8; 32], indices: [(u8, u8); 4]) -> [Vec<u8>; 4] {
    // 840 bytes = 5 SHAKE-128 blocks, enough for rejection sampling
    const OUTPUT_LEN: usize = 840;

    [
        {
            let mut xof = expand_a(rho, indices[0].0, indices[0].1);
            let mut out = vec![0u8; OUTPUT_LEN];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_a(rho, indices[1].0, indices[1].1);
            let mut out = vec![0u8; OUTPUT_LEN];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_a(rho, indices[2].0, indices[2].1);
            let mut out = vec![0u8; OUTPUT_LEN];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_a(rho, indices[3].0, indices[3].1);
            let mut out = vec![0u8; OUTPUT_LEN];
            xof.read(&mut out);
            out
        },
    ]
}

/// ExpandS: Expand secret vectors s1, s2 from seed ρ'
///
/// Uses SHAKE-256 to expand secret polynomials from a seed.
///
/// # Arguments
/// * `rho_prime` - 64-byte seed
/// * `index` - Polynomial index
///
/// # Returns
/// SHAKE-256 XOF instance ready to sample coefficients
pub fn expand_s(rho_prime: &[u8; 64], index: u16) -> Shake256Xof {
    let mut input = [0u8; 66];
    input[..64].copy_from_slice(rho_prime);
    input[64] = (index & 0xFF) as u8;
    input[65] = ((index >> 8) & 0xFF) as u8;
    Shake256Xof::new(&input)
}

/// ExpandMask: Expand masking vector y from seed ρ' and counter κ
///
/// Uses SHAKE-256 to expand the masking polynomial y in signing.
///
/// # Arguments
/// * `rho_prime` - Seed for mask generation
/// * `kappa` - Counter value
/// * `index` - Polynomial index (for vectors)
///
/// # Returns
/// SHAKE-256 XOF instance ready to sample coefficients
pub fn expand_mask(rho_prime: &[u8], kappa: u16, index: u8) -> Shake256Xof {
    // Pre-allocate: rho_prime + 2 bytes for kappa + 1 byte for index
    let mut input = Vec::with_capacity(rho_prime.len() + 3);
    input.extend_from_slice(rho_prime);
    input.push((kappa & 0xFF) as u8);
    input.push(((kappa >> 8) & 0xFF) as u8);
    input.push(index);
    Shake256Xof::new(&input)
}

/// J function for concatenation
///
/// J(a, b) = a || b (simple concatenation)
///
/// # Arguments
/// * `a` - First input
/// * `b` - Second input
///
/// # Returns
/// Concatenated result
#[inline]
pub fn j<const N: usize>(a: &[u8], b: &[u8]) -> [u8; N] {
    debug_assert_eq!(a.len() + b.len(), N);
    let mut result = [0u8; N];
    result[..a.len()].copy_from_slice(a);
    result[a.len()..].copy_from_slice(b);
    result
}

/// Batched ExpandS (4-way parallel SHAKE-256)
///
/// Expands 4 secret polynomials using SHAKE-256.
///
/// # Arguments
/// * `rho_prime` - 64-byte seed
/// * `indices` - Array of 4 polynomial indices
///
/// # Returns
/// Array of 4 SHAKE-256 XOF outputs (256 bytes each for eta sampling)
#[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
pub fn expand_s_x4_avx2(rho_prime: &[u8; 64], indices: [u16; 4]) -> [Vec<u8>; 4] {
    [
        {
            let mut xof = expand_s(rho_prime, indices[0]);
            let mut out = vec![0u8; 256];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_s(rho_prime, indices[1]);
            let mut out = vec![0u8; 256];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_s(rho_prime, indices[2]);
            let mut out = vec![0u8; 256];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_s(rho_prime, indices[3]);
            let mut out = vec![0u8; 256];
            xof.read(&mut out);
            out
        },
    ]
}

/// Batched ExpandMask (4-way parallel SHAKE-256)
///
/// Expands 4 masking polynomials using SHAKE-256.
///
/// # Arguments
/// * `rho_prime` - 64-byte seed for mask generation
/// * `kappas` - Array of 4 counter values
///
/// # Returns
/// Array of 4 SHAKE-256 XOF outputs (640 bytes each for mask sampling)
#[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
pub fn expand_mask_x4_avx2(rho_prime: &[u8; 64], kappas: [u16; 4]) -> [Vec<u8>; 4] {
    [
        {
            let mut xof = expand_mask(rho_prime, kappas[0], 0);
            let mut out = vec![0u8; 640];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_mask(rho_prime, kappas[1], 0);
            let mut out = vec![0u8; 640];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_mask(rho_prime, kappas[2], 0);
            let mut out = vec![0u8; 640];
            xof.read(&mut out);
            out
        },
        {
            let mut xof = expand_mask(rho_prime, kappas[3], 0);
            let mut out = vec![0u8; 640];
            xof.read(&mut out);
            out
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xof_deterministic() {
        let seed = b"test seed";

        let mut xof1 = Xof::new(seed);
        let mut output1 = [0u8; 64];
        xof1.read(&mut output1);

        let mut xof2 = Xof::new(seed);
        let mut output2 = [0u8; 64];
        xof2.read(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_xof_different_seeds() {
        let mut xof1 = Xof::new(b"seed1");
        let mut output1 = [0u8; 64];
        xof1.read(&mut output1);

        let mut xof2 = Xof::new(b"seed2");
        let mut output2 = [0u8; 64];
        xof2.read(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_shake256_xof_deterministic() {
        let input = b"test input";

        let mut xof1 = Shake256Xof::new(input);
        let mut output1 = [0u8; 128];
        xof1.read(&mut output1);

        let mut xof2 = Shake256Xof::new(input);
        let mut output2 = [0u8; 128];
        xof2.read(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_h_deterministic() {
        let input = b"test input";
        let output1 = h(input);
        let output2 = h(input);
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_h_output_size() {
        let output = h(b"test");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_h256_deterministic() {
        let input = b"test input";
        let output1 = h256(input);
        let output2 = h256(input);
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_h256_output_size() {
        let output = h256(b"test");
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_h_and_h256_different() {
        let input = b"test";
        let h_out = h(input);
        let h256_out = h256(input);
        // First 32 bytes should match since h256 is just truncated h
        assert_eq!(&h_out[..32], &h256_out[..]);
    }

    #[test]
    fn test_j_concatenation() {
        let a = [1, 2, 3];
        let b = [4, 5];
        let result: [u8; 5] = j(&a, &b);
        assert_eq!(result, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_j_empty() {
        let a = [1, 2, 3];
        let b: [u8; 0] = [];
        let result: [u8; 3] = j(&a, &b);
        assert_eq!(result, [1, 2, 3]);
    }

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [0x42u8; 32];
        let mut xof1 = expand_a(&rho, 0, 1);
        let mut xof2 = expand_a(&rho, 0, 1);

        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        xof1.read(&mut out1);
        xof2.read(&mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_expand_a_different_indices() {
        let rho = [0x42u8; 32];
        let mut xof1 = expand_a(&rho, 0, 0);
        let mut xof2 = expand_a(&rho, 0, 1);

        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        xof1.read(&mut out1);
        xof2.read(&mut out2);

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_expand_s_deterministic() {
        let rho_prime = [0x55u8; 64];
        let mut xof1 = expand_s(&rho_prime, 0);
        let mut xof2 = expand_s(&rho_prime, 0);

        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        xof1.read(&mut out1);
        xof2.read(&mut out2);

        assert_eq!(out1, out2);
    }
}
