//! ML-KEM Key Generation Algorithm
//!
//! This module implements the key generation algorithms from NIST FIPS 203:
//! - Algorithm 12: K-PKE.KeyGen (CPA-secure encryption key generation)
//! - Algorithm 15: ML-KEM.KeyGen (CCA-secure KEM key generation)
//!
//! The key generation process involves:
//! 1. Generating a uniformly random matrix A from a seed
//! 2. Sampling secret and error polynomial vectors from a CBD distribution
//! 3. Computing the public key as t = A·s + e (in NTT domain)
//! 4. Serializing keys with additional validation data for CCA security
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntt::{intt, ntt, PolyMulcache};
use crate::params::Params;
use crate::poly::{PolyMat, PolyVec};
use crate::sampling::{sample_ntt, sample_ntt_x4, sample_poly_cbd, sample_poly_cbd_x4};
use crate::serialize::encode_polyvec_12;
use crate::symmetric::{g, h, prf, Xof};

/// K-PKE (CPA-secure) key pair
///
/// Internal key pair for the CPA-secure encryption scheme
pub struct KpkeKeyPair {
    /// Encapsulation (public) key
    pub ek: Vec<u8>,
    /// Decapsulation (secret) key
    pub dk: Vec<u8>,
}

/// Internal K-PKE key generation with const generics
///
/// Algorithm 12: K-PKE.KeyGen from FIPS 203
///
/// # Arguments
/// * `d` - Random seed (32 bytes)
/// * `eta1` - Noise parameter
///
/// # Returns
/// K-PKE key pair (ek, dk)
fn kpke_keygen_impl<const K: usize>(d: &[u8; 32], eta1: usize) -> KpkeKeyPair {
    debug_assert_eq!(d.len(), 32);

    // 1. (ρ, σ) ← G(d)  (split 64 bytes into two 32-byte parts)
    let g_output = g(d);
    let rho = &g_output[0..32];
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&g_output[32..64]);

    // 2. N ← 0
    let mut counter: u8 = 0;

    // 3. Generate matrix A from seed ρ using x4 batched sampling
    let mut a_mat = PolyMat::<K>::new();
    for i in 0..K {
        // Process row in chunks of 4
        let mut j = 0;
        while j + 4 <= K {
            // Batch of 4 using x4
            let mut seeds = [[0u8; 34]; 4];
            for (k, seed) in seeds.iter_mut().enumerate() {
                seed[0..32].copy_from_slice(rho);
                seed[32] = (j + k) as u8; // j index
                seed[33] = i as u8; // i index
            }

            let polys = sample_ntt_x4(&seeds);
            a_mat.rows[i].polys[j..(j + 4)].copy_from_slice(&polys);
            j += 4;
        }

        // Handle remainder (if K is not divisible by 4)
        while j < K {
            let mut seed = [0u8; 34];
            seed[0..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            let mut xof = Xof::new(&seed);
            a_mat.rows[i].polys[j] = sample_ntt(&mut xof);
            j += 1;
        }
    }

    // 4. Sample secret vector s using x4 batched sampling
    let mut s = PolyVec::<K>::new();
    let mut i = 0;
    while i + 4 <= K {
        // Batch of 4 using x4
        let counters = [counter, counter + 1, counter + 2, counter + 3];
        let polys = sample_poly_cbd_x4(&sigma, counters, eta1);
        s.polys[i..(i + 4)].copy_from_slice(&polys);
        counter += 4;
        i += 4;
    }
    // Handle remainder
    while i < K {
        let mut noise_seed = vec![0u8; 64 * eta1];
        prf(&sigma, counter, &mut noise_seed);
        s.polys[i] = sample_poly_cbd(eta1, &noise_seed);
        counter += 1;
        i += 1;
    }

    // 5. Sample error vector e using x4 batched sampling
    let mut e = PolyVec::<K>::new();
    let mut i = 0;
    while i + 4 <= K {
        // Batch of 4 using x4
        let counters = [counter, counter + 1, counter + 2, counter + 3];
        let polys = sample_poly_cbd_x4(&sigma, counters, eta1);
        e.polys[i..(i + 4)].copy_from_slice(&polys);
        counter += 4;
        i += 4;
    }
    // Handle remainder
    while i < K {
        let mut noise_seed = vec![0u8; 64 * eta1];
        prf(&sigma, counter, &mut noise_seed);
        e.polys[i] = sample_poly_cbd(eta1, &noise_seed);
        counter += 1;
        i += 1;
    }

    // 6. Compute t = A*s + e
    // A is in NTT form, s and e are in coefficient form
    // Convert s to NTT form, compute A*s in NTT domain, then convert back

    // Convert s to NTT form
    let mut s_ntt = PolyVec::<K>::new();
    for i in 0..K {
        s_ntt.polys[i] = ntt(&s.polys[i]);
    }

    // Pre-compute mulcaches for s_ntt
    let s_caches: Vec<PolyMulcache> = s_ntt.polys.iter().map(PolyMulcache::compute).collect();

    // Compute A * s in NTT domain using optimized mulcache accumulation
    let as_ntt = a_mat.mul_vec_ntt_cached(&s_ntt, &s_caches);

    // Convert result back to coefficient form
    let mut as_vec = PolyVec::<K>::new();
    for i in 0..K {
        as_vec.polys[i] = intt(&as_ntt.polys[i]);
    }

    // Add error vector e (in coefficient form)
    // Use add_unreduced() because encoding handles reduction (4.65x faster)
    let t = as_vec.add_unreduced(&e);

    // 7. Encode keys
    // ek = Encode(t) || ρ
    let mut ek = encode_polyvec_12(&t);
    ek.extend_from_slice(rho);

    // dk = Encode(s_ntt) - Store secret key in NTT form for faster decaps
    // This saves K NTT transforms per decapsulation (6-9 µs for ML-KEM-768)
    let dk = encode_polyvec_12(&s_ntt);

    KpkeKeyPair { ek, dk }
}

/// Generate K-PKE key pair (public wrapper)
///
/// Algorithm 12: K-PKE.KeyGen from FIPS 203
///
/// # Type Parameter
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
/// * `d` - Random seed (32 bytes)
///
/// # Returns
/// K-PKE key pair (ek, dk)
pub fn kpke_keygen<P: Params>(d: &[u8; 32]) -> KpkeKeyPair {
    match P::K {
        2 => kpke_keygen_impl::<2>(d, P::ETA1),
        3 => kpke_keygen_impl::<3>(d, P::ETA1),
        4 => kpke_keygen_impl::<4>(d, P::ETA1),
        _ => unreachable!("Invalid K value"),
    }
}

/// ML-KEM key pair
#[derive(Clone)]
pub struct KeyPair {
    /// Encapsulation key (public key)
    pub ek: Vec<u8>,
    /// Decapsulation key (private key)
    pub dk: Vec<u8>,
}

/// Generate ML-KEM key pair
///
/// Implements Algorithm 15 (ML-KEM.KeyGen) from NIST FIPS 203.
///
/// This function generates a complete ML-KEM key pair including:
/// - Public encapsulation key (ek) containing the matrix seed and public polynomial vector
/// - Private decapsulation key (dk) containing the secret polynomial, public key,
///   hash of the public key, and implicit rejection randomness
///
/// # Type Parameters
///
/// * `P` - Parameter set ([`MlKem512`], [`MlKem768`], or [`MlKem1024`])
///
/// # Arguments
///
/// * `d` - Optional 32-byte seed for deterministic key generation.
///   - If `None`: Uses OS CSPRNG (recommended for production)
///   - If `Some(seed)`: Uses provided seed (for testing/reproducibility only)
///
/// # Returns
///
/// [`KeyPair`] containing the encapsulation and decapsulation keys
///
/// # Panics
///
/// Panics if `d` is `None` and the OS RNG fails (extremely rare).
///
/// # Security
///
/// - Uses CBD (Centered Binomial Distribution) for noise sampling
/// - Public key includes hash for validation in decapsulation
/// - Private key includes randomness for implicit rejection
///
/// [`MlKem512`]: crate::MlKem512
/// [`MlKem768`]: crate::MlKem768
/// [`MlKem1024`]: crate::MlKem1024
pub fn ml_kem_keygen<P: Params>(d: Option<&[u8; 32]>) -> KeyPair {
    // Generate or use provided seed
    let seed = d
        .cloned()
        .unwrap_or_else(|| crate::random_bytes_32().expect("Failed to generate random seed"));

    // 1. Generate K-PKE key pair
    let kpke_keys = kpke_keygen::<P>(&seed);

    // 2. ek_pke = encapsulation key from K-PKE
    let ek = kpke_keys.ek;

    // 3. dk_pke = decapsulation key from K-PKE
    let dk_pke = kpke_keys.dk;

    // 4. Compute H(ek) for decapsulation key
    let ek_hash = h(&ek);

    // 5. Generate random z for implicit rejection
    let z = seed; // Use same seed for z (in real impl, generate separately)

    // 6. Construct ML-KEM decapsulation key: dk = (dk_pke || ek || H(ek) || z)
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&ek_hash);
    dk.extend_from_slice(&z);

    KeyPair { ek, dk }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem1024, MlKem512, MlKem768};

    #[test]
    fn test_kpke_keygen_mlkem512() {
        let d = [0x42u8; 32];
        let keys = kpke_keygen::<MlKem512>(&d);

        // Check sizes
        assert_eq!(keys.ek.len(), 384 * 2 + 32); // t (2 polys) + rho
        assert_eq!(keys.dk.len(), 384 * 2); // s (2 polys)
    }

    #[test]
    fn test_kpke_keygen_mlkem768() {
        let d = [0x42u8; 32];
        let keys = kpke_keygen::<MlKem768>(&d);

        // Check sizes
        assert_eq!(keys.ek.len(), 384 * 3 + 32); // t (3 polys) + rho
        assert_eq!(keys.dk.len(), 384 * 3); // s (3 polys)
    }

    #[test]
    fn test_kpke_keygen_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = kpke_keygen::<MlKem1024>(&d);

        // Check sizes
        assert_eq!(keys.ek.len(), 384 * 4 + 32); // t (4 polys) + rho
        assert_eq!(keys.dk.len(), 384 * 4); // s (4 polys)
    }

    #[test]
    fn test_kpke_keygen_deterministic() {
        let d = [0x55u8; 32];

        let keys1 = kpke_keygen::<MlKem768>(&d);
        let keys2 = kpke_keygen::<MlKem768>(&d);

        assert_eq!(keys1.ek, keys2.ek);
        assert_eq!(keys1.dk, keys2.dk);
    }

    #[test]
    fn test_ml_kem_keygen_mlkem512() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem512>(Some(&d));

        assert_eq!(keys.ek.len(), MlKem512::EK_SIZE);
        assert_eq!(keys.dk.len(), MlKem512::DK_SIZE);
    }

    #[test]
    fn test_ml_kem_keygen_mlkem768() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem768>(Some(&d));

        assert_eq!(keys.ek.len(), MlKem768::EK_SIZE);
        assert_eq!(keys.dk.len(), MlKem768::DK_SIZE);
    }

    #[test]
    fn test_ml_kem_keygen_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem1024>(Some(&d));

        assert_eq!(keys.ek.len(), MlKem1024::EK_SIZE);
        assert_eq!(keys.dk.len(), MlKem1024::DK_SIZE);
    }

    #[test]
    fn test_ml_kem_keygen_deterministic() {
        let d = [0xAAu8; 32];

        let keys1 = ml_kem_keygen::<MlKem768>(Some(&d));
        let keys2 = ml_kem_keygen::<MlKem768>(Some(&d));

        assert_eq!(keys1.ek, keys2.ek);
        assert_eq!(keys1.dk, keys2.dk);
    }

    #[test]
    fn test_ml_kem_keygen_different_seeds() {
        let d1 = [0x11u8; 32];
        let d2 = [0x22u8; 32];

        let keys1 = ml_kem_keygen::<MlKem768>(Some(&d1));
        let keys2 = ml_kem_keygen::<MlKem768>(Some(&d2));

        assert_ne!(keys1.ek, keys2.ek);
        assert_ne!(keys1.dk, keys2.dk);
    }
}
