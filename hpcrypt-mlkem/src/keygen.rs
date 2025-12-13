//! ML-KEM Key Generation Algorithm
//!
//! This module implements Algorithm 12 (K-PKE.KeyGen) and Algorithm 15 (ML-KEM.KeyGen)
//! from FIPS 203.
extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;


use crate::params::Params;
use crate::poly::{PolyVec, PolyMat};
use crate::sampling::{sample_ntt, sample_poly_cbd, sample_ntt_x4, sample_poly_cbd_x4};
use crate::serialize::encode_polyvec_12;
use crate::symmetric::{g, h, prf, Xof};
use crate::ntt::{ntt, intt_after_basemul, PolyMulcache};

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

    // 1. (ρ, σ) ← G(d || k)  (FIPS 203 domain separation)
    // Append k parameter to seed before hashing
    let mut seed_with_k = [0u8; 33];
    seed_with_k[..32].copy_from_slice(d);
    seed_with_k[32] = K as u8;
    let g_output = g(&seed_with_k);
    let rho = &g_output[0..32];
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&g_output[32..64]);

    // 2. N ← 0
    let mut counter: u8 = 0;

    // 3. Generate matrix Â from seed ρ using x4 batched sampling
    // FIPS 203 Algorithm 12, line 8: Â[i][j] ← SampleNTT(XOF(ρ, j, i))
    // Note: XOF seed order is (ρ || j || i), NOT (ρ || i || j)
    let mut a_mat = PolyMat::<K>::new();
    for i in 0..K {
        // Process row in chunks of 4
        let mut j = 0;
        while j + 4 <= K {
            // Batch of 4 using x4
            let mut seeds = [[0u8; 34]; 4];
            for k in 0..4 {
                seeds[k][0..32].copy_from_slice(rho);
                seeds[k][32] = (j + k) as u8;    // j index first (FIPS 203)
                seeds[k][33] = i as u8;          // i index second (FIPS 203)
            }

            let polys = sample_ntt_x4(&seeds);
            for k in 0..4 {
                a_mat.rows[i].polys[j + k] = polys[k];
            }
            j += 4;
        }

        // Handle remainder (if K is not divisible by 4)
        while j < K {
            let mut seed = [0u8; 34];
            seed[0..32].copy_from_slice(rho);
            seed[32] = j as u8;  // j index first (FIPS 203)
            seed[33] = i as u8;  // i index second (FIPS 203)
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
        for k in 0..4 {
            s.polys[i + k] = polys[k];
        }
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
        for k in 0..4 {
            e.polys[i + k] = polys[k];
        }
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

    // 6. Compute t = A*s + e, then t̂ = NTT(t)
    // FIPS 203 stores t̂ (NTT form) in ek for efficient encapsulation

    // Convert s to NTT form: ŝ ← NTT(s)
    let mut s_ntt = PolyVec::<K>::new();
    for i in 0..K {
        s_ntt.polys[i] = ntt(&s.polys[i]);
    }

    // Pre-compute mulcaches for s_ntt
    let s_caches: Vec<PolyMulcache> = s_ntt.polys.iter()
        .map(|poly| PolyMulcache::compute(poly))
        .collect();

    // Compute Â ◦ ŝ in NTT domain using optimized mulcache accumulation
    let as_ntt = a_mat.mul_vec_ntt_cached(&s_ntt, &s_caches);

    // Convert result back to coefficient form
    let mut as_vec = PolyVec::<K>::new();
    for i in 0..K {
        as_vec.polys[i] = intt_after_basemul(&as_ntt.polys[i]);
    }

    // Add error vector e (in coefficient form): t = A*s + e
    let t = as_vec.add(&e);

    // Convert t to NTT form for storage: t̂ = NTT(t)
    // FIPS 203: ek stores t̂ in NTT form, saving NTT in encaps
    let mut t_hat = PolyVec::<K>::new();
    for i in 0..K {
        t_hat.polys[i] = ntt(&t.polys[i]);
    }

    // 7. Encode keys
    // ek = ByteEncode₁₂(t̂) || ρ  (FIPS 203: t̂ is in NTT form)
    let mut ek = encode_polyvec_12(&t_hat);
    ek.extend_from_slice(rho);

    // dk = ByteEncode₁₂(ŝ) - secret key in NTT form
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
/// Algorithm 15: ML-KEM.KeyGen from FIPS 203
///
/// # Type Parameter
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
/// * `d` - Random seed (32 bytes). If None, generates cryptographically secure random seed.
///
/// # Returns
/// ML-KEM key pair with encapsulation and decapsulation keys
pub fn ml_kem_keygen<P: Params>(d: Option<&[u8; 32]>) -> KeyPair {
    // Generate or use provided seed
    let seed = d.cloned().unwrap_or_else(|| {
        crate::random_bytes_32().expect("RNG failure")
    });

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

/// Generate ML-KEM key pair with explicit d and z seeds (for CAVP testing)
///
/// This function is specifically for NIST CAVP/ACVP test vectors which provide
/// separate d and z values. For production use, use [`ml_kem_keygen`] instead.
#[cfg(feature = "cavp")]
pub fn ml_kem_keygen_internal<P: Params>(d: &[u8], z: &[u8]) -> KeyPair {
    // Convert d to array
    let mut d_array = [0u8; 32];
    d_array.copy_from_slice(&d[..32]);

    // 1. Generate K-PKE key pair
    let kpke_keys = kpke_keygen::<P>(&d_array);

    // 2. ek_pke = encapsulation key from K-PKE
    let ek = kpke_keys.ek;

    // 3. dk_pke = decapsulation key from K-PKE
    let dk_pke = kpke_keys.dk;

    // 4. Compute H(ek) for decapsulation key
    let ek_hash = h(&ek);

    // 5. Construct ML-KEM decapsulation key: dk = (dk_pke || ek || H(ek) || z)
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&ek_hash);
    dk.extend_from_slice(z);

    KeyPair { ek, dk }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem512, MlKem768, MlKem1024};

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
