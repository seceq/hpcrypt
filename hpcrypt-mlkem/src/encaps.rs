//! ML-KEM Encapsulation Algorithm
//!
//! This module implements Algorithm 13 (K-PKE.Encrypt) and Algorithm 16 (ML-KEM.Encaps)
//! from FIPS 203.
extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;


use crate::params::{Params, N};
use crate::poly::{Poly, PolyVec, PolyMat};
use crate::sampling::{sample_ntt, sample_poly_cbd, sample_ntt_x4, sample_poly_cbd_x4};
use crate::serialize::{
    decode_polyvec_12, encode_poly_compressed, encode_polyvec_compressed,
};
use crate::compress::decompress;
use crate::symmetric::{g, h, j, prf, Xof};
use crate::ntt::{ntt, intt_after_basemul, PolyMulcache};

/// Encapsulation result
pub struct EncapsResult {
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    /// Shared secret key (32 bytes)
    pub shared_secret: [u8; 32],
}

/// K-PKE Encrypt
///
/// Algorithm 13: K-PKE.Encrypt from FIPS 203
///
/// # Arguments
/// * `ek` - Encapsulation (public) key
/// * `m` - Message to encrypt (32 bytes)
/// * `r` - Randomness (32 bytes)
///
/// # Returns
/// Ciphertext
fn kpke_encrypt_impl<const K: usize>(ek: &[u8], m: &[u8; 32], r: &[u8; 32], eta1: usize, eta2: usize, du: u32, dv: u32) -> Vec<u8> {
    debug_assert_eq!(ek.len(), 384 * K + 32);

    // 1. Decode public key: ek = (t, ρ)
    let t = decode_polyvec_12::<K>(&ek[0..384 * K]);
    let rho = &ek[384 * K..384 * K + 32];

    // 2. Sample matrix A^T from ρ using x4 batched sampling
    let mut at_mat = PolyMat::<K>::new();
    for i in 0..K {
        // Process row in chunks of 4
        let mut j = 0;
        while j + 4 <= K {
            // Batch of 4 using x4
            let mut seeds = [[0u8; 34]; 4];
            for (k, seed) in seeds.iter_mut().enumerate() {
                seed[0..32].copy_from_slice(rho);
                // Note: indices for A^T
                seed[32] = i as u8;
                seed[33] = (j + k) as u8;
            }

            let polys = sample_ntt_x4(&seeds);
            at_mat.rows[i].polys[j..(j + 4)].copy_from_slice(&polys);
            j += 4;
        }

        // Handle remainder
        while j < K {
            let mut seed = [0u8; 34];
            seed[0..32].copy_from_slice(rho);
            seed[32] = i as u8;
            seed[33] = j as u8;
            let mut xof = Xof::new(&seed);
            at_mat.rows[i].polys[j] = sample_ntt(&mut xof);
            j += 1;
        }
    }

    // 3. Sample random vectors r, e1, e2 from CBD using x4 batched sampling
    let mut counter: u8 = 0;

    // Sample r vector
    let mut r_vec = PolyVec::<K>::new();
    let mut i = 0;
    while i + 4 <= K {
        let counters = [counter, counter + 1, counter + 2, counter + 3];
        let polys = sample_poly_cbd_x4(r, counters, eta1);
        r_vec.polys[i..(i + 4)].copy_from_slice(&polys);
        counter += 4;
        i += 4;
    }
    while i < K {
        let mut noise_seed = vec![0u8; 64 * eta1];
        prf(r, counter, &mut noise_seed);
        r_vec.polys[i] = sample_poly_cbd(eta1, &noise_seed);
        counter += 1;
        i += 1;
    }

    // Sample e1 vector
    let mut e1 = PolyVec::<K>::new();
    let mut i = 0;
    while i + 4 <= K {
        let counters = [counter, counter + 1, counter + 2, counter + 3];
        let polys = sample_poly_cbd_x4(r, counters, eta2);
        e1.polys[i..(i + 4)].copy_from_slice(&polys);
        counter += 4;
        i += 4;
    }
    while i < K {
        let mut noise_seed = vec![0u8; 64 * eta2];
        prf(r, counter, &mut noise_seed);
        e1.polys[i] = sample_poly_cbd(eta2, &noise_seed);
        counter += 1;
        i += 1;
    }

    // Sample e2 (single polynomial)
    let mut e2_noise = vec![0u8; 64 * eta2];
    prf(r, counter, &mut e2_noise);
    let e2 = sample_poly_cbd(eta2, &e2_noise);

    // 4. Compute u = A^T * r + e1
    // A^T is in NTT form, r and e1 are in coefficient form
    // Convert r to NTT form, compute A^T * r in NTT domain, then convert back

    // Convert r to NTT form
    let mut r_ntt = PolyVec::<K>::new();
    for i in 0..K {
        r_ntt.polys[i] = ntt(&r_vec.polys[i]);
    }

    // Pre-compute mulcaches for r_ntt
    let r_caches: Vec<PolyMulcache> = r_ntt.polys.iter().map(PolyMulcache::compute).collect();

    // Compute A^T * r in NTT domain using optimized mulcache accumulation
    let atr_ntt = at_mat.mul_vec_ntt_cached(&r_ntt, &r_caches);

    // Convert result back to coefficient form using lazy INTT (18.2% faster for basemul outputs)
    let mut atr = PolyVec::<K>::new();
    for i in 0..K {
        atr.polys[i] = intt_after_basemul(&atr_ntt.polys[i]);
    }

    // Add error vector e1 (in coefficient form)
    // Use add_unreduced() because compression handles reduction (4.65x faster)
    let u = atr.add_unreduced(&e1);

    // 5. Decompress message m to polynomial
    let mut m_poly = Poly::new();
    for i in 0..N {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (m[byte_idx] >> bit_idx) & 1;
        m_poly.coeffs[i] = decompress(bit as u16, 1);
    }

    // 6. Compute v = t^T * r + e2 + m
    // t is in coefficient form (decoded from public key), r is in coefficient form
    // We already have r_ntt and r_caches from above

    // Convert t to NTT form
    let mut t_ntt = PolyVec::<K>::new();
    for i in 0..K {
        t_ntt.polys[i] = ntt(&t.polys[i]);
    }

    // Compute t^T * r in NTT domain using cached r
    let tr_ntt = t_ntt.dot_ntt_cached(&r_ntt, &r_caches);

    // Convert result back to coefficient form using lazy INTT (18.2% faster for basemul outputs)
    let tr = intt_after_basemul(&tr_ntt);

    // Add error and message
    // Use add_unreduced() because compression handles reduction (4.65x faster)
    let tr_e2 = tr.add_unreduced(&e2);
    let v = tr_e2.add_unreduced(&m_poly);

    // 7. Encode ciphertext: c = (Compress(u, du), Compress(v, dv))
    let c1 = encode_polyvec_compressed(&u, du);
    let c2 = encode_poly_compressed(&v, dv);

    let mut ciphertext = c1;
    ciphertext.extend(c2);

    ciphertext
}

/// K-PKE Encrypt (public wrapper)
///
/// Algorithm 13: K-PKE.Encrypt from FIPS 203
///
/// # Type Parameter
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
/// * `ek` - Encapsulation (public) key
/// * `m` - Message to encrypt (32 bytes)
/// * `r` - Randomness (32 bytes)
///
/// # Returns
/// Ciphertext
pub fn kpke_encrypt<P: Params>(ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    match P::K {
        2 => kpke_encrypt_impl::<2>(ek, m, r, P::ETA1, P::ETA2, P::DU as u32, P::DV as u32),
        3 => kpke_encrypt_impl::<3>(ek, m, r, P::ETA1, P::ETA2, P::DU as u32, P::DV as u32),
        4 => kpke_encrypt_impl::<4>(ek, m, r, P::ETA1, P::ETA2, P::DU as u32, P::DV as u32),
        _ => unreachable!("Invalid K value"),
    }
}

/// ML-KEM Encapsulation
///
/// Algorithm 16: ML-KEM.Encaps from FIPS 203
///
/// # Arguments
/// * `ek` - Encapsulation (public) key
/// * `m` - Optional random message (32 bytes). If None, generates cryptographically secure random message.
///
/// # Returns
/// Encapsulation result with ciphertext and shared secret
pub fn ml_kem_encaps<P: Params>(ek: &[u8], m: Option<&[u8; 32]>) -> EncapsResult {
    debug_assert_eq!(ek.len(), P::EK_SIZE);

    // 1. Generate or use provided random message
    let message = m.cloned().unwrap_or_else(|| {
        crate::random_bytes_32().expect("RNG failure")
    });

    // 2. Compute (K̄, r) = G(m || H(ek))
    let ek_hash = h(ek);
    let g_input: [u8; 64] = j(&message, &ek_hash);
    let g_output = g(&g_input);

    let k_bar = &g_output[0..32];
    let mut r = [0u8; 32];
    r.copy_from_slice(&g_output[32..64]);

    // 3. Encrypt: c = K-PKE.Encrypt(ek, m, r)
    let ciphertext = kpke_encrypt::<P>(ek, &message, &r);

    // 4. Compute shared secret: K = KDF(K̄ || H(c))
    let c_hash = h(&ciphertext);
    let kdf_input: [u8; 64] = j(k_bar, &c_hash);
    let shared_secret = crate::symmetric::kdf(&kdf_input);

    EncapsResult {
        ciphertext,
        shared_secret,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem512, MlKem768, MlKem1024};
    use crate::keygen::ml_kem_keygen;

    #[test]
    fn test_kpke_encrypt_mlkem512() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem512>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = kpke_encrypt::<MlKem512>(&keys.ek, &m, &r);

        // Check ciphertext size
        assert_eq!(ct.len(), MlKem512::CT_SIZE);
    }

    #[test]
    fn test_kpke_encrypt_mlkem768() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem768>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = kpke_encrypt::<MlKem768>(&keys.ek, &m, &r);

        assert_eq!(ct.len(), MlKem768::CT_SIZE);
    }

    #[test]
    fn test_kpke_encrypt_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem1024>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = kpke_encrypt::<MlKem1024>(&keys.ek, &m, &r);

        assert_eq!(ct.len(), MlKem1024::CT_SIZE);
    }

    #[test]
    fn test_kpke_encrypt_deterministic() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem768>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct1 = kpke_encrypt::<MlKem768>(&keys.ek, &m, &r);
        let ct2 = kpke_encrypt::<MlKem768>(&keys.ek, &m, &r);

        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_ml_kem_encaps_mlkem512() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem512>(Some(&d));

        let m = [0x11u8; 32];
        let result = ml_kem_encaps::<MlKem512>(&keys.ek, Some(&m));

        assert_eq!(result.ciphertext.len(), MlKem512::CT_SIZE);
        assert_eq!(result.shared_secret.len(), 32);
    }

    #[test]
    fn test_ml_kem_encaps_mlkem768() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem768>(Some(&d));

        let m = [0x11u8; 32];
        let result = ml_kem_encaps::<MlKem768>(&keys.ek, Some(&m));

        assert_eq!(result.ciphertext.len(), MlKem768::CT_SIZE);
        assert_eq!(result.shared_secret.len(), 32);
    }

    #[test]
    fn test_ml_kem_encaps_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem1024>(Some(&d));

        let m = [0x11u8; 32];
        let result = ml_kem_encaps::<MlKem1024>(&keys.ek, Some(&m));

        assert_eq!(result.ciphertext.len(), MlKem1024::CT_SIZE);
        assert_eq!(result.shared_secret.len(), 32);
    }

    #[test]
    fn test_ml_kem_encaps_deterministic() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem768>(Some(&d));

        let m = [0x11u8; 32];

        let result1 = ml_kem_encaps::<MlKem768>(&keys.ek, Some(&m));
        let result2 = ml_kem_encaps::<MlKem768>(&keys.ek, Some(&m));

        assert_eq!(result1.ciphertext, result2.ciphertext);
        assert_eq!(result1.shared_secret, result2.shared_secret);
    }
}
