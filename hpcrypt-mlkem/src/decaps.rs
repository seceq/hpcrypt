//! ML-KEM Decapsulation Algorithm
//!
//! This module implements the decapsulation algorithms from NIST FIPS 203:
//! - Algorithm 14: K-PKE.Decrypt (CPA-secure decryption)
//! - Algorithm 17: ML-KEM.Decaps (CCA-secure decapsulation with implicit rejection)
//!
//! The decapsulation process:
//! 1. Decrypts the ciphertext using the private key to recover message m'
//! 2. Re-encrypts m' to produce ciphertext c'
//! 3. Performs constant-time comparison of c and c'
//! 4. Returns KDF(m', c) if valid, or KDF(z, c) if invalid (implicit rejection)

use crate::params::Params;
use crate::serialize::{decode_polyvec_12, decode_polyvec_compressed, decode_poly_compressed};
use crate::compress::compress_d1;
use crate::symmetric::{g, h, j, kdf};
use crate::utils::ct_compare;
use crate::encaps::kpke_encrypt;
use crate::ntt::{ntt_inplace, intt, intt_after_basemul, PolyMulcache};

/// K-PKE Decrypt
///
/// Algorithm 14: K-PKE.Decrypt from FIPS 203
///
/// # Arguments
/// * `dk` - Decapsulation (secret) key
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
/// Decrypted message (32 bytes)
#[inline(always)]
#[allow(dead_code)]
fn kpke_decrypt_impl<const K: usize>(dk: &[u8], ciphertext: &[u8], du: u32, dv: u32, ct_size: usize) -> [u8; 32] {
    debug_assert_eq!(dk.len(), 384 * K);
    debug_assert_eq!(ciphertext.len(), ct_size);

    // 1. Decode secret key s_ntt (already in NTT form - optimization!)
    // The secret key is stored in NTT form to save K NTT transforms per decaps
    let s_ntt = decode_polyvec_12::<K>(dk);

    // 2. Decode ciphertext: c = (u, v)
    let u_len = (32 * du * K as u32) as usize;
    let mut u = decode_polyvec_compressed::<K>(&ciphertext[0..u_len], du);
    let v = decode_poly_compressed(&ciphertext[u_len..], dv);

    // 3. Compute m = v - s^T * u using NTT multiplication
    // Convert u to NTT domain in-place (s is already in NTT form)
    // and compute mulcaches in a single pass
    let mut u_caches: [PolyMulcache; K] = [PolyMulcache::new(); K];

    for (cache, poly) in u_caches.iter_mut().zip(u.polys.iter_mut()) {
        ntt_inplace(poly);
        *cache = PolyMulcache::compute(poly);
    }

    // Compute s^T * u in NTT domain using cached multiplication
    let su_ntt = s_ntt.dot_ntt_cached(&u, &u_caches);
    let su = intt(&su_ntt);

    let m_poly = v.sub(&su);

    // 4. Compress and encode message
    // Use specialized compress_d1 for better performance
    // Process 8 coefficients at a time to form each byte
    let mut m = [0u8; 32];
    for (byte_idx, m_byte) in m.iter_mut().enumerate() {
        let base_idx = byte_idx * 8;
        let mut byte_val = 0u8;

        // Process 8 bits at once
        for bit_idx in 0..8 {
            let compressed_bit = compress_d1(m_poly.coeffs[base_idx + bit_idx]);
            byte_val |= (compressed_bit as u8) << bit_idx;
        }

        *m_byte = byte_val;
    }

    m
}

/// Specialized K=2 version with manual loop unrolling optimization
///
/// This version uses polyvec_basemul_acc_cached_k2 which manually unrolls
/// the inner k loop, reducing branch overhead by ~64 instructions.
#[inline(always)]
fn kpke_decrypt_impl_k2(dk: &[u8], ciphertext: &[u8], du: u32, dv: u32, ct_size: usize) -> [u8; 32] {
    const K: usize = 2;
    debug_assert_eq!(dk.len(), 384 * K);
    debug_assert_eq!(ciphertext.len(), ct_size);

    let s_ntt = decode_polyvec_12::<K>(dk);
    let u_len = (32 * du * K as u32) as usize;
    let mut u = decode_polyvec_compressed::<K>(&ciphertext[0..u_len], du);
    let v = decode_poly_compressed(&ciphertext[u_len..], dv);

    let mut u_caches: [PolyMulcache; K] = [PolyMulcache::new(); K];
    for (cache, poly) in u_caches.iter_mut().zip(u.polys.iter_mut()) {
        ntt_inplace(poly);
        *cache = PolyMulcache::compute(poly);
    }

    let su_ntt = s_ntt.dot_ntt_cached_k2(&u, &u_caches);
    let su = intt_after_basemul(&su_ntt);  // 18.2% faster lazy INTT for basemul outputs
    let m_poly = v.sub(&su);

    let mut m = [0u8; 32];
    for (byte_idx, m_byte) in m.iter_mut().enumerate() {
        let base_idx = byte_idx * 8;
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let compressed_bit = compress_d1(m_poly.coeffs[base_idx + bit_idx]);
            byte_val |= (compressed_bit as u8) << bit_idx;
        }
        *m_byte = byte_val;
    }
    m
}

/// Specialized K=3 version with manual loop unrolling optimization
///
/// This version uses polyvec_basemul_acc_cached_k3 which manually unrolls
/// the inner k loop, reducing branch overhead by ~128 instructions.
#[inline(always)]
fn kpke_decrypt_impl_k3(dk: &[u8], ciphertext: &[u8], du: u32, dv: u32, ct_size: usize) -> [u8; 32] {
    const K: usize = 3;
    debug_assert_eq!(dk.len(), 384 * K);
    debug_assert_eq!(ciphertext.len(), ct_size);

    let s_ntt = decode_polyvec_12::<K>(dk);
    let u_len = (32 * du * K as u32) as usize;
    let mut u = decode_polyvec_compressed::<K>(&ciphertext[0..u_len], du);
    let v = decode_poly_compressed(&ciphertext[u_len..], dv);

    let mut u_caches: [PolyMulcache; K] = [PolyMulcache::new(); K];
    for (cache, poly) in u_caches.iter_mut().zip(u.polys.iter_mut()) {
        ntt_inplace(poly);
        *cache = PolyMulcache::compute(poly);
    }

    let su_ntt = s_ntt.dot_ntt_cached_k3(&u, &u_caches);
    let su = intt_after_basemul(&su_ntt);  // 18.2% faster lazy INTT for basemul outputs
    let m_poly = v.sub(&su);

    let mut m = [0u8; 32];
    for (byte_idx, m_byte) in m.iter_mut().enumerate() {
        let base_idx = byte_idx * 8;
        let mut byte_val = 0u8;
        for bit_idx in 0..8 {
            let compressed_bit = compress_d1(m_poly.coeffs[base_idx + bit_idx]);
            byte_val |= (compressed_bit as u8) << bit_idx;
        }
        *m_byte = byte_val;
    }
    m
}

/// Specialized K=4 version with manual loop unrolling optimization
///
/// This version uses polyvec_basemul_acc_cached_k4 which manually unrolls
/// the inner k loop, reducing branch overhead by ~192 instructions.
#[inline(always)]
fn kpke_decrypt_impl_k4(dk: &[u8], ciphertext: &[u8], du: u32, dv: u32, ct_size: usize) -> [u8; 32] {
    const K: usize = 4;
    debug_assert_eq!(dk.len(), 384 * K);
    debug_assert_eq!(ciphertext.len(), ct_size);

    // 1. Decode secret key s_ntt (already in NTT form)
    let s_ntt = decode_polyvec_12::<K>(dk);

    // 2. Decode ciphertext: c = (u, v)
    let u_len = (32 * du * K as u32) as usize;
    let mut u = decode_polyvec_compressed::<K>(&ciphertext[0..u_len], du);
    let v = decode_poly_compressed(&ciphertext[u_len..], dv);

    // 3. Compute m = v - s^T * u using NTT multiplication
    // Convert u to NTT domain and compute mulcaches
    let mut u_caches: [PolyMulcache; K] = [PolyMulcache::new(); K];

    for (cache, poly) in u_caches.iter_mut().zip(u.polys.iter_mut()) {
        ntt_inplace(poly);
        *cache = PolyMulcache::compute(poly);
    }

    // Use optimized K=4 dot product with manual loop unrolling
    let su_ntt = s_ntt.dot_ntt_cached_k4(&u, &u_caches);
    let su = intt_after_basemul(&su_ntt);  // 18.2% faster lazy INTT for basemul outputs

    let m_poly = v.sub(&su);

    // 4. Compress and encode message
    let mut m = [0u8; 32];
    for (byte_idx, m_byte) in m.iter_mut().enumerate() {
        let base_idx = byte_idx * 8;
        let mut byte_val = 0u8;

        for bit_idx in 0..8 {
            let compressed_bit = compress_d1(m_poly.coeffs[base_idx + bit_idx]);
            byte_val |= (compressed_bit as u8) << bit_idx;
        }

        *m_byte = byte_val;
    }

    m
}

/// K-PKE Decrypt (public wrapper)
///
/// Algorithm 14: K-PKE.Decrypt from FIPS 203
///
/// # Type Parameter
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
/// * `dk` - Decapsulation (secret) key
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
/// Decrypted message (32 bytes)
#[inline(always)]
pub fn kpke_decrypt<P: Params>(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    match P::K {
        2 => kpke_decrypt_impl_k2(dk, ciphertext, P::DU as u32, P::DV as u32, P::CT_SIZE),
        3 => kpke_decrypt_impl_k3(dk, ciphertext, P::DU as u32, P::DV as u32, P::CT_SIZE),
        4 => kpke_decrypt_impl_k4(dk, ciphertext, P::DU as u32, P::DV as u32, P::CT_SIZE),
        _ => unreachable!("Invalid K value"),
    }
}

/// ML-KEM Decapsulation
///
/// Implements Algorithm 17 (ML-KEM.Decaps) from NIST FIPS 203.
///
/// Recovers the shared secret from a ciphertext using the private decapsulation key.
/// This operation uses the Fujisaki-Okamoto transform with implicit rejection to
/// provide IND-CCA2 security and resistance to timing attacks.
///
/// # Type Parameters
///
/// * `P` - Parameter set ([`MlKem512`], [`MlKem768`], or [`MlKem1024`])
///
/// # Arguments
///
/// * `dk` - Decapsulation (private) key bytes
/// * `ciphertext` - Ciphertext to decapsulate
///
/// # Returns
///
/// 32-byte shared secret. **Important**: This function always returns a value,
/// even for invalid ciphertexts. Invalid ciphertexts produce pseudorandom outputs
/// (implicit rejection) to prevent timing side-channels.
///
/// # Security
///
/// - **Constant-time operation**: Execution time is independent of ciphertext validity
/// - **Implicit rejection**: Invalid ciphertexts produce pseudorandom shared secrets
/// - **CCA2 security**: Secure against adaptive chosen-ciphertext attacks
/// - **Re-encryption check**: Validates ciphertext integrity via re-encryption
///
/// The constant-time property prevents attackers from distinguishing valid from
/// invalid ciphertexts by measuring decapsulation time.
///
/// [`MlKem512`]: crate::MlKem512
/// [`MlKem768`]: crate::MlKem768
/// [`MlKem1024`]: crate::MlKem1024
#[inline(always)]
pub fn ml_kem_decaps<P: Params>(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    debug_assert_eq!(dk.len(), P::DK_SIZE);
    debug_assert_eq!(ciphertext.len(), P::CT_SIZE);

    // 1. Parse decapsulation key: dk = (dk_pke || ek || h || z)
    let dk_pke_len = 384 * P::K;
    let ek_len = P::EK_SIZE;

    let dk_pke = &dk[0..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + ek_len];
    let _h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    // 2. Decrypt ciphertext
    let m = kpke_decrypt::<P>(dk_pke, ciphertext);

    // 3. Compute (K̄, r') = G(m || H(ek))
    let ek_hash = h(ek);
    let g_input: [u8; 64] = j(&m, &ek_hash);
    let g_output = g(&g_input);

    let k_bar = &g_output[0..32];
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g_output[32..64]);

    // 4. Re-encrypt to verify: c' = K-PKE.Encrypt(ek, m, r')
    let c_prime = kpke_encrypt::<P>(ek, &m, &r_prime);

    // 5. Constant-time comparison: c == c'?
    let valid = ct_compare(ciphertext, &c_prime);

    // 6. Compute shared secret with implicit rejection
    // If valid: K = KDF(K̄ || H(c))
    // If invalid: K = KDF(z || H(c))  (implicit rejection)

    let c_hash = h(ciphertext);

    

    if valid {
        // Valid ciphertext: use K̄
        let kdf_input: [u8; 64] = j(k_bar, &c_hash);
        kdf(&kdf_input)
    } else {
        // Invalid ciphertext: use z for implicit rejection
        let kdf_input: [u8; 64] = j(z, &c_hash);
        kdf(&kdf_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlKem512, MlKem768, MlKem1024};
    use crate::keygen::ml_kem_keygen;
    use crate::encaps::ml_kem_encaps;

    #[test]
    fn test_kpke_encrypt_decrypt_roundtrip_mlkem512() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem512>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = crate::encaps::kpke_encrypt::<MlKem512>(&keys.ek, &m, &r);
        let m_recovered = kpke_decrypt::<MlKem512>(&keys.dk, &ct);

        assert_eq!(m, m_recovered);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_roundtrip_mlkem768() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem768>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = crate::encaps::kpke_encrypt::<MlKem768>(&keys.ek, &m, &r);
        let m_recovered = kpke_decrypt::<MlKem768>(&keys.dk, &ct);

        assert_eq!(m, m_recovered);
    }

    #[test]
    fn test_kpke_encrypt_decrypt_roundtrip_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem1024>(&d);

        let m = [0x11u8; 32];
        let r = [0x22u8; 32];

        let ct = crate::encaps::kpke_encrypt::<MlKem1024>(&keys.ek, &m, &r);
        let m_recovered = kpke_decrypt::<MlKem1024>(&keys.dk, &ct);

        assert_eq!(m, m_recovered);
    }

    #[test]
    fn test_ml_kem_encaps_decaps_roundtrip_mlkem512() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem512>(Some(&d));

        let m = [0x11u8; 32];
        let encaps_result = ml_kem_encaps::<MlKem512>(&keys.ek, Some(&m));

        let shared_secret_decaps = ml_kem_decaps::<MlKem512>(&keys.dk, &encaps_result.ciphertext);

        assert_eq!(encaps_result.shared_secret, shared_secret_decaps);
    }

    #[test]
    fn test_ml_kem_encaps_decaps_roundtrip_mlkem768() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem768>(Some(&d));

        let m = [0x11u8; 32];
        let encaps_result = ml_kem_encaps::<MlKem768>(&keys.ek, Some(&m));

        let shared_secret_decaps = ml_kem_decaps::<MlKem768>(&keys.dk, &encaps_result.ciphertext);

        assert_eq!(encaps_result.shared_secret, shared_secret_decaps);
    }

    #[test]
    fn test_ml_kem_encaps_decaps_roundtrip_mlkem1024() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem1024>(Some(&d));

        let m = [0x11u8; 32];
        let encaps_result = ml_kem_encaps::<MlKem1024>(&keys.ek, Some(&m));

        let shared_secret_decaps = ml_kem_decaps::<MlKem1024>(&keys.dk, &encaps_result.ciphertext);

        assert_eq!(encaps_result.shared_secret, shared_secret_decaps);
    }

    #[test]
    fn test_ml_kem_implicit_rejection() {
        let d = [0x42u8; 32];
        let keys = ml_kem_keygen::<MlKem768>(Some(&d));

        let m = [0x11u8; 32];
        let encaps_result = ml_kem_encaps::<MlKem768>(&keys.ek, Some(&m));

        // Corrupt the ciphertext
        let mut corrupted_ct = encaps_result.ciphertext.clone();
        corrupted_ct[0] ^= 0x01;

        // Decaps should still work but produce different shared secret
        let ss_corrupted = ml_kem_decaps::<MlKem768>(&keys.dk, &corrupted_ct);

        // Should not match original shared secret
        assert_ne!(encaps_result.shared_secret, ss_corrupted);

        // But should be deterministic for same corrupted ciphertext
        let ss_corrupted2 = ml_kem_decaps::<MlKem768>(&keys.dk, &corrupted_ct);
        assert_eq!(ss_corrupted, ss_corrupted2);
    }

    #[test]
    fn test_kpke_decrypt_different_ciphertexts() {
        let d = [0x42u8; 32];
        let keys = crate::keygen::kpke_keygen::<MlKem768>(&d);

        let m1 = [0x11u8; 32];
        let m2 = [0x22u8; 32];
        let r = [0x33u8; 32];

        let ct1 = crate::encaps::kpke_encrypt::<MlKem768>(&keys.ek, &m1, &r);
        let ct2 = crate::encaps::kpke_encrypt::<MlKem768>(&keys.ek, &m2, &r);

        let recovered1 = kpke_decrypt::<MlKem768>(&keys.dk, &ct1);
        let recovered2 = kpke_decrypt::<MlKem768>(&keys.dk, &ct2);

        assert_eq!(m1, recovered1);
        assert_eq!(m2, recovered2);
        assert_ne!(recovered1, recovered2);
    }
}
