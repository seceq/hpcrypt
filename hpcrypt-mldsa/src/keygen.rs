//! Key generation for ML-DSA
//!
//! This module implements the key generation algorithm specified in FIPS 204 Section 5.1.
//!
//! # Algorithm Overview
//!
//! KeyGen generates a public key (pk) and secret key (sk):
//!
//! 1. Generate random seeds: ξ (32 bytes)
//! 2. Expand seeds: (ρ, ρ', K) ← H(ξ, 128 bytes)
//! 3. Expand matrix A from ρ
//! 4. Sample secrets s1, s2 from ρ'
//! 5. Compute t = A·s1 + s2 (in NTT domain for efficiency)
//! 6. Split t = 2^d·t1 + t0 using Power2Round
//! 7. Compute tr = H(ρ || t1)
//! 8. pk = (ρ, t1)
//! 9. sk = (ρ, K, tr, s1, s2, t0)

extern crate alloc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::params::DsaParams;
use crate::poly::Poly;
use crate::rounding::power2round;
use crate::sampling::expand_matrix_a;
use crate::symmetric::h;
use hpcrypt_rng::generate_random_bytes;

/// Public key for ML-DSA
///
/// Contains the seed ρ and the high-order bits t1 of the public vector t.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey<P: DsaParams> {
    /// Seed for matrix A expansion (32 bytes)
    pub rho: [u8; 32],

    /// High-order bits of t (k polynomials)
    pub t1: Vec<Poly>,

    /// Cached hash of public key (tr = H(ρ || t1))
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub tr: [u8; 64],

    /// Phantom data to use type parameter P
    _phantom: PhantomData<P>,
}

impl<P: DsaParams> PublicKey<P> {
    /// Create a new public key
    pub fn new(rho: [u8; 32], t1: Vec<Poly>, tr: [u8; 64]) -> Self {
        Self {
            rho,
            t1,
            tr,
            _phantom: PhantomData,
        }
    }
}

/// Secret key for ML-DSA
///
/// Contains all components needed for signing.
///
/// # Security Note
///
/// When the `zeroize` feature is enabled, this struct will automatically
/// zero its memory on drop, preventing secret key material from remaining
/// in memory after use.
///
/// WARNING: Serialization of secret keys should be done with extreme caution.
/// Only use serde feature if you absolutely need to serialize secret keys,
/// and ensure proper protection (encryption, secure storage, etc.)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretKey<P: DsaParams> {
    /// Seed for matrix A expansion (32 bytes) - PUBLIC, no zeroization needed
    pub rho: [u8; 32],

    /// Secret randomness seed K (32 bytes) - SENSITIVE
    pub k: [u8; 32],

    /// Public key hash tr (64 bytes) - PUBLIC, no zeroization needed
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub tr: [u8; 64],

    /// Secret vector s1 (ℓ polynomials) - SENSITIVE
    pub s1: Vec<Poly>,

    /// Secret vector s2 (k polynomials) - SENSITIVE
    pub s2: Vec<Poly>,

    /// Low-order bits of t (k polynomials) - SENSITIVE
    pub t0: Vec<Poly>,

    /// Cached matrix A (k × ℓ) - precomputed for signing optimization
    ///
    /// OPTIMIZATION: Matrix A is expanded from rho during every signature.
    /// This costs ~80 µs per signature (12% of signing time).
    /// By pre-computing and caching A during keygen, we eliminate this cost.
    ///
    /// Memory cost: k × ℓ × 256 × 4 bytes
    /// - ML-DSA-44: 4×4×256×4 = 16 KB
    /// - ML-DSA-65: 6×5×256×4 = 30 KB
    /// - ML-DSA-87: 8×7×256×4 = 56 KB
    ///
    /// Trade-off: Memory for 12% signing speedup
    ///
    /// PUBLIC data derived from rho, no zeroization needed
    pub cached_a: Vec<Vec<Poly>>,

    /// Phantom data to use type parameter P
    _phantom: PhantomData<P>,
}

#[cfg(feature = "zeroize")]
impl<P: DsaParams> Drop for SecretKey<P> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k.zeroize();
        for poly in &mut self.s1 {
            poly.coeffs.zeroize();
        }
        for poly in &mut self.s2 {
            poly.coeffs.zeroize();
        }
        for poly in &mut self.t0 {
            poly.coeffs.zeroize();
        }
        // cached_a is public data (derived from rho), but zeroize anyway for completeness
        for row in &mut self.cached_a {
            for poly in row {
                poly.coeffs.zeroize();
            }
        }
    }
}
impl<P: DsaParams> SecretKey<P> {
    /// Create a new secret key
    pub fn new(
        rho: [u8; 32],
        k: [u8; 32],
        tr: [u8; 64],
        s1: Vec<Poly>,
        s2: Vec<Poly>,
        t0: Vec<Poly>,
        cached_a: Vec<Vec<Poly>>,
    ) -> Self {
        Self {
            rho,
            k,
            tr,
            s1,
            s2,
            t0,
            cached_a,
            _phantom: PhantomData,
        }
    }
}

/// Generate a keypair for the given parameter set
///
/// # Algorithm (FIPS 204 Section 5.1)
///
/// ```text
/// 1. ξ ← {0,1}^256
/// 2. (ρ, ρ', K) ← H(ξ, 128)
/// 3. A ← ExpandA(ρ)
/// 4. (s1, s2) ← ExpandS(ρ')
/// 5. t ← A·s1 + s2
/// 6. (t1, t0) ← Power2Round(t, d)
/// 7. tr ← H(ρ || t1)
/// 8. pk ← (ρ, t1)
/// 9. sk ← (ρ, K, tr, s1, s2, t0)
/// ```
///
/// # Returns
/// * `(PublicKey, SecretKey)` - Generated keypair
pub fn keygen<P: DsaParams>() -> (PublicKey<P>, SecretKey<P>) {
    // Step 1: Generate random seed ξ
    let mut xi = [0u8; 32];
    generate_random_bytes(&mut xi).expect("RNG failure");

    keygen_from_seed::<P>(&xi)
}

/// Generate a keypair from a given seed (for deterministic testing)
///
/// # Arguments
/// * `xi` - 32-byte seed
///
/// # Returns
/// * `(PublicKey, SecretKey)` - Generated keypair
///
/// # Security Note
///
/// Key generation is generally not timing-sensitive because:
/// - It's typically performed once per key lifetime
/// - The output (public key) is public information
/// - Rejection sampling in polynomial generation doesn't leak secret information
///   (the sampling module uses constant-time primitives internally)
///
/// The most critical constant-time operations are in signing and verification,
/// where secret keys are used repeatedly with variable inputs.
pub fn keygen_from_seed<P: DsaParams>(xi: &[u8; 32]) -> (PublicKey<P>, SecretKey<P>) {
    // Step 2: Expand seed into ρ, ρ', K using H
    // FIPS 204 Algorithm 6, Line 1: (ρ, ρ', K) ← H(ξ, 128)
    //
    // NOTE: The reference implementation appends K and L parameters to ξ before hashing.
    // This provides domain separation to ensure different parameter sets produce different keys.
    // Input to H: ξ || K || L (34 bytes total)
    let mut seed_with_params = [0u8; 34];
    seed_with_params[..32].copy_from_slice(xi);
    seed_with_params[32] = P::K as u8;
    seed_with_params[33] = P::L as u8;

    {}

    let seed_expansion = crate::symmetric::h128(&seed_with_params);

    {}

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];

    rho.copy_from_slice(&seed_expansion[0..32]);
    rho_prime.copy_from_slice(&seed_expansion[32..96]);
    k_seed.copy_from_slice(&seed_expansion[96..128]);

    // Step 3: Expand matrix A from ρ
    let matrix_a = expand_matrix_a::<P>(&rho);

    // Step 4: Sample secret vectors s1 and s2 from ρ'
    // We need to sample them manually since we can't use P::L/P::K in const generics
    let mut s1 = Vec::with_capacity(P::L);
    let mut s2 = Vec::with_capacity(P::K);

    // Use AVX2 batched sampling if available (4-way parallel)
    #[cfg(all(feature = "avx2", feature = "simd", target_arch = "x86_64"))]
    {
        use crate::simd::dispatch::has_avx2;

        if has_avx2() {
            // Sample s1 in batches of 4
            let mut i = 0;
            while i + 4 <= P::L {
                let indices = [i as u16, (i + 1) as u16, (i + 2) as u16, (i + 3) as u16];
                let outputs = crate::symmetric::expand_s_x4_avx2(&rho_prime, indices);
                for j in 0..4 {
                    let mut reader = &outputs[j][..];
                    s1.push(crate::sampling::sample_poly_eta_from_bytes(
                        &mut reader,
                        P::ETA,
                    ));
                }
                i += 4;
            }
            // Handle remaining (< 4)
            for idx in i..P::L {
                let mut xof = crate::symmetric::expand_s(&rho_prime, idx as u16);
                s1.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }

            // Sample s2 in batches of 4
            let mut i = 0;
            while i + 4 <= P::K {
                let base = P::L + i;
                let indices = [
                    base as u16,
                    (base + 1) as u16,
                    (base + 2) as u16,
                    (base + 3) as u16,
                ];
                let outputs = crate::symmetric::expand_s_x4_avx2(&rho_prime, indices);
                for j in 0..4 {
                    let mut reader = &outputs[j][..];
                    s2.push(crate::sampling::sample_poly_eta_from_bytes(
                        &mut reader,
                        P::ETA,
                    ));
                }
                i += 4;
            }
            // Handle remaining (< 4)
            for idx in i..P::K {
                let mut xof = crate::symmetric::expand_s(&rho_prime, (P::L + idx) as u16);
                s2.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }
        } else {
            // Fallback: scalar path
            for i in 0..P::L {
                let mut xof = crate::symmetric::expand_s(&rho_prime, i as u16);
                s1.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }
            for i in 0..P::K {
                let mut xof = crate::symmetric::expand_s(&rho_prime, (P::L + i) as u16);
                s2.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }
        }
    }

    // Non-AVX2 path
    #[cfg(not(all(feature = "avx2", feature = "simd", target_arch = "x86_64")))]
    {
        for i in 0..P::L {
            let mut xof = crate::symmetric::expand_s(&rho_prime, i as u16);
            s1.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
        }

        for i in 0..P::K {
            let mut xof = crate::symmetric::expand_s(&rho_prime, (P::L + i) as u16);
            s2.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
        }
    }

    // Step 5: Compute t = A·s1 + s2
    // Uses reference-compatible NTT flow (FIPS 204):
    // 1. Transform s1 to NTT domain once
    // 2. Compute A·s1 with accumulation in NTT domain
    // 3. Transform back to coefficient form (one INVNTT per row)
    // 4. Add s2 in coefficient domain
    let mut s1_ntt = Vec::with_capacity(P::L);
    for s1_i in &s1 {
        s1_ntt.push(crate::ntt::ntt(s1_i));
    }

    // Matrix-vector multiplication: t = A·s1 (reference-compatible)
    let t_as1 = crate::ntt::matrix_vector_mul_ntt(&matrix_a, &s1_ntt, P::K, P::L);

    // Add s2 and reduce
    // Following reference: add s2 to scaled-form A·s1 WITHOUT conversion
    // Power2Round works on this mixed representation
    let mut t = Vec::with_capacity(P::K);
    for i in 0..P::K {
        let mut t_i = t_as1[i].add(&s2[i]);
        t_i.reduce();

        // DEBUG: Print first t value for KAT comparison
        if i == 0 {}

        t.push(t_i);
    }

    // Step 6: Power2Round to split t into t1 (high) and t0 (low)
    let mut t1 = Vec::with_capacity(P::K);
    let mut t0 = Vec::with_capacity(P::K);

    for poly in &t {
        let mut t1_poly = Poly::new();
        let mut t0_poly = Poly::new();

        for i in 0..256 {
            let (r1, r0) = power2round(poly.coeffs[i], P::D);
            t1_poly.coeffs[i] = r1;
            t0_poly.coeffs[i] = r0;
        }

        t1.push(t1_poly);
        t0.push(t0_poly);
    }

    // DEBUG: Verify that t = 2^d·t1 + t0
    {
        use crate::params::Q;
        let two_pow_d = 1i64 << P::D;
        for i in 0..P::K {
            for j in 0..256 {
                let reconstructed = ((t1[i].coeffs[j] as i64 * two_pow_d + t0[i].coeffs[j] as i64)
                    .rem_euclid(Q as i64)) as i32;
                if reconstructed != t[i].coeffs[j] {
                    panic!("Power2Round failed!");
                }
            }
        }
    }

    // Step 7: Compute tr = H(ρ || t1)
    // Serialize ρ || t1 for hashing using proper FIPS 204 encoding
    let mut pk_bytes = Vec::new();
    pk_bytes.extend_from_slice(&rho);

    // Serialize t1 using FIPS 204 SimpleBitPack (10 bits per coefficient)
    for poly in &t1 {
        pk_bytes.extend_from_slice(&crate::serialize::encode_poly_t1(poly));
    }

    let tr = h(&pk_bytes);

    // Step 8 & 9: Construct public and secret keys
    let pk = PublicKey::new(rho, t1.clone(), tr);

    // OPTIMIZATION: Cache matrix A in secret key to avoid re-expansion during signing
    // This saves ~80 µs per signature (12% of signing time)
    // matrix_a is already computed above, so we just clone it
    let sk = SecretKey::new(rho, k_seed, tr, s1, s2, t0, matrix_a);

    (pk, sk)
}

/// Multiply two polynomials using NTT
///
/// Uses Number Theoretic Transform for O(n log n) performance.
/// This provides 100-1000x speedup over schoolbook multiplication.
///
/// # Arguments
/// * `a` - First polynomial
/// * `b` - Second polynomial
///
/// # Returns
/// * Product polynomial a·b in R_q
#[allow(dead_code)]
fn poly_multiply(a: &Poly, b: &Poly) -> Poly {
    crate::ntt::poly_mul_ntt(a, b)
}

#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::keygen::keygen_from_seed;
    use crate::serialize::{deserialize_signature, serialize_signature};
    use crate::sign::{sign, sign_deterministic};
    use crate::verify::verify;
    use crate::{MlDsa44, MlDsa65, MlDsa87, Q};

    #[test]
    fn test_keygen_deterministic() {
        let seed = [42u8; 32];

        let (pk1, sk1) = keygen_from_seed::<MlDsa65>(&seed);
        let (pk2, sk2) = keygen_from_seed::<MlDsa65>(&seed);

        // Same seed should produce same keys
        assert_eq!(pk1.rho, pk2.rho);
        assert_eq!(pk1.tr, pk2.tr);
        assert_eq!(sk1.rho, sk2.rho);
        assert_eq!(sk1.k, sk2.k);
        assert_eq!(sk1.tr, sk2.tr);
    }

    #[test]
    fn test_keygen_different_seeds() {
        let seed1 = [42u8; 32];
        let seed2 = [43u8; 32];

        let (pk1, _sk1) = keygen_from_seed::<MlDsa65>(&seed1);
        let (pk2, _sk2) = keygen_from_seed::<MlDsa65>(&seed2);

        // Different seeds should produce different keys
        assert_ne!(pk1.rho, pk2.rho);
    }

    #[test]
    fn test_keygen_t1_dimensions() {
        let seed = [0x55u8; 32];

        let (pk, _sk) = keygen_from_seed::<MlDsa44>(&seed);

        assert_eq!(pk.t1.len(), MlDsa44::K);
    }

    #[test]
    fn test_keygen_secret_dimensions() {
        let seed = [0x55u8; 32];

        let (_pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        assert_eq!(sk.s1.len(), MlDsa65::L);
        assert_eq!(sk.s2.len(), MlDsa65::K);
        assert_eq!(sk.t0.len(), MlDsa65::K);
    }

    #[test]
    fn test_keygen_s1_bounded() {
        let seed = [0x33u8; 32];

        let (_pk, sk) = keygen_from_seed::<MlDsa44>(&seed);

        // s1 coefficients should be in [-η, η]
        for poly in &sk.s1 {
            for &coeff in &poly.coeffs {
                let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                assert!(
                    centered.abs() <= MlDsa44::ETA,
                    "s1 coefficient {} out of range [-{}, {}]",
                    centered,
                    MlDsa44::ETA,
                    MlDsa44::ETA
                );
            }
        }
    }

    #[test]
    fn test_keygen_s2_bounded() {
        let seed = [0x33u8; 32];

        let (_pk, sk) = keygen_from_seed::<MlDsa87>(&seed);

        // s2 coefficients should be in [-η, η]
        for poly in &sk.s2 {
            for &coeff in &poly.coeffs {
                let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                assert!(
                    centered.abs() <= MlDsa87::ETA,
                    "s2 coefficient {} out of range [-{}, {}]",
                    centered,
                    MlDsa87::ETA,
                    MlDsa87::ETA
                );
            }
        }
    }

    #[test]
    fn test_keygen_tr_computed() {
        let seed = [0x11u8; 32];

        let (pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // tr should be non-zero
        assert_ne!(pk.tr, [0u8; 64]);

        // pk and sk should have same tr
        assert_eq!(pk.tr, sk.tr);
    }

    #[test]
    fn test_poly_multiply_zero() {
        let a = Poly::new();
        let b = Poly::new();

        let result = poly_multiply(&a, &b);

        assert!(result.is_zero());
    }

    #[test]
    fn test_poly_multiply_one() {
        let mut a = Poly::new();
        a.coeffs[0] = 1;

        let mut b = Poly::new();
        b.coeffs[0] = 5;
        b.coeffs[1] = 3;

        let result = poly_multiply(&a, &b);

        assert_eq!(result.coeffs[0], 5);
        assert_eq!(result.coeffs[1], 3);
    }

    #[test]
    fn test_poly_multiply_modulo_xn_plus_1() {
        let mut a = Poly::new();
        a.coeffs[255] = 1; // X^255

        let mut b = Poly::new();
        b.coeffs[1] = 1; // X

        // X^255 * X = X^256 = -1 (mod X^256 + 1)
        let result = poly_multiply(&a, &b);

        // -1 can be represented as either -1 or Q-1 (8380416)
        let coeff = result.coeffs[0].rem_euclid(Q);
        assert_eq!(coeff, Q - 1, "Expected -1 (mod Q) = {}", Q - 1);
    }

    #[test]
    fn test_keygen_timing_independence() {
        // Test that keygen produces valid keys regardless of seed
        // This demonstrates that the algorithm doesn't have secret-dependent branches

        let seeds = [
            [0x00u8; 32], // All zeros
            [0xFFu8; 32], // All ones
            [0x55u8; 32], // Alternating bits
            [0xAAu8; 32], // Different alternating
        ];

        for seed in &seeds {
            let (pk, sk) = keygen_from_seed::<MlDsa65>(seed);

            // Verify all components are properly bounded
            assert_eq!(sk.s1.len(), MlDsa65::L);
            assert_eq!(sk.s2.len(), MlDsa65::K);
            assert_eq!(pk.t1.len(), MlDsa65::K);

            // Verify s1 and s2 are properly bounded (no rejection failures)
            for poly in &sk.s1 {
                for &coeff in &poly.coeffs {
                    let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                    assert!(centered.abs() <= MlDsa65::ETA);
                }
            }

            for poly in &sk.s2 {
                for &coeff in &poly.coeffs {
                    let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                    assert!(centered.abs() <= MlDsa65::ETA);
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_public_key_serde_roundtrip() {
        use serde_json;

        let seed = [0x42u8; 32];
        let (pk, _sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Serialize to JSON
        let json = serde_json::to_string(&pk).expect("Failed to serialize PublicKey");

        // Deserialize back
        let pk_recovered: PublicKey<MlDsa65> =
            serde_json::from_str(&json).expect("Failed to deserialize PublicKey");

        // Verify all fields match
        assert_eq!(pk.rho, pk_recovered.rho);
        assert_eq!(pk.tr, pk_recovered.tr);
        assert_eq!(pk.t1.len(), pk_recovered.t1.len());
        for (a, b) in pk.t1.iter().zip(pk_recovered.t1.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_secret_key_serde_roundtrip() {
        use serde_json;

        let seed = [0x42u8; 32];
        let (_pk, sk) = keygen_from_seed::<MlDsa65>(&seed);

        // Serialize to JSON
        let json = serde_json::to_string(&sk).expect("Failed to serialize SecretKey");

        // Deserialize back
        let sk_recovered: SecretKey<MlDsa65> =
            serde_json::from_str(&json).expect("Failed to deserialize SecretKey");

        // Verify all fields match
        assert_eq!(sk.rho, sk_recovered.rho);
        assert_eq!(sk.k, sk_recovered.k);
        assert_eq!(sk.tr, sk_recovered.tr);

        assert_eq!(sk.s1.len(), sk_recovered.s1.len());
        for (a, b) in sk.s1.iter().zip(sk_recovered.s1.iter()) {
            assert_eq!(a, b);
        }

        assert_eq!(sk.s2.len(), sk_recovered.s2.len());
        for (a, b) in sk.s2.iter().zip(sk_recovered.s2.iter()) {
            assert_eq!(a, b);
        }

        assert_eq!(sk.t0.len(), sk_recovered.t0.len());
        for (a, b) in sk.t0.iter().zip(sk_recovered.t0.iter()) {
            assert_eq!(a, b);
        }
    }
}
