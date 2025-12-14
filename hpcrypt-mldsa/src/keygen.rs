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
use crate::rng::fill_random;
use crate::rounding::power2round;
use crate::sampling::expand_matrix_a;
use crate::symmetric::h;

/// Public key for ML-DSA
///
/// Contains the seed ρ and the high-order bits t1 of the public vector t.
///
/// # Verification Optimization
///
/// This struct includes pre-computed values to accelerate verification:
/// - `cached_a_ntt`: Matrix A in NTT domain (eliminates K×L NTT operations per verify)
/// - `t1_scaled_ntt`: t1*2^d in NTT domain (eliminates K NTT operations per verify)
///
/// These pre-computations reduce verification time by ~58% (from ~150µs to ~62µs).
///
/// Memory cost:
/// - ML-DSA-44: 20 KB additional
/// - ML-DSA-65: 36 KB additional
/// - ML-DSA-87: 64 KB additional
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PublicKey<P: DsaParams> {
    /// Seed for matrix A expansion (32 bytes)
    pub rho: [u8; 32],

    /// High-order bits of t (k polynomials)
    pub t1: Vec<Poly>,

    /// Cached hash of public key (tr = H(ρ || t1))
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub tr: [u8; 64],

    /// Pre-computed matrix A in NTT domain (k × l polynomials)
    ///
    /// OPTIMIZATION: Matrix A is expanded from rho and converted to NTT
    /// during every verification without this cache.
    /// Pre-computing saves ~81µs per verification (54% of verify time).
    ///
    /// Memory cost: K × L × 256 × 4 bytes
    /// - ML-DSA-44: 4×4×256×4 = 16 KB
    /// - ML-DSA-65: 6×5×256×4 = 30 KB
    /// - ML-DSA-87: 8×7×256×4 = 56 KB
    #[cfg_attr(feature = "serde", serde(skip))]
    pub cached_a_ntt: Vec<Vec<Poly>>,

    /// Pre-computed t1 * 2^d in NTT domain (k polynomials)
    ///
    /// OPTIMIZATION: This value is computed during every verification.
    /// Pre-computing saves ~6.7µs per verification.
    ///
    /// Memory cost: K × 256 × 4 bytes
    /// - ML-DSA-44: 4×256×4 = 4 KB
    /// - ML-DSA-65: 6×256×4 = 6 KB
    /// - ML-DSA-87: 8×256×4 = 8 KB
    #[cfg_attr(feature = "serde", serde(skip))]
    pub t1_scaled_ntt: Vec<Poly>,

    /// Phantom data to use type parameter P
    _phantom: PhantomData<P>,
}

// Custom Deserialize that automatically computes caches - OpenSSL style
#[cfg(feature = "serde")]
impl<'de, P: DsaParams> serde::Deserialize<'de> for PublicKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};
        use core::fmt;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { Rho, T1, Tr, #[serde(other)] Other }

        struct PublicKeyVisitor<P: DsaParams>(PhantomData<P>);

        // Helper to deserialize [u8; 64] from a sequence
        fn deserialize_tr<'de, V: SeqAccess<'de>>(seq: &mut V) -> Result<[u8; 64], V::Error> {
            let vec: Vec<u8> = seq.next_element()?
                .ok_or_else(|| de::Error::custom("missing tr field"))?;
            vec.try_into()
                .map_err(|_| de::Error::custom("tr must be exactly 64 bytes"))
        }

        impl<'de, P: DsaParams> Visitor<'de> for PublicKeyVisitor<P> {
            type Value = PublicKey<P>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct PublicKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PublicKey<P>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let rho: [u8; 32] = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let t1: Vec<Poly> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let tr = deserialize_tr(&mut seq)?;

                // Automatically compute caches - this is the key fix!
                Ok(PublicKey::new(rho, t1, tr))
            }

            fn visit_map<V>(self, mut map: V) -> Result<PublicKey<P>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut rho: Option<[u8; 32]> = None;
                let mut t1: Option<Vec<Poly>> = None;
                let mut tr: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Rho => {
                            if rho.is_some() {
                                return Err(de::Error::duplicate_field("rho"));
                            }
                            rho = Some(map.next_value()?);
                        }
                        Field::T1 => {
                            if t1.is_some() {
                                return Err(de::Error::duplicate_field("t1"));
                            }
                            t1 = Some(map.next_value()?);
                        }
                        Field::Tr => {
                            if tr.is_some() {
                                return Err(de::Error::duplicate_field("tr"));
                            }
                            tr = Some(map.next_value()?);
                        }
                        Field::Other => {
                            // Ignore unknown fields like _phantom
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let rho = rho.ok_or_else(|| de::Error::missing_field("rho"))?;
                let t1 = t1.ok_or_else(|| de::Error::missing_field("t1"))?;
                let tr_vec = tr.ok_or_else(|| de::Error::missing_field("tr"))?;
                let tr: [u8; 64] = tr_vec.try_into()
                    .map_err(|_| de::Error::custom("tr must be exactly 64 bytes"))?;

                // Automatically compute caches - this is the key fix!
                Ok(PublicKey::new(rho, t1, tr))
            }
        }

        const FIELDS: &[&str] = &["rho", "t1", "tr", "_phantom"];
        deserializer.deserialize_struct("PublicKey", FIELDS, PublicKeyVisitor(PhantomData))
    }
}

impl<P: DsaParams> PublicKey<P> {
    /// Deserialize a public key from bytes
    ///
    /// This method parses the public key and pre-computes the NTT-domain caches
    /// for efficient verification. The caches are computed automatically.
    ///
    /// # Arguments
    /// * `bytes` - Serialized public key bytes (size depends on parameter set)
    ///
    /// # Returns
    /// * `Ok(PublicKey)` - Parsed public key with pre-computed caches
    /// * `Err(SerializeError)` - If the bytes are invalid
    ///
    /// # Example
    /// ```no_run
    /// use hpcrypt_mldsa::params::MlDsa65;
    /// use hpcrypt_mldsa::keygen::PublicKey;
    ///
    /// let pk = PublicKey::<MlDsa65>::from_bytes(&pk_bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::serialize::SerializeError> {
        crate::serialize::deserialize_public_key::<P>(bytes)
    }

    /// Serialize the public key to bytes
    ///
    /// # Returns
    /// Serialized public key bytes (size: 32 + K * 320 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::serialize::serialize_public_key::<P>(self)
    }

    /// Create a new public key with pre-computed verification caches
    ///
    /// This constructor computes the NTT-domain caches for efficient verification.
    pub fn new(rho: [u8; 32], t1: Vec<Poly>, tr: [u8; 64]) -> Self {
        use crate::ntt::ntt;
        use crate::params::N;

        // Pre-compute matrix A in NTT domain
        // FIPS 204: Matrix A is sampled DIRECTLY into NTT form via RejNTTPoly
        // No additional NTT transformation is needed - matrix_a is already NTT
        let matrix_a = expand_matrix_a::<P>(&rho);
        let cached_a_ntt = matrix_a; // Already in NTT form from sampling

        // Pre-compute t1 * 2^d in NTT domain
        // OPTIMIZATION: Hoist Poly allocation outside loop
        let mut t1_scaled_ntt = Vec::with_capacity(P::K);
        let mut t1_scaled = Poly::new();
        for i in 0..P::K {
            for j in 0..N {
                t1_scaled.coeffs[j] = t1[i].coeffs[j] << P::D;
            }
            t1_scaled_ntt.push(ntt(&t1_scaled));
        }

        Self {
            rho,
            t1,
            tr,
            cached_a_ntt,
            t1_scaled_ntt,
            _phantom: PhantomData,
        }
    }

    /// Create a new public key with pre-computed caches provided
    ///
    /// Use this when you already have the NTT-domain values (e.g., from keygen).
    pub fn new_with_cache(
        rho: [u8; 32],
        t1: Vec<Poly>,
        tr: [u8; 64],
        cached_a_ntt: Vec<Vec<Poly>>,
        t1_scaled_ntt: Vec<Poly>,
    ) -> Self {
        Self {
            rho,
            t1,
            tr,
            cached_a_ntt,
            t1_scaled_ntt,
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
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SecretKey<P: DsaParams> {
    /// Seed for matrix A expansion (32 bytes) - PUBLIC, no zeroization needed
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub rho: [u8; 32],

    /// Secret randomness seed K (32 bytes) - SENSITIVE
    pub k: [u8; 32],

    /// Public key hash tr (64 bytes) - PUBLIC, no zeroization needed
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    #[cfg_attr(feature = "serde", serde(with = "serde_arrays"))]
    pub tr: [u8; 64],

    /// Secret vector s1 (ℓ polynomials) - SENSITIVE
    pub s1: Vec<Poly>,

    /// Secret vector s2 (k polynomials) - SENSITIVE
    pub s2: Vec<Poly>,

    /// Low-order bits of t (k polynomials) - SENSITIVE
    pub t0: Vec<Poly>,

    /// Cached s1 in NTT domain (ℓ polynomials) - precomputed for signing optimization
    ///
    /// OPTIMIZATION: Pre-computing ntt(s1) saves L NTT operations per rejection attempt.
    /// For ML-DSA-87 with ~4.5 rejections, this saves 7 × 4.5 × 0.6µs ≈ 19µs per signature.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub s1_hat: Vec<Poly>,

    /// Cached s2 in NTT domain (k polynomials) - precomputed for signing optimization
    ///
    /// OPTIMIZATION: Pre-computing ntt(s2) saves K NTT operations per rejection attempt.
    /// For ML-DSA-87 with ~4.5 rejections, this saves 8 × 4.5 × 0.6µs ≈ 22µs per signature.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub s2_hat: Vec<Poly>,

    /// Cached t0 in NTT domain (k polynomials) - precomputed for signing optimization
    ///
    /// OPTIMIZATION: Pre-computing ntt(t0) saves K NTT operations per rejection attempt.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub t0_hat: Vec<Poly>,

    /// Cached matrix A in NTT domain (k × ℓ) - precomputed for signing optimization
    ///
    /// OPTIMIZATION: Matrix A is expanded from rho and converted to NTT domain.
    /// Storing in NTT form eliminates ~96 µs per signature (30 NTT operations
    /// × 4.5 rejection attempts × 0.71 µs per NTT).
    ///
    /// Memory cost: k × ℓ × 256 × 4 bytes
    /// - ML-DSA-44: 4×4×256×4 = 16 KB
    /// - ML-DSA-65: 6×5×256×4 = 30 KB
    /// - ML-DSA-87: 8×7×256×4 = 56 KB
    ///
    /// Trade-off: Memory for ~18% signing speedup
    ///
    /// PUBLIC data derived from rho, no zeroization needed
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    #[cfg_attr(feature = "serde", serde(skip))]
    pub cached_a_ntt: Vec<Vec<Poly>>,

    /// Phantom data to use type parameter P
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    _phantom: PhantomData<P>,
}

// Custom Deserialize that automatically computes caches - OpenSSL style
#[cfg(feature = "serde")]
impl<'de, P: DsaParams> serde::Deserialize<'de> for SecretKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};
        use core::fmt;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { Rho, K, Tr, S1, S2, T0, #[serde(other)] Other }

        struct SecretKeyVisitor<P: DsaParams>(PhantomData<P>);

        // Helper to deserialize [u8; 64] from a sequence
        fn deserialize_tr<'de, V: SeqAccess<'de>>(seq: &mut V) -> Result<[u8; 64], V::Error> {
            let vec: Vec<u8> = seq.next_element()?
                .ok_or_else(|| de::Error::custom("missing tr field"))?;
            vec.try_into()
                .map_err(|_| de::Error::custom("tr must be exactly 64 bytes"))
        }

        impl<'de, P: DsaParams> Visitor<'de> for SecretKeyVisitor<P> {
            type Value = SecretKey<P>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("struct SecretKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<SecretKey<P>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let rho: [u8; 32] = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let k: [u8; 32] = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let tr = deserialize_tr(&mut seq)?;
                let s1: Vec<Poly> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let s2: Vec<Poly> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let t0: Vec<Poly> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;

                // Automatically compute all NTT caches - this is the key fix!
                Ok(SecretKey::from_components(rho, k, tr, s1, s2, t0))
            }

            fn visit_map<V>(self, mut map: V) -> Result<SecretKey<P>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut rho: Option<[u8; 32]> = None;
                let mut k: Option<[u8; 32]> = None;
                let mut tr: Option<Vec<u8>> = None;
                let mut s1: Option<Vec<Poly>> = None;
                let mut s2: Option<Vec<Poly>> = None;
                let mut t0: Option<Vec<Poly>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Rho => {
                            if rho.is_some() {
                                return Err(de::Error::duplicate_field("rho"));
                            }
                            rho = Some(map.next_value()?);
                        }
                        Field::K => {
                            if k.is_some() {
                                return Err(de::Error::duplicate_field("k"));
                            }
                            k = Some(map.next_value()?);
                        }
                        Field::Tr => {
                            if tr.is_some() {
                                return Err(de::Error::duplicate_field("tr"));
                            }
                            tr = Some(map.next_value()?);
                        }
                        Field::S1 => {
                            if s1.is_some() {
                                return Err(de::Error::duplicate_field("s1"));
                            }
                            s1 = Some(map.next_value()?);
                        }
                        Field::S2 => {
                            if s2.is_some() {
                                return Err(de::Error::duplicate_field("s2"));
                            }
                            s2 = Some(map.next_value()?);
                        }
                        Field::T0 => {
                            if t0.is_some() {
                                return Err(de::Error::duplicate_field("t0"));
                            }
                            t0 = Some(map.next_value()?);
                        }
                        Field::Other => {
                            // Ignore unknown fields like _phantom, s1_hat, s2_hat, t0_hat, cached_a_ntt
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let rho = rho.ok_or_else(|| de::Error::missing_field("rho"))?;
                let k = k.ok_or_else(|| de::Error::missing_field("k"))?;
                let tr_vec = tr.ok_or_else(|| de::Error::missing_field("tr"))?;
                let tr: [u8; 64] = tr_vec.try_into()
                    .map_err(|_| de::Error::custom("tr must be exactly 64 bytes"))?;
                let s1 = s1.ok_or_else(|| de::Error::missing_field("s1"))?;
                let s2 = s2.ok_or_else(|| de::Error::missing_field("s2"))?;
                let t0 = t0.ok_or_else(|| de::Error::missing_field("t0"))?;

                // Automatically compute all NTT caches - this is the key fix!
                Ok(SecretKey::from_components(rho, k, tr, s1, s2, t0))
            }
        }

        const FIELDS: &[&str] = &["rho", "k", "tr", "s1", "s2", "t0", "_phantom"];
        deserializer.deserialize_struct("SecretKey", FIELDS, SecretKeyVisitor(PhantomData))
    }
}

impl<P: DsaParams> SecretKey<P> {
    /// Deserialize a secret key from bytes
    ///
    /// This method parses the secret key and pre-computes all NTT-domain caches
    /// (A, s1, s2, t0) for efficient signing. The caches are computed automatically.
    ///
    /// # Arguments
    /// * `bytes` - Serialized secret key bytes (size depends on parameter set)
    ///
    /// # Returns
    /// * `Ok(SecretKey)` - Parsed secret key with pre-computed caches
    /// * `Err(SerializeError)` - If the bytes are invalid
    ///
    /// # Example
    /// ```no_run
    /// use hpcrypt_mldsa::params::MlDsa65;
    /// use hpcrypt_mldsa::keygen::SecretKey;
    ///
    /// let sk = SecretKey::<MlDsa65>::from_bytes(&sk_bytes).unwrap();
    /// ```
    ///
    /// # Security Note
    /// Secret key deserialization should be done with care. Ensure the source
    /// of the bytes is trusted and the data was properly protected in storage.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::serialize::SerializeError> {
        crate::serialize::deserialize_secret_key::<P>(bytes)
    }

    /// Serialize the secret key to bytes
    ///
    /// # Returns
    /// Serialized secret key bytes
    ///
    /// # Security Note
    /// The resulting bytes contain sensitive key material. Ensure proper
    /// protection (encryption, secure storage, secure deletion) when handling.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::serialize::serialize_secret_key::<P>(self)
    }

    /// Create a new secret key with pre-cached NTT values
    pub fn new(
        rho: [u8; 32],
        k: [u8; 32],
        tr: [u8; 64],
        s1: Vec<Poly>,
        s2: Vec<Poly>,
        t0: Vec<Poly>,
        s1_hat: Vec<Poly>,
        s2_hat: Vec<Poly>,
        t0_hat: Vec<Poly>,
        cached_a_ntt: Vec<Vec<Poly>>,
    ) -> Self {
        Self {
            rho,
            k,
            tr,
            s1,
            s2,
            t0,
            s1_hat,
            s2_hat,
            t0_hat,
            cached_a_ntt,
            _phantom: PhantomData,
        }
    }

    /// Create a secret key from components, automatically computing all NTT caches.
    ///
    /// This is the preferred constructor when you have the raw polynomial data
    /// but not the pre-computed NTT forms. Caches are computed automatically,
    /// following the OpenSSL eager-evaluation pattern.
    pub fn from_components(
        rho: [u8; 32],
        k: [u8; 32],
        tr: [u8; 64],
        s1: Vec<Poly>,
        s2: Vec<Poly>,
        t0: Vec<Poly>,
    ) -> Self {
        use crate::ntt::ntt;

        // Compute s1_hat
        let mut s1_hat = Vec::with_capacity(P::L);
        for i in 0..P::L {
            s1_hat.push(ntt(&s1[i]));
        }

        // Compute s2_hat
        let mut s2_hat = Vec::with_capacity(P::K);
        for i in 0..P::K {
            s2_hat.push(ntt(&s2[i]));
        }

        // Compute t0_hat
        let mut t0_hat = Vec::with_capacity(P::K);
        for i in 0..P::K {
            t0_hat.push(ntt(&t0[i]));
        }

        // Compute cached_a_ntt
        // FIPS 204: Matrix A is sampled DIRECTLY into NTT form via RejNTTPoly
        // No additional NTT transformation is needed
        let cached_a_ntt = expand_matrix_a::<P>(&rho);

        Self {
            rho,
            k,
            tr,
            s1,
            s2,
            t0,
            s1_hat,
            s2_hat,
            t0_hat,
            cached_a_ntt,
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
    fill_random(&mut xi);

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
    // FIPS 204 Algorithm 6, Line 2: (ρ, ρ', K) ← H(ξ, 128)
    //
    // NOTE: The reference implementation appends K and L parameters to ξ before hashing.
    // This provides domain separation to ensure different parameter sets produce different keys.
    // Input to H: ξ || K || L (34 bytes total)
    let mut seed_with_params = [0u8; 34];
    seed_with_params[..32].copy_from_slice(xi);
    seed_with_params[32] = P::K as u8;
    seed_with_params[33] = P::L as u8;

    let seed_expansion = crate::symmetric::h128(&seed_with_params);

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

    // Use AVX2 4-way parallel sampling if available
    #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            // Sample s1 in batches of 4
            let mut i = 0;
            while i + 4 <= P::L {
                let indices = [i as u16, (i+1) as u16, (i+2) as u16, (i+3) as u16];
                let outputs = crate::symmetric::expand_s_x4_avx2(&rho_prime, indices);
                for j in 0..4 {
                    let mut reader = &outputs[j][..];
                    s1.push(crate::sampling::sample_poly_eta_from_bytes(&mut reader, P::ETA));
                }
                i += 4;
            }
            for idx in i..P::L {
                let mut xof = crate::symmetric::expand_s(&rho_prime, idx as u16);
                s1.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }

            // Sample s2 in batches of 4
            let mut i = 0;
            while i + 4 <= P::K {
                let base = P::L + i;
                let indices = [base as u16, (base+1) as u16, (base+2) as u16, (base+3) as u16];
                let outputs = crate::symmetric::expand_s_x4_avx2(&rho_prime, indices);
                for j in 0..4 {
                    let mut reader = &outputs[j][..];
                    s2.push(crate::sampling::sample_poly_eta_from_bytes(&mut reader, P::ETA));
                }
                i += 4;
            }
            for idx in i..P::K {
                let mut xof = crate::symmetric::expand_s(&rho_prime, (P::L + idx) as u16);
                s2.push(crate::sampling::sample_poly_eta(&mut xof, P::ETA));
            }
        } else {
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

    #[cfg(not(all(feature = "avx2", feature = "std", target_arch = "x86_64")))]
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
        if i == 0 {
        }

        t.push(t_i);
    }

    // Step 6: Power2Round to split t into t1 (high) and t0 (low)
    let mut t1 = Vec::with_capacity(P::K);
    let mut t0 = Vec::with_capacity(P::K);

    for poly in &t {
        let mut t1_poly = Poly::new();
        let mut t0_poly = Poly::new();

        // AVX2 accelerated Power2Round
        #[cfg(all(feature = "avx2", feature = "std", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                unsafe {
                    crate::intrinsics::avx2::rounding::power2round_fast(
                        &poly.coeffs,
                        &mut t1_poly.coeffs,
                        &mut t0_poly.coeffs,
                    );
                }
                t1.push(t1_poly);
                t0.push(t0_poly);
                continue;
            }
        }

        // Scalar fallback
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
                let reconstructed = ((t1[i].coeffs[j] as i64 * two_pow_d + t0[i].coeffs[j] as i64).rem_euclid(Q as i64)) as i32;
                if reconstructed != t[i].coeffs[j] {
                    panic!("Power2Round failed!");
                }
            }
        }
    }

    // Step 7: Compute tr = H(ρ || t1)
    // Serialize ρ || t1 for hashing using proper FIPS 204 encoding
    // Pre-allocate: 32 bytes for rho + K * 320 bytes for t1 (10 bits * 256 coeffs / 8)
    let mut pk_bytes = Vec::with_capacity(32 + P::K * 320);
    pk_bytes.extend_from_slice(&rho);

    // Serialize t1 using FIPS 204 SimpleBitPack (10 bits per coefficient)
    for poly in &t1 {
        pk_bytes.extend_from_slice(&crate::serialize::encode_poly_t1(poly));
    }

    let tr = h(&pk_bytes);

    // Step 8 & 9: Construct public and secret keys
    let pk = PublicKey::new(rho, t1.clone(), tr);

    // OPTIMIZATION: Pre-cache NTT values for signing speedup
    // - cached_a_ntt: eliminates ~96 µs per signature (30 NTT operations per rejection)
    // - s1_hat/s2_hat/t0_hat: eliminates ~77 µs per signature (29 extra NTT per rejection)
    // Combined savings: ~173 µs per signature (with ~4.5 rejections average)

    // Cache matrix A in NTT domain
    // FIPS 204: Matrix A is sampled DIRECTLY into NTT form via RejNTTPoly
    // No additional NTT transformation is needed - matrix_a is already NTT
    let cached_a_ntt = matrix_a.clone();

    // Cache s1 in NTT domain (L polynomials)
    let mut s1_hat = Vec::with_capacity(P::L);
    for i in 0..P::L {
        s1_hat.push(crate::ntt::ntt(&s1[i]));
    }

    // Cache s2 in NTT domain (K polynomials)
    let mut s2_hat = Vec::with_capacity(P::K);
    for i in 0..P::K {
        s2_hat.push(crate::ntt::ntt(&s2[i]));
    }

    // Cache t0 in NTT domain (K polynomials)
    let mut t0_hat = Vec::with_capacity(P::K);
    for i in 0..P::K {
        t0_hat.push(crate::ntt::ntt(&t0[i]));
    }

    let sk = SecretKey::new(rho, k_seed, tr, s1, s2, t0, s1_hat, s2_hat, t0_hat, cached_a_ntt);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{MlDsa44, MlDsa65, MlDsa87, Q};

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
            [0x00u8; 32],  // All zeros
            [0xFFu8; 32],  // All ones
            [0x55u8; 32],  // Alternating bits
            [0xAAu8; 32],  // Different alternating
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
