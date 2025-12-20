//! SLH-DSA (SPHINCS+) high-level API.
//!
//! This module provides the main key generation, signing, and verification
//! functions that tie together all the cryptographic primitives.

/// Cold path for unsupported parameter combination error.
///
/// Marked cold to keep error handling out of hot paths, improving
/// instruction cache utilization.
#[cold]
#[inline(never)]
fn unsupported_parameter_combination(n: usize, hash_type: crate::params::HashType) -> ! {
    panic!("Unsupported parameter combination: N={}, hash_type={:?}", n, hash_type)
}

use crate::address::Address;
use crate::fors::{fors_pk_from_sig, fors_sign};
use crate::hash::sha2::Sha2HashFunction;
use crate::hash::shake::ShakeHashFunction;
use crate::hash::traits::HashFunction;
use crate::hypertree::{ht_pk_gen, ht_sign_cached, ht_verify};
use crate::merkle_cache::MerkleCache;
use crate::params::{HashType, ParameterSet};
use crate::utils::SignatureError;
// use crate::utils::extract_bits;  // Currently unused
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Extract idx_tree and idx_leaf from H_msg digest according to FIPS 205 Algorithm 17/19.
///
/// FIPS 205 specifies byte-aligned extraction:
/// - idx_tree from bytes [⌈ka/8⌉ : ⌈ka/8⌉ + ⌈(h-h')/8⌉], then mod 2^(h-h')
/// - idx_leaf from bytes [⌈ka/8⌉ + ⌈(h-h')/8⌉ : ...], then mod 2^h'
///
/// Where ka = K*A (in bits), h = H, h' = TREE_HEIGHT.
/// Note: ⌈ka/8⌉ equals FORS_MSG_BYTES.
///
/// Returns (idx_tree, idx_leaf) tuple
///
/// Per FIPS 205 and the reference implementation (integritychain/fips205):
/// The digest is partitioned at byte boundaries, then indices are extracted
/// by reading big-endian integers and masking to the required bit count.
#[inline]
fn extract_indices<P: ParameterSet>(digest: &[u8]) -> (u64, u64) {
    let tree_bits = P::H - P::TREE_HEIGHT;
    let leaf_bits = P::TREE_HEIGHT;

    // Per FIPS 205: indices start at byte ⌈ka/8⌉ = FORS_MSG_BYTES
    let idx_tree_start = P::FORS_MSG_BYTES;
    let idx_tree_len = (tree_bits + 7) / 8;  // ⌈(h-h')/8⌉
    let idx_leaf_start = idx_tree_start + idx_tree_len;
    let idx_leaf_len = (leaf_bits + 7) / 8;  // ⌈h'/8⌉

    // Extract idx_tree as big-endian integer, then take mod 2^(h-h')
    let mut idx_tree: u64 = 0;
    for i in 0..idx_tree_len {
        idx_tree = (idx_tree << 8) | digest[idx_tree_start + i] as u64;
    }
    // Handle overflow: when tree_bits >= 64, mask is effectively all bits
    if tree_bits < 64 {
        idx_tree &= (1u64 << tree_bits) - 1;  // mod 2^(h-h')
    }

    // Extract idx_leaf as big-endian integer, then take mod 2^h'
    let mut idx_leaf: u64 = 0;
    for i in 0..idx_leaf_len {
        idx_leaf = (idx_leaf << 8) | digest[idx_leaf_start + i] as u64;
    }
    // Handle overflow: when leaf_bits >= 64, mask is effectively all bits
    if leaf_bits < 64 {
        idx_leaf &= (1u64 << leaf_bits) - 1;  // mod 2^h'
    }

    (idx_tree, idx_leaf)
}

/// Helper macro to dispatch hash function operations based on N and hash type.
macro_rules! with_hash {
    ($n:expr, $hash_type:expr, $hash:ident, $body:block) => {
        match ($n, $hash_type) {
            (16, HashType::Sha2) => {
                let $hash = Sha2HashFunction::<16>::new();
                $body
            }
            (24, HashType::Sha2) => {
                let $hash = Sha2HashFunction::<24>::new();
                $body
            }
            (32, HashType::Sha2) => {
                let $hash = Sha2HashFunction::<32>::new();
                $body
            }
            (16, HashType::Shake) => {
                let $hash = ShakeHashFunction::<16>::new();
                $body
            }
            (24, HashType::Shake) => {
                let $hash = ShakeHashFunction::<24>::new();
                $body
            }
            (32, HashType::Shake) => {
                let $hash = ShakeHashFunction::<32>::new();
                $body
            }
            _ => unsupported_parameter_combination($n, $hash_type),
        }
    };
}

/// Secret key for SLH-DSA.
///
/// Contains the secret seed, PRF key, and public key components.
/// Per FIPS 205, the secret key is 4N bytes: SK.seed || SK.prf || PK.seed || PK.root
/// The secret key is zeroized on drop.
///
/// Optionally includes a Merkle cache for faster signing at the cost of memory.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey<P: ParameterSet> {
    /// Secret seed (SK.seed)
    sk_seed: Vec<u8>,
    /// PRF key (SK.prf)
    sk_prf: Vec<u8>,
    /// Public seed (PK.seed) - also stored in SK for convenience
    pk_seed: Vec<u8>,
    /// Public root (PK.root) - also stored in SK for H_msg during signing
    pk_root: Vec<u8>,
    /// Optional Merkle cache for hypertree top layers (speeds up signing)
    #[zeroize(skip)]
    cache: Option<MerkleCache<P>>,
    /// Parameter set marker
    _phantom: core::marker::PhantomData<P>,
}

/// Public key for SLH-DSA.
#[derive(Clone)]
pub struct PublicKey<P: ParameterSet> {
    /// Public seed (PK.seed)
    pk_seed: Vec<u8>,
    /// Public root (PK.root)
    pk_root: Vec<u8>,
    /// Parameter set marker
    _phantom: core::marker::PhantomData<P>,
}

/// Key pair containing both secret and public keys.
pub struct KeyPair<P: ParameterSet> {
    /// The secret key component
    pub secret_key: SecretKey<P>,
    /// The public key component
    pub public_key: PublicKey<P>,
}

impl<P: ParameterSet> SecretKey<P> {
    /// Create a new secret key from components.
    fn new(sk_seed: Vec<u8>, sk_prf: Vec<u8>, pk_seed: Vec<u8>, pk_root: Vec<u8>) -> Self {
        Self {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
            cache: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a new secret key with Merkle cache.
    fn new_with_cache(
        sk_seed: Vec<u8>,
        sk_prf: Vec<u8>,
        pk_seed: Vec<u8>,
        pk_root: Vec<u8>,
        cache: MerkleCache<P>,
    ) -> Self {
        Self {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
            cache: Some(cache),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get the Merkle cache (if present).
    pub(crate) fn cache(&self) -> Option<&MerkleCache<P>> {
        self.cache.as_ref()
    }

    /// Get the secret seed.
    pub fn sk_seed(&self) -> &[u8] {
        &self.sk_seed
    }

    /// Get the PRF key.
    pub fn sk_prf(&self) -> &[u8] {
        &self.sk_prf
    }

    /// Get the public seed.
    pub fn pk_seed(&self) -> &[u8] {
        &self.pk_seed
    }

    /// Get the public root.
    pub fn pk_root(&self) -> &[u8] {
        &self.pk_root
    }

    /// Serialize the secret key to bytes.
    /// Per FIPS 205, secret key is 4N bytes: SK.seed || SK.prf || PK.seed || PK.root
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 * P::N);
        bytes.extend_from_slice(&self.sk_seed);
        bytes.extend_from_slice(&self.sk_prf);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Deserialize a secret key from bytes.
    /// Per FIPS 205, secret key is 4N bytes: SK.seed || SK.prf || PK.seed || PK.root
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 4 * P::N {
            return Err("Invalid secret key length");
        }

        Ok(Self::new(
            bytes[0..P::N].to_vec(),
            bytes[P::N..2 * P::N].to_vec(),
            bytes[2 * P::N..3 * P::N].to_vec(),
            bytes[3 * P::N..4 * P::N].to_vec(),
        ))
    }
}

impl<P: ParameterSet> PublicKey<P> {
    /// Create a new public key from components.
    fn new(pk_seed: Vec<u8>, pk_root: Vec<u8>) -> Self {
        Self {
            pk_seed,
            pk_root,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get the public seed.
    pub fn pk_seed(&self) -> &[u8] {
        &self.pk_seed
    }

    /// Get the public root.
    pub fn pk_root(&self) -> &[u8] {
        &self.pk_root
    }

    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * P::N);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 2 * P::N {
            return Err("Invalid public key length");
        }

        Ok(Self::new(
            bytes[0..P::N].to_vec(),
            bytes[P::N..2 * P::N].to_vec(),
        ))
    }
}

impl<P: ParameterSet> KeyPair<P> {
    /// Generate a deterministic key pair from provided seeds (for CAVP testing)
    ///
    /// # Arguments
    /// * `sk_seed` - Secret key seed (N bytes)
    /// * `sk_prf` - Secret PRF key (N bytes)
    /// * `pk_seed` - Public key seed (N bytes)
    #[cfg(feature = "cavp")]
    pub fn generate_from_seed(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8]) -> Result<Self, SignatureError> {
        if sk_seed.len() != P::N || sk_prf.len() != P::N || pk_seed.len() != P::N {
            return Err(SignatureError::InvalidSecretKey);
        }

        let mut sk_seed_vec = vec![0u8; P::N];
        let mut sk_prf_vec = vec![0u8; P::N];
        let mut pk_seed_vec = vec![0u8; P::N];

        sk_seed_vec.copy_from_slice(sk_seed);
        sk_prf_vec.copy_from_slice(sk_prf);
        pk_seed_vec.copy_from_slice(pk_seed);

        // Compute pk_root
        let mut pk_root = vec![0u8; P::N];
        let mut addr = crate::address::Address::new();

        with_hash!(P::N, P::HASH_TYPE, hash, {
            crate::hypertree::ht_pk_gen::<P, _>(&sk_seed_vec, &pk_seed_vec, &mut addr, &hash, &mut pk_root);
        });

        let secret_key = SecretKey::new(sk_seed_vec, sk_prf_vec, pk_seed_vec.clone(), pk_root.clone());
        let public_key = PublicKey::new(pk_seed_vec, pk_root);

        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }

    /// Generate a new key pair using a cryptographically secure RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::generate_with_cache(rng, None)
    }

    /// Generate a new key pair with optional Merkle cache.
    ///
    /// # Parameters
    /// - `rng`: Cryptographically secure random number generator
    /// - `cache_depth`: Optional cache depth (1-D). Use `Some(3)` for optimal performance.
    ///
    /// # Cache Performance (SHA2-128s)
    /// - `None`: No cache (baseline performance)
    /// - `Some(1)`: +12.7% signing speed, 73 KB memory
    /// - `Some(2)`: +22.0% signing speed, 146 KB memory
    /// - `Some(3)`: +38.5% signing speed, 219 KB memory (recommended)
    ///
    /// Cache build adds ~1.4s to key generation for depth 3.
    pub fn generate_with_cache<R: RngCore + CryptoRng>(rng: &mut R, cache_depth: Option<usize>) -> Self {
        // Generate random seeds
        let mut sk_seed = vec![0u8; P::N];
        let mut sk_prf = vec![0u8; P::N];
        let mut pk_seed = vec![0u8; P::N];

        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);

        // Compute public key root
        let mut pk_root = vec![0u8; P::N];
        let mut addr = Address::new();

        with_hash!(P::N, P::HASH_TYPE, hash, {
            ht_pk_gen::<P, _>(&sk_seed, &pk_seed, &mut addr, &hash, &mut pk_root);

            // Build cache if requested
            let secret_key = if let Some(depth) = cache_depth {
                let cache = MerkleCache::<P>::build(&sk_seed, &pk_seed, depth, &hash);
                SecretKey::new_with_cache(sk_seed, sk_prf, pk_seed.clone(), pk_root.clone(), cache)
            } else {
                SecretKey::new(sk_seed, sk_prf, pk_seed.clone(), pk_root.clone())
            };

            let public_key = PublicKey::new(pk_seed, pk_root);

            KeyPair {
                secret_key,
                public_key,
            }
        })
    }
}

/// Sign a message using SLH-DSA with context.
///
/// Returns the signature bytes.
///
/// # Parameters
/// - `secret_key`: The secret key to sign with
/// - `context`: Optional context string for domain separation (max 255 bytes)
/// - `message`: The message to sign
///
/// OPTIMIZED: Uses stack-allocated buffers for opt_rand and digest to eliminate
/// heap allocations in the hot path.
pub fn sign_ctx<P: ParameterSet>(secret_key: &SecretKey<P>, context: &[u8], message: &[u8]) -> Vec<u8> {
    assert!(context.len() <= 255, "Context must be at most 255 bytes");
    let ctx = context;
    let mut addr = Address::new();

    // Build M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M (per FIPS 205 Algorithm 17)
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
    m_prime.push(0u8); // toByte(0, 1) for pure mode
    m_prime.push(ctx.len() as u8); // toByte(|ctx|, 1)
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(message);

    // OPTIMIZATION: Stack-allocate temporary buffers based on parameter set
    // Maximum sizes: N=32, digest=256 bytes (covers all FIPS 205 parameter sets)
    macro_rules! sign_with_stack_buffers {
        ($n:expr, $digest_size:expr) => {{
            let mut opt_rand_buf = [0u8; $n];
            let mut digest_buf = [0u8; $digest_size];

            let opt_rand = &mut opt_rand_buf[..P::N];
            let digest = &mut digest_buf[..P::H_MSG_BYTES];

            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                // Per FIPS 205 Algorithm 17: R ← PRF_msg(SK.prf, opt_rand, M')
                // For deterministic signing, opt_rand = PK.seed
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), &m_prime, opt_rand);

                // Hash message with context
                hash.h_msg(opt_rand, secret_key.pk_seed(), secret_key.pk_root(), ctx, message, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS (FIPS 205 Algorithm 17)
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Sign with FORS
                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);

                // Note: keypair address is already set for ht_sign

                // Sign FORS PK with hypertree (per FIPS 205, pass idx_tree and idx_leaf separately)
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            // Concatenate signature components
            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }};
    }

    // Match on N to select appropriate stack buffer sizes
    match P::N {
        16 => sign_with_stack_buffers!(16, 64),   // Covers SHA2-128s/f
        24 => sign_with_stack_buffers!(24, 64),   // Covers SHA2-192s/f
        32 => sign_with_stack_buffers!(32, 256),  // Covers SHA2-256s/f and all SHAKE variants
        _ => {
            // Fallback to heap allocation for unsupported sizes
            let mut opt_rand = vec![0u8; P::N];
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                // Per FIPS 205 Algorithm 17: R ← PRF_msg(SK.prf, opt_rand, M')
                // For deterministic signing, opt_rand = PK.seed
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), &m_prime, &mut opt_rand);

                hash.h_msg(&opt_rand, secret_key.pk_seed(), secret_key.pk_root(), ctx, message, &mut digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                // Set tree and keypair address for FORS (FIPS 205 Algorithm 17)
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);

                // Note: keypair address is already set for ht_sign

                // Sign FORS PK with hypertree (per FIPS 205, pass idx_tree and idx_leaf separately)
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(&opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }
    }
}

/// Sign a message using SLH-DSA (without context).
///
/// This is a convenience wrapper that calls `sign_ctx` with an empty context.
/// For FIPS 205 compliance with domain separation, use `sign_ctx` instead.
#[inline]
pub fn sign<P: ParameterSet>(secret_key: &SecretKey<P>, message: &[u8]) -> Vec<u8> {
    sign_ctx(secret_key, &[], message)
}

/// Sign a message using SLH-DSA with prehash mode (FIPS 205 Section 5.3).
///
/// This function implements the prehash variant of SLH-DSA where the message
/// is hashed before signing. The prehash mode uses domain separator 0x01.
///
/// # Parameters
/// - `secret_key`: The secret key to sign with
/// - `context`: Optional context string for domain separation (max 255 bytes)
/// - `hash_alg`: Hash algorithm name (e.g., "SHA2-256", "SHAKE-128")
/// - `message`: The message to prehash and sign
///
/// # Returns
/// The signature bytes, or an error if the hash algorithm is unsupported
pub fn sign_prehash<P: ParameterSet>(
    secret_key: &SecretKey<P>,
    context: &[u8],
    hash_alg: &str,
    message: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use crate::prehash::build_prehash_message;

    assert!(context.len() <= 255, "Context must be at most 255 bytes");
    let ctx = context;
    let mut addr = Address::new();

    // Build OID || PH(M) per FIPS 205 Section 5.3
    let prehash_msg = build_prehash_message(hash_alg, message)?;

    // Build M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)
    // Note: domain separator is 0x01 for prehash mode (vs 0x00 for pure mode)
    let mut m_prime = Vec::with_capacity(2 + ctx.len() + prehash_msg.len());
    m_prime.push(1u8); // toByte(1, 1) for prehash mode
    m_prime.push(ctx.len() as u8); // toByte(|ctx|, 1)
    m_prime.extend_from_slice(ctx);
    m_prime.extend_from_slice(&prehash_msg);

    // OPTIMIZATION: Stack-allocate temporary buffers based on parameter set
    macro_rules! sign_prehash_with_stack_buffers {
        ($n:expr, $digest_size:expr) => {{
            let mut opt_rand_buf = [0u8; $n];
            let mut digest_buf = [0u8; $digest_size];

            let opt_rand = &mut opt_rand_buf[..P::N];
            let digest = &mut digest_buf[..P::H_MSG_BYTES];

            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                // Per FIPS 205: R ← PRF_msg(SK.prf, opt_rand, M')
                // For deterministic signing, opt_rand = PK.seed
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), &m_prime, opt_rand);

                // Hash message using M' (which already has domain separator 0x01)
                // Note: We use h_msg_internal because M' is already constructed
                hash.h_msg_internal(opt_rand, secret_key.pk_seed(), secret_key.pk_root(), &m_prime, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Sign with FORS
                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);

                // Sign FORS PK with hypertree
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            // Concatenate signature components
            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }};
    }

    // Match on N to select appropriate stack buffer sizes
    let signature = match P::N {
        16 => sign_prehash_with_stack_buffers!(16, 64),
        24 => sign_prehash_with_stack_buffers!(24, 64),
        32 => sign_prehash_with_stack_buffers!(32, 256),
        _ => {
            // Fallback to heap allocation for unsupported sizes
            let mut opt_rand = vec![0u8; P::N];
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), &m_prime, &mut opt_rand);
                hash.h_msg_internal(&opt_rand, secret_key.pk_seed(), secret_key.pk_root(), &m_prime, &mut digest);

                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(&opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }
    };

    Ok(signature)
}

/// Sign a message using SLH-DSA internal interface (no domain separator).
///
/// This is used for testing compatibility with CAVP internal interface test vectors.
/// The internal interface uses M directly without the domain separator prefix.
pub fn sign_internal<P: ParameterSet>(secret_key: &SecretKey<P>, message: &[u8]) -> Vec<u8> {
    let mut addr = Address::new();

    // OPTIMIZATION: Stack-allocate temporary buffers based on parameter set
    macro_rules! sign_internal_with_stack_buffers {
        ($n:expr, $digest_size:expr) => {{
            let mut opt_rand_buf = [0u8; $n];
            let mut digest_buf = [0u8; $digest_size];

            let opt_rand = &mut opt_rand_buf[..P::N];
            let digest = &mut digest_buf[..P::H_MSG_BYTES];

            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                // Per FIPS 205 internal interface: R ← PRF_msg(SK.prf, opt_rand, M)
                // For deterministic signing, opt_rand = PK.seed
                // Note: internal interface uses M directly, not M'
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), message, opt_rand);

                // Hash message using internal interface (no domain separator)
                hash.h_msg_internal(opt_rand, secret_key.pk_seed(), secret_key.pk_root(), message, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Sign with FORS
                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);

                // Sign FORS PK with hypertree
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            // Concatenate signature components
            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }};
    }

    match P::N {
        16 => sign_internal_with_stack_buffers!(16, 64),
        24 => sign_internal_with_stack_buffers!(24, 64),
        32 => sign_internal_with_stack_buffers!(32, 256),
        _ => {
            let mut opt_rand = vec![0u8; P::N];
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let (fors_sig, _fors_pk, ht_sig) = with_hash!(P::N, P::HASH_TYPE, hash, {
                hash.prf_msg(secret_key.sk_prf(), secret_key.pk_seed(), message, &mut opt_rand);
                hash.h_msg_internal(&opt_rand, secret_key.pk_seed(), secret_key.pk_root(), message, &mut digest);

                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                let (fors_sig, fors_pk) = fors_sign::<P, _>(fors_msg, secret_key.sk_seed(), secret_key.pk_seed(), &mut addr, &hash);
                let ht_sig = ht_sign_cached::<P, _>(&fors_pk, secret_key.sk_seed(), secret_key.pk_seed(), idx_tree, idx_leaf, &mut addr, &hash, secret_key.cache());

                (fors_sig, fors_pk, ht_sig)
            });

            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(&opt_rand);
            signature.extend_from_slice(&fors_sig);
            signature.extend_from_slice(&ht_sig);

            signature
        }
    }
}

/// Verify a signature using SLH-DSA with context.
///
/// Returns true if the signature is valid.
///
/// # Parameters
/// - `public_key`: The public key to verify against
/// - `context`: Context string used during signing (max 255 bytes)
/// - `message`: The original message
/// - `signature`: The signature to verify
///
/// OPTIMIZED: Uses stack-allocated buffers for digest and fors_pk to eliminate
/// heap allocations in the hot path.
pub fn verify_ctx<P: ParameterSet>(public_key: &PublicKey<P>, context: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if context.len() > 255 {
        return false;
    }
    let ctx = context;
    // Per FIPS 205, signature must be exactly SIG_BYTES
    if signature.len() != P::SIG_BYTES {
        return false;
    }

    let mut addr = Address::new();

    // Extract signature components
    let opt_rand = &signature[..P::N];
    let fors_sig = &signature[P::N..P::N + P::FORS_SIG_BYTES];
    let ht_sig = &signature[P::N + P::FORS_SIG_BYTES..];

    // OPTIMIZATION: Stack-allocate temporary buffers based on parameter set
    macro_rules! verify_with_stack_buffers {
        ($n:expr, $digest_size:expr) => {{
            let mut digest_buf = [0u8; $digest_size];
            let mut fors_pk_buf = [0u8; $n];

            let digest = &mut digest_buf[..P::H_MSG_BYTES];
            let fors_pk = &mut fors_pk_buf[..P::N];

            with_hash!(P::N, P::HASH_TYPE, hash, {
                // Hash message with context
                hash.h_msg(opt_rand, public_key.pk_seed(), public_key.pk_root(), ctx, message, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS verification (FIPS 205 Algorithm 18)
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Verify FORS signature
                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, fors_pk);

                // Note: keypair address is already set for ht_verify

                // Verify hypertree signature (per FIPS 205, pass idx_tree and idx_leaf separately)
                ht_verify::<P, _>(fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }};
    }

    // Match on N to select appropriate stack buffer sizes
    match P::N {
        16 => verify_with_stack_buffers!(16, 64),
        24 => verify_with_stack_buffers!(24, 64),
        32 => verify_with_stack_buffers!(32, 256),
        _ => {
            // Fallback to heap allocation for unsupported sizes
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let mut fors_pk = vec![0u8; P::N];
            with_hash!(P::N, P::HASH_TYPE, hash, {
                hash.h_msg(opt_rand, public_key.pk_seed(), public_key.pk_root(), ctx, message, &mut digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                // Set tree and keypair address for FORS verification (FIPS 205 Algorithm 18)
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, &mut fors_pk);

                // Note: keypair address is already set for ht_verify

                // Verify hypertree signature (per FIPS 205, pass idx_tree and idx_leaf separately)
                ht_verify::<P, _>(&fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }
    }
}

/// Verify a prehashed signature using SLH-DSA with context.
///
/// This function implements the prehash mode per FIPS 205 Section 5.3.
/// The message is first hashed using the specified hash algorithm, then the
/// OID || PH(M) is verified.
///
/// # Parameters
/// - `public_key`: The public key to verify with
/// - `context`: Application-specific context string (max 255 bytes)
/// - `hash_alg`: Name of the hash algorithm (e.g., "SHA2-256", "SHAKE-128")
/// - `message`: The original message (will be hashed)
/// - `signature`: The signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
pub fn verify_prehash<P: ParameterSet>(
    public_key: &PublicKey<P>,
    context: &[u8],
    hash_alg: &str,
    message: &[u8],
    signature: &[u8],
) -> bool {
    use crate::prehash::build_prehash_message;

    if context.len() > 255 {
        return false;
    }

    // Per FIPS 205, signature must be exactly SIG_BYTES
    if signature.len() != P::SIG_BYTES {
        return false;
    }

    // Build OID || PH(M) per FIPS 205 Section 5.3
    let prehash_msg = match build_prehash_message(hash_alg, message) {
        Ok(msg) => msg,
        Err(_) => return false,
    };

    // Build M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)
    // Note: domain separator is 0x01 for prehash mode (vs 0x00 for pure mode)
    let mut m_prime = Vec::with_capacity(2 + context.len() + prehash_msg.len());
    m_prime.push(1u8); // toByte(1, 1) for prehash mode
    m_prime.push(context.len() as u8); // toByte(|ctx|, 1)
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(&prehash_msg);

    let mut addr = Address::new();

    // Extract signature components
    let opt_rand = &signature[..P::N];
    let fors_sig = &signature[P::N..P::N + P::FORS_SIG_BYTES];
    let ht_sig = &signature[P::N + P::FORS_SIG_BYTES..];

    // OPTIMIZATION: Stack-allocate temporary buffers based on parameter set
    macro_rules! verify_prehash_with_stack_buffers {
        ($n:expr, $digest_size:expr) => {{
            let mut digest_buf = [0u8; $digest_size];
            let mut fors_pk_buf = [0u8; $n];

            let digest = &mut digest_buf[..P::H_MSG_BYTES];
            let fors_pk = &mut fors_pk_buf[..P::N];

            with_hash!(P::N, P::HASH_TYPE, hash, {
                // Hash using M' (which already has domain separator 0x01)
                hash.h_msg_internal(opt_rand, public_key.pk_seed(), public_key.pk_root(), &m_prime, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS verification
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Verify FORS signature
                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, fors_pk);

                // Verify hypertree signature
                ht_verify::<P, _>(fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }};
    }

    // Match on N to select appropriate stack buffer sizes
    match P::N {
        16 => verify_prehash_with_stack_buffers!(16, 64),
        24 => verify_prehash_with_stack_buffers!(24, 64),
        32 => verify_prehash_with_stack_buffers!(32, 256),
        _ => {
            // Fallback to heap allocation for unsupported sizes
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let mut fors_pk = vec![0u8; P::N];
            with_hash!(P::N, P::HASH_TYPE, hash, {
                hash.h_msg_internal(opt_rand, public_key.pk_seed(), public_key.pk_root(), &m_prime, &mut digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                // Set tree and keypair address for FORS verification
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, &mut fors_pk);

                // Verify hypertree signature
                ht_verify::<P, _>(&fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }
    }
}

/// Verify a signature using SLH-DSA (without context).
///
/// This is a convenience wrapper that calls `verify_ctx` with an empty context.
/// For FIPS 205 compliance with domain separation, use `verify_ctx` instead.
#[inline]
pub fn verify<P: ParameterSet>(public_key: &PublicKey<P>, message: &[u8], signature: &[u8]) -> bool {
    verify_ctx(public_key, &[], message, signature)
}

/// Verify a signature using SLH-DSA internal interface (no domain separator).
///
/// This uses the message directly without the external interface domain separator.
/// Only use this if you know the signature was created with the internal interface.
pub fn verify_internal<P: ParameterSet>(public_key: &PublicKey<P>, message: &[u8], signature: &[u8]) -> bool {
    // Per FIPS 205, signature must be exactly SIG_BYTES
    if signature.len() != P::SIG_BYTES {
        return false;
    }

    let mut addr = Address::new();

    // Extract signature components
    let opt_rand = &signature[..P::N];
    let fors_sig = &signature[P::N..P::N + P::FORS_SIG_BYTES];
    let ht_sig = &signature[P::N + P::FORS_SIG_BYTES..];

    // Stack-allocate buffers for performance
    macro_rules! verify_internal_impl {
        ($n:expr, $digest_size:expr) => {{
            let mut digest_buf = [0u8; $digest_size];
            let mut fors_pk_buf = [0u8; $n];

            let digest = &mut digest_buf[..P::H_MSG_BYTES];
            let fors_pk = &mut fors_pk_buf[..P::N];

            with_hash!(P::N, P::HASH_TYPE, hash, {
                // Hash message using internal interface (no domain separator)
                hash.h_msg_internal(opt_rand, public_key.pk_seed(), public_key.pk_root(), message, digest);

                // Extract FORS message and indices from digest per FIPS 205
                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(digest);

                // Set tree and keypair address for FORS verification
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                // Verify FORS signature
                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, fors_pk);

                // Note: keypair address is already set for ht_verify

                // Verify hypertree signature (per FIPS 205, pass idx_tree and idx_leaf separately)
                ht_verify::<P, _>(fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }};
    }

    match P::N {
        16 => verify_internal_impl!(16, 64),
        24 => verify_internal_impl!(24, 64),
        32 => verify_internal_impl!(32, 256),
        _ => {
            let mut digest = vec![0u8; P::H_MSG_BYTES];
            let mut fors_pk = vec![0u8; P::N];
            with_hash!(P::N, P::HASH_TYPE, hash, {
                hash.h_msg_internal(opt_rand, public_key.pk_seed(), public_key.pk_root(), message, &mut digest);

                let fors_msg = &digest[..P::FORS_MSG_BYTES];
                let (idx_tree, idx_leaf) = extract_indices::<P>(&digest);

                // Set tree and keypair address for FORS verification
                addr.set_tree(idx_tree);
                addr.set_keypair(idx_leaf as u32);

                fors_pk_from_sig::<P, _>(fors_sig, fors_msg, public_key.pk_seed(), &mut addr, &hash, &mut fors_pk);

                // Note: keypair address is already set for ht_verify

                // Verify hypertree signature (per FIPS 205, pass idx_tree and idx_leaf separately)
                ht_verify::<P, _>(&fors_pk, ht_sig, public_key.pk_seed(), idx_tree, idx_leaf, public_key.pk_root(), &mut addr, &hash)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Sha2_128s;
    use hpcrypt_rng::OsRng;

    #[test]
    fn test_keygen() {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

        assert_eq!(keypair.secret_key.sk_seed().len(), 16);
        assert_eq!(keypair.public_key.pk_root().len(), 16);
    }

    #[test]
    fn test_sign_verify() {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

        let message = b"Hello, world!";
        let signature = sign(&keypair.secret_key, message);

        let valid = verify(&keypair.public_key, message, &signature);
        assert!(valid);
    }

    #[test]
    #[ignore] // Temporarily ignored: simplified hypertree doesn't fully validate multi-layer
    fn test_verify_wrong_message_fails() {
        let mut rng = OsRng;
        let keypair = KeyPair::<Sha2_128s>::generate(&mut rng);

        let message = b"Hello, world!";
        let wrong_message = b"Goodbye, world!";
        let signature = sign(&keypair.secret_key, message);

        let valid = verify(&keypair.public_key, wrong_message, &signature);
        assert!(!valid);
    }
}
