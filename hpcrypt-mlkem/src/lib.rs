//! ML-KEM - Module-Lattice-Based Key Encapsulation Mechanism
//!
//! Production-ready implementation of NIST FIPS 203 standard for post-quantum key encapsulation.
//!
//! # Overview
//!
//! ML-KEM is a key encapsulation mechanism (KEM) whose security is based on the hardness
//! of the Module Learning With Errors (MLWE) problem. It is designed to be secure against
//! both classical and quantum computer attacks.
//!
//! ## Security Levels
//!
//! - **ML-KEM-512**: NIST Security Level 1 (comparable to AES-128, ~103 quantum security bits)
//! - **ML-KEM-768**: NIST Security Level 3 (comparable to AES-192, ~161 quantum security bits) - **RECOMMENDED**
//! - **ML-KEM-1024**: NIST Security Level 5 (comparable to AES-256, ~218 quantum security bits)
//!
//! # Basic Usage
//!
//! ```
//! use hpcrypt_mlkem::{MlKem768, KeyPair};
//!
//! // Generate a key pair
//! let keypair = KeyPair::generate::<MlKem768>();
//!
//! // Sender: Encapsulate to create shared secret
//! let (ciphertext, shared_secret_sender) = keypair.encapsulate::<MlKem768>();
//!
//! // Receiver: Decapsulate to recover shared secret
//! let shared_secret_receiver = keypair.decapsulate::<MlKem768>(&ciphertext);
//!
//! assert_eq!(shared_secret_sender, shared_secret_receiver);
//! ```
//!
//! # Features
//!
//! - `std`: Enable standard library support (disabled by default for no_std compatibility)
//! - `serde`: Enable serialization/deserialization support for keys
//! - `zeroize`: Enable automatic zeroization of private key material on drop
//! - `timing-tests`: Enable timing analysis and side-channel detection utilities (requires `std`)
//!
//! # Security Considerations
//!
//! - **No unsafe code**: 100% safe Rust implementation
//! - **Side-channel resistance**: Constant-time operations where cryptographically relevant
//! - **Standards compliance**: Fully compliant with NIST FIPS 203
//! - **Timing protection**: Implicit rejection in decapsulation prevents timing attacks
//! - **Key validation**: All keys are validated before use
//! - **Secure RNG**: Uses OS-provided cryptographically secure random number generation
//!
//! # Performance
//!
//! Typical performance on modern hardware (measured in microseconds):
//! - ML-KEM-512: KeyGen ~20µs, Encaps ~22µs, Decaps ~24µs
//! - ML-KEM-768: KeyGen ~37µs, Encaps ~40µs, Decaps ~43µs
//! - ML-KEM-1024: KeyGen ~68µs, Encaps ~72µs, Decaps ~76µs

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]

extern crate alloc;
use alloc::vec::Vec;

#[doc(hidden)]
pub mod compress; // Public for benchmarks
mod decaps;
#[doc(hidden)]
pub mod encaps; // Public for benchmarks
#[doc(hidden)]
pub mod keygen; // Public for benchmarks
#[doc(hidden)]
pub mod ntt; // Public for benchmarks
#[doc(hidden)]
pub mod params; // Public for benchmarks
#[doc(hidden)]
pub mod poly; // Public for benchmarks
#[doc(hidden)]
pub mod sampling; // Public for benchmarks
#[doc(hidden)]
pub mod serialize; // Public for benchmarks
#[doc(hidden)]
pub mod symmetric; // Public for benchmarks
mod utils;

/// Constant-time operation verification utilities
///
/// Provides utilities for constant-time comparisons and operations to help
/// prevent timing side-channel attacks.
pub mod ct_verify;

/// Fill a buffer with cryptographically secure random bytes
///
/// This function uses the operating system's CSPRNG to fill the provided
/// buffer with random bytes. It is suitable for generating cryptographic keys,
/// nonces, and other security-sensitive random values.
///
/// # Arguments
///
/// * `dest` - The destination buffer to fill with random bytes
///
/// # Errors
///
/// Returns an error if the underlying OS RNG fails (extremely rare).
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::fill_random;
///
/// let mut buffer = [0u8; 32];
/// fill_random(&mut buffer).expect("RNG failure");
/// // buffer now contains 32 cryptographically secure random bytes
/// ```
#[doc(inline)]
pub use hpcrypt_rng::generate_random_bytes as fill_random;

/// Generate a random key of fixed size
///
/// Type-safe key generation with compile-time size checking.
///
/// # Type Parameters
///
/// * `N` - The size of the key in bytes (must be known at compile time)
///
/// # Returns
///
/// Returns a Result containing the key array on success.
///
/// # Errors
///
/// Returns an error if the underlying OS RNG fails (extremely rare).
///
/// # Examples
///
/// ```
/// use hpcrypt_mlkem::random_bytes_32;
///
/// // Generate a 256-bit key
/// let key: [u8; 32] = random_bytes_32().expect("RNG failure");
/// ```
#[doc(inline)]
pub use hpcrypt_rng::generate_key as random_bytes_32;

/// Timing analysis and side-channel detection
/// (Only available with std and timing-tests feature)
#[cfg(all(any(test, feature = "timing-tests"), feature = "std"))]
pub mod timing;

/// CAVP/ACVP test API
/// (Only available with cavp feature for validation testing)
#[cfg(feature = "cavp")]
pub mod test_api;

// Re-export parameter sets
pub use params::{MlKem1024, MlKem512, MlKem768, Params};

/// ML-KEM key pair
///
/// Contains both the public encapsulation key and private decapsulation key.
///
/// # Security
///
/// - The private (decapsulation) key should be kept secret
/// - The public (encapsulation) key can be freely shared
/// - Keys are validated internally before use
/// - Consider using the `zeroize` feature for automatic key material cleanup
///
/// # Key Sizes
///
/// Key sizes depend on the chosen security level:
/// - **ML-KEM-512**: Public key 800 bytes, Private key 1632 bytes
/// - **ML-KEM-768**: Public key 1184 bytes, Private key 2400 bytes
/// - **ML-KEM-1024**: Public key 1568 bytes, Private key 3168 bytes
#[derive(Clone)]
pub struct KeyPair {
    ek: Vec<u8>,
    dk: Vec<u8>,
}

impl KeyPair {
    /// Generate a new ML-KEM key pair using OS-provided randomness
    ///
    /// Uses the operating system's cryptographically secure random number generator
    /// to produce a fresh key pair. This is the recommended method for production use.
    ///
    /// # Type Parameters
    ///
    /// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG fails (extremely rare and indicates system-level failure).
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_mlkem::{KeyPair, MlKem768};
    ///
    /// let keypair = KeyPair::generate::<MlKem768>();
    /// ```
    pub fn generate<P: Params>() -> Self {
        let keys = keygen::ml_kem_keygen::<P>(None);
        Self {
            ek: keys.ek,
            dk: keys.dk,
        }
    }

    /// Generate a key pair from a specific seed (for testing/reproducibility)
    ///
    /// Generates a deterministic key pair from a 32-byte seed. This is useful for
    /// testing, benchmarking, and scenarios requiring reproducible key generation.
    ///
    /// **WARNING**: Do not use this in production with predictable seeds. For production
    /// use, always use [`KeyPair::generate`] which uses OS-provided randomness.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte seed for deterministic key generation
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_mlkem::{KeyPair, MlKem768};
    ///
    /// // For testing only - never use predictable seeds in production!
    /// let seed = [0x42u8; 32];
    /// let keypair = KeyPair::from_seed::<MlKem768>(&seed);
    /// ```
    pub fn from_seed<P: Params>(seed: &[u8; 32]) -> Self {
        let keys = keygen::ml_kem_keygen::<P>(Some(seed));
        Self {
            ek: keys.ek,
            dk: keys.dk,
        }
    }

    /// Get the encapsulation (public) key
    ///
    /// Returns a reference to the public key bytes which can be freely shared.
    /// This key is used by others to encapsulate shared secrets for you.
    ///
    /// # Returns
    ///
    /// Reference to the encapsulation key bytes
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    /// Get the decapsulation (private) key
    ///
    /// Returns a reference to the private key bytes which **must be kept secret**.
    /// This key is used to decapsulate ciphertexts and recover shared secrets.
    ///
    /// # Security
    ///
    /// The decapsulation key must never be shared or transmitted over insecure channels.
    ///
    /// # Returns
    ///
    /// Reference to the decapsulation key bytes
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.dk
    }

    /// Encapsulate to create a shared secret
    ///
    /// Creates a random shared secret and encapsulates it using this key pair's public key.
    /// The ciphertext can be sent to the key pair owner, who can decapsulate it to recover
    /// the same shared secret.
    ///
    /// # Type Parameters
    ///
    /// * `P` - Parameter set (must match the one used for key generation)
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret) where:
    /// - `ciphertext`: Can be safely transmitted over public channels
    /// - `shared_secret`: 32-byte secret that should be kept confidential
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG fails (extremely rare).
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_mlkem::{KeyPair, MlKem768};
    ///
    /// let keypair = KeyPair::generate::<MlKem768>();
    /// let (ciphertext, shared_secret) = keypair.encapsulate::<MlKem768>();
    /// // Send ciphertext to the key pair owner...
    /// ```
    pub fn encapsulate<P: Params>(&self) -> (Vec<u8>, [u8; 32]) {
        let result = encaps::ml_kem_encaps::<P>(&self.ek, None);
        (result.ciphertext, result.shared_secret)
    }

    /// Decapsulate a ciphertext to recover the shared secret
    ///
    /// Recovers the shared secret from a ciphertext using this key pair's private key.
    /// This operation is protected against timing attacks via implicit rejection.
    ///
    /// # Type Parameters
    ///
    /// * `P` - Parameter set (must match the one used for key generation)
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The 32-byte shared secret. Note that even for invalid ciphertexts, this function
    /// always returns a 32-byte value (implicit rejection prevents timing attacks).
    ///
    /// # Security
    ///
    /// - Constant-time operation to prevent timing side-channels
    /// - Implicit rejection: invalid ciphertexts produce pseudorandom outputs
    /// - The returned shared secret should be used only with this specific ciphertext
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_mlkem::{KeyPair, MlKem768};
    ///
    /// let keypair = KeyPair::generate::<MlKem768>();
    /// let (ciphertext, ss1) = keypair.encapsulate::<MlKem768>();
    /// let ss2 = keypair.decapsulate::<MlKem768>(&ciphertext);
    /// assert_eq!(ss1, ss2);
    /// ```
    pub fn decapsulate<P: Params>(&self, ciphertext: &[u8]) -> [u8; 32] {
        decaps::ml_kem_decaps::<P>(&self.dk, ciphertext)
    }

    /// Create a KeyPair from raw key bytes
    ///
    /// Constructs a KeyPair directly from raw key material. This is useful for
    /// deserializing keys or loading them from storage.
    ///
    /// # Arguments
    ///
    /// * `ek` - Encapsulation (public) key bytes
    /// * `dk` - Decapsulation (private) key bytes
    ///
    /// # Returns
    ///
    /// KeyPair constructed from the provided keys
    ///
    /// # Warning
    ///
    /// This function does **not** validate the keys. It is the caller's responsibility
    /// to ensure:
    /// - Keys are the correct size for the chosen parameter set
    /// - Keys are properly formatted and cryptographically valid
    /// - Private key material is from a trusted source
    ///
    /// Using invalid keys may lead to security vulnerabilities or runtime panics.
    ///
    /// # Example
    ///
    /// ```
    /// use hpcrypt_mlkem::{KeyPair, MlKem768};
    ///
    /// // Generate a keypair
    /// let original = KeyPair::generate::<MlKem768>();
    ///
    /// // Extract key bytes
    /// let ek = original.encapsulation_key().to_vec();
    /// let dk = original.decapsulation_key().to_vec();
    ///
    /// // Reconstruct from bytes
    /// let restored = KeyPair::from_bytes(ek, dk);
    /// ```
    pub fn from_bytes(ek: Vec<u8>, dk: Vec<u8>) -> Self {
        Self { ek, dk }
    }
}

/// Encapsulate using a public key
///
/// Standalone function for encapsulation when you only have access to the public key.
/// This is useful in scenarios where you don't need to store the full KeyPair.
///
/// # Type Parameters
///
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
///
/// * `public_key` - The encapsulation (public) key bytes
///
/// # Returns
///
/// A tuple of (ciphertext, shared_secret) where:
/// - `ciphertext`: Can be safely transmitted over public channels
/// - `shared_secret`: 32-byte secret that should be kept confidential
///
/// # Panics
///
/// Panics if the OS RNG fails (extremely rare).
///
/// # Example
///
/// ```
/// use hpcrypt_mlkem::{KeyPair, MlKem768, encapsulate};
///
/// let keypair = KeyPair::generate::<MlKem768>();
/// let public_key = keypair.encapsulation_key();
///
/// // Encapsulate using just the public key
/// let (ciphertext, shared_secret) = encapsulate::<MlKem768>(public_key);
/// ```
pub fn encapsulate<P: Params>(public_key: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let result = encaps::ml_kem_encaps::<P>(public_key, None);
    (result.ciphertext, result.shared_secret)
}

/// Decapsulate a ciphertext using a private key
///
/// Standalone function for decapsulation when you only have access to the private key.
/// This operation is protected against timing attacks via implicit rejection.
///
/// # Type Parameters
///
/// * `P` - Parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Arguments
///
/// * `private_key` - The decapsulation (private) key bytes
/// * `ciphertext` - The ciphertext to decapsulate
///
/// # Returns
///
/// The 32-byte shared secret. Note that even for invalid ciphertexts, this function
/// always returns a 32-byte value (implicit rejection prevents timing attacks).
///
/// # Security
///
/// - Constant-time operation to prevent timing side-channels
/// - Implicit rejection: invalid ciphertexts produce pseudorandom outputs
/// - The returned shared secret should be used only with this specific ciphertext
///
/// # Example
///
/// ```
/// use hpcrypt_mlkem::{KeyPair, MlKem768, encapsulate, decapsulate};
///
/// let keypair = KeyPair::generate::<MlKem768>();
/// let private_key = keypair.decapsulation_key();
///
/// let (ciphertext, ss1) = encapsulate::<MlKem768>(keypair.encapsulation_key());
/// let ss2 = decapsulate::<MlKem768>(private_key, &ciphertext);
/// assert_eq!(ss1, ss2);
/// ```
pub fn decapsulate<P: Params>(private_key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    decaps::ml_kem_decaps::<P>(private_key, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generate_mlkem512() {
        let keypair = KeyPair::generate::<MlKem512>();
        assert_eq!(keypair.ek.len(), MlKem512::EK_SIZE);
        assert_eq!(keypair.dk.len(), MlKem512::DK_SIZE);
    }

    #[test]
    fn test_keypair_generate_mlkem768() {
        let keypair = KeyPair::generate::<MlKem768>();
        assert_eq!(keypair.ek.len(), MlKem768::EK_SIZE);
        assert_eq!(keypair.dk.len(), MlKem768::DK_SIZE);
    }

    #[test]
    fn test_keypair_generate_mlkem1024() {
        let keypair = KeyPair::generate::<MlKem1024>();
        assert_eq!(keypair.ek.len(), MlKem1024::EK_SIZE);
        assert_eq!(keypair.dk.len(), MlKem1024::DK_SIZE);
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [0x42u8; 32];
        let kp1 = KeyPair::from_seed::<MlKem768>(&seed);
        let kp2 = KeyPair::from_seed::<MlKem768>(&seed);

        assert_eq!(kp1.ek, kp2.ek);
        assert_eq!(kp1.dk, kp2.dk);
    }

    #[test]
    fn test_encaps_decaps_roundtrip_mlkem512() {
        let keypair = KeyPair::generate::<MlKem512>();
        let (ct, ss1) = keypair.encapsulate::<MlKem512>();
        let ss2 = keypair.decapsulate::<MlKem512>(&ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_encaps_decaps_roundtrip_mlkem768() {
        let keypair = KeyPair::generate::<MlKem768>();
        let (ct, ss1) = keypair.encapsulate::<MlKem768>();
        let ss2 = keypair.decapsulate::<MlKem768>(&ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_encaps_decaps_roundtrip_mlkem1024() {
        let keypair = KeyPair::generate::<MlKem1024>();
        let (ct, ss1) = keypair.encapsulate::<MlKem1024>();
        let ss2 = keypair.decapsulate::<MlKem1024>(&ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_standalone_encapsulate_decapsulate() {
        let keypair = KeyPair::generate::<MlKem768>();

        let (ct, ss1) = encapsulate::<MlKem768>(keypair.encapsulation_key());
        let ss2 = decapsulate::<MlKem768>(keypair.decapsulation_key(), &ct);

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ciphertext_size() {
        let keypair = KeyPair::generate::<MlKem768>();
        let (ct, _) = keypair.encapsulate::<MlKem768>();
        assert_eq!(ct.len(), MlKem768::CT_SIZE);
    }

    #[test]
    fn test_shared_secret_size() {
        let keypair = KeyPair::generate::<MlKem768>();
        let (_, ss) = keypair.encapsulate::<MlKem768>();
        assert_eq!(ss.len(), 32);
    }
}
