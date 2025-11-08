//! Common traits for cryptographic primitives

// Re-export AeadError for use in trait signatures and backwards compatibility
pub use crate::error::AeadError;

/// Digest/Hash function trait
pub trait Digest {
    /// Output type
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    /// Output size in bytes
    const OUTPUT_SIZE: usize;
    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Create a new hasher
    fn new() -> Self;

    /// Update the hash with input data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the digest
    fn finalize(self) -> Self::Output;

    /// Chain update operations
    fn chain(mut self, data: &[u8]) -> Self
    where
        Self: Sized,
    {
        self.update(data);
        self
    }
}

/// Message Authentication Code trait
pub trait Mac {
    /// Output type
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Create a new MAC with a key
    fn new(key: &[u8]) -> Self;

    /// Update with input data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the tag
    fn finalize(self) -> Self::Output;

    /// Verify a tag in constant time
    fn verify(self, tag: &[u8]) -> bool
    where
        Self: Sized,
    {
        use crate::ct_utils::ConstantTimeEq;
        let computed = self.finalize();
        computed.as_ref().ct_eq(tag).into()
    }
}

/// Authenticated Encryption with Associated Data trait
#[cfg(feature = "alloc")]
pub trait Aead {
    /// Key size in bytes
    const KEY_SIZE: usize;
    /// Nonce size in bytes
    const NONCE_SIZE: usize;
    /// Tag size in bytes
    const TAG_SIZE: usize;

    /// Encrypt plaintext with associated data
    ///
    /// Returns ciphertext || tag
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError>;

    /// Decrypt ciphertext with associated data
    ///
    /// Expects ciphertext || tag
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError>;
}

/// Key Derivation Function trait
pub trait Kdf {
    /// Derive key material
    ///
    /// # Arguments
    /// * `ikm` - Input keying material
    /// * `salt` - Optional salt
    /// * `info` - Optional context/application specific information
    /// * `okm` - Output keying material buffer
    fn derive(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm: &mut [u8]);
}

/// Digital signature trait
pub trait Signature {
    /// Public key type
    type PublicKey: AsRef<[u8]>;
    /// Secret key type
    type SecretKey: AsRef<[u8]>;
    /// Signature type
    type Signature: AsRef<[u8]>;

    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    /// Generate a keypair
    fn generate_keypair() -> (Self::SecretKey, Self::PublicKey);

    /// Sign a message
    fn sign(secret_key: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    /// Verify a signature
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool;
}

/// Key exchange trait
pub trait KeyExchange {
    /// Public key type
    type PublicKey: AsRef<[u8]>;
    /// Secret key type
    type SecretKey: AsRef<[u8]>;
    /// Shared secret type
    type SharedSecret: AsRef<[u8]>;

    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    /// Shared secret size in bytes
    const SHARED_SECRET_SIZE: usize;

    /// Generate a keypair
    fn generate_keypair() -> (Self::SecretKey, Self::PublicKey);

    /// Compute shared secret
    fn compute_shared_secret(
        secret_key: &Self::SecretKey,
        public_key: &Self::PublicKey,
    ) -> Self::SharedSecret;
}
