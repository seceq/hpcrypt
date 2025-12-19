//! Generic traits for hash functions and XOFs
//!
//! This module provides trait-based abstractions for hash functions,
//! enabling generic programming over different hash implementations.

/// Generic hash function trait for fixed-output hash functions
///
/// This trait provides a common interface for all hash functions that produce
/// a fixed-size output (SHA-256, SHA-512, BLAKE2, etc.).
///
/// # Example
/// ```ignore
/// fn hash_data<H: HashFunction>(data: &[u8]) -> impl AsRef<[u8]> {
///     let mut hasher = H::new();
///     hasher.update(data);
///     hasher.finalize()
/// }
///
/// let sha256_hash = hash_data::<Sha256>(b"hello world");
/// let sha512_hash = hash_data::<Sha512>(b"hello world");
/// ```
pub trait HashFunction: Clone + Default {
    /// Output type - typically a fixed-size array
    type Output: AsRef<[u8]>;

    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Create a new hash instance
    fn new() -> Self;

    /// Update with additional data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash
    fn finalize(self) -> Self::Output;

    /// Finalize and reset for reuse
    ///
    /// This is more efficient than cloning for contexts that need to be reused.
    fn finalize_reset(&mut self) -> Self::Output;

    /// Convenience method: hash data in one shot
    #[inline]
    fn hash(data: &[u8]) -> Self::Output {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// Generic trait for extendable-output functions (XOFs)
///
/// This trait provides a common interface for XOFs like SHAKE128 and SHAKE256
/// that can produce variable-length output.
///
/// # Example
/// ```ignore
/// fn generate_key_material<X: XofFunction>(seed: &[u8], length: usize) -> Vec<u8> {
///     let mut xof = X::new();
///     xof.update(seed);
///     let mut output = vec![0u8; length];
///     xof.finalize_xof(&mut output);
///     output
/// }
/// ```
pub trait XofFunction: Clone + Default {
    /// XOF reader type for incremental output
    type Reader;

    /// Create a new XOF instance
    fn new() -> Self;

    /// Update with additional data
    fn update(&mut self, data: &[u8]);

    /// Finalize and fill output buffer with requested length
    fn finalize(self, output: &mut [u8]);

    /// Finalize and return an XOF reader for incremental output
    fn finalize_xof(self) -> Self::Reader;
}

