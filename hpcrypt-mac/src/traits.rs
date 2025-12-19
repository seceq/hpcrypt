//! Generic traits for message authentication codes (MACs)
//!
//! This module provides trait-based abstractions for MAC algorithms,
//! enabling generic programming over different MAC implementations.

/// Generic MAC trait for message authentication codes
///
/// This trait provides a common interface for all MAC algorithms (HMAC, CMAC, KMAC, etc.).
///
/// # Example
/// ```ignore
/// fn authenticate<M: Mac>(key: &[u8], data: &[u8]) -> impl AsRef<[u8]> {
///     let mut mac = M::new(key);
///     mac.update(data);
///     mac.finalize()
/// }
///
/// let hmac_tag = authenticate::<HmacSha256>(key, message);
/// let cmac_tag = authenticate::<AesCmac128>(key, message);
/// ```
pub trait Mac: Clone {
    /// Output type - typically a fixed-size array
    type Output: AsRef<[u8]>;

    /// Context type for incremental MAC computation
    type Context: MacContext<Output = Self::Output>;

    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Create a new MAC instance with the given key
    fn new(key: &[u8]) -> Self;

    /// One-shot MAC computation
    ///
    /// Computes MAC(key, data) in a single call.
    fn compute(key: &[u8], data: &[u8]) -> Self::Output;

    /// Start incremental MAC computation
    ///
    /// Returns a context that can be used for streaming MAC computation.
    fn start(self) -> Self::Context;

    /// Convenience method: Create a new MAC and immediately start context
    #[inline]
    fn new_context(key: &[u8]) -> Self::Context {
        Self::new(key).start()
    }
}

/// Context for incremental MAC computation
///
/// This trait allows streaming MAC computation with multiple update() calls.
pub trait MacContext {
    /// Output type
    type Output: AsRef<[u8]>;

    /// Update with additional data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the MAC tag
    fn finalize(self) -> Self::Output;

    /// Verify a MAC tag in constant time
    ///
    /// Returns true if the provided tag matches the computed MAC.
    /// Note: This consumes self. If you need to preserve the context, clone it first.
    fn verify(self, tag: &[u8]) -> bool
    where
        Self: Sized,
    {
        use subtle::ConstantTimeEq;
        let computed = self.finalize();
        computed.as_ref().ct_eq(tag).into()
    }

    /// Clone the context
    fn clone(&self) -> Self;
}
