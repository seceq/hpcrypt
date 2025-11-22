//! HMAC (Hash-based Message Authentication Code)
//!
//! HMAC provides message authentication using a cryptographic hash function
//! combined with a secret key. Specified in RFC 2104 and FIPS 198-1.
//!
//! ## Optimizations
//!
//! This implementation uses several optimizations per RFC 2104 Section 4:
//!
//! 1. **Precomputed Hash States**: The hash states after processing (K ⊕ ipad) and
//!    (K ⊕ opad) are computed once during key setup and cached. This saves two
//!    block compressions per HMAC operation when reusing the same key.
//!
//! 2. **Fixed-Size Arrays**: Uses stack-allocated arrays instead of Vec to avoid
//!    heap allocations.
//!
//! 3. **XOR Trick**: Uses the identity `ipad ⊕ opad = 0x6A` to convert ipad_key
//!    to opad_key with a single XOR pass instead of two separate operations.
//!
//! 4. **Unrolled XOR Loops**: Uses macros for readable 8-way unrolled XOR operations.

/// Inner padding byte (0x36)
const IPAD: u8 = 0x36;

/// XOR of IPAD and OPAD for fast conversion: 0x36 ^ 0x5C = 0x6A
const IPAD_XOR_OPAD: u8 = 0x6A;

// ============================================================================
// Rolling macros for unrolled XOR operations
// ============================================================================

/// Unrolled XOR: dst[i] = src[i] ^ val for 8 elements starting at offset
macro_rules! xor_block_8 {
    ($dst:expr, $src:expr, $val:expr, $offset:expr) => {{
        $dst[$offset] = $src[$offset] ^ $val;
        $dst[$offset + 1] = $src[$offset + 1] ^ $val;
        $dst[$offset + 2] = $src[$offset + 2] ^ $val;
        $dst[$offset + 3] = $src[$offset + 3] ^ $val;
        $dst[$offset + 4] = $src[$offset + 4] ^ $val;
        $dst[$offset + 5] = $src[$offset + 5] ^ $val;
        $dst[$offset + 6] = $src[$offset + 6] ^ $val;
        $dst[$offset + 7] = $src[$offset + 7] ^ $val;
    }};
}

/// Unrolled in-place XOR: buf[i] ^= val for 8 elements starting at offset
macro_rules! xor_inplace_8 {
    ($buf:expr, $val:expr, $offset:expr) => {{
        $buf[$offset] ^= $val;
        $buf[$offset + 1] ^= $val;
        $buf[$offset + 2] ^= $val;
        $buf[$offset + 3] ^= $val;
        $buf[$offset + 4] ^= $val;
        $buf[$offset + 5] ^= $val;
        $buf[$offset + 6] ^= $val;
        $buf[$offset + 7] ^= $val;
    }};
}

/// XOR 64-byte block (SHA-256 block size): dst = src ^ val
macro_rules! xor_block_64 {
    ($dst:expr, $src:expr, $val:expr) => {{
        xor_block_8!($dst, $src, $val, 0);
        xor_block_8!($dst, $src, $val, 8);
        xor_block_8!($dst, $src, $val, 16);
        xor_block_8!($dst, $src, $val, 24);
        xor_block_8!($dst, $src, $val, 32);
        xor_block_8!($dst, $src, $val, 40);
        xor_block_8!($dst, $src, $val, 48);
        xor_block_8!($dst, $src, $val, 56);
    }};
}

/// In-place XOR 64-byte block: buf ^= val
macro_rules! xor_inplace_64 {
    ($buf:expr, $val:expr) => {{
        xor_inplace_8!($buf, $val, 0);
        xor_inplace_8!($buf, $val, 8);
        xor_inplace_8!($buf, $val, 16);
        xor_inplace_8!($buf, $val, 24);
        xor_inplace_8!($buf, $val, 32);
        xor_inplace_8!($buf, $val, 40);
        xor_inplace_8!($buf, $val, 48);
        xor_inplace_8!($buf, $val, 56);
    }};
}

/// XOR 128-byte block (SHA-512 block size): dst = src ^ val
macro_rules! xor_block_128 {
    ($dst:expr, $src:expr, $val:expr) => {{
        xor_block_8!($dst, $src, $val, 0);
        xor_block_8!($dst, $src, $val, 8);
        xor_block_8!($dst, $src, $val, 16);
        xor_block_8!($dst, $src, $val, 24);
        xor_block_8!($dst, $src, $val, 32);
        xor_block_8!($dst, $src, $val, 40);
        xor_block_8!($dst, $src, $val, 48);
        xor_block_8!($dst, $src, $val, 56);
        xor_block_8!($dst, $src, $val, 64);
        xor_block_8!($dst, $src, $val, 72);
        xor_block_8!($dst, $src, $val, 80);
        xor_block_8!($dst, $src, $val, 88);
        xor_block_8!($dst, $src, $val, 96);
        xor_block_8!($dst, $src, $val, 104);
        xor_block_8!($dst, $src, $val, 112);
        xor_block_8!($dst, $src, $val, 120);
    }};
}

/// In-place XOR 128-byte block: buf ^= val
macro_rules! xor_inplace_128 {
    ($buf:expr, $val:expr) => {{
        xor_inplace_8!($buf, $val, 0);
        xor_inplace_8!($buf, $val, 8);
        xor_inplace_8!($buf, $val, 16);
        xor_inplace_8!($buf, $val, 24);
        xor_inplace_8!($buf, $val, 32);
        xor_inplace_8!($buf, $val, 40);
        xor_inplace_8!($buf, $val, 48);
        xor_inplace_8!($buf, $val, 56);
        xor_inplace_8!($buf, $val, 64);
        xor_inplace_8!($buf, $val, 72);
        xor_inplace_8!($buf, $val, 80);
        xor_inplace_8!($buf, $val, 88);
        xor_inplace_8!($buf, $val, 96);
        xor_inplace_8!($buf, $val, 104);
        xor_inplace_8!($buf, $val, 112);
        xor_inplace_8!($buf, $val, 120);
    }};
}

// ============================================================================
// HMAC-SHA256
// ============================================================================

use hpcrypt_hash::sha256::{Sha256, BLOCK_LEN as SHA256_BLOCK_LEN};

/// HMAC-SHA256 with precomputed hash states
///
/// Stores the hash state after processing (K ⊕ ipad) and (K ⊕ opad),
/// allowing efficient computation when the same key is used for multiple messages.
pub struct HmacSha256 {
    /// Precomputed inner hash state
    inner_state: Sha256,
    /// Precomputed outer hash state
    outer_state: Sha256,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance with the given key
    ///
    /// This performs the one-time precomputation of inner and outer hash states.
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA256_BLOCK_LEN];

        if key.len() > SHA256_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..32].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA256_BLOCK_LEN];
        xor_block_64!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha256::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_64!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha256::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    /// Compute HMAC-SHA256 for the given data
    #[inline]
    pub fn compute(&self, data: &[u8]) -> [u8; 32] {
        // Clone precomputed inner state and process message
        let mut inner = self.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = self.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Verify an HMAC tag in constant time
    #[inline]
    pub fn verify(&self, data: &[u8], tag: &[u8; 32]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }

    /// Compute truncated HMAC-SHA256
    ///
    /// Returns the first N bytes of the HMAC. Per RFC 2104, N should be
    /// at least half the hash output (16 bytes for SHA-256) and at least 10 bytes.
    #[inline]
    pub fn compute_truncated<const N: usize>(&self, data: &[u8]) -> [u8; N] {
        assert!(N <= 32, "truncation length cannot exceed 32 bytes");
        assert!(N >= 10, "truncation length must be at least 10 bytes (80 bits)");

        let full = self.compute(data);
        let mut truncated = [0u8; N];
        truncated.copy_from_slice(&full[..N]);
        truncated
    }

    /// Verify a truncated HMAC tag in constant time
    #[inline]
    pub fn verify_truncated<const N: usize>(&self, data: &[u8], tag: &[u8; N]) -> bool {
        assert!(N <= 32, "truncation length cannot exceed 32 bytes");
        assert!(N >= 10, "truncation length must be at least 10 bytes");

        use hpcrypt_core::ct::CtEqual;
        let computed: [u8; N] = self.compute_truncated(data);
        computed.ct_eq(tag).into()
    }

    /// Start a streaming HMAC computation
    #[inline]
    pub fn start(&self) -> HmacSha256Context {
        HmacSha256Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

// ============================================================================
// Streaming HMAC-SHA256 Context
// ============================================================================

/// Streaming HMAC-SHA256 context for incremental updates
pub struct HmacSha256Context {
    inner: Sha256,
    outer_state: Sha256,
}

impl HmacSha256Context {
    /// Update the HMAC computation with additional data
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the HMAC tag
    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Finalize and verify against expected tag in constant time
    #[inline]
    pub fn verify(self, tag: &[u8; 32]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.finalize();
        computed.ct_eq(tag).into()
    }
}

// ============================================================================
// HMAC-SHA384
// ============================================================================

use hpcrypt_hash::sha384::{Sha384, BLOCK_LEN as SHA384_BLOCK_LEN};

/// HMAC-SHA384 with precomputed hash states
pub struct HmacSha384 {
    inner_state: Sha384,
    outer_state: Sha384,
}

impl HmacSha384 {
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = [0u8; SHA384_BLOCK_LEN];

        if key.len() > SHA384_BLOCK_LEN {
            let mut hasher = Sha384::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..48].copy_from_slice(&hash);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut ipad_key = [0u8; SHA384_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        let mut inner_state = Sha384::new();
        inner_state.update(&ipad_key);

        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        let mut outer_state = Sha384::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    pub fn compute(&self, data: &[u8]) -> [u8; 48] {
        let mut inner = self.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = self.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    pub fn verify(&self, data: &[u8], tag: &[u8; 48]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }

    /// Start a streaming HMAC computation
    #[inline]
    pub fn start(&self) -> HmacSha384Context {
        HmacSha384Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

/// Streaming HMAC-SHA384 context
pub struct HmacSha384Context {
    inner: Sha384,
    outer_state: Sha384,
}

impl HmacSha384Context {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    pub fn finalize(self) -> [u8; 48] {
        let inner_hash = self.inner.finalize();
        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    pub fn verify(self, tag: &[u8; 48]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.finalize();
        computed.ct_eq(tag).into()
    }
}

// ============================================================================
// HMAC-SHA512
// ============================================================================

use hpcrypt_hash::sha512::{Sha512, BLOCK_LEN as SHA512_BLOCK_LEN};

/// HMAC-SHA512 with precomputed hash states
pub struct HmacSha512 {
    inner_state: Sha512,
    outer_state: Sha512,
}

impl HmacSha512 {
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = [0u8; SHA512_BLOCK_LEN];

        if key.len() > SHA512_BLOCK_LEN {
            let mut hasher = Sha512::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..64].copy_from_slice(&hash);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut ipad_key = [0u8; SHA512_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        let mut inner_state = Sha512::new();
        inner_state.update(&ipad_key);

        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        let mut outer_state = Sha512::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    pub fn compute(&self, data: &[u8]) -> [u8; 64] {
        let mut inner = self.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = self.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    pub fn verify(&self, data: &[u8], tag: &[u8; 64]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }

    /// Start a streaming HMAC computation
    #[inline]
    pub fn start(&self) -> HmacSha512Context {
        HmacSha512Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

/// Streaming HMAC-SHA512 context
pub struct HmacSha512Context {
    inner: Sha512,
    outer_state: Sha512,
}

impl HmacSha512Context {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    pub fn finalize(self) -> [u8; 64] {
        let inner_hash = self.inner.finalize();
        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    pub fn verify(self, tag: &[u8; 64]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.finalize();
        computed.ct_eq(tag).into()
    }
}

// ============================================================================
// HMAC-BLAKE2b
// ============================================================================

use hpcrypt_hash::blake2b::{Blake2b, BLOCK_LEN as BLAKE2B_BLOCK_LEN};

/// HMAC-BLAKE2b with precomputed hash states
///
/// Note: BLAKE2b has native keyed mode which is more efficient,
/// but this provides HMAC compatibility.
pub struct HmacBlake2b {
    inner_state: Blake2b,
    outer_state: Blake2b,
}

impl HmacBlake2b {
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = [0u8; BLAKE2B_BLOCK_LEN];

        if key.len() > BLAKE2B_BLOCK_LEN {
            let hash = hpcrypt_hash::blake2b::blake2b(key);
            padded_key[..64].copy_from_slice(&hash);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut ipad_key = [0u8; BLAKE2B_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        let mut inner_state = Blake2b::new();
        inner_state.update(&ipad_key);

        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        let mut outer_state = Blake2b::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    pub fn compute(&self, data: &[u8]) -> [u8; 64] {
        let mut inner = self.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = self.outer_state.clone();
        outer.update(&inner_hash);
        let result = outer.finalize();

        // Convert Vec to array
        let mut out = [0u8; 64];
        out.copy_from_slice(&result);
        out
    }
}

// ============================================================================
// One-shot functions
// ============================================================================

/// One-shot HMAC-SHA256
#[inline]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let hmac = HmacSha256::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-SHA384
#[inline]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let hmac = HmacSha384::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-SHA512
#[inline]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let hmac = HmacSha512::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-BLAKE2b
#[inline]
pub fn hmac_blake2b(key: &[u8], data: &[u8]) -> [u8; 64] {
    let hmac = HmacBlake2b::new(key);
    hmac.compute(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test vectors for HMAC-SHA256
    #[test]
    fn test_hmac_sha256_rfc4231_1() {
        let key = [0x0b; 20];
        let data = b"Hi There";

        let mac = hmac_sha256(&key, data);
        let expected =
            hex_literal::hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let mac = hmac_sha256(key, data);
        let expected =
            hex_literal::hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_3() {
        let key = [0xaa; 20];
        let data = [0xdd; 50];

        let mac = hmac_sha256(&key, &data);
        let expected =
            hex_literal::hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // Test with key longer than block size (should be hashed)
        let key = [0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let mac = hmac_sha256(&key, data);
        let expected =
            hex_literal::hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let hmac = HmacSha256::new(key);
        let mac = hmac.compute(data);

        // Should verify correctly
        assert!(hmac.verify(data, &mac));

        // Should fail with wrong tag
        let mut wrong_mac = mac;
        wrong_mac[0] ^= 1;
        assert!(!hmac.verify(data, &wrong_mac));

        // Should fail with wrong data
        assert!(!hmac.verify(b"wrong data", &mac));
    }

    #[test]
    fn test_hmac_sha512_basic() {
        let key = b"secret key";
        let data = b"message";

        let mac = hmac_sha512(key, data);
        assert_eq!(mac.len(), 64);

        // Should be deterministic
        let mac2 = hmac_sha512(key, data);
        assert_eq!(mac, mac2);

        // Should differ with different key
        let mac3 = hmac_sha512(b"different key", data);
        assert_ne!(mac, mac3);
    }

    #[test]
    fn test_hmac_blake2b_basic() {
        let key = b"secret key";
        let data = b"message";

        let mac = hmac_blake2b(key, data);
        assert_eq!(mac.len(), 64);

        // Should be deterministic
        let mac2 = hmac_blake2b(key, data);
        assert_eq!(mac, mac2);
    }

    #[test]
    fn test_hmac_key_reuse() {
        let key = b"shared secret key";
        let hmac = HmacSha256::new(key);

        // Multiple messages with same key should work correctly
        let mac1 = hmac.compute(b"message 1");
        let mac2 = hmac.compute(b"message 2");
        let mac3 = hmac.compute(b"message 1");

        assert_ne!(mac1, mac2);
        assert_eq!(mac1, mac3);
    }

    #[test]
    fn test_hmac_streaming_sha256() {
        let key = b"secret key";
        let data = b"hello world this is a test message";

        // One-shot computation
        let hmac = HmacSha256::new(key);
        let expected = hmac.compute(data);

        // Streaming computation (single update)
        let mut ctx = hmac.start();
        ctx.update(data);
        let streaming_result = ctx.finalize();
        assert_eq!(expected, streaming_result);

        // Streaming computation (multiple updates)
        let mut ctx = hmac.start();
        ctx.update(b"hello ");
        ctx.update(b"world ");
        ctx.update(b"this is a test message");
        let chunked_result = ctx.finalize();
        assert_eq!(expected, chunked_result);
    }

    #[test]
    fn test_hmac_streaming_verify() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let hmac = HmacSha256::new(key);
        let tag = hmac.compute(data);

        // Verify via streaming
        let mut ctx = hmac.start();
        ctx.update(data);
        assert!(ctx.verify(&tag));
    }

    #[test]
    fn test_hmac_truncated() {
        let key = b"secret key";
        let data = b"message";

        let hmac = HmacSha256::new(key);
        let full = hmac.compute(data);

        // 16-byte truncation (128 bits)
        let truncated_16: [u8; 16] = hmac.compute_truncated(data);
        assert_eq!(&truncated_16[..], &full[..16]);

        // 12-byte truncation (96 bits)
        let truncated_12: [u8; 12] = hmac.compute_truncated(data);
        assert_eq!(&truncated_12[..], &full[..12]);

        // 10-byte minimum
        let truncated_10: [u8; 10] = hmac.compute_truncated(data);
        assert_eq!(&truncated_10[..], &full[..10]);

        // Verify truncated
        assert!(hmac.verify_truncated(data, &truncated_16));
    }

    #[test]
    #[should_panic(expected = "truncation length must be at least 10 bytes")]
    fn test_hmac_truncated_too_short() {
        let hmac = HmacSha256::new(b"key");
        let _: [u8; 8] = hmac.compute_truncated(b"data");
    }
}
