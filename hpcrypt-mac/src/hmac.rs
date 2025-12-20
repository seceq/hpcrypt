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

use hpcrypt_hash::HashFunction;
use hpcrypt_hash::sha256::{Sha256, BLOCK_LEN as SHA256_BLOCK_LEN};

/// HMAC-SHA256 with precomputed hash states
///
/// Stores the hash state after processing (K ⊕ ipad) and (K ⊕ opad),
/// allowing efficient computation when the same key is used for multiple messages.
#[derive(Clone)]
pub struct HmacSha256 {
    /// Precomputed inner hash state
    inner_state: Sha256,
    /// Precomputed outer hash state
    outer_state: Sha256,
}

impl HmacSha256 {
    // All public methods removed - now only available through Mac trait
    // Private/internal helpers can remain here if needed
}

// ============================================================================
// Streaming HMAC-SHA256 Context
// ============================================================================

/// Streaming HMAC-SHA256 context for incremental updates
#[derive(Clone)]
pub struct HmacSha256Context {
    inner: Sha256,
    outer_state: Sha256,
}

impl HmacSha256Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-SHA384
// ============================================================================

use hpcrypt_hash::sha384::{Sha384, BLOCK_LEN as SHA384_BLOCK_LEN};

/// HMAC-SHA384 with precomputed hash states
#[derive(Clone)]
pub struct HmacSha384 {
    inner_state: Sha384,
    outer_state: Sha384,
}

impl HmacSha384 {
    // All public methods removed - now only available through Mac trait
    // Private/internal helpers can remain here if needed
}

/// Streaming HMAC-SHA384 context
#[derive(Clone)]
pub struct HmacSha384Context {
    inner: Sha384,
    outer_state: Sha384,
}

impl HmacSha384Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-SHA512
// ============================================================================

use hpcrypt_hash::sha512::{Sha512, BLOCK_LEN as SHA512_BLOCK_LEN};

/// HMAC-SHA512 with precomputed hash states
#[derive(Clone)]
pub struct HmacSha512 {
    inner_state: Sha512,
    outer_state: Sha512,
}

impl HmacSha512 {
    // All public methods removed - now only available through Mac trait
    // Private/internal helpers can remain here if needed
}

/// Streaming HMAC-SHA512 context
#[derive(Clone)]
pub struct HmacSha512Context {
    inner: Sha512,
    outer_state: Sha512,
}

impl HmacSha512Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-SHA224
// ============================================================================

use hpcrypt_hash::sha224::{Sha224, BLOCK_LEN as SHA224_BLOCK_LEN};

/// HMAC-SHA224 with precomputed hash states
#[derive(Clone)]
pub struct HmacSha224 {
    inner_state: Sha224,
    outer_state: Sha224,
}

impl HmacSha224 {
    // All public methods removed - now only available through Mac trait
}

/// Streaming HMAC-SHA224 context
#[derive(Clone)]
pub struct HmacSha224Context {
    inner: Sha224,
    outer_state: Sha224,
}

impl HmacSha224Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-SHA512/224
// ============================================================================

use hpcrypt_hash::sha512_224::{Sha512_224, BLOCK_LEN as SHA512_224_BLOCK_LEN};

/// HMAC-SHA512/224 with precomputed hash states
#[derive(Clone)]
pub struct HmacSha512_224 {
    inner_state: Sha512_224,
    outer_state: Sha512_224,
}

impl HmacSha512_224 {
    // All public methods removed - now only available through Mac trait
}

/// Streaming HMAC-SHA512/224 context
#[derive(Clone)]
pub struct HmacSha512_224Context {
    inner: Sha512_224,
    outer_state: Sha512_224,
}

impl HmacSha512_224Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-SHA512/256
// ============================================================================

use hpcrypt_hash::sha512_256::{Sha512_256, BLOCK_LEN as SHA512_256_BLOCK_LEN};

/// HMAC-SHA512/256 with precomputed hash states
#[derive(Clone)]
pub struct HmacSha512_256 {
    inner_state: Sha512_256,
    outer_state: Sha512_256,
}

impl HmacSha512_256 {
    // All public methods removed - now only available through Mac trait
}

/// Streaming HMAC-SHA512/256 context
#[derive(Clone)]
pub struct HmacSha512_256Context {
    inner: Sha512_256,
    outer_state: Sha512_256,
}

impl HmacSha512_256Context {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// HMAC-BLAKE2b
// ============================================================================

use hpcrypt_hash::blake2b::{Blake2b, BLOCK_LEN as BLAKE2B_BLOCK_LEN};

/// HMAC-BLAKE2b with precomputed hash states
///
/// Note: BLAKE2b has native keyed mode which is more efficient,
/// but this provides HMAC compatibility.
#[derive(Clone)]
pub struct HmacBlake2b {
    inner_state: Blake2b,
    outer_state: Blake2b,
}

impl HmacBlake2b {
    // All public methods removed - now only available through Mac trait
    // Private/internal helpers can remain here if needed
}

/// Streaming HMAC-BLAKE2b context
#[derive(Clone)]
pub struct HmacBlake2bContext {
    inner: Blake2b,
    outer_state: Blake2b,
}

impl HmacBlake2bContext {
    // All public methods removed - now only available through MacContext trait
}

// ============================================================================
// One-shot functions
// ============================================================================

/// One-shot HMAC-SHA256
#[inline]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use crate::traits::Mac;
    HmacSha256::compute(key, data)
}

/// One-shot HMAC-SHA384
#[inline]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    use crate::traits::Mac;
    HmacSha384::compute(key, data)
}

/// One-shot HMAC-SHA512
#[inline]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use crate::traits::Mac;
    HmacSha512::compute(key, data)
}

/// One-shot HMAC-SHA224
#[inline]
pub fn hmac_sha224(key: &[u8], data: &[u8]) -> [u8; 28] {
    use crate::traits::Mac;
    HmacSha224::compute(key, data)
}

/// One-shot HMAC-SHA512/224
#[inline]
pub fn hmac_sha512_224(key: &[u8], data: &[u8]) -> [u8; 28] {
    use crate::traits::Mac;
    HmacSha512_224::compute(key, data)
}

/// One-shot HMAC-SHA512/256
#[inline]
pub fn hmac_sha512_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use crate::traits::Mac;
    HmacSha512_256::compute(key, data)
}

/// One-shot HMAC-BLAKE2b
#[inline]
pub fn hmac_blake2b(key: &[u8], data: &[u8]) -> [u8; 64] {
    use crate::traits::Mac;
    HmacBlake2b::compute(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Mac;

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
        use subtle::ConstantTimeEq;
        let key = b"secret key";
        let data = b"message to authenticate";

        let computed = HmacSha256::compute(key, data);

        // Should verify correctly
        let is_equal: bool = computed.ct_eq(&computed).into();
        assert!(is_equal);

        // Should fail with wrong tag
        let mut wrong_mac = computed;
        wrong_mac[0] ^= 1;
        let is_equal: bool = computed.ct_eq(&wrong_mac).into();
        assert!(!is_equal);

        // Should fail with wrong data
        let computed_wrong_data = HmacSha256::compute(key, b"wrong data");
        let is_equal: bool = computed.ct_eq(&computed_wrong_data).into();
        assert!(!is_equal);
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

        // Multiple messages with same key should work correctly
        let mac1 = HmacSha256::compute(key, b"message 1");
        let mac2 = HmacSha256::compute(key, b"message 2");
        let mac3 = HmacSha256::compute(key, b"message 1");

        assert_ne!(mac1, mac2);
        assert_eq!(mac1, mac3);
    }

    #[test]
    fn test_hmac_streaming_sha256() {
        use crate::traits::MacContext;
        let key = b"secret key";
        let data = b"hello world this is a test message";

        // One-shot computation
        let expected = HmacSha256::compute(key, data);

        // Streaming computation (single update)
        let mut ctx = HmacSha256::new_context(key);
        ctx.update(data);
        let streaming_result = ctx.finalize();
        assert_eq!(expected, streaming_result);

        // Streaming computation (multiple updates)
        let mut ctx = HmacSha256::new_context(key);
        ctx.update(b"hello ");
        ctx.update(b"world ");
        ctx.update(b"this is a test message");
        let chunked_result = ctx.finalize();
        assert_eq!(expected, chunked_result);
    }

    #[test]
    fn test_hmac_streaming_verify() {
        use crate::traits::MacContext;
        let key = b"secret key";
        let data = b"message to authenticate";

        let tag = HmacSha256::compute(key, data);

        // Verify via streaming
        let mut ctx = HmacSha256::new_context(key);
        ctx.update(data);
        assert!(ctx.verify(&tag));
    }

    #[test]
    fn test_hmac_truncated() {
        use subtle::ConstantTimeEq;
        let key = b"secret key";
        let data = b"message";

        let full = HmacSha256::compute(key, data);

        // 16-byte truncation (128 bits)
        let mut truncated_16 = [0u8; 16];
        truncated_16.copy_from_slice(&full[..16]);
        assert_eq!(&truncated_16[..], &full[..16]);

        // 12-byte truncation (96 bits)
        let mut truncated_12 = [0u8; 12];
        truncated_12.copy_from_slice(&full[..12]);
        assert_eq!(&truncated_12[..], &full[..12]);

        // 10-byte minimum
        let mut truncated_10 = [0u8; 10];
        truncated_10.copy_from_slice(&full[..10]);
        assert_eq!(&truncated_10[..], &full[..10]);

        // Verify truncated (manual comparison)
        let recomputed = HmacSha256::compute(key, data);
        let is_equal: bool = recomputed[..16].ct_eq(&truncated_16).into();
        assert!(is_equal);
    }

    #[test]
    fn test_hmac_truncated_manual_too_short() {
        // Note: Since compute_truncated was removed, this test now just verifies
        // that manual truncation to less than 10 bytes is still possible but not recommended.
        // The 10-byte minimum was an API-level restriction that no longer exists.
        let key = b"key";
        let data = b"data";
        let full = HmacSha256::compute(key, data);

        // Manual truncation to 8 bytes (not recommended for security, but technically possible)
        let mut truncated_8 = [0u8; 8];
        truncated_8.copy_from_slice(&full[..8]);
        assert_eq!(&truncated_8[..], &full[..8]);
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

impl crate::traits::Mac for HmacSha256 {
    type Output = [u8; 32];
    type Context = HmacSha256Context;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new(key: &[u8]) -> Self {
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

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha256Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha256Context {
    type Output = [u8; 32];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacSha384 {
    type Output = [u8; 48];
    type Context = HmacSha384Context;
    const OUTPUT_SIZE: usize = 48;

    #[inline]
    fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA384_BLOCK_LEN];

        if key.len() > SHA384_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha384::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..48].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA384_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha384::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha384::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha384Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha384Context {
    type Output = [u8; 48];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacSha512 {
    type Output = [u8; 64];
    type Context = HmacSha512Context;
    const OUTPUT_SIZE: usize = 64;

    #[inline]
    fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA512_BLOCK_LEN];

        if key.len() > SHA512_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha512::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..64].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA512_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha512::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha512::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha512Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha512Context {
    type Output = [u8; 64];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacSha224 {
    type Output = [u8; 28];
    type Context = HmacSha224Context;
    const OUTPUT_SIZE: usize = 28;

    #[inline]
    fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA224_BLOCK_LEN];

        if key.len() > SHA224_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha224::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..28].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA224_BLOCK_LEN];
        xor_block_64!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha224::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_64!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha224::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha224Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha224Context {
    type Output = [u8; 28];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacSha512_224 {
    type Output = [u8; 28];
    type Context = HmacSha512_224Context;
    const OUTPUT_SIZE: usize = 28;

    #[inline]
    fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA512_224_BLOCK_LEN];

        if key.len() > SHA512_224_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha512_224::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..28].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA512_224_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha512_224::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha512_224::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha512_224Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha512_224Context {
    type Output = [u8; 28];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacSha512_256 {
    type Output = [u8; 32];
    type Context = HmacSha512_256Context;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new(key: &[u8]) -> Self {
        // Derive the padded key
        let mut padded_key = [0u8; SHA512_256_BLOCK_LEN];

        if key.len() > SHA512_256_BLOCK_LEN {
            // Key longer than block size: hash it first
            let mut hasher = Sha512_256::new();
            hasher.update(key);
            let hash = hasher.finalize();
            padded_key[..32].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; SHA512_256_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Sha512_256::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Sha512_256::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacSha512_256Context {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacSha512_256Context {
    type Output = [u8; 32];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}

impl crate::traits::Mac for HmacBlake2b {
    type Output = [u8; 64];
    type Context = HmacBlake2bContext;
    const OUTPUT_SIZE: usize = 64;

    #[inline]
    fn new(key: &[u8]) -> Self {
        use hpcrypt_hash::HashFunction;
        // Derive the padded key
        let mut padded_key = [0u8; BLAKE2B_BLOCK_LEN];

        if key.len() > BLAKE2B_BLOCK_LEN {
            // Key longer than block size: hash it first
            let hash = hpcrypt_hash::blake2b::blake2b(key);
            padded_key[..64].copy_from_slice(&hash);
        } else {
            // Key shorter or equal: copy and zero-pad
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Compute (K ⊕ ipad)
        let mut ipad_key = [0u8; BLAKE2B_BLOCK_LEN];
        xor_block_128!(ipad_key, padded_key, IPAD);

        // Precompute inner state
        let mut inner_state = Blake2b::new();
        inner_state.update(&ipad_key);

        // Convert ipad_key to opad_key using XOR trick
        xor_inplace_128!(ipad_key, IPAD_XOR_OPAD);

        // Precompute outer state
        let mut outer_state = Blake2b::new();
        outer_state.update(&ipad_key);

        Self {
            inner_state,
            outer_state,
        }
    }

    #[inline]
    fn compute(key: &[u8], data: &[u8]) -> Self::Output {
        use hpcrypt_hash::HashFunction;
        let mac = Self::new(key);

        // Clone precomputed inner state and process message
        let mut inner = mac.inner_state.clone();
        inner.update(data);
        let inner_hash = inner.finalize();

        // Clone precomputed outer state and process inner hash
        let mut outer = mac.outer_state.clone();
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn start(self) -> Self::Context {
        HmacBlake2bContext {
            inner: self.inner_state.clone(),
            outer_state: self.outer_state.clone(),
        }
    }
}

impl crate::traits::MacContext for HmacBlake2bContext {
    type Output = [u8; 64];

    #[inline]
    fn update(&mut self, data: &[u8]) {
        use hpcrypt_hash::HashFunction;
        self.inner.update(data);
    }

    #[inline]
    fn finalize(self) -> Self::Output {
        use hpcrypt_hash::HashFunction;
        let inner_hash = self.inner.finalize();

        let mut outer = self.outer_state;
        outer.update(&inner_hash);
        outer.finalize()
    }

    #[inline]
    fn clone(&self) -> Self {
        Clone::clone(self)
    }
}
