//! HMAC (Hash-based Message Authentication Code)
//!
//! HMAC provides message authentication using a cryptographic hash function
//! combined with a secret key. Specified in RFC 2104 and FIPS 198-1.
//!
//! HMAC can be used with any cryptographic hash function (e.g., SHA-256, SHA-512, BLAKE2).
//!
//! Security properties:
//! - Provides message authenticity and integrity
//! - Resists length extension attacks
//! - Key-dependent pseudorandom function

extern crate alloc;
use alloc::vec::Vec;

/// Inner padding byte
const IPAD: u8 = 0x36;

/// Outer padding byte
const OPAD: u8 = 0x5C;

/// HMAC-SHA256
pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance with the given key
    pub fn new(key: &[u8]) -> Self {
        use hpcrypt_hash::sha256::{Sha256, BLOCK_LEN};

        let mut derived_key = Vec::with_capacity(BLOCK_LEN);

        // If key is longer than block size, hash it first
        if key.len() > BLOCK_LEN {
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(key);
                hasher.finalize()
            };
            derived_key.extend_from_slice(&hash);
        } else {
            derived_key.extend_from_slice(key);
        }

        // Pad key to block size
        derived_key.resize(BLOCK_LEN, 0);

        Self { key: derived_key }
    }

    /// Compute HMAC-SHA256
    pub fn compute(&self, data: &[u8]) -> [u8; 32] {
        use hpcrypt_hash::sha256::{Sha256, BLOCK_LEN};

        // Compute inner hash: H((K ⊕ ipad) || message)
        let mut inner = Sha256::new();

        // XOR key with ipad (key is already padded to BLOCK_LEN)
        let mut ipad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            ipad_key[i] = self.key[i] ^ IPAD;
        }
        inner.update(&ipad_key);
        inner.update(data);
        let inner_hash = inner.finalize();

        // Compute outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer = Sha256::new();

        // XOR key with opad
        let mut opad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            opad_key[i] = self.key[i] ^ OPAD;
        }
        outer.update(&opad_key);
        outer.update(&inner_hash);
        outer.finalize()
    }

    /// Verify an HMAC tag in constant time
    pub fn verify(&self, data: &[u8], tag: &[u8; 32]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }
}

/// HMAC-SHA384
pub struct HmacSha384 {
    key: Vec<u8>,
}

impl HmacSha384 {
    pub fn new(key: &[u8]) -> Self {
        use hpcrypt_hash::sha384::{Sha384, BLOCK_LEN};

        let mut derived_key = Vec::with_capacity(BLOCK_LEN);

        if key.len() > BLOCK_LEN {
            let hash = {
                let mut hasher = Sha384::new();
                hasher.update(key);
                hasher.finalize()
            };
            derived_key.extend_from_slice(&hash);
        } else {
            derived_key.extend_from_slice(key);
        }

        derived_key.resize(BLOCK_LEN, 0);

        Self { key: derived_key }
    }

    pub fn compute(&self, data: &[u8]) -> [u8; 48] {
        use hpcrypt_hash::sha384::{Sha384, BLOCK_LEN};

        // Compute inner hash: H((K ⊕ ipad) || message)
        let mut inner = Sha384::new();
        let mut ipad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            ipad_key[i] = self.key[i] ^ IPAD;
        }
        inner.update(&ipad_key);
        inner.update(data);
        let inner_hash = inner.finalize();

        // Compute outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer = Sha384::new();
        let mut opad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            opad_key[i] = self.key[i] ^ OPAD;
        }
        outer.update(&opad_key);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn verify(&self, data: &[u8], tag: &[u8; 48]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }
}

/// HMAC-SHA512
pub struct HmacSha512 {
    key: Vec<u8>,
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        use hpcrypt_hash::sha512::{Sha512, BLOCK_LEN};

        let mut derived_key = Vec::with_capacity(BLOCK_LEN);

        if key.len() > BLOCK_LEN {
            let hash = {
                let mut hasher = Sha512::new();
                hasher.update(key);
                hasher.finalize()
            };
            derived_key.extend_from_slice(&hash);
        } else {
            derived_key.extend_from_slice(key);
        }

        derived_key.resize(BLOCK_LEN, 0);

        Self { key: derived_key }
    }

    pub fn compute(&self, data: &[u8]) -> [u8; 64] {
        use hpcrypt_hash::sha512::{Sha512, BLOCK_LEN};

        // Compute inner hash: H((K ⊕ ipad) || message)
        let mut inner = Sha512::new();
        let mut ipad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            ipad_key[i] = self.key[i] ^ IPAD;
        }
        inner.update(&ipad_key);
        inner.update(data);
        let inner_hash = inner.finalize();

        // Compute outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer = Sha512::new();
        let mut opad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            opad_key[i] = self.key[i] ^ OPAD;
        }
        outer.update(&opad_key);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn verify(&self, data: &[u8], tag: &[u8; 64]) -> bool {
        use hpcrypt_core::ct::CtEqual;
        let computed = self.compute(data);
        computed.ct_eq(tag).into()
    }
}

/// HMAC-BLAKE2b
pub struct HmacBlake2b {
    key: Vec<u8>,
}

impl HmacBlake2b {
    pub fn new(key: &[u8]) -> Self {
        use hpcrypt_hash::blake2b::BLOCK_LEN;

        let mut derived_key = Vec::with_capacity(BLOCK_LEN);

        if key.len() > BLOCK_LEN {
            let hash = hpcrypt_hash::blake2b::blake2b(key);
            derived_key.extend_from_slice(&hash);
        } else {
            derived_key.extend_from_slice(key);
        }

        derived_key.resize(BLOCK_LEN, 0);

        Self { key: derived_key }
    }

    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        use hpcrypt_hash::blake2b::{Blake2b, BLOCK_LEN};

        // Compute inner hash: H((K ⊕ ipad) || message)
        let mut inner = Blake2b::new();
        let mut ipad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            ipad_key[i] = self.key[i] ^ IPAD;
        }
        inner.update(&ipad_key);
        inner.update(data);
        let inner_hash = inner.finalize();

        // Compute outer hash: H((K ⊕ opad) || inner_hash)
        let mut outer = Blake2b::new();
        let mut opad_key = [0u8; BLOCK_LEN];
        #[allow(clippy::needless_range_loop)]
        for i in 0..BLOCK_LEN {
            opad_key[i] = self.key[i] ^ OPAD;
        }
        outer.update(&opad_key);
        outer.update(&inner_hash);
        outer.finalize()
    }
}

/// One-shot HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let hmac = HmacSha256::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-SHA384
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let hmac = HmacSha384::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-SHA512
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let hmac = HmacSha512::new(key);
    hmac.compute(data)
}

/// One-shot HMAC-BLAKE2b
pub fn hmac_blake2b(key: &[u8], data: &[u8]) -> Vec<u8> {
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
}
