//! CMAC - Cipher-based Message Authentication Code (NIST SP 800-38B)
//!
//! CMAC is a block cipher-based MAC algorithm that provides message authentication
//! using a block cipher (typically AES). It's used in various cryptographic protocols
//! and standards.
//!
//! # References
//!
//! - [NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
//! - [RFC 4493: The AES-CMAC Algorithm](https://tools.ietf.org/html/rfc4493)

use hpcrypt_cipher::Aes;

const BLOCK_SIZE: usize = 16; // AES block size

/// AES-CMAC with 128-bit key
pub struct AesCmac128 {
    cipher: Aes,
    subkey1: [u8; BLOCK_SIZE],
    subkey2: [u8; BLOCK_SIZE],
}

impl AesCmac128 {
    /// Create a new AES-CMAC instance with a 128-bit key
    pub fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes::new_128(key);
        let (subkey1, subkey2) = generate_subkeys(&cipher);

        Self {
            cipher,
            subkey1,
            subkey2,
        }
    }

    /// Compute CMAC tag for given message
    pub fn compute(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        // Fast path for exactly 16 bytes
        if message.len() == BLOCK_SIZE {
            return self.compute_exact_16(message);
        }

        // Fast path for short messages
        if message.len() < BLOCK_SIZE {
            return self.compute_short(message);
        }

        let last_block_complete = message.len() % BLOCK_SIZE == 0;
        let total_blocks = if last_block_complete {
            message.len() / BLOCK_SIZE
        } else {
            (message.len() / BLOCK_SIZE) + 1
        };

        // Specialized paths for 2-4 blocks
        match total_blocks {
            2 => return self.compute_2_blocks(message, last_block_complete),
            3 => return self.compute_3_blocks(message, last_block_complete),
            4 => return self.compute_4_blocks(message, last_block_complete),
            _ => {}
        }

        // General path for 5+ blocks
        let (n_blocks, last_block_start) = if last_block_complete {
            (
                message.len() / BLOCK_SIZE - 1,
                (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE,
            )
        } else {
            (
                message.len() / BLOCK_SIZE,
                (message.len() / BLOCK_SIZE) * BLOCK_SIZE,
            )
        };

        let mut c = [0u8; BLOCK_SIZE];

        for block in message[..n_blocks * BLOCK_SIZE].chunks_exact(BLOCK_SIZE) {
            xor_block_slice(&mut c, block);
            c = self.cipher.encrypt_block(&c);
        }

        if last_block_complete {
            xor_block_slice(&mut c, &message[last_block_start..]);
            xor_block(&mut c, &self.subkey1);
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - last_block_start;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[last_block_start..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
        }

        self.cipher.encrypt_block(&c)
    }

    /// Fast path for exactly 16 bytes
    #[inline]
    fn compute_exact_16(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        debug_assert_eq!(message.len(), BLOCK_SIZE);

        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(message);
        xor_block(&mut block, &self.subkey1);
        self.cipher.encrypt_block(&block)
    }

    /// Fast path for messages < 16 bytes
    #[inline]
    fn compute_short(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        debug_assert!(message.len() < BLOCK_SIZE);

        let mut block = [0u8; BLOCK_SIZE];
        if !message.is_empty() {
            block[..message.len()].copy_from_slice(message);
        }
        block[message.len()] = 0x80;
        xor_block(&mut block, &self.subkey2);

        self.cipher.encrypt_block(&block)
    }

    /// Specialized path for exactly 2 blocks (32 bytes)
    #[inline]
    fn compute_2_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        if complete {
            xor_block_slice(&mut c, &message[0..BLOCK_SIZE]);
            c = self.cipher.encrypt_block(&c);

            xor_block_slice(&mut c, &message[BLOCK_SIZE..2 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            xor_block_slice(&mut c, &message[0..BLOCK_SIZE]);
            c = self.cipher.encrypt_block(&c);

            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Specialized path for exactly 3 blocks (48 bytes)
    #[inline]
    fn compute_3_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        macro_rules! process_block {
            ($offset:expr) => {
                xor_block_slice(&mut c, &message[$offset..$offset + BLOCK_SIZE]);
                c = self.cipher.encrypt_block(&c);
            };
        }

        process_block!(0 * BLOCK_SIZE);
        process_block!(1 * BLOCK_SIZE);

        if complete {
            xor_block_slice(&mut c, &message[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - 2 * BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[2 * BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Specialized path for exactly 4 blocks (64 bytes)
    #[inline]
    fn compute_4_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        macro_rules! process_blocks {
            ($($offset:expr),*) => {
                $(
                    xor_block_slice(&mut c, &message[$offset * BLOCK_SIZE..($offset + 1) * BLOCK_SIZE]);
                    c = self.cipher.encrypt_block(&c);
                )*
            };
        }

        process_blocks!(0, 1, 2);

        if complete {
            xor_block_slice(&mut c, &message[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - 3 * BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[3 * BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Verify a CMAC tag
    pub fn verify(&self, message: &[u8], tag: &[u8; BLOCK_SIZE]) -> bool {
        let computed = self.compute(message);
        constant_time_compare(&computed, tag)
    }
}

/// AES-CMAC with 256-bit key
pub struct AesCmac256 {
    cipher: Aes,
    subkey1: [u8; BLOCK_SIZE],
    subkey2: [u8; BLOCK_SIZE],
}

impl AesCmac256 {
    /// Create a new AES-CMAC instance with a 256-bit key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes::new_256(key);
        let (subkey1, subkey2) = generate_subkeys(&cipher);

        Self {
            cipher,
            subkey1,
            subkey2,
        }
    }

    /// Compute CMAC tag for given message
    pub fn compute(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        // Fast path for exactly 16 bytes
        if message.len() == BLOCK_SIZE {
            return self.compute_exact_16(message);
        }

        // Fast path for short messages
        if message.len() < BLOCK_SIZE {
            return self.compute_short(message);
        }

        let last_block_complete = message.len() % BLOCK_SIZE == 0;
        let total_blocks = if last_block_complete {
            message.len() / BLOCK_SIZE
        } else {
            (message.len() / BLOCK_SIZE) + 1
        };

        // Specialized paths for 2-4 blocks
        match total_blocks {
            2 => return self.compute_2_blocks(message, last_block_complete),
            3 => return self.compute_3_blocks(message, last_block_complete),
            4 => return self.compute_4_blocks(message, last_block_complete),
            _ => {}
        }

        // General path for 5+ blocks
        let (n_blocks, last_block_start) = if last_block_complete {
            (
                message.len() / BLOCK_SIZE - 1,
                (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE,
            )
        } else {
            (
                message.len() / BLOCK_SIZE,
                (message.len() / BLOCK_SIZE) * BLOCK_SIZE,
            )
        };

        let mut c = [0u8; BLOCK_SIZE];

        for block in message[..n_blocks * BLOCK_SIZE].chunks_exact(BLOCK_SIZE) {
            xor_block_slice(&mut c, block);
            c = self.cipher.encrypt_block(&c);
        }

        if last_block_complete {
            xor_block_slice(&mut c, &message[last_block_start..]);
            xor_block(&mut c, &self.subkey1);
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - last_block_start;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[last_block_start..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
        }

        self.cipher.encrypt_block(&c)
    }

    /// Fast path for exactly 16 bytes
    #[inline]
    fn compute_exact_16(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        debug_assert_eq!(message.len(), BLOCK_SIZE);

        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(message);
        xor_block(&mut block, &self.subkey1);
        self.cipher.encrypt_block(&block)
    }

    /// Fast path for messages < 16 bytes
    #[inline]
    fn compute_short(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        debug_assert!(message.len() < BLOCK_SIZE);

        let mut block = [0u8; BLOCK_SIZE];
        if !message.is_empty() {
            block[..message.len()].copy_from_slice(message);
        }
        block[message.len()] = 0x80;
        xor_block(&mut block, &self.subkey2);

        self.cipher.encrypt_block(&block)
    }

    /// Specialized path for exactly 2 blocks (32 bytes)
    #[inline]
    fn compute_2_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        if complete {
            xor_block_slice(&mut c, &message[0..BLOCK_SIZE]);
            c = self.cipher.encrypt_block(&c);

            xor_block_slice(&mut c, &message[BLOCK_SIZE..2 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            xor_block_slice(&mut c, &message[0..BLOCK_SIZE]);
            c = self.cipher.encrypt_block(&c);

            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Specialized path for exactly 3 blocks (48 bytes)
    #[inline]
    fn compute_3_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        macro_rules! process_block {
            ($offset:expr) => {
                xor_block_slice(&mut c, &message[$offset..$offset + BLOCK_SIZE]);
                c = self.cipher.encrypt_block(&c);
            };
        }

        process_block!(0 * BLOCK_SIZE);
        process_block!(1 * BLOCK_SIZE);

        if complete {
            xor_block_slice(&mut c, &message[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - 2 * BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[2 * BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Specialized path for exactly 4 blocks (64 bytes)
    #[inline]
    fn compute_4_blocks(&self, message: &[u8], complete: bool) -> [u8; BLOCK_SIZE] {
        let mut c = [0u8; BLOCK_SIZE];

        macro_rules! process_blocks {
            ($($offset:expr),*) => {
                $(
                    xor_block_slice(&mut c, &message[$offset * BLOCK_SIZE..($offset + 1) * BLOCK_SIZE]);
                    c = self.cipher.encrypt_block(&c);
                )*
            };
        }

        process_blocks!(0, 1, 2);

        if complete {
            xor_block_slice(&mut c, &message[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
            xor_block(&mut c, &self.subkey1);
            self.cipher.encrypt_block(&c)
        } else {
            let mut last_block = [0u8; BLOCK_SIZE];
            let remaining = message.len() - 3 * BLOCK_SIZE;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[3 * BLOCK_SIZE..]);
            }
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
            xor_block(&mut c, &last_block);
            self.cipher.encrypt_block(&c)
        }
    }

    /// Verify a CMAC tag
    pub fn verify(&self, message: &[u8], tag: &[u8; BLOCK_SIZE]) -> bool {
        let computed = self.compute(message);
        constant_time_compare(&computed, tag)
    }
}

/// Generate both K1 and K2 subkeys
#[inline]
fn generate_subkeys(cipher: &Aes) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

    // Generate K1 from L
    let mut k1 = [0u8; BLOCK_SIZE];
    let mut overflow = 0u8;
    for i in (0..BLOCK_SIZE).rev() {
        k1[i] = (l[i] << 1) | overflow;
        overflow = l[i] >> 7;
    }
    let mask1 = 0u8.wrapping_sub(l[0] >> 7);
    k1[BLOCK_SIZE - 1] ^= 0x87 & mask1;

    // Generate K2 from K1
    let mut k2 = [0u8; BLOCK_SIZE];
    overflow = 0u8;
    for i in (0..BLOCK_SIZE).rev() {
        k2[i] = (k1[i] << 1) | overflow;
        overflow = k1[i] >> 7;
    }
    let mask2 = 0u8.wrapping_sub(k1[0] >> 7);
    k2[BLOCK_SIZE - 1] ^= 0x87 & mask2;

    (k1, k2)
}

/// XOR two blocks
#[inline(always)]
fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    macro_rules! xor_unroll {
        ($($i:expr),*) => {
            $(a[$i] ^= b[$i];)*
        };
    }

    xor_unroll!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
}

/// XOR array with slice
#[inline(always)]
fn xor_block_slice(a: &mut [u8; BLOCK_SIZE], b: &[u8]) {
    debug_assert_eq!(b.len(), BLOCK_SIZE);

    macro_rules! xor_unroll {
        ($($i:expr),*) => {
            $(a[$i] ^= b[$i];)*
        };
    }

    xor_unroll!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
}

/// Constant-time comparison
#[inline]
fn constant_time_compare(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> bool {
    let mut diff = 0u8;
    for i in 0..BLOCK_SIZE {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Convenience function for AES-128-CMAC
pub fn aes_cmac_128(key: &[u8; 16], message: &[u8]) -> [u8; BLOCK_SIZE] {
    let cmac = AesCmac128::new(key);
    cmac.compute(message)
}

/// Convenience function for AES-256-CMAC
pub fn aes_cmac_256(key: &[u8; 32], message: &[u8]) -> [u8; BLOCK_SIZE] {
    let cmac = AesCmac256::new(key);
    cmac.compute(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_cmac_128_rfc4493() {
        // RFC 4493 Test Vector 1: Empty message
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let message = b"";
        let expected = hex_literal::hex!("bb1d6929e95937287fa37d129b756746");

        let cmac = AesCmac128::new(&key);
        let tag = cmac.compute(message);

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_aes_cmac_128_rfc4493_16bytes() {
        // RFC 4493 Test Vector 2: 16-byte message
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let message = hex_literal::hex!("6bc1bee22e409f96e93d7e117393172a");
        let expected = hex_literal::hex!("070a16b46b4d4144f79bdd9dd04a287c");

        let cmac = AesCmac128::new(&key);
        let tag = cmac.compute(&message);

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_aes_cmac_128_rfc4493_40bytes() {
        // RFC 4493 Test Vector 3: 40-byte message
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let message = hex_literal::hex!(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411"
        );
        let expected = hex_literal::hex!("dfa66747de9ae63030ca32611497c827");

        let cmac = AesCmac128::new(&key);
        let tag = cmac.compute(&message);

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_aes_cmac_128_rfc4493_64bytes() {
        // RFC 4493 Test Vector 4: 64-byte message
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let message = hex_literal::hex!(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710"
        );
        let expected = hex_literal::hex!("51f0bebf7e3b9d92fc49741779363cfe");

        let cmac = AesCmac128::new(&key);
        let tag = cmac.compute(&message);

        assert_eq!(tag, expected);
    }

    #[test]
    fn test_aes_cmac_128_verify() {
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let message = b"test message";

        let cmac = AesCmac128::new(&key);
        let tag = cmac.compute(message);

        // Correct tag should verify
        assert!(cmac.verify(message, &tag));

        // Wrong tag should not verify
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert!(!cmac.verify(message, &wrong_tag));
    }

    #[test]
    fn test_aes_cmac_256_basic() {
        let key = [0x42; 32];
        let message = b"Hello, AES-CMAC-256!";

        let cmac = AesCmac256::new(&key);
        let tag1 = cmac.compute(message);
        let tag2 = cmac.compute(message);

        // Same input should produce same output
        assert_eq!(tag1, tag2);

        // Verification should work
        assert!(cmac.verify(message, &tag1));

        // Different message should produce different tag
        let tag3 = cmac.compute(b"Different message");
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_combined_subkey_generation() {
        let key = hex_literal::hex!("2b7e151628aed2a6abf7158809cf4f3c");
        let cipher = Aes::new_128(&key);

        let (k1, k2) = generate_subkeys(&cipher);

        // K1 and K2 should be different
        assert_ne!(k1, k2);

        // Should not be all zeros
        assert_ne!(k1, [0u8; BLOCK_SIZE]);
        assert_ne!(k2, [0u8; BLOCK_SIZE]);
    }
}
