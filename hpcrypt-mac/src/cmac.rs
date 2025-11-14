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

        // Generate subkeys K1 and K2
        let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

        let subkey1 = left_shift_one_bit(&l);
        let subkey2 = left_shift_one_bit(&subkey1);

        Self {
            cipher,
            subkey1,
            subkey2,
        }
    }

    /// Compute CMAC tag for given message
    pub fn compute(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        let last_block_complete = message.len() % BLOCK_SIZE == 0 && !message.is_empty();

        let (n_blocks, last_block_start) = if last_block_complete {
            // Process all but last block normally, treat last block specially
            (
                message.len() / BLOCK_SIZE - 1,
                (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE,
            )
        } else {
            // Process all complete blocks normally, treat incomplete block specially
            (
                message.len() / BLOCK_SIZE,
                (message.len() / BLOCK_SIZE) * BLOCK_SIZE,
            )
        };

        // Prepare last block
        let mut last_block = [0u8; BLOCK_SIZE];

        if last_block_complete {
            // Complete last block: XOR with K1
            last_block.copy_from_slice(&message[last_block_start..]);
            xor_block(&mut last_block, &self.subkey1);
        } else {
            // Incomplete last block: pad and XOR with K2
            let remaining = message.len() - last_block_start;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[last_block_start..]);
            }
            // Padding: append 0x80 then zeros
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
        }

        // Process complete blocks
        let mut c = [0u8; BLOCK_SIZE];

        for i in 0..n_blocks {
            let block_start = i * BLOCK_SIZE;
            let block = &message[block_start..block_start + BLOCK_SIZE];

            for j in 0..BLOCK_SIZE {
                c[j] ^= block[j];
            }

            c = self.cipher.encrypt_block(&c);
        }

        // Process last block
        for j in 0..BLOCK_SIZE {
            c[j] ^= last_block[j];
        }

        self.cipher.encrypt_block(&c)
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

        // Generate subkeys K1 and K2
        let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);

        let subkey1 = left_shift_one_bit(&l);
        let subkey2 = left_shift_one_bit(&subkey1);

        Self {
            cipher,
            subkey1,
            subkey2,
        }
    }

    /// Compute CMAC tag for given message
    pub fn compute(&self, message: &[u8]) -> [u8; BLOCK_SIZE] {
        let last_block_complete = message.len() % BLOCK_SIZE == 0 && !message.is_empty();

        let (n_blocks, last_block_start) = if last_block_complete {
            // Process all but last block normally, treat last block specially
            (
                message.len() / BLOCK_SIZE - 1,
                (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE,
            )
        } else {
            // Process all complete blocks normally, treat incomplete block specially
            (
                message.len() / BLOCK_SIZE,
                (message.len() / BLOCK_SIZE) * BLOCK_SIZE,
            )
        };

        // Prepare last block
        let mut last_block = [0u8; BLOCK_SIZE];

        if last_block_complete {
            // Complete last block: XOR with K1
            last_block.copy_from_slice(&message[last_block_start..]);
            xor_block(&mut last_block, &self.subkey1);
        } else {
            // Incomplete last block: pad and XOR with K2
            let remaining = message.len() - last_block_start;
            if remaining > 0 {
                last_block[..remaining].copy_from_slice(&message[last_block_start..]);
            }
            // Padding: append 0x80 then zeros
            last_block[remaining] = 0x80;
            xor_block(&mut last_block, &self.subkey2);
        }

        // Process complete blocks
        let mut c = [0u8; BLOCK_SIZE];

        for i in 0..n_blocks {
            let block_start = i * BLOCK_SIZE;
            let block = &message[block_start..block_start + BLOCK_SIZE];

            for j in 0..BLOCK_SIZE {
                c[j] ^= block[j];
            }

            c = self.cipher.encrypt_block(&c);
        }

        // Process last block
        for j in 0..BLOCK_SIZE {
            c[j] ^= last_block[j];
        }

        self.cipher.encrypt_block(&c)
    }

    /// Verify a CMAC tag
    pub fn verify(&self, message: &[u8], tag: &[u8; BLOCK_SIZE]) -> bool {
        let computed = self.compute(message);
        constant_time_compare(&computed, tag)
    }
}

/// Left shift by one bit (for subkey generation)
fn left_shift_one_bit(input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    let mut overflow = 0u8;

    // Process from right to left (LSB to MSB in big-endian)
    for i in (0..BLOCK_SIZE).rev() {
        output[i] = (input[i] << 1) | overflow;
        overflow = input[i] >> 7;
    }

    // If MSB of input was 1, XOR output with Rb
    // Rb for AES (128-bit block) = 0x87
    if input[0] & 0x80 != 0 {
        output[BLOCK_SIZE - 1] ^= 0x87;
    }

    output
}

/// XOR two blocks
#[inline]
fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

/// Constant-time comparison
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
}
