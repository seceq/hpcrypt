//! Ascon Hash and XOF implementations
//!
//! This module implements the Ascon family of cryptographic hash functions
//! and extendable output functions (XOFs) as specified in NIST SP 800-232.
//!
//! **Standards Compliance**: NIST SP 800-232 (Ascon v1.3)
//!
//! # Implemented Algorithms
//!
//! - **Ascon-Hash** - 256-bit cryptographic hash function
//! - **Ascon-XOF** - Extendable Output Function
//! - **Ascon-cXOF** - Customizable XOF (with customization string)
//!
//! # Security Properties
//!
//! - 128-bit security level
//! - Collision resistance (Ascon-Hash)
//! - Preimage resistance
//! - Second preimage resistance
//! - Constant-time implementation
//!
//! # Standards
//!
//! - NIST SP 800-232 (finalized August 2025)
//! - NIST Lightweight Cryptography Winner (2023)
//! - Specified in: <https://ascon.iaik.tugraz.at/>
//!
//! # References
//!
//! - Dobraunig, Eichlseder, Mendel, Schläffer: "Ascon v1.3 (NIST SP 800-232)"
//! - NIST LWC Standardization: <https://csrc.nist.gov/projects/lightweight-cryptography>
//! - Official Specification: <https://ascon.iaik.tugraz.at/specification.html>

#[cfg(feature = "alloc")]
extern crate alloc;

use hpcrypt_core::ascon::ascon_permutation;

/// Ascon-Hash - 256-bit cryptographic hash function
///
/// **✅ NIST-STANDARDIZED** - NIST SP 800-232
///
/// Fixed-length hash function producing a 256-bit (32-byte) digest.
/// Based on the Ascon permutation with 128-bit security.
///
/// # Example
///
/// ```
/// use hpcrypt_hash::ascon::AsconHash;
///
/// let message = b"Hello, Ascon!";
/// let digest = AsconHash::hash(message);
/// assert_eq!(digest.len(), 32); // 256 bits
/// ```
#[derive(Debug, Clone)]
pub struct AsconHash {
    state: [u64; 5],
    buffer: [u8; 8],
    buffer_len: usize,
    total_len: usize,
}

/// Ascon-XOF - Extendable Output Function
///
/// **✅ NIST-STANDARDIZED** - NIST SP 800-232
///
/// Produces variable-length output from a message. Can generate
/// arbitrary amounts of pseudorandom output.
///
/// # Example
///
/// ```
/// use hpcrypt_hash::ascon::AsconXof;
///
/// let message = b"Hello, Ascon!";
/// let mut xof = AsconXof::new();
/// xof.absorb(message);
///
/// let mut output = vec![0u8; 64]; // Get 64 bytes of output
/// xof.squeeze(&mut output);
/// ```
#[derive(Debug, Clone)]
pub struct AsconXof {
    state: [u64; 5],
    buffer: [u8; 8],
    buffer_len: usize,
    squeezing: bool,
}

/// Ascon-cXOF - Customizable Extendable Output Function
///
/// **✅ NIST-STANDARDIZED** - NIST SP 800-232
///
/// Similar to Ascon-XOF but includes a customization string for
/// domain separation. Different customization strings produce
/// independent hash functions.
///
/// # Example
///
/// ```
/// use hpcrypt_hash::ascon::AsconCxof;
///
/// let message = b"Hello, Ascon!";
/// let customization = b"MyApp v1.0";
///
/// let mut cxof = AsconCxof::new(customization);
/// cxof.absorb(message);
///
/// let mut output = vec![0u8; 64];
/// cxof.squeeze(&mut output);
/// ```
#[derive(Debug, Clone)]
pub struct AsconCxof {
    xof: AsconXof,
}

// NIST SP 800-232 Initialization Vectors
// Calculated using the formula from the official C reference implementation:
// IV = (variant << 0) | (pa_rounds << 16) | (pb_rounds << 20) | (hash_bytes*8 << 24) | (rate << 40)
//
// - Ascon-Hash256:  variant=2, pa=12, pb=12, hash_bytes=32 (256 bits), rate=8
//   IV = (2 << 0) | (12 << 16) | (12 << 20) | (256 << 24) | (8 << 40) = 0x0000080100cc0002
//
// - Ascon-XOF128:   variant=3, pa=12, pb=12, hash_bytes=0, rate=8
//   IV = (3 << 0) | (12 << 16) | (12 << 20) | (0 << 24) | (8 << 40) = 0x0000080000cc0003
//
// - Ascon-CXOF128:  variant=4, pa=12, pb=12, hash_bytes=0, rate=8
//   IV = (4 << 0) | (12 << 16) | (12 << 20) | (0 << 24) | (8 << 40) = 0x0000080000cc0004

/// Ascon-Hash256 IV (NIST SP 800-232)
const ASCON_HASH_IV: u64 = 0x0000080100cc0002;

/// Ascon-XOF128 IV (NIST SP 800-232)
const ASCON_XOF_IV: u64 = 0x0000080000cc0003;

/// Ascon-CXOF128 IV (NIST SP 800-232)
const ASCON_CXOF_IV: u64 = 0x0000080000cc0004;

// Round constants for Ascon permutation
// Ascon permutation functions and constants are now provided by hpcrypt-core::ascon
// This eliminates code duplication between hpcrypt-aead and hpcrypt-hash

impl AsconHash {
    /// Number of permutation rounds (both absorption and finalization)
    /// NIST SP 800-232: Ascon-Hash uses 12 rounds for all operations
    const ROUNDS: usize = 12;
    /// Rate in bytes (64 bits = 8 bytes)
    const RATE: usize = 8;

    /// Create a new Ascon-Hash instance
    pub fn new() -> Self {
        let mut state = [ASCON_HASH_IV, 0, 0, 0, 0];

        // Apply initial permutation (pa rounds)
        ascon_permutation(&mut state, Self::ROUNDS);

        Self {
            state,
            buffer: [0u8; 8],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Hash a message and return the 256-bit digest
    pub fn hash(message: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize()
    }

    /// Update the hash state with more data
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Process buffered data first
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(Self::RATE - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos += to_copy;

            if self.buffer_len == Self::RATE {
                let block = u64::from_le_bytes(self.buffer);
                self.state[0] ^= block;
                ascon_permutation(&mut self.state, Self::ROUNDS);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while pos + Self::RATE <= data.len() {
            let block = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            self.state[0] ^= block;
            ascon_permutation(&mut self.state, Self::ROUNDS);
            pos += Self::RATE;
        }

        // Buffer remaining data
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_len = remaining;
        }

        self.total_len += data.len();
    }

    /// Finalize the hash and return the 256-bit digest
    pub fn finalize(mut self) -> [u8; 32] {
        // Process final block with padding
        let pad_value = 0x01u64 << (8 * self.buffer_len);
        self.state[0] ^= pad_value;

        if self.buffer_len > 0 {
            let mut temp = [0u8; 8];
            temp[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            let data_block = u64::from_le_bytes(temp);
            self.state[0] ^= data_block;
        }

        // Final permutation
        ascon_permutation(&mut self.state, Self::ROUNDS);

        // Squeeze output (like XOF but fixed 32 bytes)
        // Extract 256-bit digest by squeezing 4 blocks of 8 bytes each
        let mut digest = [0u8; 32];

        // First 8 bytes from state[0]
        digest[0..8].copy_from_slice(&self.state[0].to_le_bytes());
        ascon_permutation(&mut self.state, Self::ROUNDS);

        // Second 8 bytes from state[0] after permutation
        digest[8..16].copy_from_slice(&self.state[0].to_le_bytes());
        ascon_permutation(&mut self.state, Self::ROUNDS);

        // Third 8 bytes from state[0] after permutation
        digest[16..24].copy_from_slice(&self.state[0].to_le_bytes());
        ascon_permutation(&mut self.state, Self::ROUNDS);

        // Fourth 8 bytes from state[0] after permutation
        digest[24..32].copy_from_slice(&self.state[0].to_le_bytes());

        digest
    }
}

impl Default for AsconHash {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconXof {
    /// Number of permutation rounds (both absorption and squeezing)
    /// NIST SP 800-232: Ascon-XOF uses 12 rounds for all operations
    const ROUNDS: usize = 12;
    /// Rate in bytes (64 bits = 8 bytes)
    const RATE: usize = 8;

    /// Create a new Ascon-XOF instance
    pub fn new() -> Self {
        let mut state = [ASCON_XOF_IV, 0, 0, 0, 0];

        // Apply initial permutation (pa rounds)
        ascon_permutation(&mut state, Self::ROUNDS);

        Self {
            state,
            buffer: [0u8; 8],
            buffer_len: 0,
            squeezing: false,
        }
    }

    /// Absorb input data into the XOF state
    ///
    /// Can be called multiple times. Once `squeeze` is called,
    /// further `absorb` calls are not allowed.
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "Cannot absorb after squeezing");

        let mut pos = 0;

        // Process buffered data first
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(Self::RATE - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            pos += to_copy;

            if self.buffer_len == Self::RATE {
                let block = u64::from_le_bytes(self.buffer);
                self.state[0] ^= block;
                ascon_permutation(&mut self.state, Self::ROUNDS);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while pos + Self::RATE <= data.len() {
            let block = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            self.state[0] ^= block;
            ascon_permutation(&mut self.state, Self::ROUNDS);
            pos += Self::RATE;
        }

        // Buffer remaining data
        if pos < data.len() {
            let remaining = data.len() - pos;
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buffer_len = remaining;
        }
    }

    /// Squeeze output from the XOF state
    ///
    /// Can be called multiple times to produce arbitrary amounts of output.
    /// Once called, no further `absorb` calls are allowed.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // Transition from absorbing to squeezing
        if !self.squeezing {
            // Apply padding
            let pad_value = 0x01u64 << (8 * self.buffer_len);
            self.state[0] ^= pad_value;

            if self.buffer_len > 0 {
                let mut temp = [0u8; 8];
                temp[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
                let data_block = u64::from_le_bytes(temp);
                self.state[0] ^= data_block;
            }

            // Apply permutation for squeezing phase
            ascon_permutation(&mut self.state, Self::ROUNDS);
            self.squeezing = true;
            self.buffer_len = 0;
        }

        let mut pos = 0;

        // If we have buffered output, use it first
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(self.buffer_len, output.len());
            let buf_start = Self::RATE - self.buffer_len;
            output[..to_copy].copy_from_slice(&self.buffer[buf_start..buf_start + to_copy]);
            self.buffer_len -= to_copy;
            pos += to_copy;
        }

        // Squeeze full blocks
        while pos + Self::RATE <= output.len() {
            let block_bytes = self.state[0].to_le_bytes();
            output[pos..pos + Self::RATE].copy_from_slice(&block_bytes);
            ascon_permutation(&mut self.state, Self::ROUNDS);
            pos += Self::RATE;
        }

        // Handle partial block
        if pos < output.len() {
            let remaining = output.len() - pos;
            let block_bytes = self.state[0].to_le_bytes();
            output[pos..].copy_from_slice(&block_bytes[..remaining]);

            // Buffer the rest for next squeeze call
            self.buffer.copy_from_slice(&block_bytes);
            self.buffer_len = Self::RATE - remaining;
            ascon_permutation(&mut self.state, Self::ROUNDS);
        }
    }

    /// One-shot XOF: absorb message and squeeze output
    pub fn hash(message: &[u8], output: &mut [u8]) {
        let mut xof = Self::new();
        xof.absorb(message);
        xof.squeeze(output);
    }
}

impl Default for AsconXof {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconCxof {
    /// Create a new Ascon-cXOF instance with customization string
    ///
    /// The customization string provides domain separation. Different
    /// customization strings produce independent hash functions.
    ///
    /// According to NIST SP 800-232 and the C reference implementation,
    /// cXOF processing is:
    /// 1. Initialize with CXOF IV and permute
    /// 2. XOR customization length in bits and permute
    /// 3. Absorb customization string with padding and permute
    /// 4. Then absorb message normally
    pub fn new(customization: &[u8]) -> Self {
        // Create XOF state with cXOF IV
        let mut state = [ASCON_CXOF_IV, 0, 0, 0, 0];

        // Apply initial permutation
        ascon_permutation(&mut state, AsconXof::ROUNDS);

        // XOR customization length in bits into state[0] and permute
        let cs_len_bits = (customization.len() * 8) as u64;
        state[0] ^= cs_len_bits;
        ascon_permutation(&mut state, AsconXof::ROUNDS);

        // Absorb customization string in full blocks
        let mut cs_offset = 0;
        while cs_offset + 8 <= customization.len() {
            let block = u64::from_le_bytes(
                customization[cs_offset..cs_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            state[0] ^= block;
            ascon_permutation(&mut state, AsconXof::ROUNDS);
            cs_offset += 8;
        }

        // Absorb final partial block with padding
        let cs_remainder = customization.len() - cs_offset;
        if cs_remainder > 0 {
            let mut temp = [0u8; 8];
            temp[..cs_remainder].copy_from_slice(&customization[cs_offset..]);
            let data_block = u64::from_le_bytes(temp);
            state[0] ^= data_block;
        }
        // Apply padding: 0x01 followed by zeros at the byte boundary
        let pad_value = 0x01u64 << (8 * cs_remainder);
        state[0] ^= pad_value;
        ascon_permutation(&mut state, AsconXof::ROUNDS);

        // Create XOF with initialized state - ready to absorb message
        let xof = AsconXof {
            state,
            buffer: [0u8; 8],
            buffer_len: 0,
            squeezing: false,
        };

        Self { xof }
    }

    /// Absorb input data into the cXOF state
    pub fn absorb(&mut self, data: &[u8]) {
        self.xof.absorb(data);
    }

    /// Squeeze output from the cXOF state
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.xof.squeeze(output);
    }

    /// One-shot cXOF: absorb message with customization and squeeze output
    pub fn hash(customization: &[u8], message: &[u8], output: &mut [u8]) {
        let mut cxof = Self::new(customization);
        cxof.absorb(message);
        cxof.squeeze(output);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascon_hash_empty() {
        let digest = AsconHash::hash(b"");
        assert_eq!(digest.len(), 32);

        // Known test vector for empty message
        let expected = hex_literal::hex!("0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_ascon_hash_basic() {
        let message = b"Hello, Ascon!";
        let digest = AsconHash::hash(message);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_ascon_hash_incremental() {
        let mut hasher1 = AsconHash::new();
        hasher1.update(b"Hello, ");
        hasher1.update(b"Ascon!");
        let digest1 = hasher1.finalize();

        let digest2 = AsconHash::hash(b"Hello, Ascon!");

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_ascon_xof_basic() {
        let message = b"Hello, Ascon!";
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        AsconXof::hash(message, &mut output1);
        AsconXof::hash(message, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_ascon_xof_variable_output() {
        let message = b"test";

        let mut output32 = [0u8; 32];
        let mut output64 = [0u8; 64];

        let mut xof1 = AsconXof::new();
        xof1.absorb(message);
        xof1.squeeze(&mut output32);

        let mut xof2 = AsconXof::new();
        xof2.absorb(message);
        xof2.squeeze(&mut output64);

        // First 32 bytes should match
        assert_eq!(&output32[..], &output64[..32]);
    }

    #[test]
    fn test_ascon_cxof_basic() {
        let customization = b"test customization";
        let message = b"Hello, Ascon!";
        let mut output = [0u8; 64];

        AsconCxof::hash(customization, message, &mut output);

        // Different customization should produce different output
        let mut output2 = [0u8; 64];
        AsconCxof::hash(b"different", message, &mut output2);

        assert_ne!(output, output2);
    }

    #[test]
    fn test_ascon_cxof_empty_customization() {
        let message = b"test";
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        AsconCxof::hash(b"", message, &mut output1);
        AsconCxof::hash(b"", message, &mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_ascon_xof_incremental_squeeze() {
        let message = b"test";

        let mut xof1 = AsconXof::new();
        xof1.absorb(message);
        let mut output1a = [0u8; 32];
        let mut output1b = [0u8; 32];
        xof1.squeeze(&mut output1a);
        xof1.squeeze(&mut output1b);

        let mut xof2 = AsconXof::new();
        xof2.absorb(message);
        let mut output2 = [0u8; 64];
        xof2.squeeze(&mut output2);

        // Incremental squeeze should match one-shot
        assert_eq!(&output1a[..], &output2[..32]);
        assert_eq!(&output1b[..], &output2[32..]);
    }
}
