//! HASH_DRBG (Hash-based Deterministic Random Bit Generator)
//!
//! NIST SP 800-90A compliant DRBG using SHA-256.
//! This is one of the approved DRBGs for cryptographic applications.
//!
//! # Production Ready
//!
//! This implementation uses SHA-256 from `hpcrypt-hash`, providing:
//! - **NIST SP 800-90A Rev. 1 compliance**
//! - **FIPS 140-2/3 approved algorithm**
//! - **No block cipher or MAC required** (just hash function)
//! - **Widely deployed** (used in various cryptographic systems)
//!
//! # Design
//!
//! - **Algorithm**: SHA-256
//! - **Security**: 256-bit security strength
//! - **State**: Seed (V) + Constant (C), both 440 bits (seedlen)
//! - **Reseed interval**: 2^48 requests
//! - **Max request**: 2^19 bits (64 KB)
//!
//! # NIST SP 800-90A Compliance
//!
//! This implementation follows NIST SP 800-90A Rev. 1:
//! - Section 10.1.1: HASH_DRBG algorithm
//! - FIPS 140-2/3 approved
//! - Uses SHA-256 as the underlying hash function
//!
//! # Algorithm Overview
//!
//! 1. **Instantiate**: Initialize V and C from seed
//! 2. **Generate**: Hash V to generate output, update V
//! 3. **Hashgen**: Iteratively hash to produce requested bits
//! 4. **Reseed**: Update state with fresh entropy
//!
//! # References
//!
//! - NIST SP 800-90A Rev. 1 (2015) Section 10.1.1
//! - FIPS 140-2/3 approved DRBG
//! - Used in: Various cryptographic implementations

extern crate alloc;

use super::Drbg;
use crate::{Result, RngError};
use zeroize::{Zeroize, ZeroizeOnDrop};

use hpcrypt_hash::{HashFunction, Sha256};

/// SHA-256 output length (256 bits)
const OUTLEN: usize = 32;

/// Seed length for HASH_DRBG with SHA-256 (440 bits = 55 bytes)
/// As per NIST SP 800-90A Table 2: seedlen = 440 bits for SHA-256
const SEEDLEN: usize = 55;

/// Maximum bytes per generate request (2^19 bits = 64 KB)
const MAX_GENERATE_LENGTH: usize = 1 << 16;

/// Reseed interval in requests (2^48)
const RESEED_INTERVAL: u64 = 1 << 48;

/// HASH_DRBG using SHA-256
///
/// A NIST SP 800-90A compliant deterministic random bit generator.
///
/// # Example
///
/// ```
/// use hpcrypt_rng::{HashDrbg, Drbg};
///
/// // Create with OS entropy
/// let mut drbg = HashDrbg::new().expect("Failed to create DRBG");
///
/// // Generate random bytes
/// let mut output = [0u8; 32];
/// drbg.generate(&mut output).expect("Failed to generate");
///
/// // Or create from seed for reproducibility
/// let seed = [42u8; 55];
/// let mut drbg = HashDrbg::from_seed(&seed).expect("Invalid seed");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HashDrbg {
    /// Internal state value (V) - 440 bits
    v: [u8; SEEDLEN],

    /// Constant (C) - 440 bits
    c: [u8; SEEDLEN],

    /// Reseed counter (requests since last reseed)
    reseed_counter: u64,
}

impl HashDrbg {
    /// Security strength in bits
    pub const SECURITY_STRENGTH: usize = 256;

    /// Hash_df (Hash Derivation Function) - NIST SP 800-90A Section 10.3.1
    ///
    /// Derives requested number of bits from input data using iterative hashing.
    fn hash_df(input: &[u8], requested_bits: usize) -> alloc::vec::Vec<u8> {
        let requested_bytes = (requested_bits + 7) / 8;
        let mut output = alloc::vec::Vec::with_capacity(requested_bytes);

        let len_bits = (requested_bits as u32).to_be_bytes();
        let mut counter = 1u8;

        while output.len() < requested_bytes {
            let mut hasher = Sha256::new();
            hasher.update(&[counter]);
            hasher.update(&len_bits);
            hasher.update(input);

            let hash = hasher.finalize();
            output.extend_from_slice(&hash);
            counter = counter.wrapping_add(1);
        }

        output.truncate(requested_bytes);
        output
    }

    /// Hashgen function (NIST SP 800-90A Section 10.1.1.4)
    ///
    /// Generates random bits by iteratively hashing the state.
    fn hashgen(v: &[u8; SEEDLEN], requested_bytes: usize) -> alloc::vec::Vec<u8> {
        let mut data = *v;
        let mut output = alloc::vec::Vec::with_capacity(requested_bytes);

        while output.len() < requested_bytes {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let hash = hasher.finalize();

            output.extend_from_slice(&hash);

            // Increment data as a big-endian integer
            for i in (0..SEEDLEN).rev() {
                data[i] = data[i].wrapping_add(1);
                if data[i] != 0 {
                    break;
                }
            }
        }

        output.truncate(requested_bytes);
        data.zeroize();
        output
    }

    /// Add two seedlen values modulo 2^seedlen (NIST SP 800-90A Section 10.1.1)
    fn add_mod_seedlen(a: &[u8; SEEDLEN], b: &[u8; SEEDLEN]) -> [u8; SEEDLEN] {
        let mut result = [0u8; SEEDLEN];
        let mut carry = 0u16;

        // Add from right to left (big-endian)
        for i in (0..SEEDLEN).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        result
    }

    /// HASH_DRBG_Instantiate function (NIST SP 800-90A Section 10.1.1.2)
    fn instantiate(entropy_input: &[u8]) -> Self {
        // 1. seed_material = entropy_input
        // 2. seed = Hash_df(seed_material, seedlen)
        let seed_vec = Self::hash_df(entropy_input, SEEDLEN * 8);
        let mut seed = [0u8; SEEDLEN];
        seed.copy_from_slice(&seed_vec[..SEEDLEN]);

        // 3. V = seed
        let v = seed;

        // 4. C = Hash_df((0x00 || V), seedlen)
        let mut c_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        c_input.push(0x00);
        c_input.extend_from_slice(&v);

        let c_vec = Self::hash_df(&c_input, SEEDLEN * 8);
        let mut c = [0u8; SEEDLEN];
        c.copy_from_slice(&c_vec[..SEEDLEN]);

        // 5. reseed_counter = 1
        Self {
            v,
            c,
            reseed_counter: 1,
        }
    }

    /// HASH_DRBG_Update function (NIST SP 800-90A Section 10.1.1.2)
    ///
    /// Note: Currently unused in this implementation but reserved for
    /// additional data mixing in future NIST compliance updates.
    #[allow(dead_code)]
    fn update(&mut self, provided_data: Option<&[u8]>) {
        // 1. Create input: 0x01 || V || provided_data
        let mut hash_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN + provided_data.map(|d| d.len()).unwrap_or(0));
        hash_input.push(0x01);
        hash_input.extend_from_slice(&self.v);
        if let Some(data) = provided_data {
            hash_input.extend_from_slice(data);
        }

        // 2. seed_material = Hash_df(hash_input, seedlen)
        let seed_material_vec = Self::hash_df(&hash_input, SEEDLEN * 8);
        let mut seed_material = [0u8; SEEDLEN];
        seed_material.copy_from_slice(&seed_material_vec[..SEEDLEN]);

        // 3. V = (V + seed_material) mod 2^seedlen
        self.v = Self::add_mod_seedlen(&self.v, &seed_material);

        // Zeroize temporary data
        hash_input.zeroize();
        seed_material.zeroize();
    }
}

impl Drbg for HashDrbg {
    fn new() -> Result<Self> {
        #[cfg(feature = "os-rng")]
        {
            let mut seed = [0u8; SEEDLEN];
            crate::generate_random_bytes(&mut seed)?;
            Ok(Self::instantiate(&seed))
        }

        #[cfg(not(feature = "os-rng"))]
        {
            Err(RngError::OsRngFailed)
        }
    }

    fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < SEEDLEN {
            return Err(RngError::InvalidSeedLength);
        }

        Ok(Self::instantiate(seed))
    }

    fn generate(&mut self, output: &mut [u8]) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        if output.len() > MAX_GENERATE_LENGTH {
            return Err(RngError::InternalError);
        }

        if self.needs_reseed() {
            return Err(RngError::NotSeeded);
        }

        // HASH_DRBG_Generate (NIST SP 800-90A Section 10.1.1.4)

        // 1. Generate bits using Hashgen
        let generated = Self::hashgen(&self.v, output.len());
        output.copy_from_slice(&generated);

        // 2. Create H input: 0x03 || V
        let mut h_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        h_input.push(0x03);
        h_input.extend_from_slice(&self.v);

        // 3. H = Hash(0x03 || V)
        let mut hasher = Sha256::new();
        hasher.update(&h_input);
        let h = hasher.finalize();

        // 4. V = (V + H + C + reseed_counter) mod 2^seedlen
        // First extend H to seedlen by padding with zeros on the left
        let mut h_extended = [0u8; SEEDLEN];
        h_extended[SEEDLEN - OUTLEN..].copy_from_slice(&h);

        // Add reseed_counter (extended to seedlen, big-endian)
        let mut counter_extended = [0u8; SEEDLEN];
        counter_extended[SEEDLEN - 8..].copy_from_slice(&self.reseed_counter.to_be_bytes());

        // V = V + H
        self.v = Self::add_mod_seedlen(&self.v, &h_extended);
        // V = V + C
        self.v = Self::add_mod_seedlen(&self.v, &self.c);
        // V = V + reseed_counter
        self.v = Self::add_mod_seedlen(&self.v, &counter_extended);

        // 5. reseed_counter = reseed_counter + 1
        self.reseed_counter = self.reseed_counter.saturating_add(1);

        // Zeroize temporary data
        h_input.zeroize();

        Ok(())
    }

    fn reseed(&mut self) -> Result<()> {
        #[cfg(feature = "os-rng")]
        {
            let mut entropy = [0u8; SEEDLEN];
            crate::generate_random_bytes(&mut entropy)?;
            self.reseed_with(&entropy)?;
            entropy.zeroize();
            Ok(())
        }

        #[cfg(not(feature = "os-rng"))]
        {
            Err(RngError::OsRngFailed)
        }
    }

    fn reseed_with(&mut self, entropy: &[u8]) -> Result<()> {
        if entropy.len() < SEEDLEN {
            return Err(RngError::InvalidSeedLength);
        }

        // HASH_DRBG_Reseed (NIST SP 800-90A Section 10.1.1.3)

        // 1. seed_material = 0x01 || V || entropy_input
        let mut seed_material = alloc::vec::Vec::with_capacity(1 + SEEDLEN + entropy.len());
        seed_material.push(0x01);
        seed_material.extend_from_slice(&self.v);
        seed_material.extend_from_slice(entropy);

        // 2. seed = Hash_df(seed_material, seedlen)
        let seed_vec = Self::hash_df(&seed_material, SEEDLEN * 8);
        let mut seed = [0u8; SEEDLEN];
        seed.copy_from_slice(&seed_vec[..SEEDLEN]);

        // 3. V = seed
        self.v = seed;

        // 4. C = Hash_df((0x00 || V), seedlen)
        let mut c_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        c_input.push(0x00);
        c_input.extend_from_slice(&self.v);

        let c_vec = Self::hash_df(&c_input, SEEDLEN * 8);
        self.c.copy_from_slice(&c_vec[..SEEDLEN]);

        // 5. reseed_counter = 1
        self.reseed_counter = 1;

        // Zeroize temporary data
        seed_material.zeroize();
        seed.zeroize();
        c_input.zeroize();

        Ok(())
    }

    fn security_strength(&self) -> usize {
        Self::SECURITY_STRENGTH
    }

    fn needs_reseed(&self) -> bool {
        self.reseed_counter >= RESEED_INTERVAL
    }

    // ========================================================================
    // NIST SP 800-90A Compliant Methods
    // ========================================================================

    fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // NIST SP 800-90A Section 10.1.1.2: HASH_DRBG_Instantiate_algorithm

        // 1. seed_material = entropy_input || nonce || personalization_string
        let mut seed_material = alloc::vec::Vec::with_capacity(
            entropy.len() + nonce.len() + personalization.len()
        );
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // 2. seed = Hash_df(seed_material, seedlen)
        let seed_vec = Self::hash_df(&seed_material, SEEDLEN * 8);
        let mut seed = [0u8; SEEDLEN];
        seed.copy_from_slice(&seed_vec[..SEEDLEN]);

        // 3. V = seed
        let v = seed;

        // 4. C = Hash_df((0x00 || V), seedlen)
        let mut c_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        c_input.push(0x00);
        c_input.extend_from_slice(&v);

        let c_vec = Self::hash_df(&c_input, SEEDLEN * 8);
        let mut c = [0u8; SEEDLEN];
        c.copy_from_slice(&c_vec[..SEEDLEN]);

        // 5. reseed_counter = 1
        Ok(Self {
            v,
            c,
            reseed_counter: 1,
        })
    }

    fn generate_with_additional(
        &mut self,
        output: &mut [u8],
        additional: &[u8],
    ) -> Result<()> {
        // NIST SP 800-90A Section 10.1.1.4: HASH_DRBG_Generate_algorithm

        if output.is_empty() {
            return Ok(());
        }

        if output.len() > MAX_GENERATE_LENGTH {
            return Err(RngError::InternalError);
        }

        if self.needs_reseed() {
            return Err(RngError::NotSeeded);
        }

        // 1. If additional_input != Null, then:
        //      w = Hash(0x02 || V || additional_input)
        //      V = (V + w) mod 2^seedlen
        if !additional.is_empty() {
            let mut hash_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN + additional.len());
            hash_input.push(0x02);
            hash_input.extend_from_slice(&self.v);
            hash_input.extend_from_slice(additional);

            let mut hash = Sha256::new();
            hash.update(&hash_input);
            let w_result = hash.finalize();

            // Extend w to seedlen by padding with zeros on the LEFT (big-endian style)
            let mut w_extended = [0u8; SEEDLEN];
            w_extended[SEEDLEN - OUTLEN..].copy_from_slice(&w_result);

            // V = (V + w) mod 2^seedlen
            self.v = Self::add_mod_seedlen(&self.v, &w_extended);
        }

        // 2. (V, data) = Hashgen(requested_number_of_bits, V)
        let generated = Self::hashgen(&self.v, output.len());
        output.copy_from_slice(&generated);

        // 3. H = Hash(0x03 || V)
        let mut h_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        h_input.push(0x03);
        h_input.extend_from_slice(&self.v);

        let mut hash_h = Sha256::new();
        hash_h.update(&h_input);
        let h_result = hash_h.finalize();

        // 4. V = (V + H + C + reseed_counter) mod 2^seedlen
        // Extend H to seedlen by padding with zeros on the LEFT (big-endian style)
        let mut h_extended = [0u8; SEEDLEN];
        h_extended[SEEDLEN - OUTLEN..].copy_from_slice(&h_result);

        // Add reseed_counter (extended to seedlen, big-endian)
        let mut counter_extended = [0u8; SEEDLEN];
        counter_extended[SEEDLEN - 8..].copy_from_slice(&self.reseed_counter.to_be_bytes());

        // V = V + H
        self.v = Self::add_mod_seedlen(&self.v, &h_extended);
        // V = V + C
        self.v = Self::add_mod_seedlen(&self.v, &self.c);
        // V = V + reseed_counter
        self.v = Self::add_mod_seedlen(&self.v, &counter_extended);

        // 5. reseed_counter = reseed_counter + 1
        self.reseed_counter += 1;

        Ok(())
    }

    fn reseed_with_additional(
        &mut self,
        entropy: &[u8],
        additional: &[u8],
    ) -> Result<()> {
        // NIST SP 800-90A Section 10.1.1.3: HASH_DRBG_Reseed_algorithm

        // 1. seed_material = 0x01 || V || entropy_input || additional_input
        let mut seed_material = alloc::vec::Vec::with_capacity(
            1 + SEEDLEN + entropy.len() + additional.len()
        );
        seed_material.push(0x01);
        seed_material.extend_from_slice(&self.v);
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional);

        // 2. seed = Hash_df(seed_material, seedlen)
        let seed_vec = Self::hash_df(&seed_material, SEEDLEN * 8);
        let mut seed = [0u8; SEEDLEN];
        seed.copy_from_slice(&seed_vec[..SEEDLEN]);

        // 3. V = seed
        self.v = seed;

        // 4. C = Hash_df((0x00 || V), seedlen)
        let mut c_input = alloc::vec::Vec::with_capacity(1 + SEEDLEN);
        c_input.push(0x00);
        c_input.extend_from_slice(&self.v);

        let c_vec = Self::hash_df(&c_input, SEEDLEN * 8);
        self.c.copy_from_slice(&c_vec[..SEEDLEN]);

        // 5. reseed_counter = 1
        self.reseed_counter = 1;

        Ok(())
    }
}

impl core::fmt::Debug for HashDrbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HashDrbg")
            .field("algorithm", &"SHA-256")
            .field("security_strength", &Self::SECURITY_STRENGTH)
            .field("reseed_counter", &self.reseed_counter)
            .field("needs_reseed", &self.needs_reseed())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [42u8; SEEDLEN];

        let mut drbg1 = HashDrbg::from_seed(&seed).unwrap();
        let mut drbg2 = HashDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Same seed should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_different_seeds_different_output() {
        let seed1 = [1u8; SEEDLEN];
        let seed2 = [2u8; SEEDLEN];

        let mut drbg1 = HashDrbg::from_seed(&seed1).unwrap();
        let mut drbg2 = HashDrbg::from_seed(&seed2).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1).unwrap();
        drbg2.generate(&mut output2).unwrap();

        // Different seeds should produce different output
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_sequential_outputs_differ() {
        let seed = [42u8; SEEDLEN];
        let mut drbg = HashDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg.generate(&mut output1).unwrap();
        drbg.generate(&mut output2).unwrap();

        // Sequential outputs should differ
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_generate_various_sizes() {
        let seed = [42u8; SEEDLEN];
        let mut drbg = HashDrbg::from_seed(&seed).unwrap();

        let mut small = [0u8; 16];
        let mut medium = [0u8; 100];
        let mut large = [0u8; 1024];

        drbg.generate(&mut small).unwrap();
        drbg.generate(&mut medium).unwrap();
        drbg.generate(&mut large).unwrap();

        // All should be non-zero
        assert_ne!(small, [0u8; 16]);
        assert_ne!(medium, [0u8; 100]);
        assert_ne!(large, [0u8; 1024]);
    }

    #[test]
    fn test_reseed_with() {
        let seed = [1u8; SEEDLEN];
        let mut drbg = HashDrbg::from_seed(&seed).unwrap();

        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1).unwrap();

        // Reseed with new entropy
        let new_entropy = [2u8; SEEDLEN];
        drbg.reseed_with(&new_entropy).unwrap();

        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2).unwrap();

        // Output after reseed should differ
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_reseed_counter_reset() {
        let seed = [42u8; SEEDLEN];
        let mut drbg = HashDrbg::from_seed(&seed).unwrap();

        // Generate some data
        let mut output = [0u8; 1024];
        drbg.generate(&mut output).unwrap();

        let counter_before = drbg.reseed_counter;
        assert!(counter_before > 1);

        // Reseed
        let new_entropy = [99u8; SEEDLEN];
        drbg.reseed_with(&new_entropy).unwrap();

        // Counter should be reset to 1
        assert_eq!(drbg.reseed_counter, 1);
    }

    #[test]
    fn test_invalid_seed_length() {
        let short_seed = [1u8; 16]; // Too short
        let result = HashDrbg::from_seed(&short_seed);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RngError::InvalidSeedLength);
    }

    #[test]
    fn test_empty_generate() {
        let seed = [42u8; SEEDLEN];
        let mut drbg = HashDrbg::from_seed(&seed).unwrap();

        let mut empty = [];
        let result = drbg.generate(&mut empty);
        assert!(result.is_ok());
    }

    #[cfg(feature = "os-rng")]
    #[test]
    fn test_new_with_os_rng() {
        let mut drbg = HashDrbg::new().unwrap();

        let mut output = [0u8; 64];
        drbg.generate(&mut output).unwrap();

        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_security_strength() {
        let seed = [42u8; SEEDLEN];
        let drbg = HashDrbg::from_seed(&seed).unwrap();

        assert_eq!(drbg.security_strength(), 256);
    }

    #[test]
    fn test_needs_reseed_initially_false() {
        let seed = [42u8; SEEDLEN];
        let drbg = HashDrbg::from_seed(&seed).unwrap();

        assert!(!drbg.needs_reseed());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_debug_impl() {
        let seed = [42u8; SEEDLEN];
        let drbg = HashDrbg::from_seed(&seed).unwrap();

        let debug_str = std::format!("{:?}", drbg);
        assert!(debug_str.contains("HashDrbg"));
        assert!(debug_str.contains("SHA-256"));
    }

    #[test]
    fn test_hash_df() {
        // Test Hash_df produces consistent output
        let input = b"test input data";
        let output1 = HashDrbg::hash_df(input, 256);
        let output2 = HashDrbg::hash_df(input, 256);

        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 32);
    }

    #[test]
    fn test_add_mod_seedlen() {
        // Test modular addition with simple values
        let mut a = [0u8; SEEDLEN];
        let mut b = [0u8; SEEDLEN];

        // Test: 1 + 1 = 2
        a[SEEDLEN - 1] = 1;
        b[SEEDLEN - 1] = 1;
        let result = HashDrbg::add_mod_seedlen(&a, &b);
        assert_eq!(result[SEEDLEN - 1], 2);

        // Test: 0xFF + 0x01 = 0x00 with carry (in rightmost byte)
        a[SEEDLEN - 1] = 0xFF;
        b[SEEDLEN - 1] = 0x01;
        let result = HashDrbg::add_mod_seedlen(&a, &b);
        assert_eq!(result[SEEDLEN - 1], 0x00);
        assert_eq!(result[SEEDLEN - 2], 0x01); // Carry to next byte
    }
}
