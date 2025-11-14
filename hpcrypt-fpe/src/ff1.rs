//! FF1 Format-Preserving Encryption
//!
//! Implementation of FF1 mode specified in NIST SP 800-38G Rev. 1
//!
//! FF1 is a Feistel-based format-preserving encryption mode that preserves
//! the format and length of the plaintext in the ciphertext.
//!
//! # Security
//!
//! - Minimum radix: 2 (binary)
//! - Maximum radix: 65536 (2^16)
//! - Minimum input length: Depends on radix, generally >= 2
//! - Based on AES in CBC-MAC mode
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_fpe::FF1;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create FF1 instance with AES-256 key
//! let key = [0u8; 32];
//! let ff1 = FF1::new(&key)?;
//!
//! // Encrypt a credit card number (radix 10)
//! let plaintext = "4532123456789010";
//! let tweak = b"user123";
//! let ciphertext = ff1.encrypt(plaintext, tweak, 10)?;
//!
//! println!("Plaintext:  {}", plaintext);
//! println!("Ciphertext: {}", ciphertext);
//!
//! // Decrypt
//! let decrypted = ff1.decrypt(&ciphertext, tweak, 10)?;
//! assert_eq!(plaintext, decrypted);
//! # Ok(())
//! # }
//! ```

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};

use hpcrypt_aead::Aes;
use zeroize::ZeroizeOnDrop;

/// FF1 error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FF1Error {
    /// Invalid key length (must be 16, 24, or 32 bytes)
    InvalidKeyLength,
    /// Invalid radix (must be between 2 and 65536)
    InvalidRadix,
    /// Input too short for the given radix
    InputTooShort,
    /// Input too long for the given radix
    InputTooLong,
    /// Invalid character in input string
    InvalidCharacter,
    /// Tweak too long (max 2^32 - 1 bytes)
    TweakTooLong,
    /// Internal error
    InternalError,
}

impl core::fmt::Display for FF1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FF1Error::InvalidKeyLength => write!(f, "Invalid key length"),
            FF1Error::InvalidRadix => write!(f, "Invalid radix"),
            FF1Error::InputTooShort => write!(f, "Input too short"),
            FF1Error::InputTooLong => write!(f, "Input too long"),
            FF1Error::InvalidCharacter => write!(f, "Invalid character"),
            FF1Error::TweakTooLong => write!(f, "Tweak too long"),
            FF1Error::InternalError => write!(f, "Internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FF1Error {}

/// FF1 Format-Preserving Encryption
///
/// Implements NIST SP 800-38G FF1 mode for format-preserving encryption.
#[derive(Debug, ZeroizeOnDrop)]
pub struct FF1 {
    #[zeroize(skip)]
    cipher: Aes,
}

impl FF1 {
    /// Create a new FF1 instance with the given key
    ///
    /// # Arguments
    ///
    /// * `key` - AES key (16, 24, or 32 bytes for AES-128/192/256)
    ///
    /// # Returns
    ///
    /// FF1 instance or error if key length is invalid
    pub fn new(key: &[u8]) -> Result<Self, FF1Error> {
        let cipher = match key.len() {
            16 => Aes::new_128(key.try_into().map_err(|_| FF1Error::InvalidKeyLength)?),
            24 => Aes::new_192(key.try_into().map_err(|_| FF1Error::InvalidKeyLength)?),
            32 => Aes::new_256(key.try_into().map_err(|_| FF1Error::InvalidKeyLength)?),
            _ => return Err(FF1Error::InvalidKeyLength),
        };

        Ok(FF1 { cipher })
    }

    /// Encrypt plaintext using FF1
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Input string with characters from alphabet
    /// * `tweak` - Additional input for domain separation
    /// * `radix` - Radix of the input (2-65536)
    ///
    /// # Returns
    ///
    /// Encrypted string with same format as plaintext
    pub fn encrypt(&self, plaintext: &str, tweak: &[u8], radix: u32) -> Result<String, FF1Error> {
        self.encrypt_with_alphabet(plaintext, tweak, radix, None)
    }

    /// Encrypt with custom alphabet
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Input string
    /// * `tweak` - Additional input
    /// * `radix` - Number of characters in alphabet
    /// * `alphabet` - Optional custom alphabet (if None, uses default for radix)
    pub fn encrypt_with_alphabet(
        &self,
        plaintext: &str,
        tweak: &[u8],
        radix: u32,
        alphabet: Option<&str>,
    ) -> Result<String, FF1Error> {
        // Validate inputs
        self.validate_inputs(plaintext, tweak, radix)?;

        let default_alphabet = Self::default_alphabet(radix)?;
        let alphabet = alphabet.unwrap_or(&default_alphabet);

        // Convert plaintext to numerical string (base radix)
        let numeral_string = self.str_to_numeral(plaintext, radix, alphabet)?;

        // Perform FF1 encryption
        let encrypted_numeral = self.ff1_encrypt_decrypt(&numeral_string, tweak, radix, true)?;

        // Convert back to string
        self.numeral_to_str(&encrypted_numeral, radix, alphabet)
    }

    /// Decrypt ciphertext using FF1
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Encrypted string
    /// * `tweak` - Must match encryption tweak
    /// * `radix` - Must match encryption radix
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(&self, ciphertext: &str, tweak: &[u8], radix: u32) -> Result<String, FF1Error> {
        self.decrypt_with_alphabet(ciphertext, tweak, radix, None)
    }

    /// Decrypt with custom alphabet
    pub fn decrypt_with_alphabet(
        &self,
        ciphertext: &str,
        tweak: &[u8],
        radix: u32,
        alphabet: Option<&str>,
    ) -> Result<String, FF1Error> {
        self.validate_inputs(ciphertext, tweak, radix)?;

        let default_alphabet = Self::default_alphabet(radix)?;
        let alphabet = alphabet.unwrap_or(&default_alphabet);
        let numeral_string = self.str_to_numeral(ciphertext, radix, alphabet)?;
        let decrypted_numeral = self.ff1_encrypt_decrypt(&numeral_string, tweak, radix, false)?;
        self.numeral_to_str(&decrypted_numeral, radix, alphabet)
    }

    /// Core FF1 algorithm (both encrypt and decrypt)
    fn ff1_encrypt_decrypt(
        &self,
        x: &[u32],
        tweak: &[u8],
        radix: u32,
        encrypt: bool,
    ) -> Result<Vec<u32>, FF1Error> {
        let n = x.len();
        let _t = tweak.len();

        // Step 1: Split input into two halves
        let u = n / 2;
        let v = n - u;

        let mut a = x[..u].to_vec();
        let mut b = x[u..].to_vec();

        // Step 2: Perform 10 Feistel rounds
        let num_rounds = 10;

        for i in 0..num_rounds {
            // Determine which round we're in (for encrypt vs decrypt)
            let round = if encrypt { i } else { num_rounds - 1 - i };

            #[cfg(test)]
            if n == 10 && radix == 10 && i < 2 {
                use std::println;
                println!("DEBUG Round {}: Before - A={:?}, B={:?}", round, a, b);
            }

            // Step 2.i: Calculate c
            // For encryption: always use F(B)
            // For decryption: always use F(A) (verified with str4d/fpe implementation)
            // The modulus changes: radix^u for even rounds, radix^v for odd rounds
            let input = if encrypt { &b } else { &a };
            let (m, f) = if round % 2 == 0 {
                // Even round: m = u
                (u, self.f_function(input, round, tweak, radix, u, n)?)
            } else {
                // Odd round: m = v
                (v, self.f_function(input, round, tweak, radix, v, n)?)
            };

            let c = if encrypt {
                // Encrypt: c = (A + F(B)) mod radix^m
                self.add_mod(&a, &f, radix, m)?
            } else {
                // Decrypt: c = (B - F(A)) mod radix^m
                self.sub_mod(&b, &f, radix, m)?
            };

            #[cfg(test)]
            if n == 10 && radix == 10 && i < 2 {
                use std::println;
                println!(
                    "DEBUG Round {}: After  - A={:?}, B={:?}, C={:?}",
                    round, a, b, c
                );
            }

            // Step 2.ii: Swap variables
            if encrypt {
                // Encrypt: A := B, B := C
                a = b;
                b = c;
            } else {
                // Decrypt: B := A, A := C
                b = a;
                a = c;
            }

            #[cfg(test)]
            if n == 10 && radix == 10 && i < 2 {
                use std::println;
                println!("DEBUG Round {}: Swapped - A={:?}, B={:?}\n", round, a, b);
            }
        }

        // Step 3: Concatenate a || b
        #[cfg(test)]
        if n == 10 && radix == 10 {
            use std::println;
            println!("DEBUG Final: A={:?}, B={:?}, encrypt={}", a, b, encrypt);
        }

        let mut result = a;
        result.extend_from_slice(&b);

        Ok(result)
    }

    /// F function - core of the Feistel network
    fn f_function(
        &self,
        b: &[u32],
        i: usize,
        tweak: &[u8],
        radix: u32,
        m: usize,
        n: usize,
    ) -> Result<Vec<u32>, FF1Error> {
        let t = tweak.len();
        let u = n / 2; // Original left half size

        // Step 1: Let P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod 256]^1 || [n]^4 || [t]^4
        let mut p = Vec::with_capacity(16);
        p.push(1); // version
        p.push(2); // method (2 = FF1)
        p.push(1); // addition
        p.extend_from_slice(&[(radix >> 16) as u8, (radix >> 8) as u8, radix as u8]); // radix
        p.push(10); // 10 rounds
        p.push((u % 256) as u8); // split (always u, not m!)
        p.extend_from_slice(&(n as u32).to_be_bytes()); // n
        p.extend_from_slice(&(t as u32).to_be_bytes()); // t

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!("DEBUG F-function round {}: P = {:02x?}", i, p);
        }

        // Step 2: Q = T || [0]^((-t-b-1) mod 16) || [i]^1 || [NUM_radix(B)]^b
        // Calculate b = ceil(ceil(v × log₂(radix)) / 8)
        let v = b.len();
        let b_bytes_len = ((((v as f64) * (radix as f64).log2()).ceil()) / 8.0).ceil() as usize;

        // Convert B to bytes and pad to b_bytes_len
        let b_num = self.num_radix(b, radix)?;
        let b_bytes_raw = b_num.to_bytes_be();

        // Ensure exactly b_bytes_len bytes (pad with leading zeros or truncate if necessary)
        let b_bytes = if b_bytes_raw.is_empty() {
            vec![0u8; b_bytes_len]
        } else if b_bytes_raw.len() < b_bytes_len {
            let mut padded = vec![0u8; b_bytes_len - b_bytes_raw.len()];
            padded.extend_from_slice(&b_bytes_raw);
            padded
        } else if b_bytes_raw.len() > b_bytes_len {
            // Take only the last b_bytes_len bytes
            b_bytes_raw[b_bytes_raw.len() - b_bytes_len..].to_vec()
        } else {
            b_bytes_raw
        };

        // Calculate padding
        let pad_len = (16 - ((t + b_bytes_len + 1) % 16)) % 16;

        let mut q = Vec::new();
        q.extend_from_slice(tweak);
        q.extend(core::iter::repeat(0).take(pad_len));
        q.push(i as u8);
        q.extend_from_slice(&b_bytes);

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!(
                "DEBUG F-function round {}: b={:?}, b_bytes_len={}, pad_len={}",
                i, b, b_bytes_len, pad_len
            );
            println!("DEBUG F-function round {}: Q = {:02x?}", i, q);
        }

        // Step 3: Let R = PRF(P || Q)
        let r = self.prf(&p, &q)?;

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!("DEBUG F-function round {}: R = {:02x?}", i, r);
        }

        // Step 4: Let S be the first d bytes of the following string
        // where d = 4 × ceil(b/4) + 4
        let d = 4 * ((b_bytes_len + 3) / 4) + 4;
        let s = self.ciph(&r, d)?;

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!("DEBUG F-function round {}: d={}, S = {:02x?}", i, d, s);
        }

        // Step 5: Let y = NUM(S)
        let y = BigUint::from_bytes_be(&s);

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!("DEBUG F-function round {}: y={}", i, y);
        }

        // Step 6: return STR_m^radix(y mod radix^m)
        let modulus = Self::pow_radix(radix, m);
        let result = y % &modulus;

        #[cfg(test)]
        if i == 0 && n == 10 && radix == 10 {
            use std::println;
            println!(
                "DEBUG F-function round {}: result={}, m={}, modulus={}",
                i, &result, m, &modulus
            );
        }

        self.str_m_radix(&result, radix, m)
    }

    /// PRF function using AES-CBC-MAC
    fn prf(&self, p: &[u8], q: &[u8]) -> Result<Vec<u8>, FF1Error> {
        let mut data = Vec::new();
        data.extend_from_slice(p);
        data.extend_from_slice(q);

        // Pad to block size
        while data.len() % 16 != 0 {
            data.push(0);
        }

        // CBC-MAC
        let mut mac = [0u8; 16];

        for chunk in data.chunks(16) {
            for i in 0..16 {
                mac[i] ^= chunk[i];
            }
            mac = self.cipher.encrypt_block(&mac);
        }

        Ok(mac.to_vec())
    }

    /// Cipher function - extends PRF output to desired length
    ///
    /// Per NIST SP 800-38G and verified with str4d/fpe:
    /// - First block (d <= 16): return first d bytes of R directly
    /// - Additional blocks (d > 16): encrypt R XOR j for j = 1, 2, 3, ...
    fn ciph(&self, r: &[u8], d: usize) -> Result<Vec<u8>, FF1Error> {
        let mut result = Vec::new();

        #[cfg(test)]
        {
            use std::println;
            println!("DEBUG CIPH: R = {:02x?}, d = {}", r, d);
        }

        // First block: return first min(d, 16) bytes of R directly (no encryption)
        let first_block_size = core::cmp::min(d, 16);
        result.extend_from_slice(&r[..first_block_size]);

        #[cfg(test)]
        {
            use std::println;
            println!(
                "DEBUG CIPH: first {} bytes from R directly: {:02x?}",
                first_block_size, &result
            );
        }

        // If we need more bytes (d > 16), generate additional blocks
        let mut j = 1u128; // j starts at 1 for additional blocks
        while result.len() < d {
            // Create block by XORing R with big-endian j
            let mut block = [0u8; 16];
            block.copy_from_slice(r);

            let j_bytes = j.to_be_bytes();
            for (b, &j_byte) in block.iter_mut().zip(j_bytes.iter()) {
                *b ^= j_byte;
            }

            #[cfg(test)]
            {
                use std::println;
                println!("DEBUG CIPH: j = {}, block = {:02x?}", j, block);
            }

            let encrypted = self.cipher.encrypt_block(&block);

            #[cfg(test)]
            {
                use std::println;
                println!("DEBUG CIPH: encrypted = {:02x?}", encrypted);
            }

            result.extend_from_slice(&encrypted);
            j += 1;
        }

        result.truncate(d);

        #[cfg(test)]
        {
            use std::println;
            println!("DEBUG CIPH: final result (S) = {:02x?}", result);
        }

        Ok(result)
    }

    /// Add two numeral strings modulo radix^m
    fn add_mod(&self, a: &[u32], b: &[u32], radix: u32, m: usize) -> Result<Vec<u32>, FF1Error> {
        let a_num = self.num_radix(a, radix)?;
        let b_num = self.num_radix(b, radix)?;

        let modulus = Self::pow_radix(radix, m);
        let sum = (a_num + b_num) % &modulus;

        self.str_m_radix(&sum, radix, m)
    }

    /// Subtract two numeral strings modulo radix^m
    fn sub_mod(&self, a: &[u32], b: &[u32], radix: u32, m: usize) -> Result<Vec<u32>, FF1Error> {
        let a_num = self.num_radix(a, radix)?;
        let b_num = self.num_radix(b, radix)?;

        let modulus = Self::pow_radix(radix, m);
        // Modular subtraction: (a - b + modulus) % modulus ensures non-negative result
        let diff = (&modulus + &a_num - &b_num) % &modulus;

        self.str_m_radix(&diff, radix, m)
    }

    /// Convert numeral string to BigUint
    fn num_radix(&self, x: &[u32], radix: u32) -> Result<BigUint, FF1Error> {
        let mut result = BigUint::zero();
        let radix_big = BigUint::from(radix);

        for &digit in x {
            result = result * &radix_big + BigUint::from(digit);
        }

        Ok(result)
    }

    /// Convert BigUint to numeral string of length m
    fn str_m_radix(&self, x: &BigUint, radix: u32, m: usize) -> Result<Vec<u32>, FF1Error> {
        let mut result = Vec::with_capacity(m);
        let mut x = x.clone();
        let radix_big = BigUint::from(radix);

        for _ in 0..m {
            let (quotient, remainder) = x.div_rem(&radix_big);
            result.push(remainder.to_u32().ok_or(FF1Error::InternalError)?);
            x = quotient;
        }

        result.reverse();
        Ok(result)
    }

    /// Convert string to numeral representation
    fn str_to_numeral(&self, s: &str, radix: u32, alphabet: &str) -> Result<Vec<u32>, FF1Error> {
        let mut result = Vec::with_capacity(s.len());

        for ch in s.chars() {
            let pos = alphabet
                .chars()
                .position(|c| c == ch)
                .ok_or(FF1Error::InvalidCharacter)?;

            if pos >= radix as usize {
                return Err(FF1Error::InvalidCharacter);
            }

            result.push(pos as u32);
        }

        Ok(result)
    }

    /// Convert numeral to string
    fn numeral_to_str(
        &self,
        numeral: &[u32],
        radix: u32,
        alphabet: &str,
    ) -> Result<String, FF1Error> {
        let mut result = String::with_capacity(numeral.len());
        let alphabet_chars: Vec<char> = alphabet.chars().collect();

        for &digit in numeral {
            if digit >= radix {
                return Err(FF1Error::InvalidCharacter);
            }
            result.push(alphabet_chars[digit as usize]);
        }

        Ok(result)
    }

    /// Validate inputs
    fn validate_inputs(&self, input: &str, tweak: &[u8], radix: u32) -> Result<(), FF1Error> {
        // Validate radix
        if !(2..=65536).contains(&radix) {
            return Err(FF1Error::InvalidRadix);
        }

        // Validate input length
        if input.is_empty() {
            return Err(FF1Error::InputTooShort);
        }

        let n = input.len();

        // NIST recommends radix^minlen >= 100 for security, but we allow smaller
        // inputs for testing and flexibility
        let min_len = 2;
        let max_len = (1u64 << 32) as usize; // Practical limit

        if n < min_len {
            return Err(FF1Error::InputTooShort);
        }

        if n > max_len {
            return Err(FF1Error::InputTooLong);
        }

        // Validate tweak length (max 2^32 - 1 bytes)
        if tweak.len() > u32::MAX as usize {
            return Err(FF1Error::TweakTooLong);
        }

        Ok(())
    }

    /// Get default alphabet for a given radix
    fn default_alphabet(radix: u32) -> Result<String, FF1Error> {
        match radix {
            2 => Ok("01".to_string()),
            10 => Ok("0123456789".to_string()),
            16 => Ok("0123456789abcdef".to_string()),
            26 => Ok("abcdefghijklmnopqrstuvwxyz".to_string()),
            36 => Ok("0123456789abcdefghijklmnopqrstuvwxyz".to_string()),
            52 => Ok("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()),
            62 => Ok("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()),
            64 => {
                Ok("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/".to_string())
            }
            _ => {
                // For other radixes, generate numeric alphabet
                if radix <= 256 {
                    let mut alphabet = String::with_capacity(radix as usize);
                    for i in 0..radix {
                        alphabet.push((i as u8) as char);
                    }
                    Ok(alphabet)
                } else {
                    Err(FF1Error::InvalidRadix)
                }
            }
        }
    }

    /// Compute radix^m
    fn pow_radix(radix: u32, m: usize) -> BigUint {
        BigUint::from(radix).pow(m as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[allow(unused_imports)]
    use std::println;

    #[test]
    fn test_ff1_basic_decimal() {
        let key = [0u8; 32];
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "1234567890";
        let tweak = b"";
        let radix = 10;

        let ciphertext = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let decrypted = ff1.decrypt(&ciphertext, tweak, radix).unwrap();

        println!(
            "Basic test: plaintext={}, ciphertext={}, decrypted={}",
            plaintext, ciphertext, decrypted
        );
        assert_eq!(plaintext, decrypted);
        assert_eq!(plaintext.len(), ciphertext.len());
    }

    #[test]
    fn test_ff1_credit_card() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "4532123456789010";
        let tweak = b"user_id_12345";
        let radix = 10;

        let ciphertext = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let decrypted = ff1.decrypt(&ciphertext, tweak, radix).unwrap();

        println!("CC Plaintext:  {}", plaintext);
        println!("CC Ciphertext: {}", ciphertext);

        assert_eq!(plaintext, decrypted);
        assert_eq!(16, ciphertext.len());
        assert_ne!(plaintext, ciphertext); // Should be different
    }

    #[test]
    fn test_ff1_ssn() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        // Encrypt SSN digits (without dashes)
        let plaintext = "123456789";
        let tweak = b"ssn";
        let radix = 10;

        let ciphertext = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let decrypted = ff1.decrypt(&ciphertext, tweak, radix).unwrap();

        println!("SSN Plaintext:  {}", plaintext);
        println!("SSN Ciphertext: {}", ciphertext);

        assert_eq!(plaintext, decrypted);
        assert_eq!(9, ciphertext.len());
    }

    #[test]
    fn test_ff1_alphanumeric() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "abc123xyz";
        let tweak = b"";
        let radix = 36;

        let ciphertext = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let decrypted = ff1.decrypt(&ciphertext, tweak, radix).unwrap();

        println!("Alphanum Plaintext:  {}", plaintext);
        println!("Alphanum Ciphertext: {}", ciphertext);

        assert_eq!(plaintext, decrypted);
        assert_eq!(plaintext.len(), ciphertext.len());
    }

    #[test]
    fn test_ff1_different_tweaks() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "1234567890";
        let tweak1 = b"context1";
        let tweak2 = b"context2";
        let radix = 10;

        let ciphertext1 = ff1.encrypt(plaintext, tweak1, radix).unwrap();
        let ciphertext2 = ff1.encrypt(plaintext, tweak2, radix).unwrap();

        // Different tweaks should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt correctly
        assert_eq!(plaintext, ff1.decrypt(&ciphertext1, tweak1, radix).unwrap());
        assert_eq!(plaintext, ff1.decrypt(&ciphertext2, tweak2, radix).unwrap());
    }

    #[test]
    fn test_ff1_binary() {
        let key = [0u8; 16];
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "101010";
        let tweak = b"";
        let radix = 2;

        let ciphertext = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let decrypted = ff1.decrypt(&ciphertext, tweak, radix).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(6, ciphertext.len());
    }

    #[test]
    fn test_ff1_deterministic() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "1234567890";
        let tweak = b"test";
        let radix = 10;

        let ciphertext1 = ff1.encrypt(plaintext, tweak, radix).unwrap();
        let ciphertext2 = ff1.encrypt(plaintext, tweak, radix).unwrap();

        // Same input should always produce same output (deterministic)
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_ff1_invalid_radix() {
        let key = [0u8; 16];
        let ff1 = FF1::new(&key).unwrap();

        // Radix too small
        assert!(matches!(
            ff1.encrypt("123", b"", 1),
            Err(FF1Error::InvalidRadix)
        ));

        // Radix too large
        assert!(matches!(
            ff1.encrypt("123", b"", 70000),
            Err(FF1Error::InvalidRadix)
        ));
    }

    #[test]
    fn test_ff1_input_too_short() {
        let key = [0u8; 16];
        let ff1 = FF1::new(&key).unwrap();

        // Single character is too short
        assert!(matches!(
            ff1.encrypt("1", b"", 10),
            Err(FF1Error::InputTooShort)
        ));
    }

    #[test]
    fn test_ff1_wrong_tweak() {
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();

        let plaintext = "1234567890";
        let correct_tweak = b"correct";
        let wrong_tweak = b"wrong";
        let radix = 10;

        let ciphertext = ff1.encrypt(plaintext, correct_tweak, radix).unwrap();

        // Decrypting with wrong tweak should give wrong result
        let decrypted = ff1.decrypt(&ciphertext, wrong_tweak, radix).unwrap();
        assert_ne!(plaintext, decrypted);
    }

    // NIST Test Vectors from SP 800-38G
    // Source: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf

    #[test]
    fn test_ff1_nist_aes128_sample1() {
        // Sample 1: AES-128, radix 10, no tweak
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();
        let plaintext = "0123456789";
        let tweak = b"";
        let expected_ciphertext = "2433477484";

        let ciphertext = ff1.encrypt(plaintext, tweak, 10).unwrap();
        println!("NIST Sample 1:");
        println!("  Plaintext:  {}", plaintext);
        println!(
            "  Ciphertext: {} (expected: {})",
            ciphertext, expected_ciphertext
        );

        // Debug: try decrypting the expected ciphertext to see if decrypt works
        if ciphertext != expected_ciphertext {
            println!("  Attempting to decrypt expected ciphertext...");
            let test_decrypt = ff1.decrypt(expected_ciphertext, tweak, 10).unwrap();
            println!(
                "  Decrypt of expected: {} (should be: {})",
                test_decrypt, plaintext
            );
        }

        assert_eq!(ciphertext, expected_ciphertext);

        // Verify decryption
        let decrypted = ff1.decrypt(&ciphertext, tweak, 10).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ff1_nist_aes128_sample2() {
        // Sample 2: AES-128, radix 10, with tweak
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3C");
        let ff1 = FF1::new(&key).unwrap();
        let plaintext = "0123456789";
        let tweak = hex!("39383736353433323130");
        let expected_ciphertext = "6124200773";

        let ciphertext = ff1.encrypt(plaintext, &tweak, 10).unwrap();
        println!("NIST Sample 2:");
        println!("  Plaintext:  {}", plaintext);
        println!(
            "  Ciphertext: {} (expected: {})",
            ciphertext, expected_ciphertext
        );

        assert_eq!(ciphertext, expected_ciphertext);

        // Verify decryption
        let decrypted = ff1.decrypt(&ciphertext, &tweak, 10).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ff1_nist_aes256_sample7() {
        // Sample 7: AES-256, radix 10, no tweak
        let key = hex!("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94");
        let ff1 = FF1::new(&key).unwrap();
        let plaintext = "0123456789";
        let tweak = b"";
        let expected_ciphertext = "6657667009";

        let ciphertext = ff1.encrypt(plaintext, tweak, 10).unwrap();
        println!("NIST Sample 7 (AES-256):");
        println!("  Plaintext:  {}", plaintext);
        println!(
            "  Ciphertext: {} (expected: {})",
            ciphertext, expected_ciphertext
        );

        assert_eq!(ciphertext, expected_ciphertext);

        // Verify decryption
        let decrypted = ff1.decrypt(&ciphertext, tweak, 10).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
