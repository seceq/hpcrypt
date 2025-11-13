//! # hpcrypt-fpe - Format-Preserving Encryption
//!
//! This crate provides Format-Preserving Encryption (FPE) implementations.
//!
//! ## FF1 Mode
//!
//! FF1 is specified in NIST SP 800-38G Rev. 1 and provides format-preserving
//! encryption using a Feistel structure with AES.
//!
//! ### Use Cases
//!
//! - **Credit card numbers**: Encrypt while preserving format (16 digits)
//! - **Social Security Numbers**: Encrypt while keeping XXX-XX-XXXX format
//! - **Database encryption**: Encrypt columns without changing schema
//! - **Legacy systems**: Encrypt data while maintaining format compatibility
//!
//! ### Example
//!
//! ```rust
//! use hpcrypt_fpe::FF1;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create FF1 instance with AES-256 key
//! let key = [0u8; 32];
//! let ff1 = FF1::new(&key)?;
//!
//! // Encrypt a credit card number (radix 10 for decimal digits)
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
//!
//! ## Security Considerations
//!
//! - **Minimum radix**: 2 (binary)
//! - **Maximum radix**: 65536 (2^16)
//! - **Minimum input length**: Depends on radix, generally >= 2
//! - **Tweak**: Optional additional input for domain separation
//! - **Key**: AES-128, AES-192, or AES-256 key

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    missing_debug_implementations
)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod ff1;

pub use ff1::{FF1Error, FF1};
