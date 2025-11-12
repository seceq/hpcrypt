//! QUIC Protocol Crypto Primitives
//!
//! This crate provides crypto primitives specific to the QUIC protocol (RFC 9001).
//!
//! # Header Protection
//!
//! QUIC uses header protection to encrypt packet headers. The protection is applied
//! using AES-128-ECB or ChaCha20, depending on the cipher suite.
//!
//! # Example
//!
//! ```rust
//! use hpcrypt_quic::{HeaderProtectionAes128, HeaderProtection};
//!
//! // Create header protection with AES-128
//! let hp_key = [0u8; 16];
//! let hp = HeaderProtectionAes128::new(&hp_key);
//!
//! // Generate mask from sample (16 bytes for AES)
//! let sample = [0u8; 16];
//! let mask = hp.generate_mask(&sample);
//! assert_eq!(mask.len(), 5);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod header_protection;

pub use header_protection::{
    HeaderProtection, HeaderProtectionAes128, HeaderProtectionAes256, HeaderProtectionChaCha20,
};
