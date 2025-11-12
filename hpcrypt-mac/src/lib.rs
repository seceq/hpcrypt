#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Message Authentication Codes (MAC)
//!
//! This crate provides MAC implementations including CMAC (Cipher-based MAC).

#[cfg(feature = "std")]
extern crate std;

pub mod cmac;

pub use cmac::{AesCmac128, AesCmac256, aes_cmac_128, aes_cmac_256};
