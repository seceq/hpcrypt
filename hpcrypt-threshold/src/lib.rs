//! Threshold Cryptography
//!
//! This module provides threshold cryptography primitives, including Shamir Secret Sharing.
//!
//! # Shamir Secret Sharing
//!
//! Shamir Secret Sharing is a threshold scheme that allows a secret to be divided into n shares,
//! where any k shares can reconstruct the secret, but k-1 shares reveal no information.
//!
//! ## Example
//!
//! ```rust
//! use hpcrypt_threshold::shamir::{split_secret, reconstruct_secret};
//!
//! // Split a 32-byte secret into 5 shares, requiring 3 to reconstruct
//! let secret = [42u8; 32];
//! let shares = split_secret(&secret, 3, 5).unwrap();
//!
//! // Reconstruct from any 3 shares
//! let reconstructed = reconstruct_secret(&shares[0..3]).unwrap();
//! assert_eq!(&secret[..], &reconstructed[..]);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod shamir;

pub use shamir::{reconstruct_secret, split_secret, Share};
