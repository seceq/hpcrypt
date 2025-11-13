//! Key Derivation Functions (KDF)
//!
//! This crate provides implementations of modern key derivation functions.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

pub mod argon2;
pub mod hkdf;
pub mod pbkdf2;
pub mod quic;
pub mod scrypt;
pub mod tls12;
pub mod tls13;
pub mod x963;

pub use argon2::{Argon2, Argon2d, Argon2i, Argon2id, Params};
pub use hkdf::{
    hkdf_blake2b, hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfBlake2b, HkdfSha256, HkdfSha384,
    HkdfSha512,
};
pub use pbkdf2::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};
pub use scrypt::{scrypt, ScryptParams};
pub use tls12::{prf_sha256, prf_sha384, prf_sha512};
pub use x963::{x963_kdf, x963_kdf_sha256, x963_kdf_sha384, x963_kdf_sha512};
