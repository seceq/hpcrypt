//! Authenticated Encryption with Associated Data (AEAD) implementations
//!
//! This crate provides high-performance AEAD cipher implementations:
//! - AES-GCM (AES-128/192/256 in Galois/Counter Mode)
//! - AES-GCM-SIV (Nonce Misuse-Resistant AES-GCM)
//! - AES-CCM (Counter with CBC-MAC)
//! - AES-EAX (Encrypt-then-Authenticate-then-Translate)
//! - AES-OCB3 (Offset Codebook Mode v3)
//! - AES-SIV (Synthetic IV Mode - Deterministic AEAD)
//! - ChaCha20-Poly1305
//! - XChaCha20-Poly1305
//! - Ascon-128 / Ascon-128a (NIST Lightweight Cryptography Winner)
//! - GMAC (Galois Message Authentication Code - Authentication without encryption)

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

// AEAD mode implementations
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_ccm;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_eax;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_gcm;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_gcm_siv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_ocb;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_siv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod chacha20poly1305;

// Lightweight AEAD
pub mod ascon;

// AEAD mode exports
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_ccm::{Aes128Ccm, Aes256Ccm, CcmError};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_eax::{Aes128Eax, Aes256Eax};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, NONCE_SIZE, TAG_SIZE};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_gcm_siv::Aes128GcmSiv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_ocb::{Aes128Ocb, Aes256Ocb};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_siv::{Aes128Siv, Aes256Siv};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

// Re-export from hpcrypt-cipher for convenience
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use hpcrypt_cipher::{
    Aes, ChaCha20, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE,
};

// Re-export Ascon from local module
pub use ascon::{Ascon128, Ascon128a};

// Re-export from hpcrypt-mac for convenience
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use hpcrypt_mac::{
    ghash, gmac128, gmac192, gmac256, GHashFast, Gmac128, Gmac192, Gmac256, Poly1305, Polyval,
};
