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

#[cfg(feature = "alloc")]
extern crate alloc;

// Note: When --all-features is used, both 'std' and 'ascon-only' get enabled
// We give precedence to std/alloc features (normal build) over ascon-only
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_optimized;  // Phase 1 optimizations (1.2 + 1.3) - FAILED
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_fixslice;  // Fixslicing implementation - constant-time, 4-block parallel
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod ghash;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod ghash_optimized;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod ghash_fast;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_gcm;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod polyval;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_gcm_siv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_ccm;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_eax;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_ocb;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod aes_siv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod chacha20;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod poly1305;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod chacha20poly1305;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub mod gmac;

// Ascon is always available
pub mod ascon;

#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes::{Aes, AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, BLOCK_SIZE};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use ghash::GHash;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use ghash_optimized::{GHashOptimized, GHashAggregated, ghash_optimized};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use ghash_fast::{GHashFast, ghash_fast};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, TAG_SIZE, NONCE_SIZE};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use polyval::Polyval;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_gcm_siv::Aes128GcmSiv;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_ccm::{Aes128Ccm, Aes256Ccm, CcmError};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_eax::{Aes128Eax, Aes256Eax};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_ocb::{Aes128Ocb, Aes256Ocb};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use aes_siv::{Aes128Siv, Aes256Siv};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use chacha20::ChaCha20;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use poly1305::Poly1305;
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
#[cfg(not(all(feature = "ascon-only", not(feature = "std"))))]
pub use gmac::{Gmac128, Gmac192, Gmac256, gmac128, gmac192, gmac256};

// Ascon is always exported
pub use ascon::{Ascon128, Ascon128a};
