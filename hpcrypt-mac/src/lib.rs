#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Message Authentication Codes (MAC)
//!
//! This crate provides MAC implementations:
//! - HMAC (Hash-based MAC)
//! - CMAC (Cipher-based MAC)
//! - GMAC (Galois MAC)
//! - KMAC (Keccak MAC)
//! - Poly1305 (Polynomial MAC)
//! - GHASH (Universal hash for GCM)
//! - POLYVAL (Universal hash for AES-GCM-SIV)
//!
//! Hardware acceleration is automatically used when available:
//! - AVX2 + PCLMULQDQ on x86/x86_64 for GHASH/POLYVAL
//! - NEON + PMULL on AArch64 for GHASH/POLYVAL

#[cfg(feature = "std")]
extern crate std;

// Traits
pub mod traits;

// SIMD intrinsics (architecture-specific)
pub(crate) mod intrinsics;

// MAC implementations
pub mod cmac;
pub mod ghash;
pub mod gmac;
pub mod hmac;
pub mod kmac;
pub mod poly1305;
pub mod polyval;

// Re-exports
pub use cmac::{aes_cmac_128, aes_cmac_256, AesCmac128, AesCmac256};
pub use ghash::{Ghash, GhashKey};
pub use gmac::{gmac128, gmac192, gmac256, Gmac128, Gmac192, Gmac256, GmacError};
#[cfg(feature = "alloc")]
pub use gmac::gmac_variable;
pub use hmac::{
    hmac_blake2b, hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512, hmac_sha512_224,
    hmac_sha512_256, HmacBlake2b, HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224,
    HmacSha512_256,
};
#[cfg(feature = "alloc")]
pub use kmac::{kmac128, kmac256};
pub use kmac::{CShake128, CShake256, Kmac128, Kmac256};
pub use poly1305::{poly1305, Poly1305};
pub use polyval::{polyval, Polyval};

// Re-export traits
pub use traits::{Mac, MacContext};
