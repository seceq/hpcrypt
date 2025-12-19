#![no_std]
#![forbid(unsafe_code)]
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

#[cfg(feature = "std")]
extern crate std;

// Traits
pub mod traits;

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
#[cfg(feature = "alloc")]
pub use ghash::ghash_fast;
pub use ghash::GHashFast;
pub use gmac::{gmac128, gmac192, gmac256, Gmac128, Gmac192, Gmac256};
pub use hmac::{
    hmac_blake2b, hmac_sha256, hmac_sha384, hmac_sha512, HmacBlake2b, HmacSha256, HmacSha384,
    HmacSha512,
};
#[cfg(feature = "alloc")]
pub use kmac::{kmac128, kmac256};
pub use kmac::{CShake128, CShake256, Kmac128, Kmac256};
pub use poly1305::{poly1305, Poly1305};
pub use polyval::{polyval, Polyval};

// Re-export traits
pub use traits::{Mac, MacContext};
