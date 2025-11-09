#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod blake2b;
pub mod blake2s;
pub mod blake3;
pub mod hmac;
pub mod kmac;
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod sha3;

// Re-export commonly used types
pub use blake2b::{Blake2b, blake2b, blake2b_variable, blake2b_mac};
pub use blake2s::{Blake2s, Blake2sParams, blake2s, blake2s_sized, blake2s_keyed};
pub use blake3::{Blake3, blake3, blake3_keyed, blake3_derive_key};
pub use hmac::{HmacSha256, HmacSha384, HmacSha512, HmacBlake2b, hmac_sha256, hmac_sha384, hmac_sha512, hmac_blake2b};
pub use kmac::{Kmac128, Kmac256, CShake128, CShake256};
#[cfg(feature = "alloc")]
pub use kmac::{kmac128, kmac256};
pub use sha1::{Sha1, sha1};
pub use sha256::{Sha256, sha256};
pub use sha384::Sha384;
pub use sha512::{Sha512, sha512};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};
