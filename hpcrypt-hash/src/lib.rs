#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod blake2b;
pub mod blake2s;
pub mod blake3;
pub mod sha1;
pub mod sha256;
pub mod sha3;
pub mod sha384;
pub mod sha512;
pub mod xof_reader;

// Re-export commonly used types
pub use blake2b::{blake2b, blake2b_mac, blake2b_variable, Blake2b};
pub use blake2s::{blake2s, blake2s_keyed, blake2s_sized, Blake2s, Blake2sParams};
pub use blake3::{blake3, blake3_derive_key, blake3_keyed, Blake3};
pub use sha1::{sha1, Sha1};
pub use sha256::{sha256, Sha256};
pub use sha3::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, TurboShake128, TurboShake256,
};
pub use sha384::{sha384, Sha384};
pub use sha512::{sha512, Sha512};
