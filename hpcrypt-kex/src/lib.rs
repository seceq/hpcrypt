#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Key Exchange Protocols
//!
//! This crate provides implementations of various key exchange protocols including:
//! - OPAQUE: Augmented Password-Authenticated Key Exchange (aPAKE)

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod opaque;
mod opaque_impl;
pub mod oprf;

pub use oprf::{
    Blind, BlindedElement, EvaluatedElement, OprfClient, OprfError, OprfKey, OprfServer,
};

pub use opaque::{
    Config, Group, HashFunction, InMemoryStorage, KdfFunction, KsfFunction, MacFunction,
    OpaqueClient, OpaqueError, OpaqueServer, RegistrationRecord, RegistrationRequest,
    RegistrationResponse, ServerKeyStorage, KE1, KE2, KE3,
};
