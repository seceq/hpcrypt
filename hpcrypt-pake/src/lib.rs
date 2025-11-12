#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Password-Authenticated Key Exchange (PAKE) Protocols
//!
//! This crate provides implementations of various PAKE protocols including:
//! - OPAQUE: Augmented Password-Authenticated Key Exchange (aPAKE)
//! - OPRF: Oblivious Pseudorandom Function

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod oprf;
pub mod opaque;
mod opaque_impl;

pub use oprf::{
    OprfClient, OprfServer, OprfError, OprfKey, Blind,
    BlindedElement, EvaluatedElement,
};

pub use opaque::{
    Config, Group, HashFunction, KdfFunction, MacFunction, KsfFunction,
    OpaqueClient, OpaqueServer, OpaqueError,
    RegistrationRequest, RegistrationResponse, RegistrationRecord,
    KE1, KE2, KE3,
    ServerKeyStorage, InMemoryStorage,
};
