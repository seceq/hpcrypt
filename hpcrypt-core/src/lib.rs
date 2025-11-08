//! Core utilities for HPCrypt
//!
//! This crate provides fundamental building blocks for cryptographic implementations:
//! - Constant-time operations
//! - Secure memory handling
//! - Common traits and types

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

pub mod ct;
pub mod ct_utils;
pub mod error;
pub mod traits;
pub mod utils;

// Re-export commonly used items
pub use zeroize;

pub use ct::{CtEqual, CtOption};
pub use ct_utils::{
    ct_is_zero_u64, ct_swap_array, ct_swap_u64, ct_table_lookup, Choice, ConditionallyNegatable,
    ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};
