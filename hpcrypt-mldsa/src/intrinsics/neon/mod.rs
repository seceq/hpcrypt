//! Optimized ARM NEON SIMD Implementation for ML-DSA
//!
//! This module contains only the NEON functions that have been benchmarked
//! to be FASTER than their portable counterparts on ARM Neoverse-N1.
//!
//! # Benchmark Results (ARM Neoverse-N1)
//!
//! Functions included here (all faster with NEON):
//! - NTT/InvNTT: ~2x faster
//! - pointwise_montgomery: ~2x faster
//! - decompose: ~2.4x faster
//! - highbits: ~1.94x faster
//! - lowbits: ~2.27x faster
//! - make_hint/use_hint: ~1.5-2x faster
//! - infinity_norm: faster
//! - infinity_norm_threshold: ~3.65x faster (with early exit)
//!
//! # Functions NOT included (slower than portable)
//!
//! These were benchmarked and found to be slower than scalar:
//! - poly_add, poly_sub (1.7x slower)
//! - poly_reduce (1.26x slower)
//! - power2round (1.17x slower)
//! - rej_uniform (1.35x slower)
//! - packing operations (1.5-4x slower)
//!
//! # Usage
//!
//! ```rust,ignore
//! #[cfg(target_arch = "aarch64")]
//! unsafe {
//!     // Use these (faster):
//!     neon::ntt_neon(&mut poly);
//!     neon::decompose_fast(&coeffs, &mut r1, &mut r0, alpha);
//!     neon::poly_infinity_norm_threshold(&coeffs, threshold);
//! }
//! ```

#![allow(dead_code)]

// Macros must be declared first
#[macro_use]
pub mod macros;

pub mod consts;
pub mod reduce;
pub mod ntt;
pub mod poly;
pub mod rounding;
pub mod hints;

// Re-export only the faster functions
pub use ntt::{ntt_neon, inv_ntt_neon, ntt_multiply, ntt_multiply_add};
pub use poly::{
    poly_pointwise_montgomery,
    poly_infinity_norm,
    poly_infinity_norm_centered,
    poly_infinity_norm_threshold,
    poly_infinity_norm_threshold_centered,
    poly_chknorm_centered,
};
pub use reduce::{fqmul_neon, fqmul_shoup_neon, reduce32_neon, caddq_neon};
pub use rounding::{decompose_fast, highbits_fast, lowbits_fast};
pub use hints::{make_hint_fast, use_hint_fast};
