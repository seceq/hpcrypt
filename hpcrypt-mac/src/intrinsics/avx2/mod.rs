//! AVX2 + PCLMULQDQ optimized implementations
//!
//! Requires:
//! - AVX2: 256-bit SIMD operations
//! - PCLMULQDQ: Carryless multiplication (CLMUL)
//! - SSSE3: For byte shuffling (pshufb)
//!
//! Performance: ~10-20x faster than portable implementation
//! - Small messages (16 bytes): ~2.7-5 GB/s
//! - Large messages (4KB+): ~7-14 GB/s
//!
//! Both GHASH and POLYVAL use the R/F algorithm:
//! - 4 CLMUL per block for R and F terms
//! - 1 CLMUL for reduction (Lemma 3)
//! - 4-block aggregated processing with single reduction (17 CLMULs per 64 bytes)

pub mod ghash;
pub mod polyval;

pub use ghash::{ghash_avx2, GhashAvx2, GhashAvx2Key};
pub use polyval::{polyval_avx2, PolyvalAvx2, PolyvalAvx2Key};
