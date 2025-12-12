//! Parameter sets for ML-DSA
//!
//! This module defines the three security levels specified in NIST FIPS 204:
//! - ML-DSA-44 (NIST Security Level 2, equivalent to Dilithium2)
//! - ML-DSA-65 (NIST Security Level 3, equivalent to Dilithium3) - Recommended
//! - ML-DSA-87 (NIST Security Level 5, equivalent to Dilithium5)

/// Degree of polynomials (n = 256 for all ML-DSA parameter sets)
pub const N: usize = 256;

/// Modulus q = 8380417 (prime, q ≡ 1 mod 2n)
pub const Q: i32 = 8380417;

/// Trait defining ML-DSA parameter sets
///
/// Each parameter set defines security-level-specific constants including
/// the dimensions (k, l), noise parameters (eta), and derived sizes.
pub trait DsaParams: Send + Sync + 'static {
    /// Number of rows in matrix A (k ∈ {4, 6, 8})
    const K: usize;

    /// Number of columns in matrix A / dimension of s1, z (ℓ ∈ {4, 5, 7})
    const L: usize;

    /// Secret key coefficient bound (η ∈ {2, 4})
    const ETA: i32;

    /// Number of ±1's in challenge polynomial c (τ)
    const TAU: usize;

    /// y coefficient range parameter (γ₁)
    const GAMMA1: i32;

    /// Low-order rounding range (γ₂ = (q-1)/α)
    const GAMMA2: i32;

    /// Number of bits dropped in t (d)
    const D: usize;

    /// Coefficient of hint polynomial (ω)
    const OMEGA: usize;

    /// Security strength parameter (β)
    const BETA: i32;

    /// Size of c_tilde hash in bytes (λ/4 where λ is security level in bits)
    /// ML-DSA-44: 32 bytes (λ=128), ML-DSA-65: 48 bytes (λ=192), ML-DSA-87: 64 bytes (λ=256)
    const CTILDEBYTES: usize;

    /// Size of public key in bytes
    const PK_SIZE: usize;

    /// Size of secret key in bytes
    const SK_SIZE: usize;

    /// Size of signature in bytes
    const SIG_SIZE: usize;

    /// Name of the parameter set
    const NAME: &'static str;

    /// Number of bits needed to encode w1 coefficients
    /// w1 ∈ [0, (q-1)/(2γ₂) - 1], so bits = ceil(log2((q-1)/(2γ₂)))
    /// ML-DSA-44: 6 bits (w1 ∈ [0, 43])
    /// ML-DSA-65/87: 4 bits (w1 ∈ [0, 15])
    const W1_BITS: usize;

    /// Size of encoded w1 vector in bytes = K * N * W1_BITS / 8
    const W1_ENCODED_SIZE: usize;
}

/// ML-DSA-44 parameter set (NIST Security Level 2)
///
/// Provides security roughly equivalent to SHA-256 collision resistance.
/// This is the smallest and fastest parameter set.
///
/// # Sizes
/// - Public key: 1312 bytes
/// - Secret key: 2560 bytes
/// - Signature: 2420 bytes
///
/// # Parameters
/// - (k, ℓ) = (4, 4)
/// - η = 2
/// - γ₁ = 2¹⁷ = 131072
/// - γ₂ = (q-1)/88 = 95232
#[derive(Debug, Clone, Copy)]
pub struct MlDsa44;

impl DsaParams for MlDsa44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const TAU: usize = 39;
    const GAMMA1: i32 = 1 << 17; // 2^17 = 131072
    const GAMMA2: i32 = (Q - 1) / 88; // 95232
    const D: usize = 13;
    const OMEGA: usize = 80;
    const BETA: i32 = Self::TAU as i32 * Self::ETA; // 78
    const CTILDEBYTES: usize = 32; // λ=128 bits → 32 bytes
    const PK_SIZE: usize = 1312;
    const SK_SIZE: usize = 2560;
    const SIG_SIZE: usize = 2420;
    const NAME: &'static str = "ML-DSA-44";
    const W1_BITS: usize = 6; // w1 ∈ [0, 43] for gamma2 = (q-1)/88
    const W1_ENCODED_SIZE: usize = Self::K * N * Self::W1_BITS / 8; // 4 * 256 * 6 / 8 = 768
}

/// ML-DSA-65 parameter set (NIST Security Level 3) - RECOMMENDED
///
/// Provides security roughly equivalent to SHA-384 collision resistance.
/// This is the recommended parameter set for most applications.
///
/// # Sizes
/// - Public key: 1952 bytes
/// - Secret key: 4032 bytes
/// - Signature: 3309 bytes
///
/// # Parameters
/// - (k, ℓ) = (6, 5)
/// - η = 4
/// - γ₁ = 2¹⁹ = 524288
/// - γ₂ = (q-1)/32 = 261888
#[derive(Debug, Clone, Copy)]
pub struct MlDsa65;

impl DsaParams for MlDsa65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const TAU: usize = 49;
    const GAMMA1: i32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: i32 = (Q - 1) / 32; // 261888
    const D: usize = 13;
    const OMEGA: usize = 55;
    const BETA: i32 = Self::TAU as i32 * Self::ETA; // 196
    const CTILDEBYTES: usize = 48; // λ=192 bits → 48 bytes
    const PK_SIZE: usize = 1952;
    const SK_SIZE: usize = 4032;
    const SIG_SIZE: usize = 3309;
    const NAME: &'static str = "ML-DSA-65";
    const W1_BITS: usize = 4; // w1 ∈ [0, 15] for gamma2 = (q-1)/32
    const W1_ENCODED_SIZE: usize = Self::K * N * Self::W1_BITS / 8; // 6 * 256 * 4 / 8 = 768
}

/// ML-DSA-87 parameter set (NIST Security Level 5)
///
/// Provides security roughly equivalent to SHA-512 collision resistance.
/// This is the most secure parameter set for highly sensitive applications.
///
/// # Sizes
/// - Public key: 2592 bytes
/// - Secret key: 4896 bytes
/// - Signature: 4627 bytes
///
/// # Parameters
/// - (k, ℓ) = (8, 7)
/// - η = 2
/// - γ₁ = 2¹⁹ = 524288
/// - γ₂ = (q-1)/32 = 261888
#[derive(Debug, Clone, Copy)]
pub struct MlDsa87;

impl DsaParams for MlDsa87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const TAU: usize = 60;
    const GAMMA1: i32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: i32 = (Q - 1) / 32; // 261888
    const D: usize = 13;
    const OMEGA: usize = 75;
    const BETA: i32 = Self::TAU as i32 * Self::ETA; // 120
    const CTILDEBYTES: usize = 64; // λ=256 bits → 64 bytes
    const PK_SIZE: usize = 2592;
    const SK_SIZE: usize = 4896;
    const SIG_SIZE: usize = 4627;
    const NAME: &'static str = "ML-DSA-87";
    const W1_BITS: usize = 4; // w1 ∈ [0, 15] for gamma2 = (q-1)/32
    const W1_ENCODED_SIZE: usize = Self::K * N * Self::W1_BITS / 8; // 8 * 256 * 4 / 8 = 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa44_params() {
        assert_eq!(MlDsa44::K, 4);
        assert_eq!(MlDsa44::L, 4);
        assert_eq!(MlDsa44::ETA, 2);
        assert_eq!(MlDsa44::TAU, 39);
        assert_eq!(MlDsa44::GAMMA1, 131072);
        assert_eq!(MlDsa44::GAMMA2, 95232);
        assert_eq!(MlDsa44::BETA, 78);
        assert_eq!(MlDsa44::NAME, "ML-DSA-44");
    }

    #[test]
    fn test_mldsa44_sizes() {
        assert_eq!(MlDsa44::PK_SIZE, 1312);
        assert_eq!(MlDsa44::SK_SIZE, 2560);
        assert_eq!(MlDsa44::SIG_SIZE, 2420);
    }

    #[test]
    fn test_mldsa65_params() {
        assert_eq!(MlDsa65::K, 6);
        assert_eq!(MlDsa65::L, 5);
        assert_eq!(MlDsa65::ETA, 4);
        assert_eq!(MlDsa65::TAU, 49);
        assert_eq!(MlDsa65::GAMMA1, 524288);
        assert_eq!(MlDsa65::GAMMA2, 261888);
        assert_eq!(MlDsa65::BETA, 196);
        assert_eq!(MlDsa65::NAME, "ML-DSA-65");
    }

    #[test]
    fn test_mldsa65_sizes() {
        assert_eq!(MlDsa65::PK_SIZE, 1952);
        assert_eq!(MlDsa65::SK_SIZE, 4032);
        assert_eq!(MlDsa65::SIG_SIZE, 3309);
    }

    #[test]
    fn test_mldsa87_params() {
        assert_eq!(MlDsa87::K, 8);
        assert_eq!(MlDsa87::L, 7);
        assert_eq!(MlDsa87::ETA, 2);
        assert_eq!(MlDsa87::TAU, 60);
        assert_eq!(MlDsa87::GAMMA1, 524288);
        assert_eq!(MlDsa87::GAMMA2, 261888);
        assert_eq!(MlDsa87::BETA, 120);
        assert_eq!(MlDsa87::NAME, "ML-DSA-87");
    }

    #[test]
    fn test_mldsa87_sizes() {
        assert_eq!(MlDsa87::PK_SIZE, 2592);
        assert_eq!(MlDsa87::SK_SIZE, 4896);
        assert_eq!(MlDsa87::SIG_SIZE, 4627);
    }

    #[test]
    fn test_common_params() {
        assert_eq!(N, 256);
        assert_eq!(Q, 8380417);
    }

    #[test]
    fn test_q_properties() {
        // q must be prime and q ≡ 1 (mod 2n)
        assert_eq!(Q % (2 * N as i32), 1);
    }
}
