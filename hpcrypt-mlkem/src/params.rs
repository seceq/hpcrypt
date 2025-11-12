//! Parameter sets for ML-KEM
//!
//! This module defines the three security levels specified in NIST FIPS 203:
//! - **ML-KEM-512** (NIST Security Level 1) - Equivalent to AES-128
//! - **ML-KEM-768** (NIST Security Level 3) - Equivalent to AES-192 - **Recommended**
//! - **ML-KEM-1024** (NIST Security Level 5) - Equivalent to AES-256
//!
//! Each parameter set provides a different trade-off between security level,
//! key size, ciphertext size, and computational performance.

/// Degree of polynomials (n = 256 for all ML-KEM parameter sets)
pub const N: usize = 256;

/// Modulus q = 3329 (prime, q ≡ 1 mod 2n)
pub const Q: i16 = 3329;

/// Trait defining ML-KEM parameter sets
///
/// Each parameter set defines security-level-specific constants including
/// the dimension k, eta values for noise sampling, and derived sizes.
///
/// This trait is implemented by [`MlKem512`], [`MlKem768`], and [`MlKem1024`].
/// It is sealed and cannot be implemented by external types.
pub trait Params: Send + Sync + 'static {
    /// Dimension of the module lattice (k ∈ {2, 3, 4})
    ///
    /// - ML-KEM-512: k = 2
    /// - ML-KEM-768: k = 3
    /// - ML-KEM-1024: k = 4
    const K: usize;

    /// Eta1 parameter for noise sampling during key generation (η₁)
    const ETA1: usize;

    /// Eta2 parameter for noise sampling during encapsulation (η₂)
    const ETA2: usize;

    /// Bits for compression of ciphertext u vector coefficients (dᵤ)
    const DU: usize;

    /// Bits for compression of ciphertext v polynomial coefficients (dᵥ)
    const DV: usize;

    /// Size of encapsulation key (public key) in bytes
    ///
    /// Formula: 384k + 32 (polynomial vector + seed)
    const EK_SIZE: usize = 384 * Self::K + 32;

    /// Size of decapsulation key (private key) in bytes
    ///
    /// Formula: 768k + 96 (includes ek, sk, H(ek), and z)
    const DK_SIZE: usize = 768 * Self::K + 96;

    /// Size of ciphertext in bytes
    ///
    /// Formula: 32·dᵤ·k + 32·dᵥ
    const CT_SIZE: usize = 32 * Self::DU * Self::K + 32 * Self::DV;

    /// Size of shared secret in bytes (always 32 for all parameter sets)
    const SS_SIZE: usize = 32;

    /// Human-readable name of the parameter set
    const NAME: &'static str;
}

/// ML-KEM-512 parameter set (NIST Security Level 1)
///
/// Provides security roughly equivalent to AES-128. This is the smallest and
/// fastest parameter set, suitable for applications with moderate security requirements.
///
/// # Sizes
/// - Public key: 800 bytes
/// - Private key: 1632 bytes
/// - Ciphertext: 768 bytes
/// - Shared secret: 32 bytes
#[derive(Debug, Clone, Copy)]
pub struct MlKem512;

impl Params for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-512";
}

/// ML-KEM-768 parameter set (NIST Security Level 3) - RECOMMENDED
///
/// Provides security roughly equivalent to AES-192. This is the recommended
/// parameter set for most applications, offering a good balance between
/// security and performance.
///
/// # Sizes
/// - Public key: 1184 bytes
/// - Private key: 2400 bytes
/// - Ciphertext: 1088 bytes
/// - Shared secret: 32 bytes
#[derive(Debug, Clone, Copy)]
pub struct MlKem768;

impl Params for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-768";
}

/// ML-KEM-1024 parameter set (NIST Security Level 5)
///
/// Provides security roughly equivalent to AES-256. This is the most secure
/// parameter set, suitable for highly sensitive applications or long-term
/// protection requirements.
///
/// # Sizes
/// - Public key: 1568 bytes
/// - Private key: 3168 bytes
/// - Ciphertext: 1568 bytes
/// - Shared secret: 32 bytes
#[derive(Debug, Clone, Copy)]
pub struct MlKem1024;

impl Params for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const NAME: &'static str = "ML-KEM-1024";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512_sizes() {
        assert_eq!(MlKem512::EK_SIZE, 800);
        assert_eq!(MlKem512::DK_SIZE, 1632);
        assert_eq!(MlKem512::CT_SIZE, 768);
        assert_eq!(MlKem512::SS_SIZE, 32);
    }

    #[test]
    fn test_mlkem768_sizes() {
        assert_eq!(MlKem768::EK_SIZE, 1184);
        assert_eq!(MlKem768::DK_SIZE, 2400);
        assert_eq!(MlKem768::CT_SIZE, 1088);
        assert_eq!(MlKem768::SS_SIZE, 32);
    }

    #[test]
    fn test_mlkem1024_sizes() {
        assert_eq!(MlKem1024::EK_SIZE, 1568);
        assert_eq!(MlKem1024::DK_SIZE, 3168);
        assert_eq!(MlKem1024::CT_SIZE, 1568);
        assert_eq!(MlKem1024::SS_SIZE, 32);
    }

    #[test]
    fn test_params_names() {
        assert_eq!(MlKem512::NAME, "ML-KEM-512");
        assert_eq!(MlKem768::NAME, "ML-KEM-768");
        assert_eq!(MlKem1024::NAME, "ML-KEM-1024");
    }

    #[test]
    fn test_common_params() {
        assert_eq!(N, 256);
        assert_eq!(Q, 3329);
    }
}
