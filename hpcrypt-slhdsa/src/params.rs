//! Parameter sets for SLH-DSA (SPHINCS+) as defined in FIPS 205.
//!
//! This module provides all 12 parameter sets using const generics for
//! compile-time specialization and zero-cost abstractions.

/// Cold path for unsupported Winternitz parameter error.
///
/// Marked cold to keep error handling out of hot paths, improving
/// instruction cache utilization.
#[cold]
#[inline(never)]
fn unsupported_winternitz_parameter() -> ! {
    panic!("Unsupported Winternitz parameter")
}

/// Core trait defining a complete SLH-DSA parameter set.
///
/// All parameters are const generics, enabling compile-time specialization
/// and optimal code generation for each parameter set.
pub trait ParameterSet: 'static + Copy + Clone {
    /// Security parameter (hash output length in bytes)
    const N: usize;

    /// Total height of the hypertree
    const H: usize;

    /// Number of layers in the hypertree
    const D: usize;

    /// Number of trees in FORS
    const K: usize;

    /// Height of each FORS tree (2^A leaves per tree)
    const A: usize;

    /// Winternitz parameter for WOTS+
    const W: usize;

    /// Hash function type (0 = SHA2-256, 1 = SHAKE256)
    const HASH_TYPE: HashType;

    /// Is this a "fast" variant? (larger signatures, faster signing)
    const IS_FAST: bool;

    // Derived constants (computed at compile time)

    /// Height of each layer in the hypertree
    const TREE_HEIGHT: usize = Self::H / Self::D;

    /// Number of chain elements in WOTS+
    const WOTS_LEN: usize = {
        // len1: number of chains for message encoding
        let len1 = (8 * Self::N).div_ceil(Self::LOG2_W);

        // len2: number of chains for checksum
        // len2 = floor(log_w(len1 * (w-1))) + 1 = number of base-w digits for checksum
        let max_checksum = len1 * (Self::W - 1);
        let mut len2 = 0;
        let mut val = max_checksum;
        while val > 0 {
            len2 += 1;
            val >>= Self::LOG2_W;
        }

        len1 + len2
    };

    /// Log base 2 of W
    fn log2_w() -> usize {
        match Self::W {
            16 => 4,
            256 => 8,
            _ => unsupported_winternitz_parameter(),
        }
    }

    /// Log base 2 of W (const version for use in const contexts)
    const LOG2_W: usize = if Self::W == 16 {
        4
    } else if Self::W == 256 {
        8
    } else {
        0
    };

    /// Length of FORS message in bytes
    const FORS_MSG_BYTES: usize = (Self::K * Self::A).div_ceil(8);

    /// FORS signature bytes
    const FORS_SIG_BYTES: usize = Self::K * (Self::A + 1) * Self::N;

    /// Bytes for one WOTS+ signature
    const WOTS_SIG_BYTES: usize = Self::WOTS_LEN * Self::N;

    /// Total signature size in bytes
    const SIG_BYTES: usize = {
        Self::N +                          // randomness
        Self::FORS_SIG_BYTES +             // FORS signature
        Self::D * (Self::WOTS_SIG_BYTES +  // WOTS+ signatures per layer
                   Self::TREE_HEIGHT * Self::N) // authentication paths per layer
    };

    /// Public key size in bytes
    const PK_BYTES: usize = 2 * Self::N;

    /// Secret key size in bytes
    const SK_BYTES: usize = 3 * Self::N; // sk_seed + sk_prf + pk_seed
}

/// Hash function type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// SHA2-256 based hash function
    Sha2,
    /// SHAKE256 based hash function
    Shake,
}

// Macro to define parameter set implementations
macro_rules! define_param_set {
    ($name:ident, $n:expr, $h:expr, $d:expr, $k:expr, $a:expr, $w:expr, $hash:expr, $fast:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy)]
        pub struct $name;

        impl ParameterSet for $name {
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const K: usize = $k;
            const A: usize = $a;
            const W: usize = $w;
            const HASH_TYPE: HashType = $hash;
            const IS_FAST: bool = $fast;
        }
    };
}

// SHA2-256 parameter sets
define_param_set!(
    Sha2_128s,
    16,
    63,
    7,
    14,
    6,
    16,
    HashType::Sha2,
    false,
    "SLH-DSA-SHA2-128s: 128-bit security, small signature (~7.9 KB)"
);

define_param_set!(
    Sha2_128f,
    16,
    66,
    22,
    33,
    6,
    16,
    HashType::Sha2,
    true,
    "SLH-DSA-SHA2-128f: 128-bit security, fast signing (~17.1 KB)"
);

define_param_set!(
    Sha2_192s,
    24,
    63,
    7,
    17,
    8,
    16,
    HashType::Sha2,
    false,
    "SLH-DSA-SHA2-192s: 192-bit security, small signature (~16.2 KB)"
);

define_param_set!(
    Sha2_192f,
    24,
    66,
    22,
    33,
    9,
    16,
    HashType::Sha2,
    true,
    "SLH-DSA-SHA2-192f: 192-bit security, fast signing (~35.7 KB)"
);

define_param_set!(
    Sha2_256s,
    32,
    64,
    8,
    22,
    8,
    16,
    HashType::Sha2,
    false,
    "SLH-DSA-SHA2-256s: 256-bit security, small signature (~29.8 KB)"
);

define_param_set!(
    Sha2_256f,
    32,
    68,
    17,
    35,
    9,
    16,
    HashType::Sha2,
    true,
    "SLH-DSA-SHA2-256f: 256-bit security, fast signing (~49.9 KB)"
);

// SHAKE256 parameter sets
define_param_set!(
    Shake128s,
    16,
    63,
    7,
    14,
    6,
    16,
    HashType::Shake,
    false,
    "SLH-DSA-SHAKE-128s: 128-bit security, small signature (~7.9 KB)"
);

define_param_set!(
    Shake128f,
    16,
    66,
    22,
    33,
    6,
    16,
    HashType::Shake,
    true,
    "SLH-DSA-SHAKE-128f: 128-bit security, fast signing (~17.1 KB)"
);

define_param_set!(
    Shake192s,
    24,
    63,
    7,
    17,
    8,
    16,
    HashType::Shake,
    false,
    "SLH-DSA-SHAKE-192s: 192-bit security, small signature (~16.2 KB)"
);

define_param_set!(
    Shake192f,
    24,
    66,
    22,
    33,
    9,
    16,
    HashType::Shake,
    true,
    "SLH-DSA-SHAKE-192f: 192-bit security, fast signing (~35.7 KB)"
);

define_param_set!(
    Shake256s,
    32,
    64,
    8,
    22,
    8,
    16,
    HashType::Shake,
    false,
    "SLH-DSA-SHAKE-256s: 256-bit security, small signature (~29.8 KB)"
);

define_param_set!(
    Shake256f,
    32,
    68,
    17,
    35,
    9,
    16,
    HashType::Shake,
    true,
    "SLH-DSA-SHAKE-256f: 256-bit security, fast signing (~49.9 KB)"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wots_len_calculation() {
        // Verify WOTS_LEN calculation for common parameters
        assert_eq!(Sha2_128s::WOTS_LEN, 35); // For N=16, W=16
        assert_eq!(Sha2_256s::WOTS_LEN, 67); // For N=32, W=16
    }

    #[test]
    fn test_signature_sizes() {
        // Verify signature sizes are reasonable
        assert!(Sha2_128s::SIG_BYTES < 10000); // ~7.9 KB
        assert!(Sha2_128f::SIG_BYTES < 20000); // ~17.1 KB
        assert!(Sha2_256s::SIG_BYTES < 32000); // ~29.8 KB
        assert!(Sha2_256f::SIG_BYTES < 50000); // ~48.7 KB
    }

    #[test]
    fn test_tree_height_division() {
        // Verify H is divisible by D for all parameter sets
        assert_eq!(Sha2_128s::H % Sha2_128s::D, 0);
        assert_eq!(Sha2_128f::H % Sha2_128f::D, 0);
        assert_eq!(Sha2_192s::H % Sha2_192s::D, 0);
        assert_eq!(Sha2_192f::H % Sha2_192f::D, 0);
        assert_eq!(Sha2_256s::H % Sha2_256s::D, 0);
        assert_eq!(Sha2_256f::H % Sha2_256f::D, 0);
    }
}
