//! Pre-computed Constants for ARM NEON NTT Operations
//!
//! This module contains all pre-computed constants needed for NEON-optimized
//! NTT operations. Constants are stored in formats optimized for 128-bit vectorized access.
//!
//! # Key Design Decisions
//!
//! 1. **Aligned Storage**: All arrays are 16-byte aligned for NEON loads
//! 2. **Vectorized Twiddle Factors**: Pre-expanded to avoid runtime broadcasts
//! 3. **Montgomery Form**: All twiddle factors stored in Montgomery representation
//! 4. **Layer-Specific Organization**: Constants grouped by NTT layer for cache efficiency
//!
//! # NEON vs AVX2
//!
//! - NEON uses 128-bit vectors (8 x i16) vs AVX2's 256-bit (16 x i16)
//! - Constants are duplicated/expanded for 8-element vectors

#![allow(dead_code)]

/// ML-KEM modulus q = 3329
pub const Q: i16 = 3329;

/// Polynomial degree N = 256
pub const N: usize = 256;

/// Montgomery constant R = 2^16
pub const MONT_R: i32 = 65536;

/// Montgomery inverse constant for q
/// QINV = -3327, which satisfies: q * QINV ≡ 1 (mod 2^16)
pub const QINV: i16 = -3327;

/// Montgomery factor for INTT: mont^2/128 mod q = 1441
pub const F: i16 = 1441;

/// Barrett constant: floor(2^26 / q) = 20159
pub const BARRETT_V: i16 = 20159;

// ============================================================================
// Aligned Wrapper Types for NEON (16-byte alignment)
// ============================================================================

/// Wrapper for 16-byte aligned i16 arrays of size 128
#[repr(C, align(16))]
pub struct Aligned128([i16; 128]);

impl Aligned128 {
    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }

    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 128] {
        &self.0
    }
}

/// Wrapper for 16-byte aligned i16 arrays of size 64
#[repr(C, align(16))]
pub struct Aligned64([i16; 64]);

impl Aligned64 {
    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

/// Wrapper for 16-byte aligned i16 arrays of size 8 (one NEON vector)
#[repr(C, align(16))]
pub struct Aligned8([i16; 8]);

impl Aligned8 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 8] {
        &self.0
    }
}

/// Wrapper for 16-byte aligned 2D i16 arrays
#[repr(C, align(16))]
pub struct Aligned2D1([[i16; 8]; 1]);

#[repr(C, align(16))]
pub struct Aligned2D2([[i16; 8]; 2]);

#[repr(C, align(16))]
pub struct Aligned2D4([[i16; 8]; 4]);

#[repr(C, align(16))]
pub struct Aligned2D8([[i16; 8]; 8]);

#[repr(C, align(16))]
pub struct Aligned2D16([[i16; 8]; 16]);

// ============================================================================
// Pre-computed Twiddle Factors
// ============================================================================

/// Pre-computed twiddle factors in Montgomery form
///
/// ZETAS[i] = ζ^bitrev(i) * R mod q where R = 2^16
/// These are identical to the reference implementation values
pub static ZETAS: Aligned128 = Aligned128([
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
]);

/// Negated ZETAS for inverse NTT
/// ZETAS_INV[i] = -ZETAS[127 - i]
pub static ZETAS_INV: Aligned128 = Aligned128([
    -1628, -1522, 1460, -958, -991, -996, 308, 108,
    -478, 870, 854, 1510, -794, 1278, 1530, 1185,
    1659, 1187, -220, 874, 1335, -1218, 136, 1215,
    -384, 1465, 1285, -1322, -610, -603, -1097, -817,
    75, 156, -329, -418, -349, 872, -644, 1590,
    -1119, 602, -1483, 777, 147, -1159, -778, 246,
    -1653, -1574, 460, 291, 235, -177, -587, -422,
    -105, -1550, -871, 1251, -843, -555, -430, 1103,
    1275, -677, 1065, -448, 725, 1508, -961, 398,
    951, 247, 1421, -107, -830, 271, 90, 853,
    -1469, -126, 1162, 1618, 666, 320, 8, -516,
    1544, 282, -1491, 1293, -1015, 552, -652, -1223,
    1571, 205, -411, 1542, -608, -732, -1017, 681,
    130, 1602, -1458, 829, -383, -264, 1325, -573,
    -1468, 1474, 1202, -962, -182, -1577, -622, 171,
    -202, -287, -1422, -1493, 1517, 359, 758, 1044
]);

// ============================================================================
// Pre-computed Vectorized Constants for NTT Layers (8 elements per vector)
// ============================================================================

/// Vectorized twiddle factors for NTT Layer 1 (len=128)
/// Only 1 twiddle factor needed, replicated 8 times for NEON
pub static NTT_ZETAS_LAYER1: Aligned2D1 = Aligned2D1([
    [-758; 8],  // ZETAS[1]
]);

/// Vectorized twiddle factors for NTT Layer 2 (len=64)
/// 2 twiddle factors, each replicated 8 times
pub static NTT_ZETAS_LAYER2: Aligned2D2 = Aligned2D2([
    [-359; 8],   // ZETAS[2]
    [-1517; 8],  // ZETAS[3]
]);

/// Vectorized twiddle factors for NTT Layer 3 (len=32)
/// 4 twiddle factors, each replicated 8 times
pub static NTT_ZETAS_LAYER3: Aligned2D4 = Aligned2D4([
    [1493; 8],  // ZETAS[4]
    [1422; 8],  // ZETAS[5]
    [287; 8],   // ZETAS[6]
    [202; 8],   // ZETAS[7]
]);

/// Vectorized twiddle factors for NTT Layer 4 (len=16)
/// 8 twiddle factors, each replicated 8 times
pub static NTT_ZETAS_LAYER4: Aligned2D8 = Aligned2D8([
    [-171; 8],   // ZETAS[8]
    [622; 8],    // ZETAS[9]
    [1577; 8],   // ZETAS[10]
    [182; 8],    // ZETAS[11]
    [962; 8],    // ZETAS[12]
    [-1202; 8],  // ZETAS[13]
    [-1474; 8],  // ZETAS[14]
    [1468; 8],   // ZETAS[15]
]);

/// Vectorized twiddle factors for NTT Layer 5 (len=8)
/// 16 twiddle factors (ZETAS[16..32])
pub static NTT_ZETAS_LAYER5: Aligned2D16 = Aligned2D16([
    [573; 8],    // ZETAS[16]
    [-1325; 8],  // ZETAS[17]
    [264; 8],    // ZETAS[18]
    [383; 8],    // ZETAS[19]
    [-829; 8],   // ZETAS[20]
    [1458; 8],   // ZETAS[21]
    [-1602; 8],  // ZETAS[22]
    [-130; 8],   // ZETAS[23]
    [-681; 8],   // ZETAS[24]
    [1017; 8],   // ZETAS[25]
    [732; 8],    // ZETAS[26]
    [608; 8],    // ZETAS[27]
    [-1542; 8],  // ZETAS[28]
    [411; 8],    // ZETAS[29]
    [-205; 8],   // ZETAS[30]
    [-1571; 8],  // ZETAS[31]
]);

// ============================================================================
// Vectorized Constants for Montgomery/Barrett Operations
// ============================================================================

/// Q replicated 8 times for NEON vectorized operations
pub static Q_VEC: Aligned8 = Aligned8([Q; 8]);

/// QINV replicated 8 times for Montgomery reduction
pub static QINV_VEC: Aligned8 = Aligned8([QINV; 8]);

/// Barrett constant V replicated 8 times
pub static BARRETT_V_VEC: Aligned8 = Aligned8([BARRETT_V; 8]);

/// F constant replicated 8 times for final INTT scaling
pub static F_VEC: Aligned8 = Aligned8([F; 8]);

/// All ones (0xFFFF) for masking operations
pub static ONES_VEC: Aligned8 = Aligned8([-1i16; 8]);

/// All zeros for comparison/initialization
pub static ZEROS_VEC: Aligned8 = Aligned8([0i16; 8]);

// ============================================================================
// Basemul Constants
// ============================================================================

/// Twiddle factors for basemul (ZETAS[64..128])
/// Organized for efficient vectorized access
pub static BASEMUL_ZETAS: Aligned64 = Aligned64([
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
]);

// ============================================================================
// fqmulprecomp Constants (3-mul optimization)
// ============================================================================

// Helper macro to compute zl = zeta * QINV mod 2^16
macro_rules! zl {
    ($zeta:expr) => {
        (($zeta as i32 * -3327i32) & 0xFFFF) as i16
    };
}

// ============================================================================
// Pre-vectorized fqmulprecomp Constants for NTT v2 (eliminates broadcasts)
// ============================================================================

/// Layer 1: zl = ZETAS[1] * QINV mod R, replicated 8 times
pub static NTT_LAYER1_ZL_VEC: Aligned8 = Aligned8([zl!(-758); 8]);
/// Layer 1: zh = ZETAS[1], replicated 8 times
pub static NTT_LAYER1_ZH_VEC: Aligned8 = Aligned8([-758; 8]);

/// Layer 2: zl vectors for ZETAS[2..4]
pub static NTT_LAYER2_ZL_VECS: [[i16; 8]; 2] = [
    [zl!(-359); 8],   // ZETAS[2] * QINV
    [zl!(-1517); 8],  // ZETAS[3] * QINV
];
/// Layer 2: zh vectors for ZETAS[2..4]
pub static NTT_LAYER2_ZH_VECS: [[i16; 8]; 2] = [
    [-359; 8],   // ZETAS[2]
    [-1517; 8],  // ZETAS[3]
];

/// Layer 3: zl vectors for ZETAS[4..8]
pub static NTT_LAYER3_ZL_VECS: [[i16; 8]; 4] = [
    [zl!(1493); 8],  // ZETAS[4] * QINV
    [zl!(1422); 8],  // ZETAS[5] * QINV
    [zl!(287); 8],   // ZETAS[6] * QINV
    [zl!(202); 8],   // ZETAS[7] * QINV
];
/// Layer 3: zh vectors for ZETAS[4..8]
pub static NTT_LAYER3_ZH_VECS: [[i16; 8]; 4] = [
    [1493; 8],  // ZETAS[4]
    [1422; 8],  // ZETAS[5]
    [287; 8],   // ZETAS[6]
    [202; 8],   // ZETAS[7]
];

/// Layer 4: zl vectors for ZETAS[8..16]
pub static NTT_LAYER4_ZL_VECS: [[i16; 8]; 8] = [
    [zl!(-171); 8],   // ZETAS[8] * QINV
    [zl!(622); 8],    // ZETAS[9] * QINV
    [zl!(1577); 8],   // ZETAS[10] * QINV
    [zl!(182); 8],    // ZETAS[11] * QINV
    [zl!(962); 8],    // ZETAS[12] * QINV
    [zl!(-1202); 8],  // ZETAS[13] * QINV
    [zl!(-1474); 8],  // ZETAS[14] * QINV
    [zl!(1468); 8],   // ZETAS[15] * QINV
];
/// Layer 4: zh vectors for ZETAS[8..16]
pub static NTT_LAYER4_ZH_VECS: [[i16; 8]; 8] = [
    [-171; 8],   // ZETAS[8]
    [622; 8],    // ZETAS[9]
    [1577; 8],   // ZETAS[10]
    [182; 8],    // ZETAS[11]
    [962; 8],    // ZETAS[12]
    [-1202; 8],  // ZETAS[13]
    [-1474; 8],  // ZETAS[14]
    [1468; 8],   // ZETAS[15]
];

/// Layer 5: zl vectors for ZETAS[16..32]
pub static NTT_LAYER5_ZL_VECS: [[i16; 8]; 16] = [
    [zl!(573); 8], [zl!(-1325); 8], [zl!(264); 8], [zl!(383); 8],
    [zl!(-829); 8], [zl!(1458); 8], [zl!(-1602); 8], [zl!(-130); 8],
    [zl!(-681); 8], [zl!(1017); 8], [zl!(732); 8], [zl!(608); 8],
    [zl!(-1542); 8], [zl!(411); 8], [zl!(-205); 8], [zl!(-1571); 8],
];
/// Layer 5: zh vectors for ZETAS[16..32]
pub static NTT_LAYER5_ZH_VECS: [[i16; 8]; 16] = [
    [573; 8], [-1325; 8], [264; 8], [383; 8],
    [-829; 8], [1458; 8], [-1602; 8], [-130; 8],
    [-681; 8], [1017; 8], [732; 8], [608; 8],
    [-1542; 8], [411; 8], [-205; 8], [-1571; 8],
];

/// Layer 6: zl vectors for ZETAS[32..64] (32 twiddles)
pub static NTT_LAYER6_ZL_VECS: [[i16; 8]; 32] = [
    [zl!(1223); 8], [zl!(652); 8], [zl!(-552); 8], [zl!(1015); 8],
    [zl!(-1293); 8], [zl!(1491); 8], [zl!(-282); 8], [zl!(-1544); 8],
    [zl!(516); 8], [zl!(-8); 8], [zl!(-320); 8], [zl!(-666); 8],
    [zl!(-1618); 8], [zl!(-1162); 8], [zl!(126); 8], [zl!(1469); 8],
    [zl!(-853); 8], [zl!(-90); 8], [zl!(-271); 8], [zl!(830); 8],
    [zl!(107); 8], [zl!(-1421); 8], [zl!(-247); 8], [zl!(-951); 8],
    [zl!(-398); 8], [zl!(961); 8], [zl!(-1508); 8], [zl!(-725); 8],
    [zl!(448); 8], [zl!(-1065); 8], [zl!(677); 8], [zl!(-1275); 8],
];
/// Layer 6: zh vectors for ZETAS[32..64]
pub static NTT_LAYER6_ZH_VECS: [[i16; 8]; 32] = [
    [1223; 8], [652; 8], [-552; 8], [1015; 8],
    [-1293; 8], [1491; 8], [-282; 8], [-1544; 8],
    [516; 8], [-8; 8], [-320; 8], [-666; 8],
    [-1618; 8], [-1162; 8], [126; 8], [1469; 8],
    [-853; 8], [-90; 8], [-271; 8], [830; 8],
    [107; 8], [-1421; 8], [-247; 8], [-951; 8],
    [-398; 8], [961; 8], [-1508; 8], [-725; 8],
    [448; 8], [-1065; 8], [677; 8], [-1275; 8],
];

/// Layer 7: (zl, zh) pairs for ZETAS[64..128] (64 twiddles, scalar loop)
/// These are stored as pairs since layer 7 uses scalar fallback
pub static NTT_LAYER7_ZL: [i16; 64] = [
    zl!(-1103), zl!(430), zl!(555), zl!(843), zl!(-1251), zl!(871), zl!(1550), zl!(105),
    zl!(422), zl!(587), zl!(177), zl!(-235), zl!(-291), zl!(-460), zl!(1574), zl!(1653),
    zl!(-246), zl!(778), zl!(1159), zl!(-147), zl!(-777), zl!(1483), zl!(-602), zl!(1119),
    zl!(-1590), zl!(644), zl!(-872), zl!(349), zl!(418), zl!(329), zl!(-156), zl!(-75),
    zl!(817), zl!(1097), zl!(603), zl!(610), zl!(1322), zl!(-1285), zl!(-1465), zl!(384),
    zl!(-1215), zl!(-136), zl!(1218), zl!(-1335), zl!(-874), zl!(220), zl!(-1187), zl!(-1659),
    zl!(-1185), zl!(-1530), zl!(-1278), zl!(794), zl!(-1510), zl!(-854), zl!(-870), zl!(478),
    zl!(-108), zl!(-308), zl!(996), zl!(991), zl!(958), zl!(-1460), zl!(1522), zl!(1628),
];
pub static NTT_LAYER7_ZH: [i16; 64] = [
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// F constant precomputed for fqmulprecomp
pub static F_ZL_VEC: Aligned8 = Aligned8([zl!(1441); 8]);
pub static F_ZH_VEC: Aligned8 = Aligned8([1441; 8]);  // F = 1441

/// Wrapper for pairs of (zl, zh) precomputed values
#[repr(C, align(16))]
pub struct ZetasPrecomp([[i16; 2]; 128]);

impl ZetasPrecomp {
    /// Get (zl, zh) pair at index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> (i16, i16) {
        (self.0[idx][0], self.0[idx][1])
    }
}

/// Pre-computed (zl, zh) pairs for fqmulprecomp optimization
/// zl = zeta * QINV mod R, zh = zeta
pub static ZETAS_PRECOMP: ZetasPrecomp = ZetasPrecomp([
    // Generated: for each zeta in ZETAS, compute (zeta * QINV mod 2^16, zeta)
    [(((-1044i32) * (-3327i32)) & 0xFFFF) as i16, -1044],
    [(((-758i32) * (-3327i32)) & 0xFFFF) as i16, -758],
    [(((-359i32) * (-3327i32)) & 0xFFFF) as i16, -359],
    [(((-1517i32) * (-3327i32)) & 0xFFFF) as i16, -1517],
    [(((1493i32) * (-3327i32)) & 0xFFFF) as i16, 1493],
    [(((1422i32) * (-3327i32)) & 0xFFFF) as i16, 1422],
    [(((287i32) * (-3327i32)) & 0xFFFF) as i16, 287],
    [(((202i32) * (-3327i32)) & 0xFFFF) as i16, 202],
    [(((-171i32) * (-3327i32)) & 0xFFFF) as i16, -171],
    [(((622i32) * (-3327i32)) & 0xFFFF) as i16, 622],
    [(((1577i32) * (-3327i32)) & 0xFFFF) as i16, 1577],
    [(((182i32) * (-3327i32)) & 0xFFFF) as i16, 182],
    [(((962i32) * (-3327i32)) & 0xFFFF) as i16, 962],
    [(((-1202i32) * (-3327i32)) & 0xFFFF) as i16, -1202],
    [(((-1474i32) * (-3327i32)) & 0xFFFF) as i16, -1474],
    [(((1468i32) * (-3327i32)) & 0xFFFF) as i16, 1468],
    [(((573i32) * (-3327i32)) & 0xFFFF) as i16, 573],
    [(((-1325i32) * (-3327i32)) & 0xFFFF) as i16, -1325],
    [(((264i32) * (-3327i32)) & 0xFFFF) as i16, 264],
    [(((383i32) * (-3327i32)) & 0xFFFF) as i16, 383],
    [(((-829i32) * (-3327i32)) & 0xFFFF) as i16, -829],
    [(((1458i32) * (-3327i32)) & 0xFFFF) as i16, 1458],
    [(((-1602i32) * (-3327i32)) & 0xFFFF) as i16, -1602],
    [(((-130i32) * (-3327i32)) & 0xFFFF) as i16, -130],
    [(((-681i32) * (-3327i32)) & 0xFFFF) as i16, -681],
    [(((1017i32) * (-3327i32)) & 0xFFFF) as i16, 1017],
    [(((732i32) * (-3327i32)) & 0xFFFF) as i16, 732],
    [(((608i32) * (-3327i32)) & 0xFFFF) as i16, 608],
    [(((-1542i32) * (-3327i32)) & 0xFFFF) as i16, -1542],
    [(((411i32) * (-3327i32)) & 0xFFFF) as i16, 411],
    [(((-205i32) * (-3327i32)) & 0xFFFF) as i16, -205],
    [(((-1571i32) * (-3327i32)) & 0xFFFF) as i16, -1571],
    [(((1223i32) * (-3327i32)) & 0xFFFF) as i16, 1223],
    [(((652i32) * (-3327i32)) & 0xFFFF) as i16, 652],
    [(((-552i32) * (-3327i32)) & 0xFFFF) as i16, -552],
    [(((1015i32) * (-3327i32)) & 0xFFFF) as i16, 1015],
    [(((-1293i32) * (-3327i32)) & 0xFFFF) as i16, -1293],
    [(((1491i32) * (-3327i32)) & 0xFFFF) as i16, 1491],
    [(((-282i32) * (-3327i32)) & 0xFFFF) as i16, -282],
    [(((-1544i32) * (-3327i32)) & 0xFFFF) as i16, -1544],
    [(((516i32) * (-3327i32)) & 0xFFFF) as i16, 516],
    [(((-8i32) * (-3327i32)) & 0xFFFF) as i16, -8],
    [(((-320i32) * (-3327i32)) & 0xFFFF) as i16, -320],
    [(((-666i32) * (-3327i32)) & 0xFFFF) as i16, -666],
    [(((-1618i32) * (-3327i32)) & 0xFFFF) as i16, -1618],
    [(((-1162i32) * (-3327i32)) & 0xFFFF) as i16, -1162],
    [(((126i32) * (-3327i32)) & 0xFFFF) as i16, 126],
    [(((1469i32) * (-3327i32)) & 0xFFFF) as i16, 1469],
    [(((-853i32) * (-3327i32)) & 0xFFFF) as i16, -853],
    [(((-90i32) * (-3327i32)) & 0xFFFF) as i16, -90],
    [(((-271i32) * (-3327i32)) & 0xFFFF) as i16, -271],
    [(((830i32) * (-3327i32)) & 0xFFFF) as i16, 830],
    [(((107i32) * (-3327i32)) & 0xFFFF) as i16, 107],
    [(((-1421i32) * (-3327i32)) & 0xFFFF) as i16, -1421],
    [(((-247i32) * (-3327i32)) & 0xFFFF) as i16, -247],
    [(((-951i32) * (-3327i32)) & 0xFFFF) as i16, -951],
    [(((-398i32) * (-3327i32)) & 0xFFFF) as i16, -398],
    [(((961i32) * (-3327i32)) & 0xFFFF) as i16, 961],
    [(((-1508i32) * (-3327i32)) & 0xFFFF) as i16, -1508],
    [(((-725i32) * (-3327i32)) & 0xFFFF) as i16, -725],
    [(((448i32) * (-3327i32)) & 0xFFFF) as i16, 448],
    [(((-1065i32) * (-3327i32)) & 0xFFFF) as i16, -1065],
    [(((677i32) * (-3327i32)) & 0xFFFF) as i16, 677],
    [(((-1275i32) * (-3327i32)) & 0xFFFF) as i16, -1275],
    [(((-1103i32) * (-3327i32)) & 0xFFFF) as i16, -1103],
    [(((430i32) * (-3327i32)) & 0xFFFF) as i16, 430],
    [(((555i32) * (-3327i32)) & 0xFFFF) as i16, 555],
    [(((843i32) * (-3327i32)) & 0xFFFF) as i16, 843],
    [(((-1251i32) * (-3327i32)) & 0xFFFF) as i16, -1251],
    [(((871i32) * (-3327i32)) & 0xFFFF) as i16, 871],
    [(((1550i32) * (-3327i32)) & 0xFFFF) as i16, 1550],
    [(((105i32) * (-3327i32)) & 0xFFFF) as i16, 105],
    [(((422i32) * (-3327i32)) & 0xFFFF) as i16, 422],
    [(((587i32) * (-3327i32)) & 0xFFFF) as i16, 587],
    [(((177i32) * (-3327i32)) & 0xFFFF) as i16, 177],
    [(((-235i32) * (-3327i32)) & 0xFFFF) as i16, -235],
    [(((-291i32) * (-3327i32)) & 0xFFFF) as i16, -291],
    [(((-460i32) * (-3327i32)) & 0xFFFF) as i16, -460],
    [(((1574i32) * (-3327i32)) & 0xFFFF) as i16, 1574],
    [(((1653i32) * (-3327i32)) & 0xFFFF) as i16, 1653],
    [(((-246i32) * (-3327i32)) & 0xFFFF) as i16, -246],
    [(((778i32) * (-3327i32)) & 0xFFFF) as i16, 778],
    [(((1159i32) * (-3327i32)) & 0xFFFF) as i16, 1159],
    [(((-147i32) * (-3327i32)) & 0xFFFF) as i16, -147],
    [(((-777i32) * (-3327i32)) & 0xFFFF) as i16, -777],
    [(((1483i32) * (-3327i32)) & 0xFFFF) as i16, 1483],
    [(((-602i32) * (-3327i32)) & 0xFFFF) as i16, -602],
    [(((1119i32) * (-3327i32)) & 0xFFFF) as i16, 1119],
    [(((-1590i32) * (-3327i32)) & 0xFFFF) as i16, -1590],
    [(((644i32) * (-3327i32)) & 0xFFFF) as i16, 644],
    [(((-872i32) * (-3327i32)) & 0xFFFF) as i16, -872],
    [(((349i32) * (-3327i32)) & 0xFFFF) as i16, 349],
    [(((418i32) * (-3327i32)) & 0xFFFF) as i16, 418],
    [(((329i32) * (-3327i32)) & 0xFFFF) as i16, 329],
    [(((-156i32) * (-3327i32)) & 0xFFFF) as i16, -156],
    [(((-75i32) * (-3327i32)) & 0xFFFF) as i16, -75],
    [(((817i32) * (-3327i32)) & 0xFFFF) as i16, 817],
    [(((1097i32) * (-3327i32)) & 0xFFFF) as i16, 1097],
    [(((603i32) * (-3327i32)) & 0xFFFF) as i16, 603],
    [(((610i32) * (-3327i32)) & 0xFFFF) as i16, 610],
    [(((1322i32) * (-3327i32)) & 0xFFFF) as i16, 1322],
    [(((-1285i32) * (-3327i32)) & 0xFFFF) as i16, -1285],
    [(((-1465i32) * (-3327i32)) & 0xFFFF) as i16, -1465],
    [(((384i32) * (-3327i32)) & 0xFFFF) as i16, 384],
    [(((-1215i32) * (-3327i32)) & 0xFFFF) as i16, -1215],
    [(((-136i32) * (-3327i32)) & 0xFFFF) as i16, -136],
    [(((1218i32) * (-3327i32)) & 0xFFFF) as i16, 1218],
    [(((-1335i32) * (-3327i32)) & 0xFFFF) as i16, -1335],
    [(((-874i32) * (-3327i32)) & 0xFFFF) as i16, -874],
    [(((220i32) * (-3327i32)) & 0xFFFF) as i16, 220],
    [(((-1187i32) * (-3327i32)) & 0xFFFF) as i16, -1187],
    [(((-1659i32) * (-3327i32)) & 0xFFFF) as i16, -1659],
    [(((-1185i32) * (-3327i32)) & 0xFFFF) as i16, -1185],
    [(((-1530i32) * (-3327i32)) & 0xFFFF) as i16, -1530],
    [(((-1278i32) * (-3327i32)) & 0xFFFF) as i16, -1278],
    [(((794i32) * (-3327i32)) & 0xFFFF) as i16, 794],
    [(((-1510i32) * (-3327i32)) & 0xFFFF) as i16, -1510],
    [(((-854i32) * (-3327i32)) & 0xFFFF) as i16, -854],
    [(((-870i32) * (-3327i32)) & 0xFFFF) as i16, -870],
    [(((478i32) * (-3327i32)) & 0xFFFF) as i16, 478],
    [(((-108i32) * (-3327i32)) & 0xFFFF) as i16, -108],
    [(((-308i32) * (-3327i32)) & 0xFFFF) as i16, -308],
    [(((996i32) * (-3327i32)) & 0xFFFF) as i16, 996],
    [(((991i32) * (-3327i32)) & 0xFFFF) as i16, 991],
    [(((958i32) * (-3327i32)) & 0xFFFF) as i16, 958],
    [(((-1460i32) * (-3327i32)) & 0xFFFF) as i16, -1460],
    [(((1522i32) * (-3327i32)) & 0xFFFF) as i16, 1522],
    [(((1628i32) * (-3327i32)) & 0xFFFF) as i16, 1628],
]);
