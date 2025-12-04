//! Pre-computed Constants for AVX2 NTT Operations
//!
//! This module contains all pre-computed constants needed for AVX2-optimized
//! NTT operations. Constants are stored in formats optimized for vectorized access.
//!
//! # Key Design Decisions
//!
//! 1. **Aligned Storage**: All arrays are 32-byte aligned for AVX2 loads
//! 2. **Vectorized Twiddle Factors**: Pre-expanded to avoid runtime broadcasts
//! 3. **Montgomery Form**: All twiddle factors stored in Montgomery representation
//! 4. **Layer-Specific Organization**: Constants grouped by NTT layer for cache efficiency

#![allow(dead_code)]

use core::arch::x86_64::*;

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
// Aligned Wrapper Types
// ============================================================================

/// Wrapper for 32-byte aligned i16 arrays of size 128
#[repr(C, align(32))]
pub struct Aligned128([i16; 128]);

/// Wrapper for 32-byte aligned i16 arrays of size 112
#[repr(C, align(32))]
pub struct Aligned112([i16; 112]);

/// Wrapper for 32-byte aligned i16 arrays of size 64
#[repr(C, align(32))]
pub struct Aligned64([i16; 64]);

/// Wrapper for 32-byte aligned i16 arrays of size 16
#[repr(C, align(32))]
pub struct Aligned16([i16; 16]);

/// Wrapper for 32-byte aligned i8 arrays of size 32
#[repr(C, align(32))]
pub struct AlignedI8_32([i8; 32]);

/// Wrapper for 32-byte aligned 2D i16 arrays
#[repr(C, align(32))]
pub struct Aligned2D1([[i16; 16]; 1]);

#[repr(C, align(32))]
pub struct Aligned2D2([[i16; 16]; 2]);

#[repr(C, align(32))]
pub struct Aligned2D4([[i16; 16]; 4]);

#[repr(C, align(32))]
pub struct Aligned2D8([[i16; 16]; 8]);

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
// Pre-computed Vectorized Constants for NTT Layers
// ============================================================================
//
// These constants are organized by layer for optimal cache access patterns.
// Each layer has its twiddle factors pre-expanded into 256-bit vectors
// to avoid runtime broadcasts (which have ~3 cycle latency).

/// Vectorized twiddle factors for NTT Layer 1 (len=128)
/// Only 1 twiddle factor needed, replicated 16 times
pub static NTT_ZETAS_LAYER1: Aligned2D1 = Aligned2D1([
    [-758; 16],  // ZETAS[1]
]);

/// Vectorized twiddle factors for NTT Layer 2 (len=64)
/// 2 twiddle factors, each replicated 16 times
pub static NTT_ZETAS_LAYER2: Aligned2D2 = Aligned2D2([
    [-359; 16],  // ZETAS[2]
    [-1517; 16], // ZETAS[3]
]);

/// Vectorized twiddle factors for NTT Layer 3 (len=32)
/// 4 twiddle factors, each replicated 16 times
pub static NTT_ZETAS_LAYER3: Aligned2D4 = Aligned2D4([
    [1493; 16],  // ZETAS[4]
    [1422; 16],  // ZETAS[5]
    [287; 16],   // ZETAS[6]
    [202; 16],   // ZETAS[7]
]);

/// Vectorized twiddle factors for NTT Layer 4 (len=16)
/// 8 twiddle factors, each replicated 16 times
pub static NTT_ZETAS_LAYER4: Aligned2D8 = Aligned2D8([
    [-171; 16],  // ZETAS[8]
    [622; 16],   // ZETAS[9]
    [1577; 16],  // ZETAS[10]
    [182; 16],   // ZETAS[11]
    [962; 16],   // ZETAS[12]
    [-1202; 16], // ZETAS[13]
    [-1474; 16], // ZETAS[14]
    [1468; 16],  // ZETAS[15]
]);

/// Vectorized twiddle factors for NTT Layers 5-7 (len=8,4,2)
/// These are processed within 16-element blocks
/// Layer 5: indices 16-31 (16 twiddles)
/// Layer 6: indices 32-63 (32 twiddles)
/// Layer 7: indices 64-127 (64 twiddles)
pub static NTT_ZETAS_LAYER567: Aligned112 = Aligned112([
    // Layer 5: ZETAS[16..32]
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    // Layer 6: ZETAS[32..64]
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    // Layer 7: ZETAS[64..128]
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
// Vectorized Constants for Montgomery/Barrett Operations
// ============================================================================

/// Q replicated 16 times for vectorized operations
pub static Q_VEC: Aligned16 = Aligned16([Q; 16]);

/// QINV replicated 16 times for Montgomery reduction
pub static QINV_VEC: Aligned16 = Aligned16([QINV; 16]);

/// Barrett constant V replicated 16 times
pub static BARRETT_V_VEC: Aligned16 = Aligned16([BARRETT_V; 16]);

/// F constant replicated 16 times for final INTT scaling
pub static F_VEC: Aligned16 = Aligned16([F; 16]);

/// All ones (0xFFFF) for masking operations
pub static ONES_VEC: Aligned16 = Aligned16([-1i16; 16]);

/// All zeros for comparison/initialization
pub static ZEROS_VEC: Aligned16 = Aligned16([0i16; 16]);

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

/// Negated basemul twiddle factors for odd-indexed pairs
pub static BASEMUL_ZETAS_NEG: Aligned64 = Aligned64([
    1103, -430, -555, -843, 1251, -871, -1550, -105,
    -422, -587, -177, 235, 291, 460, -1574, -1653,
    246, -778, -1159, 147, 777, -1483, 602, -1119,
    1590, -644, 872, -349, -418, -329, 156, 75,
    -817, -1097, -603, -610, -1322, 1285, 1465, -384,
    1215, 136, -1218, 1335, 874, -220, 1187, 1659,
    1185, 1530, 1278, -794, 1510, 854, 870, -478,
    108, 308, -996, -991, -958, 1460, -1522, -1628
]);

// ============================================================================
// Pre-computed Vectorized Basemul Zetas
// ============================================================================
//
// For vectorized basemul, each 16-coefficient block needs zetas in this pattern:
// [z0, z0, -z0, -z0, z1, z1, -z1, -z1, z2, z2, -z2, -z2, z3, z3, -z3, -z3]
// This eliminates per-block _mm256_setr_epi16 calls.

/// Wrapper for 32-byte aligned i16 arrays of size 256 (for basemul zeta vectors)
#[repr(C, align(32))]
pub struct Aligned256([i16; 256]);

impl Aligned256 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 256] {
        &self.0
    }

    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

/// Pre-computed basemul zeta vectors for all 16 blocks
/// Each block of 16 elements contains: [z0, z0, -z0, -z0, z1, z1, -z1, -z1, z2, z2, -z2, -z2, z3, z3, -z3, -z3]
/// This allows direct aligned loads instead of per-iteration _mm256_setr_epi16 calls
pub static BASEMUL_ZETAS_EXPANDED: Aligned256 = Aligned256([
    // Block 0: ZETAS[64..68] = [-1103, 430, 555, 843]
    -1103, -1103, 1103, 1103, 430, 430, -430, -430, 555, 555, -555, -555, 843, 843, -843, -843,
    // Block 1: ZETAS[68..72] = [-1251, 871, 1550, 105]
    -1251, -1251, 1251, 1251, 871, 871, -871, -871, 1550, 1550, -1550, -1550, 105, 105, -105, -105,
    // Block 2: ZETAS[72..76] = [422, 587, 177, -235]
    422, 422, -422, -422, 587, 587, -587, -587, 177, 177, -177, -177, -235, -235, 235, 235,
    // Block 3: ZETAS[76..80] = [-291, -460, 1574, 1653]
    -291, -291, 291, 291, -460, -460, 460, 460, 1574, 1574, -1574, -1574, 1653, 1653, -1653, -1653,
    // Block 4: ZETAS[80..84] = [-246, 778, 1159, -147]
    -246, -246, 246, 246, 778, 778, -778, -778, 1159, 1159, -1159, -1159, -147, -147, 147, 147,
    // Block 5: ZETAS[84..88] = [-777, 1483, -602, 1119]
    -777, -777, 777, 777, 1483, 1483, -1483, -1483, -602, -602, 602, 602, 1119, 1119, -1119, -1119,
    // Block 6: ZETAS[88..92] = [-1590, 644, -872, 349]
    -1590, -1590, 1590, 1590, 644, 644, -644, -644, -872, -872, 872, 872, 349, 349, -349, -349,
    // Block 7: ZETAS[92..96] = [418, 329, -156, -75]
    418, 418, -418, -418, 329, 329, -329, -329, -156, -156, 156, 156, -75, -75, 75, 75,
    // Block 8: ZETAS[96..100] = [817, 1097, 603, 610]
    817, 817, -817, -817, 1097, 1097, -1097, -1097, 603, 603, -603, -603, 610, 610, -610, -610,
    // Block 9: ZETAS[100..104] = [1322, -1285, -1465, 384]
    1322, 1322, -1322, -1322, -1285, -1285, 1285, 1285, -1465, -1465, 1465, 1465, 384, 384, -384, -384,
    // Block 10: ZETAS[104..108] = [-1215, -136, 1218, -1335]
    -1215, -1215, 1215, 1215, -136, -136, 136, 136, 1218, 1218, -1218, -1218, -1335, -1335, 1335, 1335,
    // Block 11: ZETAS[108..112] = [-874, 220, -1187, -1659]
    -874, -874, 874, 874, 220, 220, -220, -220, -1187, -1187, 1187, 1187, -1659, -1659, 1659, 1659,
    // Block 12: ZETAS[112..116] = [-1185, -1530, -1278, 794]
    -1185, -1185, 1185, 1185, -1530, -1530, 1530, 1530, -1278, -1278, 1278, 1278, 794, 794, -794, -794,
    // Block 13: ZETAS[116..120] = [-1510, -854, -870, 478]
    -1510, -1510, 1510, 1510, -854, -854, 854, 854, -870, -870, 870, 870, 478, 478, -478, -478,
    // Block 14: ZETAS[120..124] = [-108, -308, 996, 991]
    -108, -108, 108, 108, -308, -308, 308, 308, 996, 996, -996, -996, 991, 991, -991, -991,
    // Block 15: ZETAS[124..128] = [958, -1460, 1522, 1628]
    958, 958, -958, -958, -1460, -1460, 1460, 1460, 1522, 1522, -1522, -1522, 1628, 1628, -1628, -1628,
]);

// ============================================================================
// Shuffle Masks for NTT Butterfly Operations
// ============================================================================

/// Shuffle mask for extracting even-indexed i16 elements (0,2,4,6,8,10,12,14)
pub static SHUFFLE_EVEN: AlignedI8_32 = AlignedI8_32([
    0, 1, 4, 5, 8, 9, 12, 13,    // Lower 128-bit lane
    16, 17, 20, 21, 24, 25, 28, 29, // Upper 128-bit lane (relative)
    0, 1, 4, 5, 8, 9, 12, 13,
    16, 17, 20, 21, 24, 25, 28, 29,
]);

/// Shuffle mask for extracting odd-indexed i16 elements (1,3,5,7,9,11,13,15)
pub static SHUFFLE_ODD: AlignedI8_32 = AlignedI8_32([
    2, 3, 6, 7, 10, 11, 14, 15,
    18, 19, 22, 23, 26, 27, 30, 31,
    2, 3, 6, 7, 10, 11, 14, 15,
    18, 19, 22, 23, 26, 27, 30, 31,
]);

/// Interleave mask for layer 7 butterflies (len=2)
/// Pairs: [0,2], [1,3], [4,6], [5,7], ...
pub static SHUFFLE_LAYER7_LO: AlignedI8_32 = AlignedI8_32([
    0, 1, 4, 5, 2, 3, 6, 7,      // Pairs in lower lane
    8, 9, 12, 13, 10, 11, 14, 15, // Pairs in lower lane cont.
    0, 1, 4, 5, 2, 3, 6, 7,
    8, 9, 12, 13, 10, 11, 14, 15,
]);

/// Shuffle mask for layer 6 butterflies (len=4)
pub static SHUFFLE_LAYER6_LO: AlignedI8_32 = AlignedI8_32([
    0, 1, 2, 3, 8, 9, 10, 11,    // Elements 0-1 and 4-5
    4, 5, 6, 7, 12, 13, 14, 15,  // Elements 2-3 and 6-7
    0, 1, 2, 3, 8, 9, 10, 11,
    4, 5, 6, 7, 12, 13, 14, 15,
]);

// ============================================================================
// Pre-computed (zl, zh) pairs for fqmulprecomp Optimization
// ============================================================================
//
// The fqmulprecomp technique saves one multiplication per Montgomery reduction:
// - Standard Montgomery: 4 multiplications (mullo, mulhi, mullo_qinv, mulhi_q)
// - fqmulprecomp: 3 multiplications (mullo_zl, mulhi_zh, mulhi_q)
//
// For each zeta, we precompute:
//   zl = zeta * QINV mod R  (used for low product)
//   zh = zeta              (used for high product)
//
// The math works because:
//   (coeff * zl) mod R = (coeff * zeta * QINV) mod R
// This equals the Montgomery quotient m, enabling the 3-mul reduction.

/// Wrapper for 32-byte aligned (i16, i16) pairs array
#[repr(C, align(32))]
pub struct AlignedPrecomp128([(i16, i16); 128]);

impl AlignedPrecomp128 {
    /// Get (zl, zh) pair by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> (i16, i16) {
        self.0[idx]
    }
}

/// Precomputed (zl, zh) pairs for all 128 ZETAS values
/// zl = zeta * QINV mod R (for vpmullw - low product)
/// zh = zeta (for vpmulhw - high product)
pub static ZETAS_PRECOMP: AlignedPrecomp128 = AlignedPrecomp128([
    (   -20, -1044),(31498,  -758),(14745,  -359),(  787, -1517),
    (13525,  1493),(-12402,  1422),(28191,   287),(-16694,   202),
    (-20907,  -171),(27758,   622),(-3799,  1577),(-15690,   182),
    (10690,   962),( 1358, -1202),(-11202, -1474),(31164,  1468),
    (-5827,   573),(17363, -1325),(-26360,   264),(-29057,   383),
    ( 5571,  -829),(-1102,  1458),(21438, -1602),(-26242,  -130),
    (-28073,  -681),(24313,  1017),(-10532,   732),( 8800,   608),
    (18426, -1542),( 8859,   411),(26675,  -205),(-16163, -1571),
    (-5689,  1223),(-6516,   652),( 1496,  -552),(30967,  1015),
    (-23565, -1293),(20179,  1491),(20710,  -282),(25080, -1544),
    (-12796,   516),(26616,    -8),(16064,  -320),(-12442,  -666),
    ( 9134, -1618),( -650, -1162),(-25986,   126),(27837,  1469),
    (19883,  -853),(-28250,   -90),(-15887,  -271),(-8898,   830),
    (-28309,   107),( 9075, -1421),(-30199,  -247),(18249,  -951),
    (13426,  -398),(14017,   961),(-29156, -1508),(-12757,  -725),
    (16832,   448),( 4311, -1065),(-24155,   677),(-17915, -1275),
    ( -335, -1103),(11182,   430),(-11477,   555),(13387,   843),
    (-32227, -1251),(-14233,   871),(20494,  1550),(-21655,   105),
    (-27738,   422),(13131,   587),(  945,   177),(-4587,  -235),
    (-14883,  -291),(23092,  -460),( 6182,  1574),( 5493,  1653),
    (32010,  -246),(-32502,   778),(10631,  1159),(30317,  -147),
    (29175,  -777),(-18741,  1483),(-28762,  -602),(12639,  1119),
    (-18486, -1590),(20100,   644),(17560,  -872),(18525,   349),
    (-14430,   418),(19529,   329),(-5276,  -156),(-12619,   -75),
    (-31183,   817),(20297,  1097),(25435,   603),( 2146,   610),
    (-7382,  1322),(15355, -1285),(24391, -1465),(-32384,   384),
    (-20927, -1215),(-6280,  -136),(10946,  1218),(-14903, -1335),
    (24214,  -874),(-11044,   220),(16989, -1187),(14469, -1659),
    (10335, -1185),(-21498, -1530),(-7934, -1278),(-20198,   794),
    (-22502, -1510),(23210,  -854),(10906,  -870),(-17442,   478),
    (31636,  -108),(-23860,  -308),(28644,   996),(-20257,   991),
    (23998,   958),( 7756, -1460),(-17422,  1522),(23132,  1628),
]);

/// Precomputed layer 1 twiddle: (zl, zh) for ZETAS[1] = -758
pub static NTT_LAYER1_PRECOMP: (i16, i16) = (31498, -758);

/// Precomputed layer 2 twiddles: (zl, zh) for ZETAS[2..4]
pub static NTT_LAYER2_PRECOMP: [(i16, i16); 2] = [
    (14745, -359),   // ZETAS[2]
    (  787, -1517),  // ZETAS[3]
];

/// Precomputed layer 3 twiddles: (zl, zh) for ZETAS[4..8]
pub static NTT_LAYER3_PRECOMP: [(i16, i16); 4] = [
    (13525,  1493),  // ZETAS[4]
    (-12402, 1422),  // ZETAS[5]
    (28191,   287),  // ZETAS[6]
    (-16694,  202),  // ZETAS[7]
];

/// Precomputed layer 4 twiddles: (zl, zh) for ZETAS[8..16]
pub static NTT_LAYER4_PRECOMP: [(i16, i16); 8] = [
    (-20907,  -171), // ZETAS[8]
    (27758,    622), // ZETAS[9]
    (-3799,   1577), // ZETAS[10]
    (-15690,   182), // ZETAS[11]
    (10690,    962), // ZETAS[12]
    ( 1358,  -1202), // ZETAS[13]
    (-11202, -1474), // ZETAS[14]
    (31164,   1468), // ZETAS[15]
];

// ============================================================================
// Pre-Vectorized fqmulprecomp Constants (Eliminates Broadcast Overhead)
// ============================================================================
//
// For optimal performance, store zl and zh as pre-expanded 16-element vectors.
// This allows direct aligned loads instead of costly scalar broadcasts.
// _mm256_set1_epi16 has ~3 cycle latency; aligned load is 1 cycle.

/// Layer 1 zl (ZETAS[1] * QINV mod R = 31498), pre-expanded for direct load
pub static NTT_LAYER1_ZL_VEC: Aligned16 = Aligned16([31498; 16]);

/// Layer 1 zh (ZETAS[1] = -758), pre-expanded for direct load
pub static NTT_LAYER1_ZH_VEC: Aligned16 = Aligned16([-758; 16]);

/// Layer 2 zl vectors (ZETAS[2..4] * QINV mod R)
pub static NTT_LAYER2_ZL_VECS: [[i16; 16]; 2] = [
    [14745; 16],  // ZETAS[2] * QINV
    [787; 16],    // ZETAS[3] * QINV
];

/// Layer 2 zh vectors (ZETAS[2..4])
pub static NTT_LAYER2_ZH_VECS: [[i16; 16]; 2] = [
    [-359; 16],   // ZETAS[2]
    [-1517; 16],  // ZETAS[3]
];

/// Layer 3 zl vectors (ZETAS[4..8] * QINV mod R)
pub static NTT_LAYER3_ZL_VECS: [[i16; 16]; 4] = [
    [13525; 16],   // ZETAS[4] * QINV
    [-12402; 16],  // ZETAS[5] * QINV
    [28191; 16],   // ZETAS[6] * QINV
    [-16694; 16],  // ZETAS[7] * QINV
];

/// Layer 3 zh vectors (ZETAS[4..8])
pub static NTT_LAYER3_ZH_VECS: [[i16; 16]; 4] = [
    [1493; 16],   // ZETAS[4]
    [1422; 16],   // ZETAS[5]
    [287; 16],    // ZETAS[6]
    [202; 16],    // ZETAS[7]
];

/// Layer 4 zl vectors (ZETAS[8..16] * QINV mod R)
pub static NTT_LAYER4_ZL_VECS: [[i16; 16]; 8] = [
    [-20907; 16],  // ZETAS[8] * QINV
    [27758; 16],   // ZETAS[9] * QINV
    [-3799; 16],   // ZETAS[10] * QINV
    [-15690; 16],  // ZETAS[11] * QINV
    [10690; 16],   // ZETAS[12] * QINV
    [1358; 16],    // ZETAS[13] * QINV
    [-11202; 16],  // ZETAS[14] * QINV
    [31164; 16],   // ZETAS[15] * QINV
];

/// Layer 4 zh vectors (ZETAS[8..16])
pub static NTT_LAYER4_ZH_VECS: [[i16; 16]; 8] = [
    [-171; 16],   // ZETAS[8]
    [622; 16],    // ZETAS[9]
    [1577; 16],   // ZETAS[10]
    [182; 16],    // ZETAS[11]
    [962; 16],    // ZETAS[12]
    [-1202; 16],  // ZETAS[13]
    [-1474; 16],  // ZETAS[14]
    [1468; 16],   // ZETAS[15]
];

// ============================================================================
// Compression/Decompression Constants
// ============================================================================

/// Magic divisor for constant-time division by q
/// Computed as: floor(2^35 / 3329) = 10,321,340
pub const COMPRESS_MAGIC: u64 = 10_321_340;

/// Half of q for rounding in compression
pub const Q_HALF: u32 = 1664;

/// Decompression constants for d=10
pub const DECOMPRESS_D10_SHIFT: u32 = 10;
pub const DECOMPRESS_D10_HALF: u32 = 512;

/// Decompression constants for d=11
pub const DECOMPRESS_D11_SHIFT: u32 = 11;
pub const DECOMPRESS_D11_HALF: u32 = 1024;

// ============================================================================
// CBD Sampling Constants
// ============================================================================

/// Mask for CBD-2: 0x55555555 (odd bits)
pub const CBD2_MASK: u32 = 0x55555555;

/// Mask for CBD-3: 0x00249249 (every 3rd bit starting at 0)
pub const CBD3_MASK: u32 = 0x00249249;

// ============================================================================
// Inline Helper Functions
// ============================================================================

/// Load a vectorized constant as __m256i
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn load_const_vec(arr: &Aligned16) -> __m256i {
    _mm256_load_si256(arr.0.as_ptr() as *const __m256i)
}

/// Load an i8 shuffle mask as __m256i
///
/// # Safety
/// Requires AVX2 support
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn load_shuffle_mask(arr: &AlignedI8_32) -> __m256i {
    _mm256_load_si256(arr.0.as_ptr() as *const __m256i)
}

/// Get Q as a broadcast vector
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn q_vec() -> __m256i {
    _mm256_set1_epi16(Q)
}

/// Get QINV as a broadcast vector
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn qinv_vec() -> __m256i {
    _mm256_set1_epi16(QINV)
}

/// Get Barrett V as a broadcast vector
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn barrett_v_vec() -> __m256i {
    _mm256_set1_epi16(BARRETT_V)
}

/// Get F as a broadcast vector
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn f_vec() -> __m256i {
    _mm256_set1_epi16(F)
}

// ============================================================================
// Array Access Methods
// ============================================================================

impl Aligned128 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 128] {
        &self.0
    }

    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

impl Aligned112 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 112] {
        &self.0
    }

    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

impl Aligned64 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 64] {
        &self.0
    }

    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

impl Aligned16 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i16; 16] {
        &self.0
    }

    /// Get element by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> i16 {
        self.0[idx]
    }
}

impl AlignedI8_32 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[i8; 32] {
        &self.0
    }
}

impl Aligned2D1 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[[i16; 16]; 1] {
        &self.0
    }

    /// Get row by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> &[i16; 16] {
        &self.0[idx]
    }
}

impl Aligned2D2 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[[i16; 16]; 2] {
        &self.0
    }

    /// Get row by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> &[i16; 16] {
        &self.0[idx]
    }
}

impl Aligned2D4 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[[i16; 16]; 4] {
        &self.0
    }

    /// Get row by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> &[i16; 16] {
        &self.0[idx]
    }
}

impl Aligned2D8 {
    /// Get a reference to the inner array
    #[inline(always)]
    pub const fn as_slice(&self) -> &[[i16; 16]; 8] {
        &self.0
    }

    /// Get row by index
    #[inline(always)]
    pub const fn get(&self, idx: usize) -> &[i16; 16] {
        &self.0[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zetas_match_reference() {
        // Verify ZETAS match the reference implementation
        assert_eq!(ZETAS.get(0), -1044);
        assert_eq!(ZETAS.get(1), -758);
        assert_eq!(ZETAS.get(64), -1103);
        assert_eq!(ZETAS.get(127), 1628);
    }

    #[test]
    fn test_qinv_property() {
        // Verify QINV satisfies: q * QINV ≡ 1 (mod 2^16)
        // This is the Montgomery inverse property
        let product = (Q as i32) * (QINV as i32);
        let low16 = (product & 0xFFFF) as i16;
        assert_eq!(low16, 1);
    }

    #[test]
    fn test_alignment() {
        // Verify 32-byte alignment for AVX2 loads
        assert_eq!(ZETAS.as_slice().as_ptr() as usize % 32, 0);
        assert_eq!(Q_VEC.as_slice().as_ptr() as usize % 32, 0);
        assert_eq!(QINV_VEC.as_slice().as_ptr() as usize % 32, 0);
    }
}
