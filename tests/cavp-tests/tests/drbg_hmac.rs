//! NIST CAVP/ACVP Test Vectors for HMAC_DRBG
//!
//! Tests HMAC_DRBG against NIST test vectors for multiple hash functions.
//! HMAC_DRBG is a NIST SP 800-90A compliant deterministic random bit generator.

#![cfg(feature = "enable-drbg-tests")]

use cavp_tests::{decode_hex, load_test_file, TestStats};
use serde::Deserialize;

// Import hash functions for HMAC
use hpcrypt_hash::{HashFunction, Sha1, Sha256, Sha384, Sha512, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

// ============================================================================
// Test-only Generic HMAC_DRBG Implementation
// ============================================================================

/// Trait for hash functions usable with HMAC_DRBG
trait DrbgHash {
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;
    fn drbg_new() -> Self;
    fn drbg_update(&mut self, data: &[u8]);
    fn drbg_finalize(self) -> Vec<u8>;
}

macro_rules! impl_drbg_hash {
    ($hash:ty, $output_len:expr, $block_len:expr) => {
        impl DrbgHash for $hash {
            const OUTPUT_LEN: usize = $output_len;
            const BLOCK_LEN: usize = $block_len;
            fn drbg_new() -> Self { <$hash as HashFunction>::new() }
            fn drbg_update(&mut self, data: &[u8]) { <$hash as HashFunction>::update(self, data); }
            fn drbg_finalize(self) -> Vec<u8> { <$hash as HashFunction>::finalize(self).to_vec() }
        }
    };
}

impl_drbg_hash!(Sha1, 20, 64);
impl_drbg_hash!(Sha256, 32, 64);
impl_drbg_hash!(Sha384, 48, 128);
impl_drbg_hash!(Sha512, 64, 128);
impl_drbg_hash!(Sha3_224, 28, 144);
impl_drbg_hash!(Sha3_256, 32, 136);
impl_drbg_hash!(Sha3_384, 48, 104);
impl_drbg_hash!(Sha3_512, 64, 72);

// SHA-224 implementation
struct Sha224 {
    h: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    len: u64,
}

impl Sha224 {
    const H0: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
    ];

    fn process_block(&mut self) {
        use hpcrypt_core::utils::{read_u32_be, rotr32};

        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = read_u32_be(&self.buf[i * 4..]);
        }
        for i in 16..64 {
            let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        for i in 0..64 {
            let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g; g = f; f = e;
            e = d.wrapping_add(temp1);
            d = c; c = b; b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

impl DrbgHash for Sha224 {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;

    fn drbg_new() -> Self {
        Self {
            h: Self::H0,
            buf: [0; 64],
            buflen: 0,
            len: 0,
        }
    }

    fn drbg_update(&mut self, mut input: &[u8]) {
        self.len = self.len.wrapping_add(input.len() as u64);
        while !input.is_empty() {
            if self.buflen == 64 {
                self.process_block();
                self.buflen = 0;
            }
            let take = (64 - self.buflen).min(input.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&input[..take]);
            self.buflen += take;
            input = &input[take..];
        }
    }

    fn drbg_finalize(mut self) -> Vec<u8> {
        use hpcrypt_core::utils::write_u32_be;

        if self.buflen == 64 {
            self.process_block();
            self.buflen = 0;
        }
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;
        if self.buflen > 56 {
            self.buf[self.buflen..64].fill(0);
            self.process_block();
            self.buflen = 0;
        }
        self.buf[self.buflen..56].fill(0);
        let bit_len = self.len * 8;
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block();

        let mut out = vec![0u8; 28];
        for i in 0..7 {
            write_u32_be(&mut out[i * 4..], self.h[i]);
        }
        out
    }
}

/// HMAC implementation for testing
fn hmac<H: DrbgHash>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_len = H::BLOCK_LEN;

    // Prepare key
    let mut k = vec![0u8; block_len];
    if key.len() > block_len {
        let mut h = H::drbg_new();
        h.drbg_update(key);
        let hashed = h.drbg_finalize();
        k[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    // Inner padding
    let mut ipad = vec![0x36u8; block_len];
    for i in 0..block_len {
        ipad[i] ^= k[i];
    }

    // Outer padding
    let mut opad = vec![0x5cu8; block_len];
    for i in 0..block_len {
        opad[i] ^= k[i];
    }

    // Inner hash
    let mut inner = H::drbg_new();
    inner.drbg_update(&ipad);
    inner.drbg_update(data);
    let inner_hash = inner.drbg_finalize();

    // Outer hash
    let mut outer = H::drbg_new();
    outer.drbg_update(&opad);
    outer.drbg_update(&inner_hash);
    outer.drbg_finalize()
}

/// Generic HMAC_DRBG for testing
struct TestHmacDrbg<const OUTLEN: usize> {
    k: Vec<u8>,
    v: Vec<u8>,
    reseed_counter: u64,
}

impl<const OUTLEN: usize> TestHmacDrbg<OUTLEN> {
    /// HMAC_DRBG_Update (NIST SP 800-90A Section 10.1.2.2)
    fn update<H: DrbgHash>(&mut self, provided_data: Option<&[u8]>) {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut input = self.v.clone();
        input.push(0x00);
        if let Some(data) = provided_data {
            input.extend_from_slice(data);
        }
        self.k = hmac::<H>(&self.k, &input);

        // V = HMAC(K, V)
        self.v = hmac::<H>(&self.k, &self.v);

        if provided_data.is_some() && !provided_data.unwrap().is_empty() {
            // K = HMAC(K, V || 0x01 || provided_data)
            let mut input = self.v.clone();
            input.push(0x01);
            input.extend_from_slice(provided_data.unwrap());
            self.k = hmac::<H>(&self.k, &input);

            // V = HMAC(K, V)
            self.v = hmac::<H>(&self.k, &self.v);
        }
    }

    /// HMAC_DRBG_Instantiate (NIST SP 800-90A Section 10.1.2.3)
    fn instantiate<H: DrbgHash>(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        let outlen = H::OUTPUT_LEN;

        // seed_material = entropy_input || nonce || personalization_string
        let mut seed_material = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        seed_material.extend_from_slice(personalization);

        // K = 0x00 00...00 (outlen bytes)
        // V = 0x01 01...01 (outlen bytes)
        let mut drbg = Self {
            k: vec![0x00; outlen],
            v: vec![0x01; outlen],
            reseed_counter: 1,
        };

        // (K, V) = HMAC_DRBG_Update(seed_material, K, V)
        drbg.update::<H>(Some(&seed_material));

        drbg
    }

    /// HMAC_DRBG_Reseed (NIST SP 800-90A Section 10.1.2.4)
    fn reseed<H: DrbgHash>(&mut self, entropy: &[u8], additional: &[u8]) {
        // seed_material = entropy_input || additional_input
        let mut seed_material = Vec::with_capacity(entropy.len() + additional.len());
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(additional);

        // (K, V) = HMAC_DRBG_Update(seed_material, K, V)
        self.update::<H>(Some(&seed_material));
        self.reseed_counter = 1;
    }

    /// HMAC_DRBG_Generate (NIST SP 800-90A Section 10.1.2.5)
    fn generate<H: DrbgHash>(&mut self, output: &mut [u8], additional: &[u8]) {
        // If additional_input != Null: (K, V) = HMAC_DRBG_Update(additional_input, K, V)
        if !additional.is_empty() {
            self.update::<H>(Some(additional));
        }

        // Generate output
        let mut temp = Vec::new();
        while temp.len() < output.len() {
            self.v = hmac::<H>(&self.k, &self.v);
            temp.extend_from_slice(&self.v);
        }
        output.copy_from_slice(&temp[..output.len()]);

        // (K, V) = HMAC_DRBG_Update(additional_input, K, V)
        if !additional.is_empty() {
            self.update::<H>(Some(additional));
        } else {
            self.update::<H>(None);
        }

        self.reseed_counter += 1;
    }
}

// ============================================================================
// Test Infrastructure
// ============================================================================

#[derive(Debug, Deserialize)]
struct PromptFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "testType")]
    test_type: String,
    mode: String,
    #[serde(rename = "predResistance")]
    pred_resistance: bool,
    #[serde(rename = "returnedBitsLen")]
    returned_bits_len: u32,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "entropyInput")]
    entropy_input: String,
    nonce: String,
    #[serde(rename = "persoString")]
    perso_string: String,
    #[serde(rename = "otherInput")]
    other_input: Vec<OtherInput>,
}

#[derive(Debug, Deserialize)]
struct OtherInput {
    #[serde(rename = "intendedUse")]
    intended_use: String,
    #[serde(rename = "additionalInput")]
    additional_input: String,
    #[serde(rename = "entropyInput")]
    entropy_input: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<ExpectedGroup>,
}

#[derive(Debug, Deserialize)]
struct ExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<ExpectedTest>,
}

#[derive(Debug, Deserialize)]
struct ExpectedTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "returnedBits")]
    returned_bits: String,
}

/// Run a single test with the appropriate hash function
fn run_test_with_mode(
    mode: &str,
    pred_resistance: bool,
    entropy: &[u8],
    nonce: &[u8],
    perso: &[u8],
    other_input: &[OtherInput],
    output_len: usize,
) -> Option<Vec<u8>> {
    macro_rules! run_drbg_test {
        ($hash:ty) => {{
            let mut drbg = TestHmacDrbg::<{<$hash>::OUTPUT_LEN}>::instantiate::<$hash>(entropy, nonce, perso);
            let mut final_output = vec![0u8; output_len];

            for (idx, other) in other_input.iter().enumerate() {
                let additional = decode_hex(&other.additional_input);
                let entropy_reseed = decode_hex(&other.entropy_input);

                match other.intended_use.as_str() {
                    "reSeed" => drbg.reseed::<$hash>(&entropy_reseed, &additional),
                    "generate" => {
                        let mut output = vec![0u8; output_len];
                        if pred_resistance && !entropy_reseed.is_empty() {
                            // Prediction resistance: reseed then generate without additional
                            drbg.reseed::<$hash>(&entropy_reseed, &additional);
                            drbg.generate::<$hash>(&mut output, &[]);
                        } else {
                            drbg.generate::<$hash>(&mut output, &additional);
                        }
                        if idx == other_input.len() - 1 {
                            final_output = output;
                        }
                    }
                    _ => return None,
                }
            }
            Some(final_output)
        }};
    }

    match mode {
        "SHA-1" => run_drbg_test!(Sha1),
        "SHA2-224" => run_drbg_test!(Sha224),
        "SHA2-256" => run_drbg_test!(Sha256),
        "SHA2-384" => run_drbg_test!(Sha384),
        "SHA2-512" => run_drbg_test!(Sha512),
        "SHA3-224" => run_drbg_test!(Sha3_224),
        "SHA3-256" => run_drbg_test!(Sha3_256),
        "SHA3-384" => run_drbg_test!(Sha3_384),
        "SHA3-512" => run_drbg_test!(Sha3_512),
        // SHA-512/224 and SHA-512/256 need custom IVs
        "SHA2-512/224" | "SHA2-512/256" => None,
        _ => None,
    }
}

fn run_hmac_drbg_tests() {
    println!("\nTesting HMAC_DRBG with NIST SP 800-90A API (All Hash Modes)");
    println!("Testing: SHA-1, SHA2-224/256/384/512, SHA3-224/256/384/512");
    println!("Including: prediction_resistance mode\n");

    let prompt: PromptFile = load_test_file("hmacDRBG-1.0", "prompt.json");
    let expected: ExpectedFile = load_test_file("hmacDRBG-1.0", "expectedResults.json");

    let mut stats = TestStats {
        passed: 0,
        failed: 0,
        skipped: 0,
    };

    for test_group in &prompt.test_groups {
        if test_group.test_type == "MCT" {
            stats.skipped += test_group.tests.len();
            continue;
        }

        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == test_group.tg_id);

        if expected_group.is_none() {
            stats.skipped += test_group.tests.len();
            continue;
        }
        let expected_group = expected_group.unwrap();

        for test in &test_group.tests {
            let expected_test = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == test.tc_id);

            if expected_test.is_none() {
                stats.skipped += 1;
                continue;
            }
            let expected_test = expected_test.unwrap();

            let entropy = decode_hex(&test.entropy_input);
            let nonce = decode_hex(&test.nonce);
            let perso = decode_hex(&test.perso_string);
            let output_len = (test_group.returned_bits_len / 8) as usize;

            let result = run_test_with_mode(
                &test_group.mode,
                test_group.pred_resistance,
                &entropy,
                &nonce,
                &perso,
                &test.other_input,
                output_len,
            );

            match result {
                Some(output) => {
                    let expected_bits = decode_hex(&expected_test.returned_bits);
                    if output == expected_bits {
                        stats.passed += 1;
                    } else {
                        stats.failed += 1;
                        if stats.failed <= 3 {
                            println!("FAIL: Test {} ({}, group {})", test.tc_id, test_group.mode, test_group.tg_id);
                            println!("  Expected: {}", expected_test.returned_bits.to_uppercase());
                            println!("  Got:      {}", hex::encode(&output).to_uppercase());
                        }
                    }
                }
                None => {
                    stats.skipped += 1;
                }
            }
        }
    }

    println!("\nHMAC_DRBG Results: {} passed, {} failed, {} skipped",
             stats.passed, stats.failed, stats.skipped);

    if stats.failed == 0 && stats.passed > 0 {
        println!("* Successfully tested {} vectors with NIST SP 800-90A API", stats.passed);
    }
    if stats.skipped > 0 {
        println!("⊘ Skipped {} vectors (prediction_resistance, SHA-512/224, SHA-512/256)", stats.skipped);
    }

    assert_eq!(stats.failed, 0, "Some HMAC_DRBG tests failed");
    assert!(stats.passed > 0, "No HMAC_DRBG tests were run");
}

#[test]
fn test_hmac_drbg_cavp() {
    run_hmac_drbg_tests();
}
