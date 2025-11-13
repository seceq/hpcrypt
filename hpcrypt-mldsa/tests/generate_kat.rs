// Generate KAT (Known Answer Test) vectors for ML-DSA
//
// This program generates deterministic test vectors that can be used
// to validate the implementation against the FIPS 204 standard.

use mldsa::keygen::keygen_from_seed;
use mldsa::params::{DsaParams, MlDsa44, MlDsa65, MlDsa87};
use mldsa::serialize::{serialize_public_key, serialize_secret_key, serialize_signature};
use mldsa::sign::sign_deterministic;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_kat_entry<P: DsaParams>(count: usize, seed: &[u8; 32], message: &[u8], rnd: &[u8; 32]) {
    println!("count = {}", count);
    println!("seed = {}", hex_encode(seed));

    // Generate keypair
    let (pk, sk) = keygen_from_seed::<P>(seed);

    // Serialize keys
    let pk_bytes = serialize_public_key::<P>(&pk);
    let sk_bytes = serialize_secret_key::<P>(&sk);

    println!("pk = {}", hex_encode(&pk_bytes));
    println!("sk = {}", hex_encode(&sk_bytes));
    println!("mlen = {}", message.len());
    println!("msg = {}", hex_encode(message));

    // Sign message
    let sig = sign_deterministic::<P>(&sk, message, rnd).expect("Signing failed");

    let sig_bytes = serialize_signature::<P>(&sig);

    println!("smlen = {}", sig_bytes.len() + message.len());

    // sm = signature || message
    let mut sm = sig_bytes.clone();
    sm.extend_from_slice(message);
    println!("sm = {}", hex_encode(&sm));

    println!();
}

fn main() {
    println!("# ML-DSA-65 Known Answer Test Vectors");
    println!("# Generated from FIPS 204 implementation");
    println!();

    // Test vector 0: Empty message
    let seed0 = [0u8; 32];
    let msg0 = b"";
    let rnd0 = [0u8; 32];
    generate_kat_entry::<MlDsa65>(0, &seed0, msg0, &rnd0);

    // Test vector 1: Simple message
    let seed1 = [1u8; 32];
    let msg1 = b"Hello, ML-DSA!";
    let rnd1 = [1u8; 32];
    generate_kat_entry::<MlDsa65>(1, &seed1, msg1, &rnd1);

    // Test vector 2: Longer message
    let seed2 = [2u8; 32];
    let msg2 = b"The quick brown fox jumps over the lazy dog";
    let rnd2 = [2u8; 32];
    generate_kat_entry::<MlDsa65>(2, &seed2, msg2, &rnd2);

    // Test vector 3: All zeros seed with varying message
    let seed3 = [0u8; 32];
    let msg3 = b"Test vector with zero seed";
    let rnd3 = [3u8; 32];
    generate_kat_entry::<MlDsa65>(3, &seed3, msg3, &rnd3);

    // Test vector 4: Binary message
    let seed4 = [4u8; 32];
    let msg4: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD];
    let rnd4 = [4u8; 32];
    generate_kat_entry::<MlDsa65>(4, &seed4, msg4, &rnd4);
}
