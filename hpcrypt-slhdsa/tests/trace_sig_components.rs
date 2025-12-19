//! Trace signature component sizes to find the issue

use hpcrypt_slhdsa::{Sha2_128f, Sha2_128s, KeyPair, ParameterSet};
use rand::rngs::OsRng;

#[test]
fn trace_signature_components() {
    println!("\n=== Signature Component Size Analysis ===\n");

    // Check parameter set constants
    println!("Sha2_128f Parameters:");
    println!("  N (security parameter): {}", Sha2_128f::N);
    println!("  D (hypertree layers): {}", Sha2_128f::D);
    println!("  H (total tree height): {}", Sha2_128f::H);
    println!("  TREE_HEIGHT (per layer): {}", Sha2_128f::TREE_HEIGHT);
    println!("  K (FORS trees): {}", Sha2_128f::K);
    println!("  A (FORS tree height): {}", Sha2_128f::A);
    println!("  WOTS_LEN: {}", Sha2_128f::WOTS_LEN);

    println!("\nCalculated sizes:");
    println!("  FORS_SIG_BYTES: {}", Sha2_128f::FORS_SIG_BYTES);
    println!("  WOTS_SIG_BYTES: {}", Sha2_128f::WOTS_SIG_BYTES);
    println!("  Expected SIG_BYTES: {}", Sha2_128f::SIG_BYTES);

    let expected_sig_size = Sha2_128f::N +  // R
                           Sha2_128f::FORS_SIG_BYTES +
                           Sha2_128f::D * (Sha2_128f::WOTS_SIG_BYTES + Sha2_128f::TREE_HEIGHT * Sha2_128f::N);
    println!("  Manual calculation: {} bytes", expected_sig_size);

    println!("\nBreakdown:");
    println!("  R (randomness): {} bytes", Sha2_128f::N);
    println!("  FORS signature: {} bytes", Sha2_128f::FORS_SIG_BYTES);
    println!("  Hypertree (per layer):");
    println!("    - WOTS signature: {} bytes", Sha2_128f::WOTS_SIG_BYTES);
    println!("    - Auth path: {} bytes", Sha2_128f::TREE_HEIGHT * Sha2_128f::N);
    println!("    - Total per layer: {} bytes", Sha2_128f::WOTS_SIG_BYTES + Sha2_128f::TREE_HEIGHT * Sha2_128f::N);
    println!("  Hypertree total ({} layers): {} bytes",
             Sha2_128f::D,
             Sha2_128f::D * (Sha2_128f::WOTS_SIG_BYTES + Sha2_128f::TREE_HEIGHT * Sha2_128f::N));

    // Generate actual signatures
    println!("\n=== Actual Signature Sizes ===\n");

    let keypair = KeyPair::<Sha2_128f>::generate(&mut OsRng);
    let message = b"Test message";

    // Pure signing
    let sig_pure = hpcrypt_slhdsa::sign(&keypair.secret_key, message);
    println!("Pure sign: {} bytes (expected {})", sig_pure.len(), Sha2_128f::SIG_BYTES);
    if sig_pure.len() != Sha2_128f::SIG_BYTES {
        println!("  [FAIL] SIZE MISMATCH! Difference: {} bytes",
                 Sha2_128f::SIG_BYTES as i32 - sig_pure.len() as i32);
    }

    // Context signing
    let sig_ctx = hpcrypt_slhdsa::sign_ctx(&keypair.secret_key, b"context", message);
    println!("sign_ctx: {} bytes (expected {})", sig_ctx.len(), Sha2_128f::SIG_BYTES);
    if sig_ctx.len() != Sha2_128f::SIG_BYTES {
        println!("  [FAIL] SIZE MISMATCH! Difference: {} bytes",
                 Sha2_128f::SIG_BYTES as i32 - sig_ctx.len() as i32);
    }

    // Prehash signing
    let sig_prehash = hpcrypt_slhdsa::sign_prehash(&keypair.secret_key, b"context", "SHA2-256", message)
        .expect("Prehash signing failed");
    println!("sign_prehash: {} bytes (expected {})", sig_prehash.len(), Sha2_128f::SIG_BYTES);
    if sig_prehash.len() != Sha2_128f::SIG_BYTES {
        println!("  [FAIL] SIZE MISMATCH! Difference: {} bytes",
                 Sha2_128f::SIG_BYTES as i32 - sig_prehash.len() as i32);
    }

    // Compare with Sha2_128s (smaller parameter set)
    println!("\n=== Sha2_128s for comparison ===\n");
    println!("Sha2_128s SIG_BYTES: {}", Sha2_128s::SIG_BYTES);
    let keypair_s = KeyPair::<Sha2_128s>::generate(&mut OsRng);
    let sig_s = hpcrypt_slhdsa::sign(&keypair_s.secret_key, message);
    println!("Actual signature: {} bytes", sig_s.len());

    // Assert all sizes are correct
    assert_eq!(sig_pure.len(), Sha2_128f::SIG_BYTES, "Pure sign size mismatch");
    assert_eq!(sig_ctx.len(), Sha2_128f::SIG_BYTES, "sign_ctx size mismatch");
    assert_eq!(sig_prehash.len(), Sha2_128f::SIG_BYTES, "sign_prehash size mismatch");
}
