//! Basic ECIES usage example
//!
//! This example demonstrates:
//! - Key generation for P-256, P-384, and P-521
//! - Message encryption and decryption
//! - Error handling

use hpcrypt_ecies::{EciesP256, EciesP384, EciesP521};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    println!("=== ECIES Basic Usage Examples ===\n");

    // Example 1: P-256 (Standard Security)
    println!("1. P-256 ECIES (128-bit security)");
    println!("   - Fast performance");
    println!("   - Smallest overhead (93 bytes)");
    println!("   - Recommended for most applications\n");

    let (secret_256, public_256) = EciesP256::generate_keypair(&mut rng)?;
    println!("   Generated keys:");
    println!("   - Secret key size: {} bytes", secret_256.len());
    println!("   - Public key size: {} bytes", public_256.len());

    let message = b"Hello, ECIES! This is a confidential message.";
    let ciphertext_256 = EciesP256::encrypt(&public_256, message, &[], &mut rng)?;
    println!("   Encrypted message:");
    println!("   - Plaintext size: {} bytes", message.len());
    println!("   - Ciphertext size: {} bytes", ciphertext_256.len());
    println!(
        "   - Overhead: {} bytes\n",
        ciphertext_256.len() - message.len()
    );

    let plaintext_256 = EciesP256::decrypt(&secret_256, &ciphertext_256, &[])?;
    assert_eq!(&plaintext_256, message);
    println!("   ✓ Decryption successful\n");

    // Example 2: P-384 (High Security)
    println!("2. P-384 ECIES (192-bit security)");
    println!("   - Higher security level");
    println!("   - Government/military applications");
    println!("   - Balanced security/performance\n");

    let (secret_384, public_384) = EciesP384::generate_keypair(&mut rng)?;
    println!("   Generated keys:");
    println!("   - Secret key size: {} bytes", secret_384.len());
    println!("   - Public key size: {} bytes", public_384.len());

    let ciphertext_384 = EciesP384::encrypt(&public_384, message, &[], &mut rng)?;
    println!("   Encrypted message:");
    println!("   - Plaintext size: {} bytes", message.len());
    println!("   - Ciphertext size: {} bytes", ciphertext_384.len());
    println!(
        "   - Overhead: {} bytes\n",
        ciphertext_384.len() - message.len()
    );

    let plaintext_384 = EciesP384::decrypt(&secret_384, &ciphertext_384, &[])?;
    assert_eq!(&plaintext_384, message);
    println!("   ✓ Decryption successful\n");

    // Example 3: P-521 (Maximum Security)
    println!("3. P-521 ECIES (256-bit security)");
    println!("   - Highest security level");
    println!("   - Top-secret data protection");
    println!("   - Future-proof against advances\n");

    let (secret_521, public_521) = EciesP521::generate_keypair(&mut rng)?;
    println!("   Generated keys:");
    println!("   - Secret key size: {} bytes", secret_521.len());
    println!("   - Public key size: {} bytes", public_521.len());

    let ciphertext_521 = EciesP521::encrypt(&public_521, message, &[], &mut rng)?;
    println!("   Encrypted message:");
    println!("   - Plaintext size: {} bytes", message.len());
    println!("   - Ciphertext size: {} bytes", ciphertext_521.len());
    println!(
        "   - Overhead: {} bytes\n",
        ciphertext_521.len() - message.len()
    );

    let plaintext_521 = EciesP521::decrypt(&secret_521, &ciphertext_521, &[])?;
    assert_eq!(&plaintext_521, message);
    println!("   ✓ Decryption successful\n");

    // Example 4: Using shared info for domain separation
    println!("4. Using Shared Info (Domain Separation)");
    println!("   - Adds context to encryption");
    println!("   - Prevents cross-protocol attacks");
    println!("   - Must match between encryption/decryption\n");

    let shared_info = b"app-v1.0:user-messages";
    let ciphertext_with_info = EciesP256::encrypt(&public_256, message, shared_info, &mut rng)?;
    let plaintext_with_info = EciesP256::decrypt(&secret_256, &ciphertext_with_info, shared_info)?;
    assert_eq!(&plaintext_with_info, message);
    println!("   ✓ Encryption with shared info successful\n");

    // Example 5: Error handling - wrong shared info
    println!("5. Error Handling - Wrong Shared Info");
    let wrong_shared_info = b"wrong-context";
    match EciesP256::decrypt(&secret_256, &ciphertext_with_info, wrong_shared_info) {
        Ok(_) => println!("   ✗ Should have failed!"),
        Err(e) => println!("   ✓ Correctly rejected: {}\n", e),
    }

    // Example 6: Error handling - corrupted ciphertext
    println!("6. Error Handling - Corrupted Ciphertext");
    let mut corrupted = ciphertext_256.clone();
    let idx = corrupted.len() / 2;
    corrupted[idx] ^= 0xFF;
    match EciesP256::decrypt(&secret_256, &corrupted, &[]) {
        Ok(_) => println!("   ✗ Should have failed!"),
        Err(e) => println!("   ✓ Correctly rejected: {}\n", e),
    }

    println!("=== All Examples Completed Successfully ===");

    Ok(())
}
