//! Demonstration of the ML-KEM API with new features
//!
//! Run with: cargo run --example api_demo --features "serde,zeroize"
//!
//! NOTE: This example is currently outdated and disabled.
//! The API has changed - decapsulate() now returns [u8; 32] directly, not Result.
//! PublicKey is not exported. This needs to be rewritten to match current API.

#[cfg(disabled_outdated_example)]
use hpcrypt_mlkem::{KeyPair, MlKem768};

#[cfg(not(disabled_outdated_example))]
fn main() {
    eprintln!("This example is currently disabled - API needs updating");
    eprintln!("The API has changed: decapsulate() now returns [u8; 32] directly");
}

#[cfg(disabled_outdated_example)]
fn main() -> Result<()> {
    println!("=== ML-KEM API Demo ===\n");

    // 1. Basic key generation
    println!("1. Generating key pair...");
    let keypair = KeyPair::generate::<MlKem768>();
    println!("   ✓ Key pair generated");
    println!("   - Public key size: {} bytes", keypair.encapsulation_key().len());
    println!("   - Private key size: {} bytes", keypair.decapsulation_key().len());

    // 2. Extract public key
    println!("\n2. Extracting public key...");
    let public_key = keypair.public_key();
    println!("   ✓ Public key extracted (can be shared safely)");

    // 3. Encapsulation using public key
    println!("\n3. Encapsulating with public key...");
    let (ciphertext, shared_secret_sender) = public_key.encapsulate::<MlKem768>();
    println!("   ✓ Encapsulation complete");
    println!("   - Ciphertext size: {} bytes", ciphertext.len());
    println!("   - Shared secret: {} bytes", shared_secret_sender.len());

    // 4. Decapsulation
    println!("\n4. Decapsulating with private key...");
    let shared_secret_receiver = keypair.decapsulate::<MlKem768>(&ciphertext).unwrap();
    println!("   ✓ Decapsulation complete");

    // 5. Verify shared secrets match
    println!("\n5. Verifying shared secrets...");
    assert_eq!(shared_secret_sender, shared_secret_receiver);
    println!("   ✓ Shared secrets match!");

    // 6. Key serialization/deserialization
    #[cfg(feature = "serde")]
    {
        println!("\n6. Testing serialization (serde feature enabled)...");
        let json = serde_json::to_string(&keypair).unwrap();
        println!("   ✓ Serialized key pair to JSON ({} bytes)", json.len());

        let restored: KeyPair = serde_json::from_str(&json).unwrap();
        println!("   ✓ Deserialized key pair from JSON");

        // Verify restored keypair works
        let (ct2, ss1) = restored.encapsulate::<MlKem768>();
        let ss2 = restored.decapsulate::<MlKem768>(&ct2).unwrap();
        assert_eq!(ss1, ss2);
        println!("   ✓ Restored key pair works correctly");
    }

    #[cfg(not(feature = "serde"))]
    {
        println!("\n6. Serialization: Enable with --features serde");
    }

    // 7. Key validation
    println!("\n7. Testing key validation...");
    let ek = keypair.encapsulation_key().to_vec();
    let dk = keypair.decapsulation_key().to_vec();

    match KeyPair::from_bytes::<MlKem768>(ek.clone(), dk.clone()) {
        Ok(_) => println!("   ✓ Valid keys accepted"),
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }

    // Test invalid key
    let invalid_ek = vec![0u8; 10]; // Wrong size
    match KeyPair::from_bytes::<MlKem768>(invalid_ek, dk) {
        Ok(_) => println!("   ✗ Invalid key should be rejected"),
        Err(e) => println!("   ✓ Invalid key rejected: {}", e),
    }

    // 8. Public key validation
    println!("\n8. Testing public key validation...");
    match PublicKey::from_bytes::<MlKem768>(ek) {
        Ok(pk) => {
            println!("   ✓ Valid public key accepted");
            // Use it
            let (_ct, _ss) = pk.encapsulate::<MlKem768>();
            println!("   ✓ Public key works correctly");
        }
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }

    // 9. Zeroization info
    #[cfg(feature = "zeroize")]
    {
        println!("\n9. Zeroization (zeroize feature enabled)...");
        println!("   ✓ Private keys automatically zeroed on drop");
        {
            let _temp_key = KeyPair::generate::<MlKem768>();
            println!("   - Created temporary key");
        } // _temp_key dropped here, private key zeroed
        println!("   ✓ Temporary key dropped and zeroed");
    }

    #[cfg(not(feature = "zeroize"))]
    {
        println!("\n9. Zeroization: Enable with --features zeroize");
    }

    println!("\n=== Demo Complete ===");
    println!("\nFeatures enabled:");
    println!("  - serde: {}", cfg!(feature = "serde"));
    println!("  - zeroize: {}", cfg!(feature = "zeroize"));

    Ok(())
}
