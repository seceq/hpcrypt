// Test to reproduce RSA-PSS crash on repeated operations

use hpcrypt_rsa::{
    pss::{sign_pss, verify_pss, Sha256},
    RsaPrivateKey,
};

fn main() {
    println!("Generating 2048-bit RSA key...");
    let key = RsaPrivateKey::generate(2048).unwrap();

    let message = b"Test message for repeated PSS signing";
    let salt_len = 32; // SHA-256 output size

    println!("Starting repeated RSA-PSS signing operations (1000 iterations)...");

    for i in 1..=1000 {
        match sign_pss::<Sha256>(&key, message, salt_len) {
            Ok(signature) => {
                // Verify the signature
                match verify_pss::<Sha256>(key.public_key(), message, &signature, salt_len) {
                    Ok(_) => {
                        if i % 100 == 0 {
                            println!("Iteration {}: Sign and verify successful", i);
                        }
                    }
                    Err(e) => {
                        println!("Iteration {}: Verification failed: {:?}", i, e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                println!("Iteration {}: Signing failed: {:?}", i, e);
                std::process::exit(1);
            }
        }
    }

    println!("\nAll 1000 iterations completed successfully!");
    println!("\nTesting with multiple keys...");

    for key_num in 1..=10 {
        let key = RsaPrivateKey::generate(2048).unwrap();

        for i in 1..=100 {
            match sign_pss::<Sha256>(&key, message, salt_len) {
                Ok(signature) => {
                    match verify_pss::<Sha256>(key.public_key(), message, &signature, salt_len) {
                        Ok(_) => {}
                        Err(e) => {
                            println!(
                                "Key {}, Iteration {}: Verification failed: {:?}",
                                key_num, i, e
                            );
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    println!("Key {}, Iteration {}: Signing failed: {:?}", key_num, i, e);
                    std::process::exit(1);
                }
            }
        }
        println!("Key {}: 100 iterations successful", key_num);
    }

    println!("\nAll stress tests passed!");
}
