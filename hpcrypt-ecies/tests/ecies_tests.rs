//! ECIES integration tests

use hpcrypt_ecies::EciesP256;
use rand::thread_rng;

#[test]
fn test_p256_ecies_encrypt_decrypt() {
    let mut rng = thread_rng();
    let (private_key, public_key) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = b"ECIES test message";

    let ciphertext = EciesP256::encrypt(&public_key, plaintext, &[], &mut rng).unwrap();
    let decrypted = EciesP256::decrypt(&private_key, &ciphertext, &[]).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_p256_ecies_empty_message() {
    let mut rng = thread_rng();
    let (private_key, public_key) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = b"";

    let ciphertext = EciesP256::encrypt(&public_key, plaintext, &[], &mut rng).unwrap();
    let decrypted = EciesP256::decrypt(&private_key, &ciphertext, &[]).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_p256_ecies_large_message() {
    let mut rng = thread_rng();
    let (private_key, public_key) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = vec![0x42; 1024];

    let ciphertext = EciesP256::encrypt(&public_key, &plaintext, &[], &mut rng).unwrap();
    let decrypted = EciesP256::decrypt(&private_key, &ciphertext, &[]).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_p256_ecies_wrong_key_fails() {
    let mut rng = thread_rng();
    let (_, public_key1) = EciesP256::generate_keypair(&mut rng).unwrap();
    let (private_key2, _) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = b"Test";

    let ciphertext = EciesP256::encrypt(&public_key1, plaintext, &[], &mut rng).unwrap();

    // Decryption with wrong private key should fail
    let result = EciesP256::decrypt(&private_key2, &ciphertext, &[]);
    assert!(result.is_err() || result.unwrap() != plaintext);
}

#[test]
fn test_p256_ecies_tampering_fails() {
    let mut rng = thread_rng();
    let (private_key, public_key) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = b"Authenticated message";

    let mut ciphertext = EciesP256::encrypt(&public_key, plaintext, &[], &mut rng).unwrap();

    // Tamper with ciphertext
    let ct_len = ciphertext.len();
    if !ciphertext.is_empty() {
        ciphertext[ct_len / 2] ^= 1;
    }

    // Should fail to decrypt or produce wrong plaintext
    let result = EciesP256::decrypt(&private_key, &ciphertext, &[]);
    assert!(result.is_err() || result.unwrap() != plaintext);
}

#[test]
fn test_p256_ecies_deterministic_keys_different_ciphertexts() {
    let mut rng = thread_rng();
    let (private_key, public_key) = EciesP256::generate_keypair(&mut rng).unwrap();
    let plaintext = b"Same message";

    // Encrypt same message twice
    let ciphertext1 = EciesP256::encrypt(&public_key, plaintext, &[], &mut rng).unwrap();
    let ciphertext2 = EciesP256::encrypt(&public_key, plaintext, &[], &mut rng).unwrap();

    // Ciphertexts should be different (due to random ephemeral key)
    assert_ne!(ciphertext1, ciphertext2);

    // But both should decrypt correctly
    let decrypted1 = EciesP256::decrypt(&private_key, &ciphertext1, &[]).unwrap();
    let decrypted2 = EciesP256::decrypt(&private_key, &ciphertext2, &[]).unwrap();

    assert_eq!(plaintext, &decrypted1[..]);
    assert_eq!(plaintext, &decrypted2[..]);
}
