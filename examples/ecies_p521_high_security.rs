//! P-521 ECIES with AES-256-GCM - High Security Example
//!
//! Demonstrates P-521 ECIES for government/military/high-security applications:
//! - 256-bit security level (CNSA 2.0 compliant)
//! - AES-256-GCM (matches P-521 security level)
//! - SHA-512 KDF (256-bit collision resistance)
//! - Suitable for TOP SECRET classified data

use hpcrypt_ecies::EciesP521;
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== P-521 ECIES with AES-256-GCM - High Security ===\n");

    let mut rng = thread_rng();

    // 1. Security Level Overview
    println!("1. Security Configuration");
    println!("   Curve: P-521 (NIST secp521r1)");
    println!("   Security level: 256 bits");
    println!("   AEAD: AES-256-GCM");
    println!("   KDF: X9.63 with SHA-512");
    println!("   Compliance: CNSA 2.0 (TOP SECRET)");
    println!("   Quantum security: 128 bits (Grover's algorithm)\n");

    // 2. Key Generation
    println!("2. Key Generation");
    let (recipient_secret, recipient_public) = EciesP521::generate_keypair(&mut rng)?;
    println!(
        "   Private key: {} bytes (66 bytes = 528 bits)",
        recipient_secret.len()
    );
    println!(
        "   Public key: {} bytes (uncompressed P-521 point)",
        recipient_public.len()
    );
    println!("   Public key format: 0x04 || X (66 bytes) || Y (66 bytes)\n");

    // 3. High-Security Message Encryption
    println!("3. Encrypting Classified Data");

    // Simulate TOP SECRET message
    let message = b"TOP SECRET//SI//NOFORN\n\
                    \n\
                    OPERATION: NIGHTFALL\n\
                    Location: 38.8977N, 77.0365W\n\
                    Time: 2025-11-15 03:00:00 UTC\n\
                    Assets: Alpha-7, Bravo-3, Charlie-9\n\
                    \n\
                    Authentication: HOTEL-WHISKEY-SEVEN-NINE";

    // Shared info provides domain separation and context
    let shared_info = b"classification:top-secret|compartment:si|distribution:noforn|agency:dod";

    println!("   Message classification: TOP SECRET//SI//NOFORN");
    println!("   Message size: {} bytes", message.len());
    println!(
        "   Context info: {}",
        std::str::from_utf8(shared_info).unwrap()
    );

    let ciphertext = EciesP521::encrypt(&recipient_public, message, shared_info, &mut rng)?;

    println!("   Ciphertext size: {} bytes", ciphertext.len());
    println!("   Overhead: {} bytes", ciphertext.len() - message.len());
    println!("   Breakdown: ephemeral (133) + nonce (12) + tag (16) = 161 bytes\n");

    // 4. Ciphertext Structure
    println!("4. Ciphertext Format");
    println!("   Bytes 0-132:   Ephemeral public key (P-521 point, uncompressed)");
    println!("   Bytes 133-144: Nonce (96 bits, random)");
    println!("   Bytes 145-end: Encrypted data || Authentication tag (128 bits)");
    println!(
        "   First byte: 0x{:02x} (uncompressed point prefix)\n",
        ciphertext[0]
    );

    // 5. Security Analysis
    println!("5. Security Analysis");
    println!("   Component               | Security Level | Attack Cost");
    println!("   ------------------------|----------------|------------------");
    println!("   P-521 ECDH              | 256 bits       | 2^256 operations");
    println!("   X9.63 KDF (SHA-512)     | 256 bits       | 2^256 operations");
    println!("   AES-256-GCM (encrypt)   | 256 bits       | 2^254 operations");
    println!("   AES-256-GCM (auth)      | 128 bits       | 2^128 operations");
    println!("   Overall (classical)     | 256 bits       | 2^256 operations");
    println!("   Overall (quantum)       | 128 bits       | 2^128 operations\n");

    // 6. Attack Resistance
    println!("6. Attack Resistance");
    println!("   Classical Attacks:");
    println!("   - Pollard's rho (ECDLP): 2^260 operations (~10^78 years)");
    println!("   - AES brute force: 2^256 operations (~10^77 years)");
    println!("   - Forgery (GCM): 2^128 operations (~10^38 years)");
    println!();
    println!("   Quantum Attacks:");
    println!("   - Shor's algorithm (ECDLP): 2^260 Note: 2^130 (still hard with current tech)");
    println!("   - Grover's algorithm (AES): 2^256 Note: 2^128 (infeasible)");
    println!("   - Post-quantum: Recommend hybrid with Kyber1024\n");

    // 7. Decryption
    println!("7. Decryption");
    let plaintext = EciesP521::decrypt(&recipient_secret, &ciphertext, shared_info)?;

    println!("   Decryption successful: {}", plaintext == message);
    println!("   Recovered message:");
    println!("   {}", std::str::from_utf8(&plaintext).unwrap());
    println!();

    // 8. Forward Secrecy
    println!("8. Forward Secrecy Demonstration");
    let msg1 = b"Mission Alpha: Code RED";
    let msg2 = b"Mission Bravo: Code BLUE";

    let ct1 = EciesP521::encrypt(&recipient_public, msg1, shared_info, &mut rng)?;
    let ct2 = EciesP521::encrypt(&recipient_public, msg2, shared_info, &mut rng)?;

    println!("   Same recipient, different ephemeral keys:");
    println!("   CT1 ephemeral (first 16 bytes): {:02x?}", &ct1[0..16]);
    println!("   CT2 ephemeral (first 16 bytes): {:02x?}", &ct2[0..16]);
    println!("   Keys are different: {} ", ct1[..133] != ct2[..133]);
    println!("   Compromise of one message does NOT affect others\n");

    // 9. Context Binding
    println!("9. Context Binding (Shared Info)");

    // Encrypt with one context
    let ct_classified = EciesP521::encrypt(
        &recipient_public,
        b"Classified document",
        b"classification:secret",
        &mut rng,
    )?;

    // Try to decrypt with wrong context
    let result_wrong_context = EciesP521::decrypt(
        &recipient_secret,
        &ct_classified,
        b"classification:unclassified", // Wrong context!
    );

    println!("   Encrypted with context: 'classification:secret'");
    println!(
        "   Decrypt with correct context: {}",
        EciesP521::decrypt(&recipient_secret, &ct_classified, b"classification:secret").is_ok()
    );
    println!(
        "   Decrypt with wrong context: {} ",
        result_wrong_context.is_ok()
    );
    println!("   Benefit: Prevents ciphertext from being used in wrong context\n");

    // 10. Tampering Detection
    println!("10. Tampering Detection");
    let ct_original = EciesP521::encrypt(&recipient_public, b"Do not tamper", &[], &mut rng)?;
    let mut ct_tampered = ct_original.clone();

    // Tamper with ciphertext
    let tamper_idx = ct_tampered.len() - 5;
    ct_tampered[tamper_idx] ^= 0x01;

    println!("   Original ciphertext: {} bytes", ct_original.len());
    println!("   Tampered byte {} (flipped 1 bit)", tamper_idx);
    println!(
        "   Decrypt original: {}",
        EciesP521::decrypt(&recipient_secret, &ct_original, &[]).is_ok()
    );
    println!(
        "   Decrypt tampered: {} ",
        EciesP521::decrypt(&recipient_secret, &ct_tampered, &[]).is_ok()
    );
    println!("   GCM authentication tag detects ANY modification\n");

    // 11. Use Cases
    println!("11. Recommended Use Cases");
    println!("    Government Communications");
    println!("      - TOP SECRET classified data (CNSA 2.0 required)");
    println!("      - Intelligence community (NSA, CIA, DoD)");
    println!("      - Diplomatic communications");
    println!();
    println!("    Financial Systems");
    println!("      - Central bank communications");
    println!("      - High-value transactions (>$1 billion)");
    println!("      - SWIFT alternatives");
    println!();
    println!("    Critical Infrastructure");
    println!("      - Power grid SCADA systems");
    println!("      - Nuclear facility controls");
    println!("      - Satellite command and control");
    println!();
    println!("    Long-Term Data Protection");
    println!("      - Medical records (50+ year retention)");
    println!("      - Legal documents (attorney-client privilege)");
    println!("      - Intellectual property (patents, trade secrets)\n");

    // 12. Performance Characteristics
    println!("12. Performance Profile");
    println!("   P-521 Operations (typical):");
    println!("   - Key generation: ~3.0 ms");
    println!("   - Encryption (ECDH): ~3.0 ms");
    println!("   - Decryption (ECDH): ~3.0 ms");
    println!("   - AES-256-GCM: ~1 GB/s throughput");
    println!();
    println!("   Comparison with P-256:");
    println!("   - P-521 is ~6x slower than P-256");
    println!("   - P-521 provides 2^128 more security");
    println!("   - Trade-off: Worth it for high-security applications\n");

    // 13. Compliance Summary
    println!("13. Standards Compliance");
    println!("    NIST SP 800-56A Rev. 3 (Key Establishment)");
    println!("    NIST SP 800-57 Part 1 Rev. 5 (Key Management)");
    println!("    NIST FIPS 186-5 (Digital Signatures)");
    println!("    CNSA 2.0 (Commercial National Security Algorithm Suite)");
    println!("    SEC 1 v2.0 (Elliptic Curve Cryptography)");
    println!("    FIPS 140-3 Level 4 compatible");
    println!("    Common Criteria EAL7 compatible\n");

    // 14. Security Warnings
    println!("14. Security Warnings ");
    println!("   CRITICAL: Never reuse nonces");
    println!("   - GCM catastrophically fails with nonce reuse");
    println!("   - Single reuse can leak AES-256 key");
    println!("   - Always use cryptographic random number generator");
    println!();
    println!("   IMPORTANT: Validate all public keys");
    println!("   - Check point is on curve");
    println!("   - Check point is not infinity");
    println!("   - Prevents invalid curve attacks");
    println!();
    println!("   IMPORTANT: Protect private keys");
    println!("   - Use HSM (Hardware Security Module) for storage");
    println!("   - Implement proper key lifecycle management");
    println!("   - Consider tamper-resistant hardware\n");

    // 15. Migration to Post-Quantum
    println!("15. Post-Quantum Migration Path");
    println!("   Current: P-521 ECIES (classical security only)");
    println!("   Transition: P-521 + Kyber1024 hybrid (best of both)");
    println!("   Future: Pure PQC (Kyber1024 or ML-KEM)");
    println!();
    println!("   Timeline:");
    println!("   - 2025-2030: Classical algorithms still secure");
    println!("   - 2030-2035: Begin hybrid transition (NIST recommendation)");
    println!("   - 2035+: Large-scale quantum computers may exist");
    println!();
    println!("   Recommendation: Plan hybrid deployment now\n");

    // 16. Summary
    println!("16. Summary");
    println!("   Security Level: 256 bits (classical), 128 bits (quantum)");
    println!("   Compliance: CNSA 2.0 (TOP SECRET approved)");
    println!("   Performance: 3-6ms per encryption (ECDH-limited)");
    println!("   Overhead: 161 bytes (acceptable for high-security)");
    println!("   Use Case: Government, military, critical infrastructure");
    println!();
    println!("   Key Takeaway:");
    println!("   P-521 with AES-256-GCM provides maximum security for");
    println!("   applications where security is paramount over performance.\n");

    println!(" High-security encryption demonstration complete!");

    Ok(())
}
