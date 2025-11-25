// Debug tests for Argon2 implementation
#[cfg(test)]
mod tests {
    use hpcrypt_hash::blake2b::Blake2b;
    use hpcrypt_kdf::argon2::{Argon2, Argon2d, Params, Variant};

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_h0_computation() {
        // Test vector parameters
        let lanes = 4u32;
        let outlen = 32u32;
        let mem_cost = 32u32;
        let time_cost = 3u32;
        let version = 0x13u32;

        let password = decode_hex("0101010101010101010101010101010101010101010101010101010101010101");
        let salt = decode_hex("02020202020202020202020202020202");
        let secret = decode_hex("0303030303030303");
        let ad = decode_hex("040404040404040404040404");

        // Compute H0 for Argon2d
        let mut hasher = Blake2b::new();
        hasher.update(&lanes.to_le_bytes());
        hasher.update(&outlen.to_le_bytes());
        hasher.update(&mem_cost.to_le_bytes());
        hasher.update(&time_cost.to_le_bytes());
        hasher.update(&version.to_le_bytes());
        hasher.update(&0u32.to_le_bytes()); // Argon2d
        hasher.update(&(password.len() as u32).to_le_bytes());
        hasher.update(&password);
        hasher.update(&(salt.len() as u32).to_le_bytes());
        hasher.update(&salt);
        hasher.update(&(secret.len() as u32).to_le_bytes());
        hasher.update(&secret);
        hasher.update(&(ad.len() as u32).to_le_bytes());
        hasher.update(&ad);
        let h0 = hasher.finalize_fixed();

        println!("\nH0 (Argon2d): {}", encode_hex(&h0));

        // Also test that our implementation computes the same H0
        let params = Params::new(outlen as usize, mem_cost, time_cost, lanes).unwrap();
        let argon2 = Argon2::new(Variant::Argon2d, params);

        // We can't directly access initial_hash, but we can test the full hash
        // and see if the H0 matches by creating a minimal test
    }

    #[test]
    fn test_first_block_generation() {
        let password = decode_hex("0101010101010101010101010101010101010101010101010101010101010101");
        let salt = decode_hex("02020202020202020202020202020202");
        let secret = decode_hex("0303030303030303");
        let ad = decode_hex("040404040404040404040404");

        let params = Params::new(32, 32, 3, 4).unwrap();

        // Run Argon2d
        let result = Argon2d::hash_with_ad(&password, &salt, &secret, &ad, &params);
        match result {
            Ok(hash) => {
                println!("\nArgon2d output: {}", encode_hex(&hash));
                println!("Expected:       512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
            }
            Err(e) => {
                println!("\nError: {:?}", e);
            }
        }
    }
}
