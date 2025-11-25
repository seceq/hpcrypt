// Debug program to verify Argon2 H0 computation
use hpcrypt_hash::blake2b::Blake2b;

fn main() {
    // Test vector parameters
    let lanes = 4u32;
    let outlen = 32u32;
    let mem_cost = 32u32;
    let time_cost = 3u32;
    let version = 0x13u32;
    let variant_d = 0u32; // Argon2d

    let password = hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
    let salt = hex::decode("02020202020202020202020202020202").unwrap();
    let secret = hex::decode("0303030303030303").unwrap();
    let ad = hex::decode("040404040404040404040404").unwrap();

    let mut hasher = Blake2b::new();

    // H0 = H(lanes || outlen || mem_cost || time_cost || version || type ||
    //        pwdlen || pwd || saltlen || salt || secretlen || secret || adlen || ad)
    hasher.update(&lanes.to_le_bytes());
    hasher.update(&outlen.to_le_bytes());
    hasher.update(&mem_cost.to_le_bytes());
    hasher.update(&time_cost.to_le_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.update(&variant_d.to_le_bytes());

    hasher.update(&(password.len() as u32).to_le_bytes());
    hasher.update(&password);

    hasher.update(&(salt.len() as u32).to_le_bytes());
    hasher.update(&salt);

    hasher.update(&(secret.len() as u32).to_le_bytes());
    hasher.update(&secret);

    hasher.update(&(ad.len() as u32).to_le_bytes());
    hasher.update(&ad);

    let h0 = hasher.finalize_fixed();

    println!("H0 (Argon2d): {}", hex::encode(h0));

    // Also compute for Argon2i and Argon2id
    let variant_i = 1u32;
    let mut hasher = Blake2b::new();
    hasher.update(&lanes.to_le_bytes());
    hasher.update(&outlen.to_le_bytes());
    hasher.update(&mem_cost.to_le_bytes());
    hasher.update(&time_cost.to_le_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.update(&variant_i.to_le_bytes());
    hasher.update(&(password.len() as u32).to_le_bytes());
    hasher.update(&password);
    hasher.update(&(salt.len() as u32).to_le_bytes());
    hasher.update(&salt);
    hasher.update(&(secret.len() as u32).to_le_bytes());
    hasher.update(&secret);
    hasher.update(&(ad.len() as u32).to_le_bytes());
    hasher.update(&ad);
    let h0_i = hasher.finalize_fixed();
    println!("H0 (Argon2i): {}", hex::encode(h0_i));

    let variant_id = 2u32;
    let mut hasher = Blake2b::new();
    hasher.update(&lanes.to_le_bytes());
    hasher.update(&outlen.to_le_bytes());
    hasher.update(&mem_cost.to_le_bytes());
    hasher.update(&time_cost.to_le_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.update(&variant_id.to_le_bytes());
    hasher.update(&(password.len() as u32).to_le_bytes());
    hasher.update(&password);
    hasher.update(&(salt.len() as u32).to_le_bytes());
    hasher.update(&salt);
    hasher.update(&(secret.len() as u32).to_le_bytes());
    hasher.update(&secret);
    hasher.update(&(ad.len() as u32).to_le_bytes());
    hasher.update(&ad);
    let h0_id = hasher.finalize_fixed();
    println!("H0 (Argon2id): {}", hex::encode(h0_id));
}
