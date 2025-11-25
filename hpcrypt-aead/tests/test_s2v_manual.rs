// Manually trace S2V computation
use hpcrypt_cipher::Aes;
use hpcrypt_mac::AesCmac128;

const BLOCK_SIZE: usize = 16;

fn dbl(block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    // Left shift by 1 bit (big-endian)
    for i in (0..BLOCK_SIZE).rev() {
        result[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }

    // If MSB was 1, XOR with Rb
    if carry != 0 {
        result[BLOCK_SIZE - 1] ^= 0x87;
    }

    result
}

fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

#[test]
fn test_s2v_rfc5297() {
    let mac_key_hex = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0";
    let aad_hex = "101112131415161718191a1b1c1d1e1f2021222324252627";
    let plaintext_hex = "112233445566778899aabbccddee";

    let mac_key = hex::decode(mac_key_hex).unwrap();
    let mac_key_array: [u8; 16] = mac_key.try_into().unwrap();
    let aad = hex::decode(aad_hex).unwrap();
    let plaintext = hex::decode(plaintext_hex).unwrap();

    let cmac = AesCmac128::new(&mac_key_array);

    println!("=== S2V Computation ===");
    println!("Inputs: [AAD (26 bytes), Plaintext (14 bytes)]");
    println!("AAD: {}", aad_hex);
    println!("Plaintext: {}", plaintext_hex);
    println!();

    // Step 1: D = AES-CMAC(K, <zero>)
    let zero_block = [0u8; BLOCK_SIZE];
    let mut d = cmac.compute(&zero_block);
    println!("D = CMAC(<zero>)   = {}", hex::encode(&d));

    // Step 2: D = dbl(D) xor CMAC(AAD)
    d = dbl(&d);
    println!("dbl(D)             = {}", hex::encode(&d));
    let cmac_aad = cmac.compute(&aad);
    println!("CMAC(AAD)          = {}", hex::encode(&cmac_aad));
    xor_block(&mut d, &cmac_aad);
    println!("D after AAD        = {}", hex::encode(&d));
    println!();

    // Step 3: Process last string (plaintext, 14 bytes < 16)
    // Since len(plaintext) < 128 bits: T = dbl(D) xor pad(plaintext)
    d = dbl(&d);
    println!("dbl(D)             = {}", hex::encode(&d));

    let mut padded = [0u8; BLOCK_SIZE];
    padded[..plaintext.len()].copy_from_slice(&plaintext);
    padded[plaintext.len()] = 0x80;
    println!("pad(plaintext)     = {}", hex::encode(&padded));

    xor_block(&mut d, &padded);
    println!("T = dbl(D) ^ pad   = {}", hex::encode(&d));
    println!();

    // Step 4: V = CMAC(T)
    let v = cmac.compute(&d);
    println!("V = CMAC(T)        = {}", hex::encode(&v));
    println!();
    println!("Expected SIV:      = 85632d07c6e8f37f950acd320a2ecc93");
}
