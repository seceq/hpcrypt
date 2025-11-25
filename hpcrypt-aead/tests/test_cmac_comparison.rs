// Compare CMAC implementations
use hpcrypt_mac::AesCmac128;
use hpcrypt_cipher::Aes;

// CMAC from aes_siv.rs (copied for testing)
const BLOCK_SIZE: usize = 16;

fn cmac_from_siv(cipher: &Aes, message: &[u8]) -> [u8; BLOCK_SIZE] {
    // Generate subkeys
    let l = cipher.encrypt_block(&[0u8; BLOCK_SIZE]);
    let k1 = left_shift_one_bit_siv(&l);
    let k2 = left_shift_one_bit_siv(&k1);

    let last_block_complete = message.len() % BLOCK_SIZE == 0 && !message.is_empty();
    let n_blocks = if last_block_complete {
        message.len() / BLOCK_SIZE - 1
    } else {
        message.len() / BLOCK_SIZE
    };

    let mut state = [0u8; BLOCK_SIZE];

    // Process complete blocks
    for i in 0..n_blocks {
        let block = &message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let block_array: [u8; BLOCK_SIZE] = block.try_into().unwrap();
        xor_block(&mut state, &block_array);
        state = cipher.encrypt_block(&state);
    }

    // Process last block
    let mut last_block = [0u8; BLOCK_SIZE];
    if last_block_complete {
        let start = (message.len() / BLOCK_SIZE - 1) * BLOCK_SIZE;
        last_block.copy_from_slice(&message[start..]);
        xor_block(&mut last_block, &k1);
    } else {
        let remaining = message.len() % BLOCK_SIZE;
        if remaining > 0 {
            let start = (message.len() / BLOCK_SIZE) * BLOCK_SIZE;
            last_block[..remaining].copy_from_slice(&message[start..]);
        }
        last_block[remaining] = 0x80;
        xor_block(&mut last_block, &k2);
    }

    xor_block(&mut state, &last_block);
    cipher.encrypt_block(&state)
}

fn left_shift_one_bit_siv(input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    let mut carry = 0u8;

    for i in (0..BLOCK_SIZE).rev() {
        output[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }

    if carry != 0 {
        output[BLOCK_SIZE - 1] ^= 0x87;
    }

    output
}

fn xor_block(a: &mut [u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

#[test]
fn test_cmac_comparison() {
    let key_hex = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0";
    let key = hex::decode(key_hex).unwrap();
    let key_array: [u8; 16] = key.try_into().unwrap();

    let test_message = hex::decode("101112131415161718191a1b1c1d1e1f2021222324252627").unwrap();

    // Test with hpcrypt-mac CMAC
    let cmac_mac = AesCmac128::new(&key_array);
    let result_mac = cmac_mac.compute(&test_message);

    // Test with aes_siv CMAC
    let cipher = Aes::new_128(&key_array);
    let result_siv = cmac_from_siv(&cipher, &test_message);

    println!("Message: {}", hex::encode(&test_message));
    println!("CMAC (hpcrypt-mac): {}", hex::encode(&result_mac));
    println!("CMAC (aes_siv):     {}", hex::encode(&result_siv));

    assert_eq!(result_mac, result_siv, "CMAC implementations differ!");
}
