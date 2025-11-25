// Trace NIST Ascon state at each step

fn bytes_to_int_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(arr)
}

fn int_to_bytes_le(val: u64) -> [u8; 8] {
    val.to_le_bytes()
}

// NIST SP 800-232 round constants (same as ascon-c)
const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

fn ascon_permutation(state: &mut [u64; 5], rounds: usize) {
    let start = 12 - rounds;
    for i in start..12 {
        // Round constant
        state[2] ^= ROUND_CONSTANTS[i];

        // Substitution layer
        state[0] ^= state[4];
        state[4] ^= state[3];
        state[2] ^= state[1];

        let t0 = !state[0] & state[1];
        let t1 = !state[1] & state[2];
        let t2 = !state[2] & state[3];
        let t3 = !state[3] & state[4];
        let t4 = !state[4] & state[0];

        state[0] ^= t1;
        state[1] ^= t2;
        state[2] ^= t3;
        state[3] ^= t4;
        state[4] ^= t0;

        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];
        state[2] = !state[2];

        // Linear diffusion
        state[0] ^= state[0].rotate_right(19) ^ state[0].rotate_right(28);
        state[1] ^= state[1].rotate_right(61) ^ state[1].rotate_right(39);
        state[2] ^= state[2].rotate_right(1) ^ state[2].rotate_right(6);
        state[3] ^= state[3].rotate_right(10) ^ state[3].rotate_right(17);
        state[4] ^= state[4].rotate_right(7) ^ state[4].rotate_right(41);
    }
}

fn print_state(label: &str, state: &[u64; 5]) {
    println!("{}", label);
    for (i, &s) in state.iter().enumerate() {
        println!("  S[{}] = {:016x}", i, s);
    }
}

#[test]
fn trace_cavp_tcid1() {
    let key = hex::decode("49DADDBE884B3E523FFC655CB3BE81D6").unwrap();
    let nonce = hex::decode("667999F070DBD1F5CE5FAF070F80E3FA").unwrap();
    let ad = hex::decode("6F6F").unwrap();
    let pt = hex::decode("CC").unwrap();

    println!("\n=== CAVP Test tcId 1 - NIST AEAD128 ===\n");

    // Step 1: Initialize state
    // IV for AEAD128: version=1, a=12, b=8, taglen=128, rate=16
    // IV bytes: [1, 0, (8<<4)|12, 128&255, 128>>8, 16, 0, 0] = [0x01, 0x00, 0x8c, 0x80, 0x00, 0x10, 0x00, 0x00]
    let iv_bytes = [0x01u8, 0x00, 0x8c, 0x80, 0x00, 0x10, 0x00, 0x00];
    let iv = bytes_to_int_le(&iv_bytes);

    println!("IV bytes: {:02x?}", iv_bytes);
    println!("IV as u64: {:016x}", iv);

    let k0 = bytes_to_int_le(&key[0..8]);
    let k1 = bytes_to_int_le(&key[8..16]);
    let n0 = bytes_to_int_le(&nonce[0..8]);
    let n1 = bytes_to_int_le(&nonce[8..16]);

    println!("\nKey bytes: {:02x?}", &key[..]);
    println!("K0 = {:016x}, K1 = {:016x}", k0, k1);
    println!("\nNonce bytes: {:02x?}", &nonce[..]);
    println!("N0 = {:016x}, N1 = {:016x}", n0, n1);

    let mut state: [u64; 5] = [iv, k0, k1, n0, n1];
    print_state("\nInitial state:", &state);

    // Permutation with 12 rounds
    ascon_permutation(&mut state, 12);
    print_state("\nAfter P12:", &state);

    // XOR key back
    state[3] ^= k0;
    state[4] ^= k1;
    print_state("\nAfter key XOR (initialization complete):", &state);

    // Step 2: Process AD (2 bytes)
    // Pad: 2 bytes AD + 0x01 + zeros
    let mut padded = [0u8; 16];
    padded[0] = ad[0];
    padded[1] = ad[1];
    padded[2] = 0x01;

    let block0 = bytes_to_int_le(&padded[0..8]);
    let block1 = bytes_to_int_le(&padded[8..16]);

    println!("\nAD: {:02x?}", &ad[..]);
    println!("Padded AD: {:02x?}", padded);
    println!("AD block0 = {:016x}, block1 = {:016x}", block0, block1);

    state[0] ^= block0;
    state[1] ^= block1;
    print_state("\nAfter AD XOR:", &state);

    ascon_permutation(&mut state, 8);
    print_state("\nAfter P8 (AD):", &state);

    // Step 3: Domain separator
    state[4] ^= 1u64 << 63;
    print_state("\nAfter domain separator (S[4] ^= 1<<63):", &state);

    // Step 4: Process PT (1 byte)
    let mut pt_padded = [0u8; 16];
    pt_padded[0] = pt[0];
    pt_padded[1] = 0x01;

    let pt_block0 = bytes_to_int_le(&pt_padded[0..8]);

    println!("\nPT: {:02x?}", &pt[..]);
    println!("Padded PT: {:02x?}", &pt_padded[0..8]);
    println!("PT block0 = {:016x}", pt_block0);

    state[0] ^= pt_block0;

    // Extract CT (1 byte)
    let ct_bytes = int_to_bytes_le(state[0]);
    let ct = ct_bytes[0];

    println!("\nCT byte: {:02x}", ct);
    print_state("\nAfter PT encryption:", &state);

    // Step 5: Finalize
    // XOR key at rate/8 = 16/8 = 2
    state[2] ^= k0;
    state[3] ^= k1;
    print_state("\nAfter key XOR (pre-finalize):", &state);

    ascon_permutation(&mut state, 12);
    print_state("\nAfter P12 (finalize):", &state);

    state[3] ^= k0;
    state[4] ^= k1;
    print_state("\nAfter final key XOR:", &state);

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&int_to_bytes_le(state[3]));
    tag[8..16].copy_from_slice(&int_to_bytes_le(state[4]));

    println!("\n=== Results ===");
    println!("CT: {:02x}", ct);
    println!("Tag: {}", hex::encode(&tag));

    println!("\nExpected CT: b5");
    println!("Expected Tag: 3d2da4977f6ed6894c06405b8437b7a2");
}
