// Test hash_variable function
use hpcrypt_kdf::argon2::hash_variable;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let h0_hex = "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109";
    let h0 = hex_decode(h0_hex);

    let mut input = vec![0u8; 72];
    input[..64].copy_from_slice(&h0);
    input[64..68].copy_from_slice(&1u32.to_le_bytes());
    input[68..72].copy_from_slice(&0u32.to_le_bytes());

    let output = hash_variable(&input, 1024);

    println!("Input (first 72 bytes):");
    for i in 0..72 {
        print!("{:02x} ", input[i]);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }

    println!("\nOutput (first 64 bytes):");
    for i in 0..64 {
        print!("{:02x} ", output[i]);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }

    println!("\nOutput as u64 LE words:");
    for i in 0..8 {
        let word = u64::from_le_bytes([
            output[i*8], output[i*8+1], output[i*8+2], output[i*8+3],
            output[i*8+4], output[i*8+5], output[i*8+6], output[i*8+7],
        ]);
        println!("[{}]: {:016x}", i, word);
    }

    println!("\nExpected (P-H-C):");
    println!("[0]: ef764133b4ca7099");
    println!("[1]: 620440b335cfe9e1");
}
