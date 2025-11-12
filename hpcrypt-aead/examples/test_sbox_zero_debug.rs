// Debug test to understand S-box zero input behavior

fn main() {
    // In bitsliced representation, all zeros means:
    // - 4 blocks, each with 16 bytes of 0x00
    // - Each bit plane (u64) should be 0

    let mut state = [0u64; 8];
    println!("Input state (all zeros):");
    for (i, &val) in state.iter().enumerate() {
        println!("  state[{}] = 0x{:016x}", i, val);
    }

    // Apply S-box
    sub_bytes(&mut state);

    println!("\nOutput state after S-box:");
    for (i, &val) in state.iter().enumerate() {
        println!("  state[{}] = 0x{:016x}", i, val);
    }

    // Check what AES S-box(0x00) should be
    // According to AES spec: S-box[0x00] = 0x63
    println!("\nAES S-box mapping: 0x00 -> 0x63 (binary: 0110_0011)");
    println!("In bitsliced form with 4 blocks of 0x00:");
    println!("  Bit 0 (LSB): should be 1 (from 0x63)");
    println!("  Bit 1:       should be 1");
    println!("  Bit 2:       should be 0");
    println!("  Bit 3:       should be 0");
    println!("  Bit 4:       should be 0");
    println!("  Bit 5:       should be 1");
    println!("  Bit 6:       should be 1");
    println!("  Bit 7 (MSB): should be 0");

    // Each u64 represents one bit across all 64 byte positions
    // For 4 blocks with all bytes = 0x63, we'd expect certain bit patterns

    let all_zeros = state.iter().all(|&x| x == 0);
    println!("\nAll output bits are zero: {}", all_zeros);
}

// Inline the S-box implementation
type State = [u64; 8];

#[inline(always)]
fn sub_bytes(state: &mut State) {
    debug_assert_eq!(state.len(), 8);

    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    let y9 = u0 ^ u3;
    let y11 = y20 ^ y9;
    let t12 = y9 & y11;
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    let y17 = y10 ^ y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let y19 = y10 ^ y8;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let t7 = y13 & y16;
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    let z0 = t44 & y15;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    let z16 = t45 & y14;
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    let s2 = tc26 ^ z17;
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
}
