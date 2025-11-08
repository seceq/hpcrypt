// Debug test for step-by-step point doubling verification
#[cfg(test)]
mod doubling_debug_tests {
    extern crate std;
    use std::println;

    use crate::secp256k1::point::Point;
    use crate::secp256k1::point_montgomery::MontgomeryPoint;
    use crate::secp256k1::field_ops::FieldElement;

    #[test]
    #[ignore] // Run manually with: cargo test --package hpcrypt-curves test_doubling_step_by_step -- --ignored --nocapture
    fn test_doubling_step_by_step() {
        println!("\n=== Step-by-Step Point Doubling Verification ===\n");

        // Get generator points
        let g_std = Point::generator();
        let g_mont = MontgomeryPoint::generator();

        println!("Generator point (standard form):");
        println!("  X = {:?}", g_std.x.to_bytes());
        println!("  Y = {:?}", g_std.y.to_bytes());
        println!("  Z = {:?}", g_std.z.to_bytes());
        println!();

        // Manually compute each step for standard Point
        println!("=== Standard Point Doubling Steps ===");

        // Step 1: Y²
        let y_squared_std = g_std.y.square();
        println!("1. Y² = {:?}", y_squared_std.to_bytes());

        // Step 2: Y⁴
        let y_fourth_std = y_squared_std.square();
        println!("2. Y⁴ = {:?}", y_fourth_std.to_bytes());

        // Step 3: X·Y²
        let xy2_std = g_std.x.mul(&y_squared_std);
        println!("3. X·Y² = {:?}", xy2_std.to_bytes());

        // Step 4: S = 4·X·Y²
        let four_std = FieldElement::from_limbs([4, 0, 0, 0]);
        let s_std = xy2_std.mul(&four_std);
        println!("4. S = 4·X·Y² = {:?}", s_std.to_bytes());

        // Step 5: X²
        let x_squared_std = g_std.x.square();
        println!("5. X² = {:?}", x_squared_std.to_bytes());

        // Step 6: M = 3·X²
        let three_std = FieldElement::from_limbs([3, 0, 0, 0]);
        let m_std = x_squared_std.mul(&three_std);
        println!("6. M = 3·X² = {:?}", m_std.to_bytes());

        // Step 7: M²
        let m_squared_std = m_std.square();
        println!("7. M² = {:?}", m_squared_std.to_bytes());

        // Step 8: 2·S
        let two_std = FieldElement::from_limbs([2, 0, 0, 0]);
        let two_s_std = s_std.mul(&two_std);
        println!("8. 2·S = {:?}", two_s_std.to_bytes());

        // Step 9: X₃ = M² - 2·S
        let x3_std = m_squared_std.sub(&two_s_std);
        println!("9. X₃ = M² - 2·S = {:?}", x3_std.to_bytes());

        // Step 10: 8·Y⁴
        let eight_std = FieldElement::from_limbs([8, 0, 0, 0]);
        let eight_y4_std = y_fourth_std.mul(&eight_std);
        println!("10. 8·Y⁴ = {:?}", eight_y4_std.to_bytes());

        // Step 11: S - X₃
        let s_minus_x3_std = s_std.sub(&x3_std);
        println!("11. S - X₃ = {:?}", s_minus_x3_std.to_bytes());

        // Step 12: M·(S - X₃)
        let m_times_diff_std = m_std.mul(&s_minus_x3_std);
        println!("12. M·(S - X₃) = {:?}", m_times_diff_std.to_bytes());

        // Step 13: Y₃ = M·(S - X₃) - 8·Y⁴
        let y3_std = m_times_diff_std.sub(&eight_y4_std);
        println!("13. Y₃ = M·(S - X₃) - 8·Y⁴ = {:?}", y3_std.to_bytes());

        // Step 14: Y·Z
        let yz_std = g_std.y.mul(&g_std.z);
        println!("14. Y·Z = {:?}", yz_std.to_bytes());

        // Step 15: Z₃ = 2·Y·Z
        let z3_std = yz_std.mul(&two_std);
        println!("15. Z₃ = 2·Y·Z = {:?}", z3_std.to_bytes());

        println!();
        println!("Standard final result (via double()):");
        let g2_std = g_std.double();
        println!("  X₃ = {:?}", g2_std.x.to_bytes());
        println!("  Y₃ = {:?}", g2_std.y.to_bytes());
        println!("  Z₃ = {:?}", g2_std.z.to_bytes());

        println!();
        println!("=== Montgomery Point Doubling Steps (converted to standard) ===");

        // Montgomery computations - convert each to standard for comparison
        let y_squared_mont = g_mont.y.square();
        let y_squared_mont_std = y_squared_mont.from_montgomery();
        let y_squared_mont_fe = FieldElement::from_limbs(y_squared_mont_std);
        println!("1. Y² = {:?}", y_squared_mont_fe.to_bytes());
        let match1 = y_squared_mont_fe.to_bytes() == y_squared_std.to_bytes();
        println!("   Matches standard: {}", match1);

        let y_fourth_mont = y_squared_mont.square();
        let y_fourth_mont_std = y_fourth_mont.from_montgomery();
        let y_fourth_mont_fe = FieldElement::from_limbs(y_fourth_mont_std);
        println!("2. Y⁴ = {:?}", y_fourth_mont_fe.to_bytes());
        let match2 = y_fourth_mont_fe.to_bytes() == y_fourth_std.to_bytes();
        println!("   Matches standard: {}", match2);

        let xy2_mont = g_mont.x.mul(&y_squared_mont);
        let xy2_mont_std = xy2_mont.from_montgomery();
        let xy2_mont_fe = FieldElement::from_limbs(xy2_mont_std);
        println!("3. X·Y² = {:?}", xy2_mont_fe.to_bytes());
        let match3 = xy2_mont_fe.to_bytes() == xy2_std.to_bytes();
        println!("   Matches standard: {}", match3);

        let two_xy2_mont = xy2_mont.add(&xy2_mont);
        let s_mont = two_xy2_mont.add(&two_xy2_mont);
        let s_mont_std = s_mont.from_montgomery();
        let s_mont_fe = FieldElement::from_limbs(s_mont_std);
        println!("4. S = 4·X·Y² = {:?}", s_mont_fe.to_bytes());
        let match4 = s_mont_fe.to_bytes() == s_std.to_bytes();
        println!("   Matches standard: {} *** CRITICAL STEP", match4);

        let x_squared_mont = g_mont.x.square();
        let x_squared_mont_std = x_squared_mont.from_montgomery();
        let x_squared_mont_fe = FieldElement::from_limbs(x_squared_mont_std);
        println!("5. X² = {:?}", x_squared_mont_fe.to_bytes());
        let match5 = x_squared_mont_fe.to_bytes() == x_squared_std.to_bytes();
        println!("   Matches standard: {}", match5);

        let m_mont = x_squared_mont.mul3();
        let m_mont_std = m_mont.from_montgomery();
        let m_mont_fe = FieldElement::from_limbs(m_mont_std);
        println!("6. M = 3·X² = {:?}", m_mont_fe.to_bytes());
        let match6 = m_mont_fe.to_bytes() == m_std.to_bytes();
        println!("   Matches standard: {} *** CRITICAL STEP", match6);

        let m_squared_mont = m_mont.square();
        let m_squared_mont_std = m_squared_mont.from_montgomery();
        let m_squared_mont_fe = FieldElement::from_limbs(m_squared_mont_std);
        println!("7. M² = {:?}", m_squared_mont_fe.to_bytes());
        let match7 = m_squared_mont_fe.to_bytes() == m_squared_std.to_bytes();
        println!("   Matches standard: {}", match7);

        let two_s_mont = s_mont.add(&s_mont);
        let two_s_mont_std = two_s_mont.from_montgomery();
        let two_s_mont_fe = FieldElement::from_limbs(two_s_mont_std);
        println!("8. 2·S = {:?}", two_s_mont_fe.to_bytes());
        let match8 = two_s_mont_fe.to_bytes() == two_s_std.to_bytes();
        println!("   Matches standard: {}", match8);

        let x3_mont = m_squared_mont.sub(&two_s_mont);
        let x3_mont_std = x3_mont.from_montgomery();
        let x3_mont_fe = FieldElement::from_limbs(x3_mont_std);
        println!("9. X₃ = M² - 2·S = {:?}", x3_mont_fe.to_bytes());
        let match9 = x3_mont_fe.to_bytes() == x3_std.to_bytes();
        println!("   Matches standard: {} *** X COORDINATE", match9);

        let two_y4_mont = y_fourth_mont.add(&y_fourth_mont);
        let four_y4_mont = two_y4_mont.add(&two_y4_mont);
        let eight_y4_mont = four_y4_mont.add(&four_y4_mont);
        let eight_y4_mont_std = eight_y4_mont.from_montgomery();
        let eight_y4_mont_fe = FieldElement::from_limbs(eight_y4_mont_std);
        println!("10. 8·Y⁴ = {:?}", eight_y4_mont_fe.to_bytes());
        let match10 = eight_y4_mont_fe.to_bytes() == eight_y4_std.to_bytes();
        println!("   Matches standard: {} *** CRITICAL STEP", match10);

        let s_minus_x3_mont = s_mont.sub(&x3_mont);
        let s_minus_x3_mont_std = s_minus_x3_mont.from_montgomery();
        let s_minus_x3_mont_fe = FieldElement::from_limbs(s_minus_x3_mont_std);
        println!("11. S - X₃ = {:?}", s_minus_x3_mont_fe.to_bytes());
        let match11 = s_minus_x3_mont_fe.to_bytes() == s_minus_x3_std.to_bytes();
        println!("   Matches standard: {}", match11);

        let m_times_diff_mont = m_mont.mul(&s_minus_x3_mont);
        let m_times_diff_mont_std = m_times_diff_mont.from_montgomery();
        let m_times_diff_mont_fe = FieldElement::from_limbs(m_times_diff_mont_std);
        println!("12. M·(S - X₃) = {:?}", m_times_diff_mont_fe.to_bytes());
        let match12 = m_times_diff_mont_fe.to_bytes() == m_times_diff_std.to_bytes();
        println!("   Matches standard: {}", match12);

        let y3_mont = m_times_diff_mont.sub(&eight_y4_mont);
        let y3_mont_std = y3_mont.from_montgomery();
        let y3_mont_fe = FieldElement::from_limbs(y3_mont_std);
        println!("13. Y₃ = M·(S - X₃) - 8·Y⁴ = {:?}", y3_mont_fe.to_bytes());
        let match13 = y3_mont_fe.to_bytes() == y3_std.to_bytes();
        println!("   Matches standard: {} *** Y COORDINATE", match13);

        let yz_mont = g_mont.y.mul(&g_mont.z);
        let yz_mont_std = yz_mont.from_montgomery();
        let yz_mont_fe = FieldElement::from_limbs(yz_mont_std);
        println!("14. Y·Z = {:?}", yz_mont_fe.to_bytes());
        let match14 = yz_mont_fe.to_bytes() == yz_std.to_bytes();
        println!("   Matches standard: {}", match14);

        let z3_mont = yz_mont.add(&yz_mont);
        let z3_mont_std = z3_mont.from_montgomery();
        let z3_mont_fe = FieldElement::from_limbs(z3_mont_std);
        println!("15. Z₃ = 2·Y·Z = {:?}", z3_mont_fe.to_bytes());
        let match15 = z3_mont_fe.to_bytes() == z3_std.to_bytes();
        println!("   Matches standard: {} *** Z COORDINATE", match15);

        println!();
        println!("Montgomery final result (via double()):");
        let g2_mont = g_mont.double();
        let g2_mont_std = g2_mont.to_affine().expect("Should not be infinity").to_standard();
        println!("  X₃ = {:?}", g2_mont_std.x.to_bytes());
        println!("  Y₃ = {:?}", g2_mont_std.y.to_bytes());

        println!();
        println!("=== Summary ===");
        let all_match = match1 && match2 && match3 && match4 && match5 && match6 &&
                        match7 && match8 && match9 && match10 && match11 && match12 &&
                        match13 && match14 && match15;

        if all_match {
            println!("✅ All intermediate steps match!");
            println!("✅ Montgomery arithmetic is correct!");
        } else {
            println!("❌ Mismatch detected in intermediate steps:");
            if !match1 { println!("  - Step 1: Y²"); }
            if !match2 { println!("  - Step 2: Y⁴"); }
            if !match3 { println!("  - Step 3: X·Y²"); }
            if !match4 { println!("  - Step 4: S = 4·X·Y² *** THIS IS LIKELY THE BUG"); }
            if !match5 { println!("  - Step 5: X²"); }
            if !match6 { println!("  - Step 6: M = 3·X² *** THIS IS LIKELY THE BUG"); }
            if !match7 { println!("  - Step 7: M²"); }
            if !match8 { println!("  - Step 8: 2·S"); }
            if !match9 { println!("  - Step 9: X₃ = M² - 2·S *** THIS AFFECTS FINAL X"); }
            if !match10 { println!("  - Step 10: 8·Y⁴ *** THIS IS LIKELY THE BUG"); }
            if !match11 { println!("  - Step 11: S - X₃"); }
            if !match12 { println!("  - Step 12: M·(S - X₃)"); }
            if !match13 { println!("  - Step 13: Y₃ = M·(S - X₃) - 8·Y⁴ *** THIS AFFECTS FINAL Y"); }
            if !match14 { println!("  - Step 14: Y·Z"); }
            if !match15 { println!("  - Step 15: Z₃ = 2·Y·Z *** THIS AFFECTS FINAL Z (but we know Z matches!)"); }
        }
    }
}
