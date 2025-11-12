#[cfg(test)]
mod test {
    use hpcrypt_curves::ed448::{Point, NielsPoint};

    #[test]
    fn debug_add_niels() {
        let base = Point::generator();
        let base2 = base.add(&base);

        let base_niels = NielsPoint::from_extended(&base);

        let result_add = base.add(&base);
        let result_niels = base.add_niels(&base_niels);

        println!("\nComparing base.add(&base) vs base.add_niels(&base_niels):");
        println!("add result:");
        println!("  x[0] = {}", result_add.x.limbs()[0]);
        println!("  y[0] = {}", result_add.y.limbs()[0]);
        println!("  z[0] = {}", result_add.z.limbs()[0]);
        println!("  t[0] = {}", result_add.t.limbs()[0]);

        println!("\nadd_niels result:");
        println!("  x[0] = {}", result_niels.x.limbs()[0]);
        println!("  y[0] = {}", result_niels.y.limbs()[0]);
        println!("  z[0] = {}", result_niels.z.limbs()[0]);
        println!("  t[0] = {}", result_niels.t.limbs()[0]);

        println!("\nEqual? {}", result_add == result_niels);

        assert_eq!(result_add, result_niels);
    }
}
