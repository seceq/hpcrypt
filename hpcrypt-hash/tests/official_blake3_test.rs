#[test]
fn test_official_blake3() {
    let hash = blake3::hash(b"");
    println!("Official empty: {}", hash.to_hex());
    
    let hash2 = blake3::hash(b"hello world");
    println!("Official hello world: {}", hash2.to_hex());
}
