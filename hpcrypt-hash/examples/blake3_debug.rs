use hpcrypt_hash::blake3::Blake3;

fn main() {
    println!("Testing BLAKE3 with empty input...");
    let mut hasher = Blake3::new();
    hasher.update(b"");
    let hash = hasher.finalize();
    
    println!("Got:      {:02x}{:02x}{:02x}{:02x}...", hash[0], hash[1], hash[2], hash[3]);
    println!("Expected: af1349b9...");
    
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!("\nFull hash: {}", hex);
    println!("Expected:  af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}
