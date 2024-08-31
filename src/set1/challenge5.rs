pub fn repeating_key_xor(plaintext: &str, key: &str) -> String {
    // Convert plaintext and key to bytes
    let plaintext_bytes = plaintext.as_bytes();
    let key_bytes = key.as_bytes();
    
    // Create a vector to store the encrypted bytes
    let mut encrypted_bytes = Vec::new();
    
    // Apply XOR between plaintext bytes and key bytes (repeating the key)
    for (i, &byte) in plaintext_bytes.iter().enumerate() {
        encrypted_bytes.push(byte ^ key_bytes[i % key_bytes.len()]);
    }
    
    // Convert encrypted bytes to hexadecimal string
    let encrypted_hex: String = encrypted_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    
    encrypted_hex
}

pub fn test5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    
    let encrypted_text = repeating_key_xor(plaintext, key);
    println!("{}", encrypted_text);
}
