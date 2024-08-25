extern crate lazy_static;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use super::challenge1::hex_to_bytes;

pub fn letter_count(plaintext: String) -> HashMap<char, f32> {
    // Create a HashMap to count letter occurrences
    let mut letter_count: HashMap<char, f32> = HashMap::new();

    // Iterate through each character in the text
    for c in plaintext.chars() {
        // Update the count for the current character
        let count = letter_count.entry(c).or_insert(0.0);
        *count += 1.0;
    }

    //Get relative count
    let factor = 100.0/plaintext.len() as f32;
    // Iterate over the original HashMap and modify the count
    for (_, value) in &mut letter_count {
        *value = (*value) * factor;
    }
    return letter_count;
}

// Declare a static variable to hold the result from the book read
lazy_static! {
    pub static ref alphabet_count: HashMap<char, f32> = letter_count(fs::read_to_string("./data/sample.txt").unwrap());
}

pub fn xor_break(cipher_hex: &[u8]) -> (u8, String, f32) {
    // Convert hex string to bytes
    let len = cipher_hex.len();

    // Try all possible ASCII characters as keys
    let mut best_score = f32::INFINITY;
    let mut best_plaintext = Vec::new();
    let mut best_key: u8 = 0;
    for key in 0..=255 {
        //Perform XOR operation
        let mut result = vec![0; len];
      
        for i in 0..len {
            result[i] = cipher_hex[i] ^ key as u8;
        }

        let freq_map = letter_count(String::from_utf8_lossy(&result).to_string());
        let mut score = 0.0;

        for (key,value) in &freq_map {
            if let Some(frequency_exp) = alphabet_count.get(&key) {
                score += (frequency_exp - *value).abs();
            } else {
                score += 100.0;//This will make the string disqualified which has even single invalid ascii character
            }
        }

        if score < best_score {
            best_score = score;
            best_plaintext = result.clone();
            best_key = key;
        }
    }
    // Convert best plaintext to string
    let plaintext_str = String::from_utf8_lossy(&best_plaintext).to_string();
    let predicted = (best_key, plaintext_str, best_score);
    return predicted;
}

pub fn test3() {
    let cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let cipher_hex = hex_to_bytes(cipher);
    let result = xor_break(&cipher_hex);
    println!("Key: {} \nPlaintext: {}", result.0, result.1);
}