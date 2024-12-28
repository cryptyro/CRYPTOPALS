use crate::AES::moops::{cbc_encipher, ecb_encipher};
use crate::set1::challenge8::{has_duplicate_chunks, string_to_chunks};
use rand::rngs::OsRng;
use rand::Rng;
use std::iter;
pub fn encryption_oracle(input: &[u8]) -> (&str, Vec<u8>) {
    // Generate a random 128-bit AES key
    let mut key = [0u8; 16];
    OsRng.fill(&mut key);
    // Generate random number of bytes (5-10) to prepend and append
    let prepend_len = OsRng.gen_range(5..=10);
    let append_len = OsRng.gen_range(5..=10);
    let prepend_bytes: Vec<u8> = iter::repeat_with(|| OsRng.gen()).take(prepend_len).collect();
    let append_bytes: Vec<u8> = iter::repeat_with(|| OsRng.gen()).take(append_len).collect();
    
    // Concatenate prepend_bytes, input, and append_bytes
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prepend_bytes);
    plaintext.extend_from_slice(input);
    plaintext.extend_from_slice(&append_bytes);
        
    let mode;
    let ciphertext;
    // Randomly choose to encrypt with ECB or CBC
    if OsRng.gen_bool(0.5) {
        // ECB mode
        ciphertext = ecb_encipher(&plaintext, &key);
        mode = "ECB";
    } else {
        // CBC mode with random IV
        let mut iv = [0u8; 16];
        OsRng.fill(&mut iv);
        ciphertext = cbc_encipher(&plaintext, &key, &iv);
        mode = "CBC";
    }
    return (mode,ciphertext);
}

pub fn test11() {
    let chosen_text = [0u8; 2*16 + 11]; //as the prefix has length at least 5
    for _ in 0..10 {
        let oracle_output = encryption_oracle(&chosen_text);
        let chunks = string_to_chunks(&oracle_output.1);
        if has_duplicate_chunks(&chunks) {
            println!("Guessed: ECB | Actually working on:{}", oracle_output.0);
        } else {
            println!("Guessed: CBC | Actually working on:{}", oracle_output.0);

        }
    }
}