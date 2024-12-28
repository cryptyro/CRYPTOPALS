use rand::rngs::OsRng;
use rand::Rng;
use lazy_static::lazy_static;
use crate::AES::moops::ecb_encipher;
use crate::set1::challenge1::decode_base64;

lazy_static! {
    static ref GLOBAL_KEY: [u8;16] = generate_random_key();
}

fn generate_random_key() -> [u8;16] {
    let mut key = [0u8; 16];
    OsRng.fill(&mut key);
    return key;
}

fn oracle(plaintext: &[u8]) -> Vec<u8> {
    let appended_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let decoded_appended_string = decode_base64(appended_string);
    let mut modified_plaintext = plaintext.to_vec();
    modified_plaintext.extend_from_slice(&decoded_appended_string);

    ecb_encipher(&modified_plaintext, &*GLOBAL_KEY)
}

// Function to detect block size and length of the unknown text
fn detect_append_size() -> usize {
    let mut input = vec![]; // Start with an empty input
    let initial_length = oracle(&input).len();

    for i in 0..16 {
        input.push(0); // Append 0
        let new_length = oracle(&input).len();
        if new_length != initial_length {
            return initial_length - i - 1;
        }
    }
    panic!("Block size detection failed");
}

pub fn test12() {
    let unknown_string_len = detect_append_size();
    let mut known_bytes = vec![];
    
    for k in 0..((unknown_string_len)/16 + 1) {
        for j in 1..=16 {
            let mut input = vec![0u8; 16 - j];
            let oracle_output = oracle(&input);
            input.extend(&known_bytes);
            for i in 0..=255 {
                input.push(i);
                let output = oracle(&input);
                let start = k * 16;
                let end = start + 16;
                if output[start..end] == oracle_output[start..end] {
                    known_bytes.push(i);
                    break;
                }
                input.pop();
            }
        }
    }
    let hidden_text = std::str::from_utf8(&known_bytes)
                    .expect("invalid utf character");
    println!("{}",hidden_text);
}
