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
    let prepended_string = b"Hello, I am a random string";
    let appended_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let decoded_appended_string = decode_base64(appended_string);
    let mut modified_plaintext = Vec::new();
    modified_plaintext.extend_from_slice(prepended_string);
    modified_plaintext.extend_from_slice(plaintext);
    modified_plaintext.extend_from_slice(&decoded_appended_string);

    ecb_encipher(&modified_plaintext, &*GLOBAL_KEY)
}

fn compare_blocks(array1: &[u8], array2: &[u8]) -> Option<usize> {
    if array1.len() != array2.len() {
        panic!("Arrays must have the same length.");
    }
    if array1.len() % 16 != 0 {
        panic!("Array length must be a multiple of 16.");
    }

    let chunk_size = 16;
    for (i, (chunk1, chunk2)) in array1.chunks(chunk_size).zip(array2.chunks(chunk_size)).enumerate() {
        if chunk1 != chunk2 {
            return Some(i); // Return the index of the first differing block
        }
    }
    None
}


// Function to detect length of the prepended text
fn detect_prepend_size() -> usize {
    let mut input1 = vec![0];
    let cmp1 = oracle(&input1);
    let mut input2 = vec![1];
    let cmp2 = oracle(&input2);
    let mut len = compare_blocks(&cmp1, &cmp2).unwrap();

    for i in 1..=16 {
        input1.push(0);
        input2.insert(0, 0);
        let cmp1 = oracle(&input1);
        let cmp2 = oracle(&input2);
        if len != compare_blocks(&cmp1, &cmp2).unwrap() {
            return len*16 + 16 - i;
        }
    }
    panic!("Block size detection failed");
}

// Function to detect length of the appended text
fn detect_append_size() -> usize {
    let mut input = Vec::new();
    let initial_length = oracle(&input).len();

    for i in 1..=16 {
        input.push(0); // Append 0
        let new_length = oracle(&input).len();
        if new_length != initial_length {
            return initial_length-i-detect_prepend_size();
        }
    }
    panic!("Block size detection failed");
}

pub fn test14() {
    let unknown_string_len = detect_append_size();
    let len = detect_prepend_size();
    println!("Length of the prepended text: {}, {}", len, unknown_string_len);
    let mut known_bytes = Vec::new();

    for k in 0..((unknown_string_len)/16 + 1) {
        for j in 1..=16 {
            let mut input = vec![0u8; 21 - j];
            let oracle_output = oracle(&input);
            input.extend(&known_bytes);
            for i in 0..=255 {
                input.push(i);
                let output = oracle(&input);
                let start = 32+ k * 16;
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
