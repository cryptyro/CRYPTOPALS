use super::challenge1::{hex_to_ascii, decode_base64};
use super::challenge3::xor_break;
use super::challenge5::repeating_key_xor;
use std::fs;

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let len = a.len();
    let mut count = 0;
    for i in 0..len {
        count += (a[i] ^ b[i]).count_ones();
    }
    return count;
}

pub fn guess_key_length(ciphertext: &[u8]) -> usize {
    let mut best_dist = ciphertext.len() as f32;
    let mut best_key_len = 0;

    for key_len in 2..40 {
        let chunks: Vec<&[u8]> = ciphertext.chunks(key_len).take(4).collect();

        let mut distance = 0;
        let mut count = 0;

        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                distance += hamming_distance(chunks[i], chunks[j]);
                count += 1;
            }
        }

        let norm_dist = distance as f32 / (key_len as f32 * count as f32);
        if norm_dist < best_dist {
            best_dist = norm_dist;
            best_key_len = key_len;
        }
    }

    best_key_len
}

pub fn full_key_recovery(ciphertext: &[u8]) -> Vec<u8> {
    let key_size = guess_key_length(ciphertext);
    let mut blocks: Vec<Vec<u8>> = vec![vec![]; key_size];
    for (i, &byte) in ciphertext.iter().enumerate() {
        blocks[i % key_size].push(byte);
    }
    let mut full_key = vec![];
    for i in 0..key_size {
        full_key.push(xor_break(&blocks[i]).0);
    }
    return full_key;
}

pub fn test6() {
    let mut contents = fs::read_to_string("./data/break_repeating-key_XOR.txt")
                        .expect("Should have been able to read the file");
    // Remove newline characters
    contents = contents.replace('\n', "").replace('\r', "");
    let text = decode_base64(&contents);
    let key = full_key_recovery(&text);
    let decode = repeating_key_xor(std::str::from_utf8(&text).unwrap(), std::str::from_utf8(&key).unwrap());
    println!("Key: {:?}", String::from_utf8(key).unwrap());
    println!("Plaintext: {:?}", hex_to_ascii(&decode));
}