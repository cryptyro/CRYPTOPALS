use crate::set1::single_byte_xor::xor_break;
use crate::set1::hex_to_64::hex_to_ascii;
use crate::set1::repeating_xor::repeating_key_xor;
use itertools::Itertools;
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
        let distance: u32 = chunks.into_iter().combinations(2)
            .map(|chunk| hamming_distance(chunk[0], chunk[1]))
            .sum();

        let norm_dist = distance as f32 / key_len as f32;
        if norm_dist < best_dist {
            best_dist = norm_dist;
            best_key_len = key_len;
        }
    }
    return best_key_len;
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

pub fn repeating_key_xor_break() {
    let mut contents = fs::read_to_string("sample1.txt")
                        .expect("Should have been able to read the file");
    // Remove newline characters
    contents = contents.replace('\n', "").replace('\r', "");
    let text = base64::decode(contents).expect("decode failed");
    let key = full_key_recovery(&text);
    let decode = repeating_key_xor(std::str::from_utf8(&text).unwrap(), std::str::from_utf8(&key).unwrap());
    println!("Key: {:?}", String::from_utf8(key).unwrap());
    println!("Plaintext: {:?}", hex_to_ascii(&decode).unwrap());
}
/*
fn main(){
    repeating_key_xor_break();
}*/