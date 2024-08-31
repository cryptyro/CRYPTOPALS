use std::fs::File;
use std::io::{self, BufRead};
use std::collections::HashSet;

pub fn string_to_chunks(s: &[u8]) -> Vec<[u8; 16]> {
    let mut chunks = Vec::new();

    let mut start = 0;
    // Iterate over the bytes in steps of 16
    while start < s.len() {
        let end = start + 16;
        let mut block = [0;16];
        for i in 0..(end-start) {
            block[i] = s[start + i];
        }
        chunks.push(block);
        start = end;
    }
    chunks
}

pub fn has_duplicate_chunks(chunks: &Vec<[u8; 16]>) -> bool {
    let mut seen_chunks = HashSet::new();
    for chunk in chunks {
        if !seen_chunks.insert(chunk) {
            return true;  // Found a duplicate
        }
    }
    false
}

pub fn test8() {
    let filename = "./data/ecb_detect.txt";
    let file = File::open(filename).expect("Error Opening the file"); // Open the file
    let reader = io::BufReader::new(file);
    let mut count = 0;
    for line in reader.lines() {
        if let Ok(line) = line {
            let chunks = string_to_chunks(&line.as_bytes());
            count += 1;
            if has_duplicate_chunks(&chunks) {
                println!("This ciphertext at line {} has been encrypted in ECB mode",count);
            }
        }
    }
}
