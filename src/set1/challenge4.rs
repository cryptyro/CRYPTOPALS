use std::fs::File;
use std::env;
use std::path::PathBuf;
use std::io::{self, BufRead};
use super::challenge1::hex_to_bytes;
use super::challenge3::xor_break;

pub fn test4() {
    let current_dir = env::current_dir().unwrap();
    let mut filename = PathBuf::from(current_dir);
    filename.push("data/detect_single_XOR.txt");
    let file = File::open(filename).expect("Error Opening the file"); // Open the file
    let reader = io::BufReader::new(file);

    let mut best_score = f32::INFINITY;
    let mut best_text: (u8, String, f32) = (0, String::from("None found"), 0.0);
    for line in reader.lines() {
        if let Ok(ref line) = line {
            let result = xor_break(&(&hex_to_bytes(line)));
            if result.2 < best_score {
                best_score = result.2;
                best_text = result;
            }
        }
    }
    println!("Waldo: {}", best_text.1 )
}