use std::fs::{self, File};
use std::io::Write;
use crate::set1::challenge1::decode_base64;
use crate::aes::moops::ecb_decipher;

pub fn test7() {
    let mut contents = fs::read_to_string("./data/ecb_decrypt.txt")
                        .expect("Should have been able to read the file");
    // Remove newline characters
    contents = contents.replace('\n', "").replace('\r', "");
    let mut ciphertext = decode_base64(&contents);
    let key = "YELLOW SUBMARINE".as_bytes();
    ecb_decipher(&mut ciphertext, key);

    // Convert u8 vector to a string
    let data_str = String::from_utf8(ciphertext).expect("Invalid UTF-8 data");

    let mut file = File::create("ecb_decrypt_output.txt")
                        .expect("Unable to create output file");
    file.write_all(data_str.as_bytes())
    .expect("unable to write to the file");
    println!("Content has been written to the file ecb_decrypt_output.txt");
}