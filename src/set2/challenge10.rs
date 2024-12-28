use std::fs::{self, File};
use std::io::Write;
use crate::set1::challenge1::decode_base64;
use crate::AES::moops::cbc_decipher;
pub fn test10() {
    let mut contents = fs::read_to_string("./data/cbc_decrypt.txt")
                        .expect("Should have been able to read the file");
    // Remove newline characters
    contents = contents.replace('\n', "").replace('\r', "");
    let mut ciphertext = decode_base64(&contents);
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0; 16];
    let plaintext = cbc_decipher(&mut ciphertext, &key, &iv);

    // Convert u8 vector to a string
    let data_str = String::from_utf8(plaintext).expect("Invalid UTF-8 data");

    let mut file = File::create("cbc_decrypt_output.txt")
                        .expect("Unable to create output file");
    file.write_all(data_str.as_bytes())
    .expect("unable to write to the file");
    println!("Content has been written to the file cbc_decrypt_output.txt");

}