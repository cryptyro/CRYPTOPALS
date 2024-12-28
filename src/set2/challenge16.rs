use rand::rngs::OsRng;
use rand::Rng;
use lazy_static::lazy_static;
use crate::AES::moops::{cbc_encipher, cbc_decipher};
use crate::set1::challenge1::decode_base64;

lazy_static! {
    static ref GLOBAL_KEY: [u8;16] = generate_random_key();
}

fn generate_random_key() -> [u8;16] {
    let mut key = [0u8; 16];
    OsRng.fill(&mut key);
    return key;
}

fn sanitize_input(input: &[u8]) -> Vec<u8> {
    let mut sanitized = Vec::new();
    for &byte in input {
        match byte {
            b';' => {
                sanitized.push(b'%');
                sanitized.push(b'3');
                sanitized.push(b'B');
            }
            b'=' => {
                sanitized.push(b'%');
                sanitized.push(b'3');
                sanitized.push(b'D');
            }
            _ => sanitized.push(byte),
        }
    }
    sanitized
}

fn oracle(plaintext: &[u8]) -> Vec<u8> {
    let sanitized_plaintext = sanitize_input(plaintext);
    let prepended_string = b"comment1=cooking%20MCs;userdata=";
    let appended_string = b";comment2=%20like%20a%20pound%20of%20bacon";

    let mut modified_plaintext = Vec::new();
    modified_plaintext.extend_from_slice(prepended_string);
    modified_plaintext.extend_from_slice(&sanitized_plaintext);
    modified_plaintext.extend_from_slice(appended_string);

    let iv = [0u8; 16];
    cbc_encipher(&modified_plaintext, &*GLOBAL_KEY, &iv)
}

pub fn test16() {
    let input = b"It is a random input of 32 bytes";
    let mut ciphertext = oracle(input);
    let target = b";admin=true";
    for i in 0..11 {
        ciphertext[32 + 5 + i] ^= input[16 + 5 + i] ^ target[i];
    }
    let iv = [0u8; 16];
    let decrypted = cbc_decipher(&ciphertext, &*GLOBAL_KEY, &iv);
    
    if decrypted.windows(b";admin=true;".len()).any(|window| window == b";admin=true;"){
        println!("Admin privileges granted!");
    } else {
        println!("Admin privileges not granted.");
    }
}