use rand::rngs::OsRng;
use rand::Rng;
use lazy_static::lazy_static;
use crate::AES::moops::{cbc_decipher, cbc_encipher, ecb_decipher};
use crate::set2::challenge15::pkcs7_unpad;
use crate::set1::challenge1::decode_base64;

// Random AES key used for all encryptions
lazy_static::lazy_static! {
    static ref AES_KEY: [u8; 16] = {
        let mut key = [0u8; 16];
        OsRng.fill(&mut key);
        key
    };
}

// Function to generate a random IV
fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill(&mut iv);
    iv
}

// Randomly selects a plaintext, encrypts it with AES-CBC, and returns the ciphertext and IV
fn encrypt_random_string() -> (Vec<u8>, [u8; 16]) {
    let plaintexts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..plaintexts.len());

    let plaintext = decode_base64(plaintexts[index]);
    let iv = generate_iv();
    let ciphertext = cbc_encipher(&plaintext, &*AES_KEY, &iv);

    (ciphertext, iv)
}

// Function to decrypt the ciphertext, validate padding, and return the result
fn decrypt_and_validate(ciphertext: &[u8], iv: &[u8; 16]) -> bool {
    let plaintext = cbc_decipher(&ciphertext, &*AES_KEY, iv);

    match pkcs7_unpad(&plaintext, 16) {
        Ok(_) => true,   // Padding is valid
        Err(_) => false, // Padding is invalid
    }
}

fn break_single_block(ciphertext: &[u8], iv: &[u8]) -> [u8; 16] {
    let mut test_iv = [0u8; 16];
    let mut plaintext = [0u8; 16];
    for i in (0..16).rev() {
        for byte in 0..=255 {
            test_iv[i] = byte;
            if decrypt_and_validate(&ciphertext, &test_iv) {
                break;
            }
        }
        plaintext[i] = test_iv[i] ^ (16-i as u8) ^ iv[i];

        for j in i..16 {
            test_iv[j] ^= (16-i as u8) ^ (17-i as u8);
        }
    }
    plaintext    
}

pub fn test17() {
    let (ciphertext, iv) = encrypt_random_string();
    let mut plaintext = Vec::new();
    let mut blocks = ciphertext.chunks(16).collect::<Vec<_>>();
    blocks.insert(0, &iv);
    for i in 1..blocks.len() {
        let block = break_single_block(blocks[i], blocks[i-1]);
        plaintext.extend_from_slice(&block);
    }
    println!("Decrypted plaintext: {:?}", String::from_utf8_lossy(&plaintext));
}
