use super::utility::{cipher, inv_cipher, key_expansion};
use crate::set2::challenge9::pkcs7_pad;

pub fn ecb_encipher (input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bytes_read = 0;
    let mut block = [0;16];
    let mut padded_text = pkcs7_pad(input, 16);
    let exp_key = key_expansion(key);
    while bytes_read < input.len() {
        for i in 0..16 {
            block[i] = padded_text[bytes_read + i];
        }
        cipher(&mut block, &exp_key);
        for i in 0..16 {
            padded_text[bytes_read + i] = block[i];
        }
        bytes_read += 16;
    }
    return padded_text;
}

pub fn cbc_encipher (input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut bytes_read = 0;
    let mut block = [0;16];
    //Copy IV into first block
    for i in 0..16 {
        block[i] = iv[i];
    }
    let mut padded_text = pkcs7_pad(input, 16);
    let exp_key = key_expansion(key);
    while bytes_read < input.len() {
        for i in 0..16 {
            block[i] ^= padded_text[bytes_read + i];
        }
        cipher(&mut block, &exp_key);
        for i in 0..16 {
            padded_text[bytes_read + i] = block[i];
        }
        bytes_read += 16;
    }
    return padded_text;
}

pub fn ecb_decipher (input: &mut [u8], key: &[u8]){
    let mut bytes_read = 0;
    let mut block = [0;16];
    let exp_key = key_expansion(key);
    while bytes_read < input.len() {
        for i in 0..16 {
            block[i] = input[bytes_read + i];
        }
        inv_cipher(&mut block, &exp_key);
        for i in 0..16 {
            input[bytes_read + i] = block[i];
        }
        bytes_read += 16;
    }
}

pub fn cbc_decipher (input: &[u8], key: &[u8], iv: &[u8])-> Vec<u8>{
    let mut bytes_read = 0;
    let mut block = [0u8;16];
    let mut temp_block = [0u8;16];
    let mut prev_block= [0u8;16];
    //Copy IV into first prev_block
    for i in 0..16 {
        prev_block[i] = iv[i];
    }
    let exp_key = key_expansion(key);
    let mut output = vec![0u8; input.len()];
    while bytes_read < input.len() {
        for i in 0..16 {
            block[i] = input[bytes_read + i];
            temp_block[i] = input[bytes_read + i];
        }
        inv_cipher(&mut block, &exp_key);
        for i in 0..16 {
            output[bytes_read + i] = block[i] ^ prev_block[i];
            prev_block[i] = temp_block[i];
        }
        bytes_read += 16;
    }
    return output
}