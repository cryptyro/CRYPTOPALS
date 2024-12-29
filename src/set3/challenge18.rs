use crate::AES::utility::{cipher, key_expansion};

pub fn cbc_encipher (input: &mut [u8], key: &[u8], iv: &[u8]) {
    let mut bytes_read = 0;
    let mut block = [0;16];
    //Copy IV into first block
    for i in 0..16 {
        block[i] = iv[i];
    }
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