use crate::AES::utility::{cipher, key_expansion};
use crate::set1::challenge1::base64_to_hex;

pub fn ctr (input: &mut [u8], key: &[u8], iv: &mut [u8]) {
    let mut bytes_read = 0;
    let mut block = [0;16];
    
    let exp_key = key_expansion(key);
    while bytes_read < input.len() {
        for i in 0..16 {
            block[i] = iv[i];
        }
        cipher(&mut block, &exp_key);
        let mut len = input.len() - bytes_read;
        if len >= 16 {
            len = 16;
        }
        for i in 0..len {
            input[bytes_read + i] = block[i];
        }
         // Increament least sinificant 64 bits
        for i in 0..8 {
            iv[i] += 1;
            if iv[i] != 0 {
                break;
            }
        }
        bytes_read += 16;
    }
}

pub fn test18() {
    let key = b"YELLOW SUBMARINE";
    let mut iv = [0;16];
    iv[0] = 1;
    let mut input = vec![1,2,3,4];
    ctr(&mut input, key, &mut iv);
    println!("Encrypted text is :{:?}",input);
}