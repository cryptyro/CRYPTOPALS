//PKCS#7 unpadding
pub fn pkcs7_unpad(input: &[u8], block_size: usize) -> Result<Vec<u8>, &'static str>{
    if input.is_empty() {
        return Err("Input cannot be empty");
    }

    // Retrieve the value of the last byte
    let padding_length = *input.last().unwrap();

    // The value must be between 1 and the block size
    if padding_length as usize == 0 || padding_length as usize > block_size {
        return Err("Invalid padding length");
    }

    // Check that the last `padding_length` bytes all have the same value
    let padding_bytes = &input[input.len() - padding_length as usize..];
    if padding_bytes.iter().all(|&byte| byte == padding_length) {
        // Return the unpadded plaintext
        Ok(input[..input.len() - padding_length as usize].to_vec())
    } else {
        Err("Invalid PKCS#7 padding")
    }
}

pub fn test15() {
    // Example usage:
    let padded_message = b"ICE ICE BABY\x04\x04\x04\x04";
    let unpadded = pkcs7_unpad(padded_message, 16);
    match unpadded {
        Ok(plaintext) => println!("Valid padding. Unpadded plaintext: {:?}", String::from_utf8(plaintext).unwrap()),
        Err(err) => println!("Invalid padding: {}", err),
    }
}