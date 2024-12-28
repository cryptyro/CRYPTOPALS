//PKCS#7 padding
pub fn pkcs7_pad(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut padding_value = (block_size - (message.len() % block_size)) as u8;
    if padding_value == 0 {     //Edge case
        padding_value = block_size as u8;
    }
    let mut output = message.to_vec();
    for _ in 0..padding_value {
        output.push(padding_value);
    }
    return output;
}

pub fn test9() {
    let text = String::from("YELLOW SUBMARINE");
    let data = text.as_bytes();
    let block_size = 20;
    println!("Padded data: {:?}", pkcs7_pad(data, block_size));
}