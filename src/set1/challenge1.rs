//Convert a single hex character to its numeric value
fn hex_char_to_value(c: char) -> u8 {
    match c {
        '0'..='9' => c as u8 - '0' as u8,
        'a'..='f' => c as u8 - 'a' as u8 + 10,
        'A'..='F' => c as u8 - 'A' as u8 + 10,
        _ => panic!("Invalid hex character"),
    }
}
// Convert the entire hex string to a byte vector by combining pairs of hex characters
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars();

    while let Some(high) = chars.next() {
        if let Some(low) = chars.next() {
            bytes.push((hex_char_to_value(high) << 4) | hex_char_to_value(low));
        } else {
            panic!("Hex string has an odd number of characters");
        }
    }
    bytes
}
//Encode the byte vector to a base64 string by using a buffer to accumulate bits and map them to base64 characters.
fn encode_base64(input: &[u8]) -> String {
    const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    let mut buffer = 0u32;
    let mut bits_in_buffer = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits_in_buffer += 8;

        while bits_in_buffer >= 6 {
            let index = ((buffer >> (bits_in_buffer - 6)) & 0x3F) as usize;
            output.push(BASE64_TABLE[index] as char);
            bits_in_buffer -= 6;
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (6 - bits_in_buffer)) & 0x3F) as usize;
        output.push(BASE64_TABLE[index] as char);
    }
    //Padding is added if necessary to ensure the base64 string length is a multiple of 4
    while output.len() % 4 != 0 {
        output.push('=');
    }

    output
}

//Converts a single Base64 character to its numeric value. The padding character (=) is ignored
fn base64_char_to_value(c: char) -> u8 {
    match c {
        'A'..='Z' => c as u8 - 'A' as u8,
        'a'..='z' => c as u8 - 'a' as u8 + 26,
        '0'..='9' => c as u8 - '0' as u8 + 52,
        '+' => 62,
        '/' => 63,
        '=' => 0, // Padding character, doesn't add to value
        _ => panic!("Invalid Base64 character"),
    }
}
// Converts the Base64 string back to a byte vector by accumulating bits into a buffer and extracting bytes when there are enough bits
pub fn decode_base64(input: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits_in_buffer = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }

        buffer = (buffer << 6) | base64_char_to_value(c) as u32;
        bits_in_buffer += 6;

        if bits_in_buffer >= 8 {
            bytes.push((buffer >> (bits_in_buffer - 8)) as u8);
            bits_in_buffer -= 8;
        }
    }

    bytes
}
// Converts the byte vector into a hex string by formatting each byte as a two-character hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::new();

    for &byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string
}

pub fn base64_to_hex(base64: &str) -> String {
    let bytes = decode_base64(base64);
    bytes_to_hex(&bytes)
}

pub fn hex_to_base64(hex: &str) -> String {
    let bytes = hex_to_bytes(hex);
    encode_base64(&bytes)
}

pub fn hex_to_ascii(hex: &str) -> String {
    let bytes = hex_to_bytes(hex);
    bytes.iter().map(|&b| b as char).collect()
}

pub fn test1() {
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_str = hex_to_base64(hex_str);
    let ascii  = hex_to_ascii(hex_str);
    println!("Base64: {}", base64_str);
    println!("Plaintext: {}", ascii);
}
