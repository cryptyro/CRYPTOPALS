use super::challenge1::hex_to_bytes;

pub fn xor_hex_strings(hex_str1: &str, hex_str2: &str) -> String {
    // Convert hexadecimal strings to bytes
    let bytes1 = hex_to_bytes(hex_str1);
    let bytes2 = hex_to_bytes(hex_str2);

    // Determine the lengths of the byte arrays
    let len1 = bytes1.len();
    let len2 = bytes2.len();

    // Calculate the minimum length for iteration
    let min_len = std::cmp::min(len1, len2);

    // Perform XOR operation
    let mut result = Vec::with_capacity(min_len);
    for i in 0..min_len {
        result.push(bytes1[i] ^ bytes2[i]);
    }

    // Append remaining bytes from the longer array, if any
    if len1 > len2 {
        result.extend_from_slice(&bytes1[min_len..]);
    } else if len2 > len1 {
        result.extend_from_slice(&bytes2[min_len..]);
    }

    // Convert result bytes back to hexadecimal string
    let hex_result: String = result.iter().map(|b| format!("{:02X}", b)).collect();
    return hex_result;
}

pub fn test2() {
    // Example hexadecimal strings
    let hex_str1 = "1c0111001f010100061a024b53535009181c";
    let hex_str2 = "686974207468652062756c6c277320657965";

    // Calculate XOR of hex strings
    let result = xor_hex_strings(hex_str1, hex_str2);
    println!("XOR result: {}", result);
}