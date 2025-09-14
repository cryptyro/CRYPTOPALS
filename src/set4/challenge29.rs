use super::sha1::{sha1, mac};
pub const STATE: [u32;5] = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0];

pub fn md_padding(message_len: usize) -> Vec<u8> {
    let mut padding = Vec::new();
    // Append a single '1' bit (0x80 in hex)
    padding.push(0x80);
    // Append '0' bits until the length is congruent to 448 mod 512
    while (message_len + padding.len()) % 64 != 56 {
        padding.push(0x00);
    }
    // Append the original length in bits, as a 64-bit big-endian integer
    let bit_len = (message_len as u64) * 8;
    padding.extend_from_slice(&bit_len.to_be_bytes());
    padding
}

pub fn break_sha1() {
    let key = b"secretkey"; // The secret key (unknown to the attacker)
    let original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let new_message = b";admin=true";

    // Attacker knows the MAC of the original message (simulating the attacker's perspective)
    let mut mac = mac(key, original_message, &STATE);

    // Convert the MAC result to initial SHA-1 state
    let mut state = [0u32; 5];
    for i in 0..5 {
        state[i] = u32::from_be_bytes([mac[4*i], mac[4*i+1], mac[4*i+2], mac[4*i+3]]);
    }

    // Calculate the glue padding
    let glue_padding = md_padding(key.len() + original_message.len());

    // Calculate the new MAC with the forged message
    let mut forged_message = Vec::new();
    forged_message.extend_from_slice(original_message);
    forged_message.extend_from_slice(&glue_padding);
    forged_message.extend_from_slice(new_message);

    // Print the results
    println!("Original message: {:?}", original_message);
    println!("Glue padding: {:?}", glue_padding);
    println!("New message: {:?}", new_message);
    println!("Forged message: {:?}", forged_message);
    println!("Original MAC: {:x?}", mac_result);
    println!("New MAC: {:x?}", new_mac);
}