fn leftrotate(value: u32, bits: u32) -> u32 {
    value.rotate_left(bits)
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded_message = Vec::from(message);
    let message_len_bits = (message.len() as u64) * 8;
    
    // Append the bit '1' to the message
    padded_message.push(0x80);
    
    // Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
    while (padded_message.len() * 8) % 512 != 448 {
        padded_message.push(0x00);
    }
    
    // Append ml, the original message length in bits, as a 64-bit big-endian integer
    padded_message.extend_from_slice(&message_len_bits.to_be_bytes());
    
    padded_message
}

fn sha1(message: &[u8], init_state: &[u32;5]) -> [u8; 20] {
    let padded_message = pad_message(message);
    let mut h0 = init_state[0];
    let mut h1 = init_state[1];
    let mut h2 = init_state[2];
    let mut h3 = init_state[3];
    let mut h4 = init_state[4];

    for chunk in padded_message.chunks(64) {
        let mut w = [0u32; 80];

        // Break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        // Extend the sixteen 32-bit words into eighty 32-bit words
        for i in 16..80 {
            w[i] = leftrotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        // Initialize hash value for this chunk
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        // Main loop
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = leftrotate(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = leftrotate(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    // Produce the final hash value (big-endian) as a 160-bit number
    let mut hh = [0u8; 20];
    hh[0..4].copy_from_slice(&h0.to_be_bytes());
    hh[4..8].copy_from_slice(&h1.to_be_bytes());
    hh[8..12].copy_from_slice(&h2.to_be_bytes());
    hh[12..16].copy_from_slice(&h3.to_be_bytes());
    hh[16..20].copy_from_slice(&h4.to_be_bytes());

    hh
}

pub fn SHA1(message: &[u8]) -> [u8; 20] {
    let init_state: &[u32;5] = &[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    sha1(message, init_state)
}

pub fn mac(key: &[u8], message: &[u8]) -> [u8; 20] {
    // Create a new Sha1 hasher
    let digest = SHA1(&[key,message].concat());
    return digest;
}


pub fn test28() {
    let message = b"hello world";
    let digest = SHA1(message);
    println!("SHA1 digest: {:?}", digest);
}
