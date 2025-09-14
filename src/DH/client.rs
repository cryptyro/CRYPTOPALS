use crate::AES::moops::{cbc_encipher, cbc_decipher};
use crate::set2::challenge9::pkcs7_pad;
use crate::set2::challenge15::pkcs7_unpad;
use crate::set4::challenge28::SHA1;
use crate::set5::challenge33::{P,diffie_hellman};
use num_bigint::BigUint;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use rand::Rng;

pub fn session_key_generation(mut stream: TcpStream) -> [u8; 16] {    
    // Get the server secret key
    let mut server_public = vec![0u8; 1024];
    let bytes_read = stream.read(&mut server_public).unwrap();
    server_public.truncate(bytes_read);

    let (client_secret, client_pubic) = diffie_hellman();
    stream.write(&client_pubic.to_bytes_be()).unwrap();
    
    // Placeholder for Diffie-Hellman key exchange
    let big_num_sp = BigUint::from_bytes_be(&server_public);
    let shared_secret = &big_num_sp.modpow(&client_secret, &P);

    println!("Shared Secret: {}", shared_secret);

    let result = SHA1(&shared_secret.to_bytes_be());
    let mut key = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    key

}

pub fn client() {
    let mut stream = TcpStream::connect("127.0.0.1:9090").expect("Failed to connect to server");
    
    // Derive AES key using SHA1
    let aes_key = session_key_generation(stream.try_clone().expect("Failed to clone stream"));


    // Main thread for writing to the server
    loop {
        let session_key = aes_key.clone();

        let mut buffer = String::new();
        print!("Please enter a message: ");
        io::stdout().flush().unwrap();

        // Read input from the user
        io::stdin().read_line(&mut buffer).expect("Failed to read line");

        // If the user enters an empty message, exit the loop (e.g., close connection)
        if buffer.trim().is_empty() {
            println!("Exiting...");
            break;
        }

        // Pad and encrypt the message
        let iv: [u8; 16] = rand::thread_rng().gen();
        let cipher = cbc_encipher(&buffer.as_bytes(), &session_key, &iv);

        // Append the IV to the message
        let mut final_message = Vec::new();
        final_message.extend_from_slice(&cipher);
        final_message.extend_from_slice(&iv);

        // Write the encrypted message to the server
        stream.write_all(&final_message).expect("Failed to write to server");

        let mut buffer = vec![0u8; 1024];
        let n = stream.read(&mut buffer).expect("Failed to read from server");
        if n == 0 {
            println!("Connection closed by server.");
            break;
        }

        let response = &buffer[..n];

        // Extract IV and ciphertext from the response
        let (ciphertext, iv) = response.split_at(response.len() - 16);

        // Decrypt the message using AES-CBC
        let og_message = cbc_decipher(ciphertext, &session_key, iv);
        let decrypted_message = pkcs7_unpad(&og_message, 16);

        match decrypted_message {
            Ok(plaintext) => {
                let message = String::from_utf8(plaintext).unwrap();
                println!("Decrypted response: {}", message);
            }
            Err(err) => println!("Decryption error: {}", err),
        }
    
    }
}
