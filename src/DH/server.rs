use std::net::{TcpListener, TcpStream};
use std::thread;
use std::io::{Read, Write};
use rand::Rng;
use crate::AES::moops::{cbc_encipher, cbc_decipher};
use crate::set2::challenge9::pkcs7_pad;
use crate::set2::challenge15::pkcs7_unpad;
use crate::set4::challenge28::SHA1;
use crate::set5::challenge33::{P, diffie_hellman};
use num_bigint::BigUint;

fn session_key_generation(mut stream: TcpStream) -> [u8; 16] {
    let (server_secret, server_public) = diffie_hellman();
    stream.write(&server_public.to_bytes_be()).unwrap();

    // Get the client public key
    let mut client_public = vec![0u8; 1024];
    let bytes_read = stream.read(&mut client_public).unwrap();
    client_public.truncate(bytes_read);

    // Convert client public key to BigUint
    let big_num_cp = BigUint::from_bytes_be(&client_public);
    let shared_secret = big_num_cp.modpow(&server_secret, &P);

    println!("Shared Secret: {}", shared_secret);

    // Hash the shared secret using SHA1 and use the first 16 bytes for AES key
    let result = SHA1(&shared_secret.to_bytes_be());
    let mut key = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    key
}

pub fn decrypt(response: &[u8], aes_key: &[u8] ) -> String{
    // Extract IV and ciphertext from the response
    let (ciphertext, iv) = response.split_at(response.len() - 16);

    // Decrypt the message using AES-CBC
    let og_message = cbc_decipher(ciphertext, &aes_key, iv);
    let decrypted_message = pkcs7_unpad(&og_message, 16).unwrap();
    let message = String::from_utf8(decrypted_message).unwrap();
    println!("Decrypted message from client: {}", message);
    return message;
}

fn handle_client(mut stream: TcpStream) {
    // Derive AES key using Diffie-Hellman key exchange
    let aes_key = session_key_generation(stream.try_clone().expect("Failed to clone stream"));
    let mut buffer = vec![0u8; 1024];

    loop {
            let n = stream.read(&mut buffer).expect("Failed to read from client");
            if n == 0 {
                println!("Connection closed by client.");
                break;
            }
            println!("key is : {:?},  {}", aes_key, n);
            let response = &buffer[..n];
            let message = decrypt(response, &aes_key);

            // Pad and encrypt the message
            let iv: [u8; 16] = rand::thread_rng().gen();
            let cipher = cbc_encipher(&message.as_bytes(), &aes_key, &iv);

            // Append the IV to the message
            let mut final_message = Vec::new();
            final_message.extend_from_slice(&cipher);
            final_message.extend_from_slice(&iv);

            // Write the encrypted message to the client
            stream.write_all(&final_message).expect("Failed to write to client");
        }
}

pub fn server() -> std::io::Result<()> {
    // Bind the server to an address and port
    let listener = TcpListener::bind("127.0.0.1:8080")?;

    println!("Server listening on port 8080...");

    // Loop to accept incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connected!");

                // Spawn a new thread to handle the client
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Failed to accept client: {}", e);
            }
        }
    }

    Ok(())
}
