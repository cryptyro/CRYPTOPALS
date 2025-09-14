use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use rand::Rng;
use crate::AES::moops::{cbc_encipher, cbc_decipher};
use crate::set2::challenge9::pkcs7_pad;
use crate::set2::challenge15::pkcs7_unpad;
use crate::set4::challenge28::SHA1;
use crate::set5::challenge33::{P, diffie_hellman};
use crate::DH::server::decrypt;
use num_bigint::BigUint;
use num_traits::Zero;

pub fn sha1_key(shared_secret: &BigUint) -> [u8; 16] {
    let result = SHA1(&shared_secret.to_bytes_be());
    let mut key = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    key
}


fn handle_client(mut server_stream: TcpStream, mut client_stream: TcpStream) {    
    // Step 1: Intercept Server's DH public key
    let mut server_public = vec![0u8; 1024];
    let bytes_read = server_stream.read(&mut server_public).unwrap();
    server_public.truncate(bytes_read);

    // Step 2: Send attacker's public key to client
    client_stream.write(&P.to_bytes_be()).unwrap();

    // Step 3: Receive Client's DH public key
    let mut client_public = vec![0u8; 1024];
    let bytes_read = client_stream.read(&mut client_public).unwrap();
    client_public.truncate(bytes_read);

    // Step 4: Send attacker's public key to server
    server_stream.write(&P.to_bytes_be()).unwrap();

    // Step 5: Compute shared secrets
    // AES key for A{sha1(p^a mod p = 0)} and B{sha1(p^b mod p = 0)}
    let shared_key = sha1_key(&BigUint::zero());

    // From here, the attacker has two shared secrets: one with the client, one with the server.
    // The attacker can now intercept, decrypt, and re-encrypt communication.

    let mut buffer = [0u8; 1024];
    loop {
        // Relay data from client to server
        let bytes_read = client_stream.read(&mut buffer).expect("Failed to read from client");
        if bytes_read == 0 { break; }
        let response = &buffer[..bytes_read];
        decrypt(&response, &shared_key);
        println!("key is: {:?}", shared_key);

        server_stream.write_all(&response).expect("Failed to write to server");

        // Relay data from server to client
        let bytes_read = server_stream.read(&mut buffer).expect("Failed to read from client");
        if bytes_read == 0 { break; }
        let response = &buffer[..bytes_read];
        decrypt(&response, &shared_key);
        client_stream.write_all(&buffer).expect("Failed to write to client");
    }
}

pub fn test34() {
    // assuming the real server is at port 8080
    let server_stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to server");

    let listener = TcpListener::bind("127.0.0.1:9090").expect("Failed to bind to address");

    for client_stream in listener.incoming() {
        match client_stream {
            Ok(stream) => {
                println!("New client connected!");

                let server = server_stream.try_clone().expect("Failed to clone server stream");
                handle_client(server, stream);  
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}
