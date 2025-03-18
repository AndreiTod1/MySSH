use crate::crypto::{derive_shared_key, generate_keys, Crypto};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::exit;
use x25519_dalek::PublicKey;

pub fn client() {
    let mut stream = TcpStream::connect("127.0.0.1:2025").expect("Failed to connect.");
    let mut logged = false;

    let (client_secret, client_public) = generate_keys();
    let mut server_public_bytes = [0u8; 32];
    if stream.read_exact(&mut server_public_bytes).is_err() {
        println!("Failed to read server public key");
        exit(1);
    }
    let server_public = PublicKey::from(server_public_bytes);
    if stream.write_all(client_public.as_bytes()).is_err() {
        println!("Failed to send client public key");
        exit(1);
    }
    let shared_key = derive_shared_key(client_secret, &server_public);
    let crypto = Crypto::new(&shared_key);
    println!("Secure key established on client!");

    loop {
        let mut input = String::new();
        if logged {
            print!("Input: ");
        } else {
            println!("Login syntax: 'username:password'");
            println!("Register syntax: 'register username:password'");
        }
        io::stdout().flush().unwrap();

        if io::stdin().read_line(&mut input).is_err() {
            println!("Input error");
            continue;
        }
        let encrypted_input = crypto.encrypt(input.as_bytes());
        if stream.write_all(&encrypted_input).is_err() {
            println!("Send error");
            break;
        }

        let mut size = [0; 4];
        if stream.read_exact(&mut size).is_err() {
            println!("Read error(size)");
            break;
        }
        let mut bytes = u32::from_be_bytes(size) as usize;

        let mut encrypted_response = Vec::new();
        while bytes > 0 {
            let mut buffer = [0; 4096];
            let bytes_read = match stream.read(&mut buffer) {
                Ok(size) => size,
                Err(_) => {
                    println!("Read error");
                    break;
                }
            };
            encrypted_response.extend_from_slice(&buffer[..bytes_read]);
            bytes -= bytes_read;
        }

        let decrypted_response = crypto.decrypt(&encrypted_response);

        match String::from_utf8(decrypted_response) {
            Ok(message) => {
                if !logged && message.trim() == "User connected" {
                    logged = true;
                } else if message.trim() == "exit" {
                    println!("{}", message);
                    exit(1);
                }
                println!("{}", message);
            }
            Err(_) => {
                println!("error decrypting");
                continue;
            }
        }
    }
}
