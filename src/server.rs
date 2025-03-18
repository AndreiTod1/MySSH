use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::{env, thread};
mod execution;
use crate::crypto::{derive_shared_key, generate_keys, Crypto};
use std::collections::HashMap;
use std::process::exit;
use x25519_dalek::PublicKey;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => {
            println!("Error hashing password.");
            String::new()
        }
    }
}
fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => {
            println!("Invalid password hash format.");
            return false;
        }
    };
    let argon2 = Argon2::default();

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub struct ServerState {
    client_paths: Mutex<HashMap<String, String>>,
}

impl ServerState {
    pub fn new() -> Self {
        ServerState {
            client_paths: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_client_path(&self, client_id: String, path: String) {
        let mut paths = self.client_paths.lock().unwrap();
        paths.insert(client_id, path);
    }

    pub fn get_client_path(&self, client_id: &String) -> String {
        let paths = self.client_paths.lock().unwrap();
        paths
            .get(client_id)
            .cloned()
            .unwrap_or_else(|| String::from("/"))
    }
}

pub fn server(available_ids: Arc<Mutex<Vec<u32>>>, next_id: Arc<Mutex<u32>>) {
    let listener = TcpListener::bind("127.0.0.1:2025").expect("Server failed to start.");
    println!("Server running on 127.0.0.1:2025");

    let server_default_path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        .to_string_lossy()
        .to_string();

    let server_state = Arc::new(ServerState::new());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let ids = Arc::clone(&available_ids);
                let counter = Arc::clone(&next_id);
                let state = Arc::clone(&server_state);
                let path_clone = server_default_path.clone();
                thread::spawn(move || handle_client(stream, ids, counter, state, path_clone));
            }
            Err(_) => {
                println!("Connection failed.");
            }
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    available_ids: Arc<Mutex<Vec<u32>>>,
    next_id: Arc<Mutex<u32>>,
    state: Arc<ServerState>,
    server_default_path: String,
) {
    //criptare
    let (server_secret, server_public) = generate_keys();
    if stream.write_all(server_public.as_bytes()).is_err() {
        println!("Failed to send server public key");
        exit(1);
    };
    let mut client_public_bytes = [0u8; 32];
    if stream.read_exact(&mut client_public_bytes).is_err() {
        println!("Failed to read client public key");
        exit(1);
    };
    let client_public = PublicKey::from(client_public_bytes);
    let shared_key = derive_shared_key(server_secret, &client_public);

    println!("Secure key established on server!");

    //alegere id

    let client_id = {
        let mut ids = available_ids.lock().unwrap();
        if let Some(id) = ids.pop() {
            id
        } else {
            let mut counter = next_id.lock().unwrap();
            let id = *counter;
            *counter += 1;
            id
        }
    };
    println!("Client {} connected.", client_id);
    let mut logged: bool = false;

    // setare path
    let clona_path = server_default_path.clone();
    let client_id_str = client_id.to_string();
    state.set_client_path(client_id_str.clone(), clona_path);

    loop {
        let crypto = Crypto::new(&shared_key);
        let mut ciphertext = [0; 4096];

        let bytes_read = match stream.read(&mut ciphertext) {
            Ok(size) => size,
            Err(_) => {
                println!("Error reading from client {}.", client_id);
                break;
            }
        };
        if bytes_read == 0 {
            println!("Client {} left.", client_id);
            break;
        }
        println!("{}", String::from_utf8_lossy(&ciphertext));
        let decrypted_message = crypto.decrypt(&ciphertext[..bytes_read]);
        let command = String::from_utf8_lossy(&decrypted_message);

        println!("Client {}: {}", client_id, command);
        let mut output = String::new();

        let client_path = state.get_client_path(&client_id_str);
        if env::set_current_dir(&client_path).is_err() {
            print!("can t set correct path for client: {}", client_id);
            exit(1);
        }

        if !logged {
            if command.starts_with("register ") {
                let rest = command.trim_start_matches("register ");
                let mut parts = rest.split(":");

                let mut username = String::new();
                let mut password = String::new();

                if let Some(user) = parts.next() {
                    username.push_str(user.trim());
                } else {
                    output.push_str("Invalid format of register. Use \"username:password\" .");
                }

                if let Some(pass) = parts.next() {
                    password.push_str(pass.trim());
                } else {
                    output.push_str("Invalid format of register. Use \"username:password\" .");
                }

                if username.is_empty() || password.is_empty() {
                    output.push_str("Invalid format of register. Use \"username:password\" .");
                } else {
                    let hashed_password = hash_password(&password);
                    if hashed_password.is_empty() {
                        output.push_str("Failed to hash password.\n");
                        return;
                    }

                    match save_to_file(&username, &hashed_password) {
                        Ok(_) => output.push_str("User registered successfully.\n"),
                        Err(e) => output.push_str(&format!("Failed to register user: {}\n", e)),
                    }
                }
            } else {
                (logged, output) = login(command.to_string());
            }
        } else if logged {
            output =
                execution::execution(command.to_string(), client_id.to_string(), state.clone());
        }

        if output.is_empty() {
            output.push_str("Execution success!");
        }

        let encrypted_output = crypto.encrypt(output.as_bytes());

        let size = encrypted_output.len() as u32;
        if stream.write_all(&size.to_be_bytes()).is_err() {
            println!("Error sending data to {}.", client_id);
            break;
        }
        if stream.write_all(&encrypted_output).is_err() {
            println!("Error sending data to {}.", client_id);
            break;
        }
    }
    available_ids.lock().unwrap().push(client_id);
}

fn login(input: String) -> (bool, String) {
    let info = input.trim();
    let file_path = "users.txt";

    let file_content = match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(_) => return (false, "Error opening users file".to_string()),
    };

    let mut parts = info.split(':');
    let username = match parts.next() {
        Some(name) => name,
        None => return (false, "Input format \"username:password\"".to_string()),
    };

    let password = match parts.next() {
        Some(pass) => pass,
        None => return (false, "Input format \"username:password\"".to_string()),
    };

    for line in file_content.lines() {
        let mut line_parts = line.split(':');
        let stored_username = match line_parts.next() {
            Some(name) => name,
            None => {
                println!("Invalid data format in file");
                continue;
            }
        };

        let stored_hash = match line_parts.next() {
            Some(hash) => hash,
            None => {
                println!("Invalid data format in file");
                continue;
            }
        };

        if stored_username == username {
            if verify_password(stored_hash, password) {
                return (true, "User connected".to_string());
            } else {
                return (false, "Incorrect password".to_string());
            }
        }
    }

    (false, "Username not found".to_string())
}

fn save_to_file(username: &str, hashed_password: &str) -> Result<(), String> {
    let entry = format!("{}:{}\n", username, hashed_password);

    let file_path = "users.txt";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    file.write_all(entry.as_bytes())
        .map_err(|e| format!("Failed to write to file: {}", e))?;
    Ok(())
}
