mod client;
mod crypto;
mod server;
use std::sync::{Arc, Mutex};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} [server|client]", args[0]);
        return;
    }

    let available_ids = Arc::new(Mutex::new(Vec::new()));
    let next_id = Arc::new(Mutex::new(1));

    match args[1].as_str() {
        "server" => server::server(available_ids.clone(), next_id.clone()),
        "client" => client::client(),
        _ => println!("Unknown command. Use 'server' or 'client'."),
    }
}
