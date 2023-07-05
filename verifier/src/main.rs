use std::env::args;
use std::net::{TcpListener, TcpStream};


fn handle_connection(_stream: TcpStream) {
    println!("Connection established!");
}

fn listen(listener: TcpListener) -> Result<(), String> {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(s),
            Err(e) => return Err(format!("failed to establish connection: {e:?}")),
        }
    }
    Ok(())
}

fn run_singlethreaded_server(srv_address: &String) -> Result<(), String> {
    let listener = TcpListener::bind(srv_address);
    match listener {
        Ok(l) => listen(l),
        Err(e) => Err(format!("failed to create server: {e:?}")),
    }
}

fn get_server_address() -> String {
    let server_address = args().nth(1).expect("no server address given");
    return server_address;
}

fn main() {
    let srv_address = get_server_address();
    match run_singlethreaded_server(&srv_address) {
        Ok(_) => println!("verifier stopped"),
        Err(e) => println!("{e:?}"),
    }
}
