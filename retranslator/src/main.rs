use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};


fn get_connection_address() -> String {
    let connection_address = std::env::args().nth(2).expect("no connection address given");
    return connection_address;
}

fn get_server_address() -> String {
    let server_address = std::env::args().nth(1).expect("no server address given");
    return server_address;
}

fn handle_response(stream: &mut impl Read) {
    let mut response = String::new();
    
    match stream.read_to_string(&mut response) {
        Ok(_) => {
            println!("server response is: {}", response);
        },
        Err(e) => {
            println!("failed to read server response: {}", e);
        }
    }
}

fn exchange_msg<Stream: Read + Write>(msg: &[u8], stream: &mut Stream) {
    match utils::proto::write_msg(msg, stream) {
        Ok(_) => {
            println!("message sent");
            handle_response(stream);
        },
        Err(e) => {
            println!("failed to pass message: {}", e);
        }
    }
}

fn pass_message(msg: &[u8], receiver_addr: &str) -> Result<(), String> {

    match TcpStream::connect(receiver_addr) {
        Ok(mut stream) => {
            exchange_msg(msg, &mut stream);
            Ok(())
        },
        Err(e) => {
            return Err(format!("failed to connect: {e:?}"));
        }
    }
}

fn retranslate_stream(stream: &mut impl Read, receiver_addr: &str) -> Result<(), String> {
    match utils::proto::read_msg(stream) {
        Ok(msg) => pass_message(&msg[..], receiver_addr),
        Err(e) => Err(format!("failed to read data: {e:?}")),
    }
}

fn listen(listener: &TcpListener, connection_address: &str) -> Result<(), String> {
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let res = retranslate_stream(&mut s, connection_address);
                if res.is_err() {
                    println!("failed to stream message {}", res.unwrap_err())
                }
            },
            Err(e) => {
                return Err(format!("failed to establish connection: {e:?}"));
            }
        }
    }

    Ok(())
}

fn run_server(srv_address: &str, connection_address: &str) -> Result<(), String> {
    let listener = TcpListener::bind(srv_address);
    match listener {
        Ok(l) => return listen(&l, connection_address),
        Err(e) => Err(format!("failed to create server: {e:?}")),
    }
}

fn main() {
    let srv_address = get_server_address();
    let connection_address = get_connection_address();
    
    match run_server(&srv_address, &connection_address) {
        Ok(_) => println!("server stopped"),
        Err(e) => println!("{e:?}"),
    }
}
