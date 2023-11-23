use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};


fn select_key(key_selector: &dyn utils::crypto::PubKeySelector, sig: &[u8]) -> Result<Vec<u8>, String> {
    match key_selector.select_key(sig) {
        Ok(pub_key) => Ok(pub_key),
        Err(err) => Err(err)
    }
}

fn verify_message(msg_bin: &[u8]) -> Result<bool, String> {
    let key_selector = utils::crypto::get_key_selector();
    let msg = utils::crypto::SignedMessage::deserialize(msg_bin)?;
    let pub_key_pem = select_key(key_selector.as_ref(), &msg.sig[..])?;

    return utils::crypto::verify_signature(&msg.msg[..], &msg.sig[..], &pub_key_pem[..]);
}

fn report_result(out: &mut impl Write, result: bool) -> Result<(), String> {
    return utils::write_contents(out, result.to_string().as_bytes());
}

fn handle_message(mut stream: TcpStream, msg_bin: &[u8]) -> Result<(), String> {
    let result = verify_message(&msg_bin[..])?;
    return report_result(&mut stream, result);
}

fn handle_connection(mut stream: TcpStream) -> Result<(), String> {
    let mut msg = Vec::new();
    match stream.read_to_end(&mut msg) {
        Ok(_) => {
            println!("Connection handled!");
            return handle_message(stream, &msg[..]);
        },
        Err(e) => return Err(format!("failed to handle connection: {e:?}")),
    }
}

fn listen(listener: TcpListener) -> Result<(), String> {
    for stream in listener.incoming() {
        if stream.is_ok() {
            let res = handle_connection(stream.unwrap());
            if res.is_err() {
                println!("{}", res.unwrap_err());
            }
        } else {
            let e = stream.unwrap_err();
            println!("failed to establish connection: {e:?}");
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
    let server_address = std::env::args().nth(1).expect("no server address given");
    return server_address;
}

fn main() {
    let srv_address = get_server_address();
    match run_singlethreaded_server(&srv_address) {
        Ok(_) => println!("verifier stopped"),
        Err(e) => println!("{e:?}"),
    }
}
