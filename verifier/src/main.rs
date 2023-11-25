use std::io::{Read, Write};
use std::net::TcpListener;

use utils::crypto::{PubKeySelector, SignedMessage};


fn select_key(key_selector: &dyn PubKeySelector, sig: &[u8]) -> Result<Vec<u8>, String> {
    match key_selector.select_key(sig) {
        Ok(pub_key) => Ok(pub_key),
        Err(err) => Err(err)
    }
}

fn verify_message(key_selector: &dyn PubKeySelector, msg_bin: &[u8]) -> Result<bool, String> {
    let msg = SignedMessage::deserialize(msg_bin)?;
    let pub_key_pem = select_key(key_selector, &msg.sig[..])?;

    return utils::crypto::verify_signature(&msg.msg[..], &msg.sig[..], &pub_key_pem[..]);
}

fn report_result(out: &mut impl Write, result: bool) -> Result<(), String> {
    return utils::write_contents(result.to_string().as_bytes(), out);
}

fn handle_message<Stream: Read + Write>(key_selector: &dyn PubKeySelector, msg_bin: &[u8], stream: &mut Stream) -> Result<(), String> {
    let result = verify_message(key_selector, &msg_bin[..])?;
    return report_result(stream, result);
}

fn handle_connection<Stream: Read + Write>(key_selector: &dyn PubKeySelector, stream: &mut Stream) -> Result<(), String> {   
    match utils::proto::read_msg(stream) {
        Ok(msg) => {
            println!("connection handled");
            return handle_message(key_selector, &msg[..], stream);
        },
        Err(e) => {
            return Err(format!("failed to handle connection: {e:?}"));
        }
    }
}

fn listen(listener: &TcpListener) -> Result<(), String> {
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                println!("new connection");
                let key_selector = utils::crypto::get_key_selector();
                let res = handle_connection(key_selector.as_ref(), &mut stream);
                if res.is_err() {
                    println!("{}", res.unwrap_err());
                }
            },
            Err(e) => {
                println!("failed to establish connection: {e:?}");
            }
        }
    }
    return Ok(());
}

fn run_server(srv_address: &str) -> Result<(), String> {
    match TcpListener::bind(srv_address) {
        Ok(listener) => listen(&listener),
        Err(e) => Err(format!("failed to create server: {e:?}")),
    }
}

fn get_server_address() -> String {
    let server_address = std::env::args().nth(1).expect("no server address given");
    return server_address;
}

fn main() {
    let srv_address = get_server_address();
    println!("verifier started");
    match run_server(&srv_address) {
        Ok(_) => println!("verifier stopped"),
        Err(e) => println!("{e:?}"),
    }
}


#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

    use super::*;
    use mockall::*;

    mock! {
        ReadWriteTrait {}
        impl std::io::Write for ReadWriteTrait {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
            fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
            fn flush(&mut self) -> std::io::Result<()>;
        }

        impl std::io::Read for ReadWriteTrait {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
            fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
        }
    }

    mock! {
        PubKeySelectorTrait {}
        impl PubKeySelector for PubKeySelectorTrait {
            fn select_key(&self, signature: &[u8]) -> Result<Vec<u8>, String>;
        }
    }

    #[test]
    fn test_handle_connection_reports_verification_succeeded() {
        // arrange
        let key_pair = utils::crypto::generate_keypair_pem().unwrap();
        let test_msg = vec![6u8; 1000]; 
        let msg = Arc::new(SignedMessage {
            sig: utils::crypto::sign_msg(&test_msg[..], &key_pair[..]).unwrap(),
            msg: test_msg,
        });
        let mut mock_stream = MockReadWriteTrait::new();
        mock_stream.expect_flush().times(1).returning(||{ Ok(()) });
        mock_stream.expect_read_exact().times(2).returning({
            let msg_bin = msg.as_ref().serialize().unwrap();
            move |buf| {
                static FIRST_CALL: AtomicBool = AtomicBool::new(true);
                if FIRST_CALL.load(Ordering::SeqCst) {
                    assert!(buf.len() == utils::proto::MSG_LEN_SIZE);
                    buf.copy_from_slice(&(msg_bin.len() as u64).to_le_bytes()[..]);
                    FIRST_CALL.store(false, Ordering::SeqCst)
                } else {
                    assert!(buf.len() == msg_bin.len());
                    buf.copy_from_slice(&msg_bin[..]);
                }
                return Ok(());
            }
        });
        mock_stream.expect_write_all().once().returning(|res| {
            assert!((true).to_string().as_bytes() == res);
            return Ok(());
        });
        let mut mock_key_selector = MockPubKeySelectorTrait::new();
        mock_key_selector.expect_select_key().once().returning({
            let initial_msg = msg.clone();
            move |signature| {
                assert!(initial_msg.sig == signature);
                return utils::crypto::extract_pub_key(&key_pair[..]);
            }
        });

        // act 
        let res = handle_connection(&mock_key_selector, &mut mock_stream);
        
        // assert
        assert!(res.is_ok());
    }


    fn corrupt_data(mut data: Vec<u8>) -> Vec<u8> {
        data[0] = !data[0];
        return data;
    }

    #[test]
    fn test_handle_connection_reports_verification_failed_on_corrupted_message() {
        // arrange
        let key_pair = utils::crypto::generate_keypair_pem().unwrap();
        let test_msg = vec![6u8; 1000];
        let msg = Arc::new(SignedMessage {
            sig: utils::crypto::sign_msg(&test_msg[..], &key_pair[..]).unwrap(),
            msg: corrupt_data(test_msg),
        });
        let mut mock_stream = MockReadWriteTrait::new();
        mock_stream.expect_flush().times(1).returning(||{ Ok(()) });
        mock_stream.expect_read_exact().times(2).returning({
            let msg_bin = msg.as_ref().serialize().unwrap();
            move |buf| {
                static FIRST_CALL: AtomicBool = AtomicBool::new(true);
                if FIRST_CALL.load(Ordering::SeqCst) {
                    assert!(buf.len() == utils::proto::MSG_LEN_SIZE);
                    buf.copy_from_slice(&(msg_bin.len() as u64).to_le_bytes()[..]);
                    FIRST_CALL.store(false, Ordering::SeqCst)
                } else {
                    assert!(buf.len() == msg_bin.len());
                    buf.copy_from_slice(&msg_bin[..]);
                }
                return Ok(());
            }
        });
        mock_stream.expect_write_all().once().returning(|res| {
            assert!((false).to_string().as_bytes() == res);
            return Ok(());
        });
        let mut mock_key_selector = MockPubKeySelectorTrait::new();
        mock_key_selector.expect_select_key().once().returning({
            let initial_msg = msg.clone();
            move |signature| {
                assert!(initial_msg.sig == signature);
                return utils::crypto::extract_pub_key(&key_pair[..]);
            }
        });

        // act
        let res = handle_connection(&mock_key_selector, &mut mock_stream);
        
        // assert
        assert!(res.is_ok());
    }
}