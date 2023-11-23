use std::{thread, time};
use std::net::TcpStream;

use rand::RngCore;

use utils::crypto::{PubKeyDistributor, SignedMessage};

fn generate_signed_message(key_distributor: &dyn PubKeyDistributor) -> Result<SignedMessage, String> {
    const MSG_SIZE: usize = 100;      
    let mut msg = utils::crypto::SignedMessage {
        msg: Vec::new(),
        sig: Vec::new()
    };
    msg.msg.resize(MSG_SIZE, 0);
    rand::thread_rng().fill_bytes(&mut msg.msg[..]);
    
    let gen_res = utils::crypto::generate_keypair_pem();
    if gen_res.is_err() {
        return Err(format!("failed to generate key pair: {}", gen_res.unwrap_err()));
    }

    let key_pair_pem = gen_res.unwrap();
    let pub_key_res = utils::crypto::extract_pub_key(&key_pair_pem);
    if pub_key_res.is_err() {
        return Err(format!("failed to extract public key: {}", pub_key_res.unwrap_err()));
    }

    let pub_key = pub_key_res.unwrap();
    let distr_res = key_distributor.distribute_key(&pub_key);
    if distr_res.is_err() {
        return Err(format!("failed to distribute public key: {}", distr_res.unwrap_err()));
    }

    let sign_res = utils::crypto::sign_msg(&msg.msg, &key_pair_pem);
    if sign_res.is_err() {
        return Err(format!("failed to sign message: {}", sign_res.unwrap_err()));
    }
    msg.sig = sign_res.unwrap();


    return Ok(msg);
}

fn write_bin_message(msg: &[u8], out: &mut impl std::io::Write) -> Result<(), String> {
    match utils::write_contents(out, msg) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
    }
}

fn write_message(msg: &SignedMessage, out: &mut impl std::io::Write) -> Result<(), String> {
    let ser_res = msg.serialize();
    if ser_res.is_err() {
        return Err(format!("failed to serialize message: {}", ser_res.unwrap_err()));
    }

    return write_bin_message(&ser_res.unwrap(), out);
}

fn send_new_message(key_distributor: &dyn PubKeyDistributor, out: &mut impl std::io::Write) -> Result<(), String> {
    match generate_signed_message(key_distributor) {
        Ok(msg) => {
            return write_message(&msg, out);
        },
        Err(err) => {
            return Err(format!("failed to generate message: {}", err))
        }
    }
}

fn send_new_message_to_address(key_distributor: &dyn PubKeyDistributor, receiver_address: &str) -> Result<(), String> {
    match TcpStream::connect(receiver_address) {
        Ok(mut stream) => {
            return send_new_message(key_distributor, &mut stream)
        },
        Err(e) => {
            return Err(format!("failed to connect: {e:?}"));
        }
    }
}

fn send_messages(receiver_address: &str) {
    let key_distributor = utils::crypto::get_key_distributor();

    loop {
        if let Err(e) = send_new_message_to_address(key_distributor.as_ref(), receiver_address) {
            println!("{}", e);
        }
        thread::sleep(time::Duration::from_secs(10));
    }
}

fn get_receiver_address() -> String {
    let server_address = std::env::args().nth(1).expect("no receiver address given");
    return server_address;
}

fn main() {
    println!("Actor started");

    let receiver_address = get_receiver_address();
    send_messages(&receiver_address);

    println!("Actor stopped");
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use mockall::*;

    mock! {
        KeyDistributorTrait {}
        impl PubKeyDistributor for KeyDistributorTrait {
            fn distribute_key(&self, pub_key: &[u8]) -> Result<(), String>;
        }
    }

    mock! {
        WriteTrait {}
        impl std::io::Write for WriteTrait {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
            fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()>;
            fn flush(&mut self) -> std::io::Result<()>;
        }
    }

    #[test]
    fn test_correct_message_written() {
        // arrange
        // cannot specify explicit closure lifetime to returning(), use Arc instead 
        let msg = Arc::new(SignedMessage {
            msg: vec![6u8; 1000],
            sig: vec![7u8; 1000]
        });
        let mut mock_write = MockWriteTrait::new();
        mock_write.expect_write_all().once().returning({
            let initial_msg = msg.clone();
            move |msg_bin| {
                assert!(*initial_msg.as_ref() == SignedMessage::deserialize(msg_bin).unwrap());
                return Ok(());
        }});
        
        // act
        // assert
        assert!(write_message(msg.as_ref(), &mut mock_write).is_ok());
    }

    #[test]
    fn test_signed_message_generation_valid() {
        // arrange
        let pub_key = Arc::new(Mutex::new(Vec::new()));
        let mut mock_distributor = MockKeyDistributorTrait::new();
        mock_distributor.expect_distribute_key().returning({
            let pub_key_ptr = pub_key.clone();
            move |new_pub_key| {
                *pub_key_ptr.lock().unwrap().as_mut() = new_pub_key.to_vec();
                return Ok(());
            }
        });

        // act
        let msg_gen_res = generate_signed_message(&mock_distributor);
        
        // assert
        let msg = msg_gen_res.unwrap();
        let verify_res = utils::crypto::verify_signature(&msg.msg[..], &msg.sig[..], &pub_key.lock().unwrap()[..]);
        assert!(verify_res.unwrap());
    }
}