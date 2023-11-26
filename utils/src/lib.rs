pub mod crypto;

use std::io::{Read,Write};

pub fn write_contents(contents: &[u8], out: &mut impl Write) -> Result<(), String> {
    match out.write_all(contents) {
        Ok(_) => {
            let res = out.flush();
            if res.is_err() {
                return Err(format!("failed to flush: {}", res.unwrap_err()));
            }
            return Ok(())
        },
        Err(e) => Err(format!("failed to write content: {e:?}"))
    }
}

pub fn read_contents(input: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut contents = Vec::new();
    match input.read_to_end(&mut contents) {
        Ok(_) => Ok(contents),
        Err(err) => Err(err.to_string())
    }
}

pub fn read_exact(size: usize, input: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; size];
    match input.read_exact(&mut buf) {
        Ok(_) => Ok(buf),
        Err(err) => Err(err.to_string())
    }
}

pub mod proto {
    use std::io::{Read,Write};
    
    pub const MSG_LEN_SIZE: usize = std::mem::size_of::<u64>(); 
    fn write_mesage_size(msg: &[u8], out: &mut impl Write) -> Result<(), String> {
        // write 8 bytes
        return super::write_contents(&(msg.len() as u64).to_le_bytes()[..], out);
    }
    
    pub fn write_msg(msg: &[u8], out: &mut impl Write) -> Result<(), String> {
        let res = write_mesage_size(msg, out);
        if res.is_err() {
            return Err(format!("failed to write message size: {}", res.unwrap_err()));
        }

        return super::write_contents(msg, out); 
    }

    fn read_mesage_size(input: &mut impl Read) -> Result<u64, String> {
        // read 8 bytes
        match super::read_exact(MSG_LEN_SIZE, input) {
            Ok(buf) => Ok(u64::from_le_bytes(buf.try_into().expect("invalid buffer size"))),
            Err(e) => Err(format!("failed to read message size: {}", e))
        }
    }

    pub fn read_msg(input: &mut impl Read) -> Result<Vec<u8>, String> {
        match read_mesage_size(input) {
            Ok(msg_size) => super::read_exact(msg_size as usize, input),
            Err(e) => Err(e)
        }
    }
}