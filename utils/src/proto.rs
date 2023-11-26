use std::io::{Read,Write};
    
pub const MSG_LEN_SIZE: usize = std::mem::size_of::<u64>(); 
fn write_mesage_size(msg: &[u8], out: &mut impl Write) -> Result<(), String> {
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