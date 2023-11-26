pub mod crypto;
pub mod proto;

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