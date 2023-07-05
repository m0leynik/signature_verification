use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

fn rsa_to_pkey(rsa: Rsa<Private>) -> Result<PKey<Private>, String> {
    match PKey::from_rsa(rsa) {
        Ok(keypair) => Ok(keypair),
        Err(errstack) => Err(errstack.to_string())
    }
}

fn serialize_to_pem(rsa: Rsa<Private>) -> Result<Vec<u8>, String> {
    match rsa_to_pkey(rsa) {
        Ok(pkey) => {
            match pkey.private_key_to_pem_pkcs8() {
                Ok(bytes) => Ok(bytes),
                Err(errstack) => Err(errstack.to_string())
            }
        },
        Err(err) => Err(err)
    }
}

fn get_signature(signer: Signer) -> Result<Vec<u8>, String> {
    match signer.sign_to_vec() {
        Ok(signature) => Ok(signature),
        Err(errstack) => Err(errstack.to_string())
    }
}

fn sign_with_signer(msg: &[u8], mut signer: Signer) -> Result<Vec<u8>, String> {
    match signer.update(msg) {
        Ok(_) => get_signature(signer),
        Err(errstack) => Err(errstack.to_string())
    }
}

fn sign_msg_with_key(msg: &[u8], private_key: PKey<Private>) -> Result<Vec<u8>, String> {
    match Signer::new(MessageDigest::sha256(), &private_key) {
        Ok(signer) => {
            return sign_with_signer(msg, signer);
        },
        Err(errstack) => {
            return Err(errstack.to_string());
        }
    }
}

fn verify_sig(verifier: Verifier, sig: &[u8]) -> Result<bool, String> {
    match verifier.verify(sig) {
        Ok(result) => Ok(result),
        Err(errstack) => Err(errstack.to_string())
    }
}

fn verify_msg_signature(mut verifier: Verifier, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    match verifier.update(msg) {
        Ok(_) => verify_sig(verifier, sig),
        Err(errstack) => Err(errstack.to_string())
    }
}

fn verify_with_pub_key(msg: &[u8], sig: &[u8], pub_key: PKey<Public>) -> Result<bool, String> {
    match Verifier::new(MessageDigest::sha256(), &pub_key) {
        Ok(verifier) => verify_msg_signature(verifier, msg, sig),
        Err(errstack) => Err(errstack.to_string())
    }
}

pub fn generate_keypair_pem() -> Result<Vec<u8>, String> {
    const KEY_LENGTH: u32 = 2048;

    match Rsa::generate(KEY_LENGTH) {
        Ok(rsa) => {
            return serialize_to_pem(rsa);
        },
        Err(errstack) => {
            return Err(errstack.to_string());
        }
    }
}

pub fn sign_msg(msg: &[u8], private_key_pem: &[u8]) -> Result<Vec<u8>, String> {
    match PKey::private_key_from_pem(private_key_pem) {
        Ok(private_key) => {
            return sign_msg_with_key(msg, private_key);
        },
        Err(errstack) => {
            return Err(errstack.to_string());
        }
    }
}

pub fn verify_signature(msg: &[u8], sig: &[u8], pub_key_pem: &[u8]) -> Result<bool, String> {
    match PKey::public_key_from_pem(pub_key_pem) {
        Ok(pub_key) => {
            return verify_with_pub_key(msg, sig, pub_key);
        },
        Err(errstack) => {
            return Err(errstack.to_string());
        }
    }
}

fn extract_pub_from_pkey(key_pair: PKey<Private>) -> Result<Vec<u8>, String> {
    match key_pair.public_key_to_pem() {
        Ok(pub_key) => Ok(pub_key),
        Err(errstack) => Err(errstack.to_string())
    }
}

pub fn extract_pub_key(key_pair_pem: &[u8]) -> Result<Vec<u8>, String> {
    match PKey::private_key_from_pem(key_pair_pem) {
        Ok(key_pair) => extract_pub_from_pkey(key_pair),
        Err(errstack) => Err(format!("failed to decode key: {errstack:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_msg_test(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let gen_res = generate_keypair_pem();
        assert!(gen_res.is_ok());

        let key_pair_pem = gen_res.unwrap();
        let sign_result = sign_msg(msg, &key_pair_pem[..]);
        assert!(sign_result.is_ok());

        let signature = sign_result.unwrap(); 
        assert!(signature.len() > 0);

        return (key_pair_pem, signature);
    }
    
    #[test]
    fn test_generate_keypair_succeeded() {
        let gen_res = generate_keypair_pem();
        assert!(gen_res.is_ok());

        let keypair = gen_res.unwrap();
        assert!(keypair.len() > 0);
        
        let restored = PKey::private_key_from_pem(&keypair[..]);
        assert!(restored.is_ok());
    }

    #[test]
    fn test_sign_msg_succeeded() {
        let msg = vec![6u8; 1000];
        sign_msg_test(&msg[..]);
    }

    #[test]
    fn test_verify_signature_succeeded() {
        let msg = vec![6u8; 1000];
        let (key_pair_pem, signature) = sign_msg_test(&msg[..]);

        let pub_key = extract_pub_key(&key_pair_pem[..]);
        assert!(pub_key.is_ok());

        let verify_result = verify_signature(&msg[..], &signature[..], &pub_key.unwrap()[..]);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_verify_signature_return_false_on_corruted_msg() {
        let mut msg = vec![6u8; 1000];
        let (key_pair_pem, signature) = sign_msg_test(&msg[..]);

        let pub_key = extract_pub_key(&key_pair_pem[..]);
        assert!(pub_key.is_ok());

        // corrupt message
        msg[0] = !msg[0];

        let verify_result = verify_signature(&msg[..], &signature[..], &pub_key.unwrap()[..]);
        assert!(verify_result.is_ok());
        assert!(!verify_result.unwrap());
    }

    #[test]
    fn test_verify_signature_fails_on_corruted_pub_key() {
        let msg = vec![6u8; 1000];
        let (key_pair_pem, signature) = sign_msg_test(&msg[..]);

        let pub_key = extract_pub_key(&key_pair_pem[..]);
        assert!(pub_key.is_ok());
        let mut pub_key_pem = pub_key.unwrap();
        
        // corrupt key
        pub_key_pem[0] = !pub_key_pem[0];

        let verify_result = verify_signature(&msg[..], &signature[..], &pub_key_pem[..]);
        assert!(verify_result.is_err());
    }
}
