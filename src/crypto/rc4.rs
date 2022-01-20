use crate::crypto::crypto::{KrbEncType, WinHash};
use crate::crypto::lanman::NTLanMan;

pub struct KrbRc4;

impl KrbEncType for KrbRc4 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        println!("not yet implemented{:?}{:?}", iv, plaintext);
        return key.clone().to_vec();
    }

    fn string_to_key(secret:&str, salt: &str) -> Vec<u8> {
        return NTLanMan::from_string(&secret);
    }

    fn bytes_to_key(secret: &[u8], salt: &[u8]) -> Vec<u8> {
        return NTLanMan::from_bytes(&secret);
    }
}

