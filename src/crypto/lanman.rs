use crate::crypto::des::DesEcb;
use md4::{Md4, Digest};
use crate::crypto::crypto::{WinHash, EncType};
use bitvec::prelude::*;



pub struct LanMan;

impl WinHash for LanMan {

    fn from_bytes(plaintext: &[u8]) -> Vec<u8> {
        let mut plaintext: Vec<u8> = plaintext.iter().map(|x| x.to_ascii_uppercase()).collect();
        plaintext.truncate(14);
        plaintext.extend(vec![0; 14 - &plaintext.len()]);
        let mut i_keys = BitVec::<u8, Msb0>::from_vec(plaintext); 
        for bit in (7..128).step_by(8) {
            i_keys.insert(bit, false)
        }
        let i_keys = &i_keys.into_vec();
        let mut key = Vec::new();
        info!("[LM] clear 1/2: {}", hex::encode_upper(&i_keys[..8]));
        info!("[LM] clear 2/2: {}", hex::encode_upper(&i_keys[8..]));
        key.extend(DesEcb::encrypt(&i_keys[..8], &vec![0; 8], &String::from("KGS!@#$%").into_bytes()));
        info!("[LM] hash 1/2: {}", hex::encode_upper(&key));
        key.extend(DesEcb::encrypt(&i_keys[8..], &vec![0; 8], &String::from("KGS!@#$%").into_bytes()));
        info!("[LM] hash 2/2: {}", hex::encode_upper(&key[8..]));
        return key;
    }

    fn from_string(plaintext: &str) -> Vec<u8> {
        return LanMan::from_bytes(plaintext.as_bytes());
    }

}
 
pub struct NTLanMan;

impl WinHash for NTLanMan {
    fn from_bytes(plaintext: &[u8]) -> Vec<u8> {
        return Md4::new()
            .chain_update(&plaintext)
            .finalize().to_vec();
    }
    fn from_string(plaintext: &str) -> Vec<u8> {
        let plaintext = plaintext.encode_utf16().into_iter();
        let mut plaintext_fmt = Vec::new();
        for c in plaintext {
            plaintext_fmt.extend(c.clone().to_le_bytes());
        }
        return NTLanMan::from_bytes(&plaintext_fmt);
    }
}

