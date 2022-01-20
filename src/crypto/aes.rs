use bitvec::prelude::*;
use std::str;
//use crate::utils::des::Etype;

use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha1::Sha1;
use aes::{Aes128, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::NoPadding;
use crate::crypto::crypto::*;
use crate::utils::utils::*;

type Aes256Cbc = Cbc<Aes256, NoPadding>;
type Aes128Cbc = Cbc<Aes128, NoPadding>;


pub struct KrbAes;

impl KrbAes {
    pub fn pbkdf2_from_bytes(key: &[u8], salt: &[u8], keysize: usize) -> Vec<u8> {
        let mut out = vec![0u8; keysize / 8];
        pbkdf2::<Hmac<Sha1>>(&key, &salt, 1, &mut out);
        return out
    }

    fn nfold(constant: &str, keysize: usize) -> Vec<u8> {
        let mut constant = BitVec::<_, Msb0>::from_vec(constant.as_bytes().to_vec());
        let mut offset = 13;
        if offset > constant.len() {
            offset = offset % &constant.len();
        }
    
        let mut long_constant = constant.clone();
        for _ in 1..(lcm(&keysize, &constant.len()) / &constant.len()) {
            constant.rotate_right(offset);
            long_constant.extend(constant.clone());
        };
    
        let mut keybits = long_constant[0..keysize].to_bitvec();
        for i in 1 ..(long_constant.len()/keysize) {
            keybits = KrbAes::add_chunks_ones_comp(
                &keybits,
                &long_constant[i * keysize..((i + 1) * keysize)],
                &keysize);
        }
        return keybits.to_bitvec().into_vec();
    }

    
    fn add_chunks_ones_comp(first: &BitSlice<u8, Msb0>, second: &BitSlice<u8, Msb0>, keysize: &usize) -> BitVec::<u8, Msb0> {
        let mut result = first.clone().to_bitvec();
        let mut carry = false;
        let mut set;
        for b in (0 ..*keysize).rev(){
            if result[b] & second[b] {
                set = carry;
                carry = true;
            } else if result[b] ^ second[b] {
                set = !carry;
            } else {
                set = carry;
                carry = false;
            }
            result.set(b, set);
    
        }
        if carry {
            let mut carrybits = bitvec![u8, Msb0; 0; *keysize];
            carrybits.set(*keysize -1, carry);
            result = KrbAes::add_chunks_ones_comp(&result, &carrybits, keysize);
        }
        return result;
    }

}



pub struct KrbAes128;

impl KrbEncType for KrbAes128 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>  {
        let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext);
        return ciphertext
    }
    fn bytes_to_key(secret: &[u8], salt: &[u8]) -> Vec<u8> {
        let tkey = KrbAes::pbkdf2_from_bytes(&secret, &salt, 128);
        info!("[AES128] pbkdf2: {}", hex::encode_upper(&tkey));
        let ikey = KrbAes128::dk("kerberos", 128, &tkey);
        return ikey;
    }

    fn string_to_key(secret: &str, salt: &str) -> Vec<u8> {
        KrbAes128::bytes_to_key(&secret.as_bytes(), &salt.as_bytes())
    }
}

impl KrbAes128 {
    fn dk(constant: &str, keysize: usize, tkey: &Vec<u8>) -> Vec<u8> {
        let folded = KrbAes::nfold(constant, keysize);
        info!("[AES128] nfolded: {}", hex::encode_upper(&folded));
        let key = KrbAes128::encrypt(&tkey, &vec![0; 16], &folded);
        return key;
    }
}

 

pub struct KrbAes256;

impl KrbEncType for KrbAes256 {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>  {
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext);
        return ciphertext
    }
    fn bytes_to_key(secret: &[u8], salt: &[u8]) -> Vec<u8> {
        let tkey = KrbAes::pbkdf2_from_bytes(&secret, &salt, 256);
        info!("[AES256] pbkdf2: {}", hex::encode_upper(&tkey));
        let ikey = KrbAes256::dk("kerberos", 256, &tkey);
        return ikey;
    }

    fn string_to_key(secret: &str, salt: &str) -> Vec<u8> {
        KrbAes256::bytes_to_key(&secret.as_bytes(), &salt.as_bytes())
    }
}

impl KrbAes256 {
    fn dk(constant: &str, keysize: usize, tkey: &Vec<u8>) -> Vec<u8> {
        let folded = KrbAes::nfold(constant, keysize);
        info!("[AES256] nfolded: {}", hex::encode_upper(&folded));
        let mut key = KrbAes256::encrypt(&tkey, &vec![0; 16], &folded);
        key.truncate(&keysize / 16);
        key.extend(&KrbAes256::encrypt(&tkey, &vec![0; 16], &key)[0..&keysize / 16]); 
        return key;
    }
}
    

