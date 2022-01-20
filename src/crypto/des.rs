use crate::crypto::crypto::*;
use bitvec::prelude::*;
use des::Des;
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::block_padding::{ZeroPadding, NoPadding};


const WEAK_KEYS: [&str; 16] = [
    "0101010101010101",
    "FEFEFEFEFEFEFEFE",
    "E0E0E0E0F1F1F1F1",
    "1F1F1F1F0E0E0E0E",
    "01FE01FE01FE01FE",
    "FE01FE01FE01FE01",
    "1FE01FE00EF10EF1",
    "E01FE01FF10EF10E",
    "01E001E001F101F1",
    "E001E001F101F101",
    "1FFE1FFE0EFE0EFE",
    "FE1FFE1FFE0EFE0E",
    "011F011F010E010E",
    "1F011F010E010E01",
    "E0FEE0FEF1FEF1FE",
    "FEE0FEE0FEF1FEF1",
];

const WEAK_CORRECT: &str = "00000000000000F0";

pub struct DesEcb;
impl EncType for DesEcb {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher: Ecb<Des, NoPadding> = Ecb::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext);
        return ciphertext;
    }
}

pub struct DesCbc;
impl EncType for DesCbc {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher: Cbc<Des, ZeroPadding> = Cbc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext);
        return ciphertext;
    }
}



pub struct KrbDes; 

impl KrbEncType for KrbDes {

    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        DesCbc::encrypt(key, iv, plaintext)
    }
    fn string_to_key(secret: &str, salt: &str) -> Vec<u8>{
        KrbDes::bytes_to_key(&secret.as_bytes(), &salt.as_bytes())
    }
    fn bytes_to_key(secret: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut bytes = secret.to_vec();
        bytes.extend(salt);
        let mut bitstring = BitVec::<u8, Msb0>::from_vec(bytes.clone());
        // pad to multiple of 64
        bitstring.extend(bitvec![u8, Msb0; 0; 64 - (bitstring.len() % 64)]);
        let mut bitstring = KrbDes::fan_fold(bitstring);
        info!("[DES] Folded: {}", hex::encode_upper(&bitstring.clone().into_vec()));
        KrbDes::key_correction(&mut bitstring);
        info!("[DES] Parity Set: {}", hex::encode_upper(&bitstring.clone().into_vec()));
        let key = KrbDes::encrypt(&bitstring.clone().into_vec(), &bitstring.into_vec(), &bytes);
        let mut key = BitVec::<u8, Msb0>::from_slice(&key[&key.len() - 8 .. key.len()]);
        KrbDes::key_correction(&mut key);
        return key.into_vec();
    }
}

impl KrbDes {
    fn key_correction(mut key: &mut BitVec::<u8, Msb0>) {
        KrbDes::add_parity_bits(&mut key);
        if KrbDes::is_weak(&key) {
            KrbDes::correct_weak(&mut key);
            println!("corrected:{:02X?}", &key.clone().into_vec());
        };
    }
    
    
    fn is_weak(key: &BitVec::<u8, Msb0>) -> bool {
        let lookup = hex::encode(&key.clone().into_vec()).to_uppercase();
        return WEAK_KEYS.iter().any(|&x| x == lookup)
    }
    
    fn correct_weak(key: &mut BitVec::<u8, Msb0>) {
        let correct = BitVec::<u8, Msb0>::from_vec(hex::decode(WEAK_CORRECT).unwrap());
        for bit in 0..key.len() {
            let current = key[bit];
            key.set(bit, current ^ correct[bit]);
        }
    }
    
    fn add_parity_bits(bytes: &mut BitVec::<u8, Msb0>) {
        for byte in (0..bytes.len()).step_by(8) {
            let parity = bytes[byte..byte + 7].count_ones() % 2 == 0;
            bytes.set(byte + 7, parity);
        }
    }
    
    fn fan_fold(instring: BitVec::<u8, Msb0>) -> BitVec::<u8, Msb0> {
        let mut folded = bitvec![u8, Msb0; 0; 56];
        let mut rev = false;
        let step = 64;
        for block in (0..instring.len()).step_by(step) {
            let mut fan_piece = instring[block..block + 64].to_bitvec();
            for bit in 0..8 {
                fan_piece.remove((bit * 8) - bit);
            };
            if rev {fan_piece.reverse()};
            for bit in 0..56 {
                let current = folded[bit];
                folded.set(bit, current ^ fan_piece[bit]);
            }
            rev = !rev;
        }
        for bit in (7..64).step_by(8) {
            folded.insert(bit, false);
        }
        return folded;
    }
}

