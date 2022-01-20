pub trait KrbEncType {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>;

    fn string_to_key(secret: &str, salt: &str) -> Vec<u8>;
//    fn bytes_to_key(bytes: Vec<u8>);
    fn bytes_to_key(secret: &[u8], salt: &[u8]) -> Vec<u8>;
}


pub trait WinHash {
    fn from_bytes(plaintext: &[u8]) -> Vec<u8>;
    fn from_string(plaintext: &str) -> Vec<u8>;
}


pub trait EncType {
    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>;
}

