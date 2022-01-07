use std::time::{SystemTime};
use std::fs;


#[derive(Debug)]
struct KeytabEntry {
    size: i32,
    num_components: u16,
    realm: CountedOctetString,
    components: Vec<CountedOctetString>,
    name_type: u32,
    timestamp: u32,
    vno8: u8,
    key: Keyblock,
    vno: i32,
}

#[derive(Debug)]
struct CountedOctetString {
    length: u16,
    data: Vec<u8>,
}

impl CountedOctetString {
    fn from_hex(data: &str)  -> CountedOctetString {
        let hexbytes = match hex::decode(data) {
            Ok(decoded) => decoded,
            Err(_) => panic!("dead"),
        };
        CountedOctetString::from_bytes(hexbytes)
    }

    fn from_string(data: &str) -> CountedOctetString {
        let strbytes = data.as_bytes().to_vec();
        CountedOctetString::from_bytes(strbytes)
    }

    fn from_components(data: &str) -> Vec<CountedOctetString> {
        let components: Vec<&str> = data.split('/').collect();
        let mut cosv = Vec::new(); 
        for c in components {
            let c = CountedOctetString::from_bytes(c.as_bytes().to_vec());
            cosv.push(c);
        }
        cosv
    }

    fn from_bytes(data: Vec<u8>) -> CountedOctetString {
        let length: u16 = data.len().try_into().unwrap();
        CountedOctetString {
            length,
            data,
        }
    }
    
    fn to_string(&self) -> (&u16, String) {
        let data = self.data.clone();
        let data = &String::from_utf8(data).unwrap();
        (&self.length, data.to_string())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes  = self.length.to_be_bytes().to_vec();
        bytes.extend(self.data.clone());
        bytes 
    }
}

#[derive(Debug)]
struct Keyblock {
    key_type: u16,
    key: CountedOctetString,
}

impl Keyblock {
    fn to_bytes(&self) -> Vec<u8> { 
        let mut bytes = self.key_type.to_be_bytes().to_vec();
        bytes.extend(self.key.to_bytes());
        bytes
    }

    fn new(etype: &String, key: &String) -> Keyblock {
        let key = CountedOctetString::from_hex(key);
        let etype: u16 = match ENCRYPTION_TYPES.iter().find(|&x| x.shortname == etype || x.name == etype) {
            Some(ematch) => ematch.id.try_into().unwrap(),
           _ => panic!("nope"),
       };
       Keyblock {
           key_type: etype,
           key,
       }
    }
}


#[derive(Debug)]
struct Keytab {
    file_format_version: u16,
    entries: Vec<KeytabEntry>,
}

impl Keytab {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.file_format_version.to_be_bytes().to_vec();
        for e in &self.entries {
            bytes.extend(e.to_bytes());
        }
        bytes
    }
}

impl KeytabEntry {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.size.to_be_bytes().to_vec();
        bytes.extend(self.num_components.to_be_bytes().to_vec());
        bytes.extend(self.realm.to_bytes());
        for c in &self.components {
            bytes.extend(c.to_bytes());
        } 
        bytes.extend(self.name_type.to_be_bytes().to_vec());
        bytes.extend(self.timestamp.to_be_bytes().to_vec());
        bytes.extend(self.vno8.to_be_bytes().to_vec());
        bytes.extend(self.key.to_bytes());
        bytes.extend(self.vno.to_be_bytes().to_vec());
        bytes
    }
}

#[derive(Debug)]
struct Ref {
    name: &'static str,
    shortname: &'static str,
    id: u8,
}

const ENCRYPTION_TYPES: [Ref; 2] = [
    Ref{
        name: "aes128-cts-hmac-sha1-96",
        shortname: "aes128",
        id: 17,
    },
    Ref{
        name: "aes256-cts-hmac-sha1-96",
        shortname: "aes256",
        id: 18,
    },
];

const PRINCIPAL_TYPES: [Ref; 1] = [
    Ref{
        name: "KRB5_NT_PRINCIPAL",
        shortname: "principal",
        id: 1,
    },
];

fn now_epoch() -> u32 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(s) => s.as_secs().try_into().unwrap(),
        Err(_) => panic!("SystemTime before UNIX EPOCH"),
    }
}


fn main() {
    let etype = String::from("aes128");   
    let key = String::from("f9a9c510c3aeb65f58d6b38d6284ba36");
    let name_type = String::from("principal");   
    let vno8: u8 = 9;
    let vno: i32 = 9;


    let timestamp = now_epoch();
    //let key = CountedOctetString::from_hex(&key); 
    let realm = CountedOctetString::from_string(&String::from("COMPANY.INT"));
    let components = CountedOctetString::from_components(&String::from("delfino/test"));
    let key = Keyblock::new(&etype, &key);


    let etype: u16 = match ENCRYPTION_TYPES.iter().find(|&x| x.shortname == etype || x.name == etype){
        Some(ematch) => ematch.id.try_into().unwrap(),
        _ => panic!("nope"),
    };

    let name_type: u32 = match PRINCIPAL_TYPES.iter().find(|&x| x.shortname == name_type || x.name == name_type){
        Some(nmatch) => nmatch.id.try_into().unwrap(),
        _ => panic!("nope"),
    };

    let num_components: u16 = components.len().try_into().unwrap();
    let size:i32 = 152 + i32::from(realm.length + key.key.length + &components.iter().map(|x| x.length).sum());

    let entries = vec![KeytabEntry {
        size,
        num_components,
        //realm,
        realm: CountedOctetString::from_string(&String::from("COMPANY.INT")),
        components,
        name_type,
        timestamp,
        vno8,
        key,
        vno,
    }];

    let keytab = Keytab {
        file_format_version: 1282,
        entries: entries,

    };
   create_file(&keytab);
}


fn create_file(keytab: &Keytab) -> std::io::Result<()> {
    fs::write("test3.txt", keytab.to_bytes())?;
    Ok(())
}
