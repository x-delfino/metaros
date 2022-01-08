use std::time::{SystemTime};
use std::fs;
use byteorder::{ByteOrder, BigEndian, ReadBytesExt};

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
    vno: u32,
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

    fn from_raw_bytes(bytes: &Vec<u8>) -> CountedOctetString {
        let length = BigEndian::read_u16(&bytes[0..2].to_vec()); 
        let data = bytes[2..].to_vec();
        CountedOctetString {
            length,
            data,
        }
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
    
    fn from_bytes(bytes: &Vec<u8>) -> Keyblock {
        Keyblock {
            key_type: BigEndian::read_u16(&bytes[0..2].to_vec()),
            key: CountedOctetString::from_raw_bytes(&bytes[2..].to_vec()),
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
    fn from_bytes(bytes: &Vec<u8>) -> Keytab {
        let file_format_version = BigEndian::read_u16(&bytes[0..2].to_vec());
        let mut spl: usize = 2;
        let mut entries: Vec<KeytabEntry> = Vec::new();
        while spl < bytes.len() {
            let entry_size = BigEndian::read_i32(&bytes[spl..spl + 4].to_vec());
            if entry_size.is_positive(){
                let entry = &bytes[spl..spl + (entry_size as usize)].to_vec();
                entries.push(KeytabEntry::from_bytes(entry));
            }
            spl += entry_size as usize;
        }
        Keytab {
            file_format_version,
            entries }
    }
}

impl KeytabEntry {
    fn from_bytes(bytes: &Vec<u8>) -> KeytabEntry {
        let size = BigEndian::read_i32(&bytes[0..4].to_vec());
        let num_components = BigEndian::read_u16(&bytes[4..6].to_vec());
        let r_size = BigEndian::read_u16(&bytes[6..8].to_vec());
        let realm = CountedOctetString::from_raw_bytes(&bytes[6.. r_size as usize + 8].to_vec());
        let mut spl: usize = 8 + r_size as usize;
        let mut components: Vec<CountedOctetString> =Vec::new();
        for c in 0..num_components {
            let s_size = BigEndian::read_u16(&bytes[spl..(spl + 2)].to_vec());
            let component = CountedOctetString::from_raw_bytes(&bytes[spl..(spl + s_size as usize + 2)].to_vec());
            components.push(component);
            spl += s_size as usize + 2;
        } 
        let name_type = BigEndian::read_u32(&bytes[spl..spl+4].to_vec());
        spl += 4;
        let timestamp = BigEndian::read_u32(&bytes[spl..spl+4].to_vec());
        spl += 4;
        let vno8: u8 = bytes[spl];
        spl += 1;
        let k_size = BigEndian::read_u16(&bytes[spl + 2..spl + 4].to_vec());
        let key = Keyblock::from_bytes(&bytes[spl..(spl + k_size as usize + 4)].to_vec());
        spl += 4 + k_size as usize;
        let vno = BigEndian::read_u32(&bytes[spl..spl+4].to_vec());
        KeytabEntry {
            size,
            num_components,
            //realm,
            realm,
            components,
            name_type,
            timestamp,
            vno8,
            key,
            vno,
        } 
    }

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
    fn new(principal: &String, name_type: &String,
           timestamp: &u32, vno8: &u8,
           etype: &String, key: &String,
           vno: &u32)
           -> KeytabEntry { 
        let name_type: u32 = match PRINCIPAL_TYPES
            .iter()
            .find(|&x|x.shortname == name_type || x.name == name_type) {
                Some(nmatch) => nmatch.id.try_into().unwrap(),
                _ => panic!("nope"),
            };
        let principal: Vec<&str> = principal.split('@').collect();
        let components = CountedOctetString::from_components(principal[0]);
        let num_components: u16 = components.len().try_into().unwrap();
        let realm = CountedOctetString::from_string(principal[1]);
        let key = Keyblock::new(&etype, &key);
        let size:i32 = 25 + i32::from(realm.length + key.key.length + &components.iter().map(|x| x.length + 2).sum());
        KeytabEntry {
            size,
            num_components,
            //realm,
            realm,
            components,
            name_type,
            timestamp: *timestamp,
            vno8: *vno8,
            key,
            vno: *vno,
        }
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
    let vno: u32 = 9;
    let principal = String::from("delfino/test/test/test@COMPANY.INT");
    let timestamp = now_epoch();



    let entries = vec![KeytabEntry::new(&principal, &name_type, &timestamp, &vno8, &etype, &key, &vno)];

    let keytab = Keytab {
        file_format_version: 1282,
        entries: entries,

    };
   create_file(&keytab);
   let testfile = String::from("test3.txt");
   read_file(&testfile);
}

fn create_file(keytab: &Keytab) -> std::io::Result<()> {
    fs::write("test4.txt", keytab.to_bytes())?;
    dbg!(&keytab);
    Ok(())
}

fn read_file(path: &String) -> std::io::Result<()> {
    let bytes = fs::read(path)?;
    let test = Keytab::from_bytes(&bytes); 
    create_file(&test);


    Ok(())
}
