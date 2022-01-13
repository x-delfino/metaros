use std::{fmt, fs, error::Error};
use std::path::Path;
use byteorder::{ByteOrder, BigEndian};
use crate::kerberos::reference;
use chrono::{TimeZone, Utc};
use serde::Deserialize;


#[derive (Deserialize)]
pub struct Keytab {
    pub file_format_version: u16,
    pub entries: Vec<KeytabEntry>,
}

impl Keytab {
    pub fn new(entries: Vec<KeytabEntry>) -> Keytab {
        Keytab {
            file_format_version: 1282,
            entries,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.file_format_version.to_be_bytes().to_vec();
        for e in &self.entries {
            bytes.extend(e.to_bytes());
        }
        bytes
    }
    pub fn from_bytes(bytes: &Vec<u8>) -> Keytab {
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
    pub fn from_csv(path: &dyn AsRef<Path>) -> Result<Keytab, Box<dyn Error>> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(path)?;
        let mut entries: Vec<KeytabEntry> = Vec::new();
        for result in rdr.deserialize() {
            let entry: CsvEntry = result?;
            let name_type = match entry.kind {
                Some(k) => k,
                _ => "krb_nt_principal".to_string(),
            };
            let timestamp: u32 = match entry.timestamp {
                Some(t) => t.try_into().unwrap(),
                _ => Utc::now().timestamp().try_into().unwrap(),
            };
            let version: u32 = match entry.version {
                Some(v) => v.try_into().unwrap(),
                _ => 0,
            };
            let entry = KeytabEntry::new(
                &entry.principal,
                &name_type,
                &timestamp,
                &version.try_into().unwrap(),
                &entry.etype,
                &entry.key,
                &version,
            );
            entries.push(entry);
        };
        let keytab = Keytab::new(entries);
        Ok(keytab)
    }

    pub fn from_file(path: &dyn AsRef<Path>) -> Result<Keytab, Box<dyn Error>> {
        let bytes = fs::read(path)?;
        Ok(Keytab::from_bytes(&bytes))
    }
    
    pub fn to_file(&self, path: &dyn AsRef<Path>) -> Result<(), Box<dyn Error>> {
        fs::write(path, &self.to_bytes())?;
        Ok(())
    }
}
 

#[derive (Deserialize)]
pub struct KeytabEntry {
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

impl fmt::Display for Keytab {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"Keytab Format: {}\n", self.file_format_version)?;
        write!(f,"Entries: {}\n", self.entries.len())?;
        for (i, entry) in self.entries.iter().enumerate() {
            write!(f,"Entry[{}]\n", i + 1)?;
            write!(f,"{}\n", entry)?;
        };
        write!(f,"")
    }
}

impl fmt::Display for KeytabEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut principal: String = String::new(); 
        for i in 0..self.num_components as usize {
            principal.push_str(&self.components[i].to_string());
            principal.push('/'); 
        }
        principal.pop(); 
        principal.push('@'); 
        principal.push_str(&self.realm.to_string()); 
        write!(f,"Size: {} bytes\n", self.size)?;
        write!(f,"Principal: {}\n", principal)?;
        write!(f,"Name Type: {}\n", (reference::PRINCIPAL_TYPES.lookup(&self.name_type)).name)?;
        write!(f,"Timestamp: {}\n", (Utc.timestamp(self.timestamp as i64, 0)).to_rfc2822())?;
        write!(f,"Vno8: {}\n", self.vno8)?;
        write!(f,"{}", self.key)?;
        write!(f,"Vno: {}\n", self.vno)
    }
}

impl KeytabEntry {
    fn from_bytes(bytes: &Vec<u8>) -> KeytabEntry {
        let size = BigEndian::read_i32(&bytes[0..4].to_vec());
        let num_components = BigEndian::read_u16(&bytes[4..6].to_vec());
        let r_size = BigEndian::read_u16(&bytes[6..8].to_vec());
        let realm = CountedOctetString::from_bytes(&bytes[6.. r_size as usize + 8].to_vec(), CosKind::Text);
        let mut spl: usize = 8 + r_size as usize;
        let mut components: Vec<CountedOctetString> =Vec::new();
        for _ in 0..num_components {
            let s_size = BigEndian::read_u16(&bytes[spl..(spl + 2)].to_vec());
            let component = CountedOctetString::from_bytes(
                &bytes[spl..(spl + s_size as usize + 2)]
                .to_vec(),
                CosKind::Text);
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
    pub fn new(principal: &String, name_type: &String,
           timestamp: &u32, vno8: &u8,
           etype: &String, key: &String,
           vno: &u32) -> KeytabEntry { 
        let name_type: u32 = (reference::PRINCIPAL_TYPES.lookup(name_type)).id.try_into().unwrap();
        let principal: Vec<&str> = principal.split('@').collect();
        let components = CountedOctetString::from_components(principal[0]);
        let num_components: u16 = components.len().try_into().unwrap();
        let realm = CountedOctetString::from_string(principal[1]);
        let key = Keyblock::new(&etype, &key);
        let size:i32 = 25 + i32::from(
            realm.length + 
            key.key.length + 
            &components.iter().map(
                |x| x.length + 2).sum()
            );
        KeytabEntry {
            size,
            num_components,
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


#[derive (Deserialize)]
struct CountedOctetString {
    length: u16,
    data: Vec<u8>,
    kind: CosKind,
}

impl fmt::Display for CountedOctetString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self.kind {
            CosKind::Text => "Decoded:",
            CosKind::Hex => "Key:",
        };
        write!(f,"{} {} ({} bytes)\n", msg, self.to_string(), self.length)
    }
}

impl CountedOctetString {
    fn from_hex(data: &str)  -> CountedOctetString {
        let hexbytes = match hex::decode(data) {
            Ok(decoded) => decoded,
            Err(_) => panic!("dead"),
        };
        CountedOctetString::from_uncounted_bytes(hexbytes, CosKind::Hex)
    }

    fn from_string(data: &str) -> CountedOctetString {
        let strbytes = data.as_bytes().to_vec();
        CountedOctetString::from_uncounted_bytes(strbytes, CosKind::Text)
    }

    fn from_components(data: &str) -> Vec<CountedOctetString> {
        let components: Vec<&str> = data.split('/').collect();
        let mut cosv = Vec::new(); 
        for c in components {
            let c = CountedOctetString::from_uncounted_bytes(c.as_bytes().to_vec(), CosKind::Text);
            cosv.push(c);
        }
        cosv
    }

    fn from_uncounted_bytes(data: Vec<u8>, kind: CosKind) -> CountedOctetString {
        let length: u16 = data.len().try_into().unwrap();
        CountedOctetString {
            length,
            data,
            kind, 
        }
    }
    
    fn to_string(&self) -> String {
        let data = self.data.clone();
        let decoded = match self.kind {
            CosKind::Text => String::from_utf8(data).unwrap(),
            CosKind::Hex => hex::encode(data), 
        };
        decoded.to_string()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes  = self.length.to_be_bytes().to_vec();
        bytes.extend(self.data.clone());
        bytes 
    }

    fn from_bytes(bytes: &Vec<u8>, kind: CosKind) -> CountedOctetString {
        let length = BigEndian::read_u16(&bytes[0..2].to_vec()); 
        let data = bytes[2..].to_vec();
        CountedOctetString {
            length,
            data,
            kind,
        }
    }
}


#[derive (Deserialize)]
enum CosKind {
    Text,
    Hex,
}


#[derive (Deserialize)]
struct Keyblock {
    key_type: u16,
    key: CountedOctetString,
}

impl fmt::Display for Keyblock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"Type: {} ({})\n", (reference::ENCRYPTION_TYPES.lookup(self.key_type)).name, self.key_type)?;
        write!(f,"{}", self.key)
    }
}

impl Keyblock {
    fn to_bytes(&self) -> Vec<u8> { 
        let mut bytes = self.key_type.to_be_bytes().to_vec();
        bytes.extend(self.key.to_bytes());
        bytes
    }

    fn new(etype: &String, key: &String) -> Keyblock {
        let key = CountedOctetString::from_hex(key);
        let etype: u16 = (reference::ENCRYPTION_TYPES.lookup(etype)).id.try_into().unwrap();
       Keyblock {
           key_type: etype,
           key,
       }
    }
    
    fn from_bytes(bytes: &Vec<u8>) -> Keyblock {
        Keyblock {
            key_type: BigEndian::read_u16(&bytes[0..2].to_vec()),
            key: CountedOctetString::from_bytes(&bytes[2..].to_vec(), CosKind::Hex),
        }
    }

}


#[derive (Deserialize)]
pub struct CsvEntry {
    pub principal: String,
    pub etype: String,
    pub key: String,
    pub kind: Option<String>,
    pub timestamp: Option<u32>,
    pub version: Option<u32>,
}
       

