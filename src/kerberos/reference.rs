#[derive(Debug)]
pub struct RefTable {
    entries: Vec<RefItem>,    
}

#[derive(Debug)]
pub struct RefItem {
    pub name: &'static str,
    pub shortname: Option<&'static str>,
    pub id: u8,
}

impl RefTable {
    pub fn lookup<T: ToString>(&self, query: T) -> &RefItem {
        let query = query.to_string();
        match &self.entries
            .iter()
            .find(|&x|x.shortname.unwrap() == query || x.name == query || x.id.to_string() == query) {
                Some(nmatch) => nmatch, 
                _ => panic!("{} not found", query)
            }
    }
}


lazy_static! {
    // https://www.rfc-editor.org/rfc/rfc3961.html#section-8
    pub static ref ENCRYPTION_TYPES: RefTable = RefTable {
        entries: vec![
            RefItem{
                name: "des-cbc-crc",
                shortname: Some("des-crc"),
                id: 1,
            },
            RefItem{
                name: "des-cbc-md4",
                shortname: Some("des-md4"),
                id: 2,
            },
            RefItem{
                name: "des-cbc-md5",
                shortname: Some("des-md5"),
                id: 3,
            },
            RefItem{
                name: "des3-cbc-md5",
                shortname: Some("des3-md5"),
                id: 5,
            },
            RefItem{
                name: "des3-cbc-sha1",
                shortname: Some("des3-sha1"),
                id: 7,
            },
            RefItem{
                name: "dsaWithSHA1-CmsOID",
                shortname: None,
                id: 9,
            },
            RefItem{
                name: "md5WithRSAEncryption-CmsOID",
                shortname: None,
                id: 10,
            },
            RefItem{
                name: "sha1WithRSAEncryption-CmsOID",
                shortname: None,
                id: 11,
            },
            RefItem{
                name: "rc2CBC-EnvOID",
                shortname: None,
                id: 12,
            },
            RefItem{
                name: "rsaEncryption-EnvOID",
                shortname: None,
                id: 13,
            },
            RefItem{
                name: "rsaES-OAEP-ENV-OID",
                shortname: None,
                id: 14,
            },
            RefItem{
                name: "des-ede3-cbc-Env-OID",
                shortname: None,
                id: 15,
            },
            RefItem{
                name: "des3-cbc-sha1-kd",
                shortname: None,
                id: 16,
            },
            RefItem{
                name: "rc4-hmac",
                shortname: None,
                id: 23,
            },
            RefItem{
                name: "aes128-cts-hmac-sha1-96",
                shortname: Some("aes128"),
                id: 17,
            },
            RefItem{
                name: "aes256-cts-hmac-sha1-96",
                shortname: Some("aes256"),
                id: 18,
            },
            RefItem{
                name: "rc4-hmac-exp",
                shortname: None,
                id: 24,
            },
            RefItem{
                name: "subkey-keymaterial",
                shortname: None,
                id: 65,
            },
        ],
    };
    pub static ref PRINCIPAL_TYPES: RefTable = RefTable {
        entries: vec![
            RefItem{
                name: "krb5_nt_principal",
                shortname: Some("principal"),
                id: 1,
            },
        ],
    };
}


