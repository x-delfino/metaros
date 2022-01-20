#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

mod kerberos;
mod utils;
mod crypto;

use crate::kerberos::keytab;
use crate::utils::args::*;
use crate::crypto::{aes, des, lanman, crypto::*};
use std::error::Error;
use clap::Parser;
use loggerv;

fn main() -> Result<(), Box<dyn Error>> {

    let cli = Cli::parse();
    loggerv::Logger::new()
        .verbosity(cli.verbose)
        .module_path(false)
        .init()
        .unwrap();
    match &cli.command {
        Commands::Keytab(c) => {
            match c {
                KeytabCommands::Create(x) => {
                    let kt: keytab::Keytab;
                    match &x.infile {
                        Some(f) => {
                            println!("Input File:{}",f.display());
                            kt = keytab::Keytab::from_csv(f).unwrap();
                        },
                        None => {
                            println!("no infile");
                            kt = keytab::Keytab::new(
                                vec![keytab::KeytabEntry::new(
                                    &x.principal.as_ref().unwrap(),
                                    &x.name_type.as_ref().unwrap(),
                                    &x.timestamp.unwrap(),
                                    &x.version.unwrap().try_into().unwrap(),
                                    &x.etype.as_ref().unwrap(),
                                    &x.key.as_ref().unwrap(),
                                    &x.version.unwrap(),
                                )]
                            );
                        },
                    }
                    kt.to_file(&x.outfile)?;
                },
                KeytabCommands::Read(x) => {
                    println!("Reading: {}", x.infile.display());
                    println!(
                        "{}", 
                        keytab::Keytab::from_file(&x.infile).unwrap()
                    );
                },
            }

        }
        Commands::Key(c) => {
            match c {
                KeyCommands::Derive(sc) => {
                    if sc.all {
                        println!("lets do all");
                        println!("[AES128] {}",
                            hex::encode_upper(
                                aes::KrbAes128::string_to_key(
                                    &sc.password,
                                    &sc.salt.as_ref().unwrap() 
                                )
                            )
                        );
                        println!("[AES256] {}", 
                            hex::encode_upper(
                                aes::KrbAes256::string_to_key(
                                    &sc.password,
                                    &sc.salt.as_ref().unwrap()
                                )
                            )
                        );
                        println!("[DES] {}", 
                            hex::encode_upper(
                                des::KrbDes::string_to_key(
                                    &sc.password,
                                    &sc.salt.as_ref().unwrap() 
                                )
                            )
                        );
                        println!("[RC4/NTLM] {}", 
                            hex::encode_upper(
                                lanman::NTLanMan::from_string(
                                    &sc.password,
                                )
                            )
                        );
                        println!("[LM] {}",
                            hex::encode_upper(
                                lanman::LanMan::from_string(
                                    &sc.password,
                                )
                            )
                        );
                    }
                    else {
                        match &sc.etype.as_ref().unwrap() {
                            Etypes::Aes128 => {
                                println!("[AES128] {}", 
                                    hex::encode_upper(
                                        aes::KrbAes128::string_to_key(
                                            &sc.password,
                                            &sc.salt.as_ref().unwrap() 
                                        )
                                    )
                                );
                            }
                            Etypes::Aes256 => {
                                println!("[AES256] {}", 
                                    hex::encode_upper(
                                        aes::KrbAes256::string_to_key(
                                            &sc.password,
                                            &sc.salt.as_ref().unwrap() 
                                        )
                                    )
                                );
                            }
                            Etypes::Des => {
                                println!("[DES] {}", 
                                    hex::encode_upper(
                                        des::KrbDes::string_to_key(
                                            &sc.password,
                                            &sc.salt.as_ref().unwrap() 
                                        )
                                    )
                                );
                            }
                            Etypes::Rc4 | Etypes::Ntlm => {
                                println!("[RC4/NTLM] {}", 
                                    hex::encode_upper(
                                        lanman::NTLanMan::from_string(
                                            &sc.password,
                                        )
                                    )
                                );
                            }
                            Etypes::Lm => {
                                println!("[LM] {}",
                                    hex::encode_upper(
                                        lanman::LanMan::from_string(
                                            &sc.password,
                                        )
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}


