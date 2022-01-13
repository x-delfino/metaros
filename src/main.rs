#[macro_use]
extern crate lazy_static;

mod kerberos;
mod utils;

use crate::kerberos::keytab;
use crate::utils::args;
use std::error::Error;
use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = args::Cli::parse();
    match &cli.command {
        args::Commands::Keytab(c) => {
            match c {
                args::KeytabCommands::Create(x) => {
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
                args::KeytabCommands::Read(x) => {
                    println!("Reading: {}", x.infile.display());
                    println!(
                        "{}", 
                        keytab::Keytab::from_file(&x.infile).unwrap()
                    );
                },
            }

        }
    }
    Ok(())
 //   let etype = String::from("aes128");   
 //   let key = String::from("f9a9c510c3aeb65f58d6b38d6284ba36");
 //   let name_type = String::from("principal");   
 //   let vno8: u8 = 9;
 //   let vno: u32 = 9;
 //   let principal = String::from("delfino/server01.ad.company.com:1433@COMPANY.INT");
 //   let timestamp: u32 = Utc::now().timestamp().try_into().unwrap();
 //   let entries = vec![keytab::KeytabEntry::new(&principal, &name_type, &timestamp, &vno8, &etype, &key, &vno)];
 //   let keytab = keytab::Keytab::new(entries);
 //   let something = keytab::Keytab::from_csv(&"testdeets.txt".to_string()).unwrap();
 //   println!("{}",&something);
 //   let something2 = keytab::Keytab::from_file(&"test3.txt".to_string()).unwrap();
 //   println!("test2{}",&something2);
}


