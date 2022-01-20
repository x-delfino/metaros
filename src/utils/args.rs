use std::path::PathBuf;

use clap::{ArgEnum, AppSettings, Parser, Subcommand, Args};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(global_setting(AppSettings::PropagateVersion))]
#[clap(global_setting(AppSettings::UseLongFormatForHelpSubcommand))]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
    #[clap(short, long,
        global(true), 
        parse(from_occurrences))]
    pub verbose: u64,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[clap(subcommand)]
    /// For working with Keytabs
    Keytab (KeytabCommands),
    #[clap(subcommand)]
    /// For working with keys & hashes
    Key (KeyCommands),
}


#[derive(Debug, Subcommand)]
pub enum KeytabCommands {
    /// Create Keytab file from principal name and key (AES/NTLM/*)
    Create (KeytabCreate),
    /// Display parsed contents of a Keytab file
    Read (KeytabRead),
}

#[derive(Debug, Subcommand)]
pub enum KeyCommands {
    /// Derive keys and hashes used in Windows authentication
    Derive (KeyDerive)
}


#[derive(Debug, Args)]
pub struct KeytabCreate {
    #[clap(
        short, long,
        required_unless_present("infile"))]
    pub principal: Option<String>,

    #[clap(
        short, long,
        required_unless_present("infile"))]
    pub etype: Option<String>,

    #[clap(
        short, long,
        required_unless_present("infile"))]
    pub key: Option<String>,

    #[clap(
        short, long,
        required_unless_present("infile"))]
    pub name_type: Option<String>,

    #[clap(short, long)]
    pub timestamp: Option<u32>,

    #[clap(short, long)]
    pub version: Option<u32>,

    #[clap(
        short, long,
        parse(from_os_str)
    )]
    pub infile: Option<PathBuf>,

    #[clap(
        short, long,
        parse(from_os_str)
    )]
    pub outfile: PathBuf,
}


#[derive(Debug, Args)]
pub struct KeytabRead {
    #[clap(short, long, parse(from_os_str))]
    pub infile: PathBuf,
}


#[derive(Debug, Args)]
pub struct KeyDerive {
    #[clap(arg_enum, short, long,
        required_unless_present("all"))]
    pub etype: Option<Etypes>,
    #[clap(short, long,
        required_if_eq_any(&[
            ("etype", "aes128"),
            ("etype", "aes256"),
            ("etype", "des"),
        ]),
    )]
    pub salt: Option<String>,
    #[clap(short, long)]
    pub password: String,
    #[clap(short, long,
        requires("salt")
    )]
    pub all: bool,
}

#[derive(Debug, ArgEnum, Clone)]
pub enum Etypes {
    Aes128,
    Aes256,
    Des,
    Rc4,
    Ntlm,
    Lm
}

