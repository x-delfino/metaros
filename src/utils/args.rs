use std::path::PathBuf;

use clap::{AppSettings, Parser, Subcommand, Args};

#[derive(Debug, Parser)]
#[clap(author, version, about)]
#[clap(global_setting(AppSettings::PropagateVersion))]
#[clap(global_setting(AppSettings::UseLongFormatForHelpSubcommand))]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[clap(subcommand)]
    /// For working with Keytabs
    Keytab (KeytabCommands),
}


#[derive(Debug, Subcommand)]
pub enum KeytabCommands {
    /// Create Keytab file from principal name and key (AES/NTLM/*)
    Create (KeytabCreate),
    /// Display parsed contents of a Keytab file
    Read (KeytabRead),
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
