extern crate conceal_core;
use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

/// encrypt a file for a specific recipient or decrypt a sealed file for myself
#[derive(StructOpt, Debug)]
#[structopt(name = "conceal")]
struct Opt {
    /// decrypt a sealed file
    #[structopt(short, long)]
    decrypt: bool,

    /// pre-shared key to enhance security (the recipient shall have this as well). If enabled, it will be auto generated.
    #[structopt(long)]
    psk: bool,

    /// hash algorithm to use
    #[structopt(long, default_value = "0")]
    hash: i32,

    /// cipher algorithm to use
    #[structopt(long, default_value = "0")]
    cipher: i32,

    /// base58 string of the ed25519 public key of the recipient
    #[structopt(short, long)]
    recipient: String,

    /// files to be encrypted or decrypted
    #[structopt(name = "FILE", parse(from_os_str))]
    files: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    println!("{:#?}", opt);
    Ok(())
}
