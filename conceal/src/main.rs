extern crate conceal_core;
use anyhow::Result;
use structopt::StructOpt;

pub mod commands;
pub use commands::{Command, KeyFile, Opts};

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = Command::from_args();
    let result = match cmd {
        Command::Generate { key_file } => commands::generate(key_file).await,
        Command::Encrypt {
            opts,
            use_psk,
            recipient,
            hash,
            cipher,
        } => commands::encrypt(opts, recipient, use_psk, hash, cipher).await,
        Command::Decrypt { opts, psk } => commands::decrypt(opts, psk).await,
        Command::ShowId { key_file } => commands::show_id(key_file).await,
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
    Ok(())
}
