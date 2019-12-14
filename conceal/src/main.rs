extern crate conceal_core;
use anyhow::Result;
use structopt::StructOpt;
use tokio::runtime::Runtime;

pub mod commands;
pub use commands::{Command, KeyFile, Opts};

fn main() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let cmd = Command::from_args();
    let fut = async {
        match cmd {
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
        }
    };

    rt.block_on(fut)?;
    Ok(())
}
