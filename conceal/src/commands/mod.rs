use anyhow::{anyhow, Result};
use conceal_core::{Keypair, Psk, PublicKey};
use rand::RngCore;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::fs;

mod decrypt;
mod encrypt;
mod key_file;

pub use decrypt::decrypt;
pub use encrypt::encrypt;
pub use key_file::{generate, show_id};

fn parse_psk(src: &str) -> Result<Psk> {
    let mut buf = [0u8; 32];
    let slice = src.as_bytes();
    if slice.len() != buf.len() {
        return Err(anyhow!("pre shared key must be 32 bytes long"));
    }
    buf.copy_from_slice(src.as_bytes());
    Ok(buf)
}

fn parse_pk(src: &str) -> Result<PublicKey> {
    let pk = bs58::decode(src.as_bytes()).into_vec()?;
    if pk.len() != 32 {
        return Err(anyhow!("Please provide a valid public key by recipient (she could do `conceal show-id` to get the key)"));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&pk[..]);
    Ok(buf)
}

fn parse_dir(src: &str) -> PathBuf {
    if src.starts_with("~/") {
        dirs::home_dir().unwrap().join(src.replace("~/", ""))
    } else {
        PathBuf::from(src)
    }
}

/// encrypt a file for a specific recipient or decrypt a sealed file for myself
#[derive(StructOpt, Debug)]
#[structopt(name = "conceal")]
pub enum Command {
    /// encrypt a file for a specific recipent
    Encrypt {
        #[structopt(flatten)]
        opts: Opts,
        /// pre-shared key to enhance security (the recipient shall have this as well). If enabled, it will be auto generated.
        #[structopt(long)]
        use_psk: bool,

        /// base58 string of the ed25519 public key of the recipient
        #[structopt(short = "r", long, parse(try_from_str=parse_pk))]
        recipient: PublicKey,

        /// hash algorithm to use
        #[structopt(long, default_value = "0")]
        hash: i32,

        /// cipher algorithm to use
        #[structopt(long, default_value = "0")]
        cipher: i32,
    },

    /// decrypt a file with my keypair
    Decrypt {
        #[structopt(flatten)]
        opts: Opts,
        /// pre-shared key to enhance security (the recipient shall have this as well). Must be the same as what sender uses.
        #[structopt(long, parse(try_from_str=parse_psk))]
        psk: Option<Psk>,
    },

    /// generate a local keypair
    Generate {
        #[structopt(flatten)]
        key_file: KeyFile,
    },
    ShowId {
        #[structopt(flatten)]
        key_file: KeyFile,
    },
}

#[derive(StructOpt, Debug)]
pub struct KeyFile {
    /// keypair filename.
    #[structopt(
            name = "KEY_FILE",
            parse(from_str=parse_dir),
            default_value = "~/.conceal/identity"
        )]
    name: PathBuf,
}

#[derive(StructOpt, Debug)]
pub struct Opts {
    /// source filename to be encrypted or decrypted
    #[structopt(name = "SRC", parse(from_str=parse_dir))]
    src: PathBuf,

    /// target filename to be decrypted or encrypted
    #[structopt(name = "DST", parse(from_str=parse_dir))]
    dst: PathBuf,

    #[structopt(flatten)]
    key_file: KeyFile,
}

pub async fn write_file(name: &PathBuf, content: String) -> Result<()> {
    fs::create_dir_all(name.parent().unwrap()).await?;
    fs::write(name, content).await?;
    Ok(())
}

pub async fn read_keypair(name: &PathBuf) -> Result<Keypair> {
    let key = fs::read(name).await?;
    let buf = bs58::decode(&key).into_vec()?;
    let keypair = Keypair {
        public: buf[32..].to_vec(),
        private: buf[..32].to_vec(),
    };
    Ok(keypair)
}

fn generate_psk() -> Psk {
    let mut buf = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut buf);
    let result = bs58::encode(&buf).into_vec();
    buf.copy_from_slice(&result[..32]);
    buf
}
