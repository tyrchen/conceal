use crate::{
    commands::{generate_psk, read_keypair},
    Opts,
};
use anyhow::Result;
use conceal_core::{Header, PublicKey, Session, SessionConfig};
use std::str;

/// encrypt a file
pub async fn encrypt(
    opts: Opts,
    recipient: PublicKey,
    use_psk: bool,
    hash: i32,
    cipher: i32,
) -> Result<()> {
    let header = Header::new(cipher, hash, use_psk, Vec::new());
    let keypair = read_keypair(&opts.key_file.name).await?;
    let psk = if use_psk {
        // we generate psk for user
        let v = generate_psk();
        println!("Generated psk: {}", str::from_utf8(&v).unwrap());
        Some(v)
    } else {
        None
    };
    let config = SessionConfig::new(header, Some(recipient.to_vec()), keypair, psk);
    let mut session = Session::new(config)?;
    let len = session.encrypt_file(&opts.src, &opts.dst)?;
    println!("encrypted {} bytes for {:?}", len, &opts.dst);
    Ok(())
}
