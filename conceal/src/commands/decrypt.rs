use crate::{commands::read_keypair, Opts};
use anyhow::Result;
use conceal_core::{Psk, Session};

/// decrypt a file
pub async fn decrypt(opts: Opts, psk: Option<Psk>) -> Result<()> {
    let keypair = read_keypair(&opts.key_file.name).await?;

    let len = Session::decrypt_file(keypair, psk, &opts.src, &opts.dst)?;
    println!("decrypted {} bytes for {:?}", len, &opts.dst);
    Ok(())
}
