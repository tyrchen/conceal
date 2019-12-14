use crate::{
    commands::{read_keypair, write_file},
    KeyFile,
};
use anyhow::Result;

/// generate a keypair and store it into given <key_file>
pub async fn generate(key_file: KeyFile) -> Result<()> {
    let keypair = conceal_core::generate_keypair()?;
    let mut buf = keypair.private;
    buf.extend(keypair.public);

    let result = bs58::encode(&buf).into_string();
    write_file(&key_file.name, result).await?;
    println!("Keypair generated at: {:?}", key_file.name);
    Ok(())
}

/// show the public key as base58 string
pub async fn show_id(key_file: KeyFile) -> Result<()> {
    let keypair = read_keypair(&key_file.name).await?;
    let id = bs58::encode(&keypair.public).into_string();
    println!("Id: {}", id);
    Ok(())
}
