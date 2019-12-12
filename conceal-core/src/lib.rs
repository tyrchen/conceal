// use bytes::{BufMut, BytesMut};
use snow::{Builder, Keypair, TransportState};
use std::path::Path;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

pub mod error;
use error::ConcealError;

pub const NOISE_PARAMS: &str = "Noise_X_25519_ChaChaPoly_BLAKE2b";
pub const NOISE_MESSAGE_MAX_BUFFER: usize = 65535;
pub const NOISE_MESSAGE_MAX_SIZE: usize = NOISE_MESSAGE_MAX_BUFFER - 16;

pub const FILE_READ_SIZE: usize = 16384;

#[derive(Debug)]
pub enum Mode {
    Initiator,
    Responder,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Initiator
    }
}

pub struct SessionConfig {
    /// noise params
    pub params: String,
    /// remote static pub key. Initiator must have this but for responder this is an option
    pub rs: Option<Vec<u8>>,
    /// local static keypair
    pub keypair: Keypair,
    /// initiator's handshake message. If None, this is to encrypt, if Some, this is to decrypt
    pub handshake_message: Option<Vec<u8>>,
}

impl SessionConfig {
    pub fn new(
        params: Option<String>,
        rs: Option<Vec<u8>>,
        keypair: Keypair,
        handshake_message: Option<Vec<u8>>,
    ) -> Self {
        let params = if let Some(v) = params {
            v
        } else {
            NOISE_PARAMS.to_owned()
        };
        Self {
            params,
            rs,
            keypair,
            handshake_message,
        }
    }
}

#[derive(Debug)]
pub struct Session {
    /// Transport state
    pub state: TransportState,
    /// handshake message
    pub handshake_message: Vec<u8>,
}

impl Session {
    pub fn new(config: SessionConfig) -> Result<Self, ConcealError> {
        let noise_params = config.params.parse()?;
        // in handshake mode this should be enough
        let mut buf = [0u8; 256];

        if config.handshake_message.is_some() {
            // responder
            let mut noise = Builder::new(noise_params)
                .local_private_key(&config.keypair.private)
                .build_responder()?;
            let handshake_message = config.handshake_message.unwrap();
            let _len = noise.read_message(&handshake_message, &mut buf)?;
            let state = noise.into_transport_mode()?;
            Ok(Self {
                state,
                handshake_message,
            })
        } else {
            // initiator
            let mut noise = Builder::new(noise_params)
                .remote_public_key(&config.rs.unwrap())
                .local_private_key(&config.keypair.private)
                .build_initiator()?;

            let len = noise.write_message(&[0u8; 0], buf.as_mut())?;
            let handshake_message = buf[..len].to_vec();
            let state = noise.into_transport_mode()?;
            Ok(Self {
                state,
                handshake_message,
            })
        }
    }

    pub async fn encrypt_file(
        &mut self,
        infile: impl AsRef<Path>,
        outfile: impl AsRef<Path>,
    ) -> Result<usize, ConcealError> {
        let (chunks, remainder) = Self::get_chunks(&infile, NOISE_MESSAGE_MAX_SIZE, 0).await?;
        let mut fi = File::open(infile).await?;
        let mut fo = File::create(outfile).await?;
        let mut in_buf = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let mut out_buf = vec![0u8; NOISE_MESSAGE_MAX_BUFFER];
        let mut total_size = self.handshake_message.len() + 2;
        self.write_header(&mut fo).await?;

        for _i in 0..chunks {
            let len = fi.read_exact(&mut in_buf).await?;
            let len = self.state.write_message(&in_buf[..len], &mut out_buf)?;
            fo.write_all(&out_buf[..len]).await?;
            total_size += len;
        }
        // write the remainder
        let len = fi.read_exact(&mut in_buf[..remainder]).await?;
        let len = self.state.write_message(&in_buf[..len], &mut out_buf)?;
        let len = fo.write(&mut out_buf[..len]).await?;
        fo.sync_all().await?;

        total_size += len;
        Ok(total_size)
    }

    pub async fn decrypt_file(
        keypair: Keypair,
        infile: impl AsRef<Path>,
        outfile: impl AsRef<Path>,
    ) -> Result<usize, ConcealError> {
        let mut fi = File::open(&infile).await?;
        let handshake_message = Self::read_header(&mut fi).await?;

        let (chunks, remainder) = Self::get_chunks(
            &infile,
            NOISE_MESSAGE_MAX_BUFFER,
            handshake_message.len() + 2,
        )
        .await?;

        let config = SessionConfig::new(None, None, keypair, Some(handshake_message));
        let mut session = Session::new(config)?;

        let mut fo = File::create(outfile).await?;
        let mut in_buf = vec![0u8; NOISE_MESSAGE_MAX_BUFFER];
        let mut out_buf = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let mut total_size = 0;

        for _i in 0..chunks {
            let len = fi.read_exact(&mut in_buf).await?;
            let len = session.state.read_message(&in_buf[..len], &mut out_buf)?;
            fo.write_all(&mut out_buf[..len]).await?;
            total_size += len;
        }
        // read the remainder
        let len = fi.read_exact(&mut in_buf[..remainder]).await?;
        let len = session.state.read_message(&in_buf[..len], &mut out_buf)?;
        fo.write_all(&mut out_buf[..len]).await?;
        fo.sync_all().await?;
        total_size += len;

        Ok(total_size)
    }

    // private functions
    async fn get_chunks(
        name: impl AsRef<Path>,
        size: usize,
        offset: usize,
    ) -> Result<(usize, usize), ConcealError> {
        let metadata = fs::metadata(name).await?;
        let len = metadata.len() as usize - offset;
        let chunks = len / size;
        let remainder = len % size;
        Ok((chunks, remainder))
    }

    async fn write_header(&self, file: &mut File) -> Result<(), ConcealError> {
        let len = self.handshake_message.len() as u16;
        file.write_u16(len).await?;
        file.write(&self.handshake_message).await?;
        Ok(())
    }

    async fn read_header(file: &mut File) -> Result<Vec<u8>, ConcealError> {
        let len = file.read_u16().await?;
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

pub fn generate_keypair() -> Result<Keypair, ConcealError> {
    let keypair = Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tokio::fs;

    #[tokio::test]
    async fn encrypt_file_shall_be_decrypted() -> Result<(), ConcealError> {
        let mut in_buf = vec![0; 256 * 1024];
        let fi1 = "/tmp/cleartext1";
        let fo = "/tmp/ciphertext";
        let fi2 = "/tmp/cleartext2";
        fill_file(fi1, &mut in_buf).await;
        // fs::write(fi1, b"hello world").await.unwrap();

        let client_keypair = generate_keypair().unwrap();
        let server_keypair = generate_keypair().unwrap();

        // encrypt
        let client_config = SessionConfig::new(
            None,
            Some(server_keypair.public.clone()),
            client_keypair,
            None,
        );
        let mut client_session = Session::new(client_config)?;
        let len = client_session.encrypt_file(fi1, fo).await?;
        println!("encrypted: {}", len);
        // decrypt
        let len = Session::decrypt_file(server_keypair, fo, fi2).await?;
        println!("decrypted: {}", len);
        let out_buf = fs::read(fi2).await?;
        assert_eq!(in_buf, out_buf);
        Ok(())
    }

    async fn fill_file(name: impl AsRef<Path>, buf: &mut [u8]) {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buf);
        fs::write(name, buf).await.unwrap();
    }
}
