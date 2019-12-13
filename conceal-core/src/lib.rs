// use bytes::{BufMut, BytesMut};

use snow::{Builder, Keypair, TransportState};
use std::path::Path;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

pub mod error;
pub mod protos;
pub use error::ConcealError;
pub use protos::{CipherMode, HashMode, Header, Proto};

pub type Psk = [u8; 32];

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
    /// noise params. If the handshake_message is empty, this is to encrypt, otherwise, this is to decrypt
    pub header: Header,
    /// remote static pub key. Initiator must have this but for responder this is an option
    pub rs: Option<Vec<u8>>,
    /// local static keypair
    pub keypair: Keypair,
    /// psk
    pub psk: Option<Psk>,
}

impl SessionConfig {
    pub fn new(header: Header, rs: Option<Vec<u8>>, keypair: Keypair, psk: Option<Psk>) -> Self {
        Self {
            header,
            rs,
            keypair,
            psk,
        }
    }
}

#[derive(Debug)]
pub struct Session {
    /// Transport state
    pub state: TransportState,
    /// Session handshake related info
    pub header: Header,
}

impl Session {
    pub fn new(config: SessionConfig) -> Result<Self, ConcealError> {
        let mut header = config.header;
        let noise_params = header.to_string().parse()?;
        // in handshake mode this should be enough
        let mut buf = [0u8; 256];

        if header.handshake_message.is_empty() {
            // initiator
            let mut noise = if !header.use_psk {
                Builder::new(noise_params)
                    .remote_public_key(&config.rs.unwrap())
                    .local_private_key(&config.keypair.private)
                    .build_initiator()?
            } else {
                Builder::new(noise_params)
                    .remote_public_key(&config.rs.unwrap())
                    .local_private_key(&config.keypair.private)
                    .psk(1, &config.psk.unwrap())
                    .build_initiator()?
            };

            let len = noise.write_message(&[0u8; 0], buf.as_mut())?;
            let handshake_message = buf[..len].to_vec();
            header.handshake_message = handshake_message;
            let state = noise.into_transport_mode()?;
            Ok(Self { state, header })
        } else {
            // responder
            let mut noise = if !header.use_psk {
                Builder::new(noise_params)
                    .local_private_key(&config.keypair.private)
                    .build_responder()?
            } else {
                Builder::new(noise_params)
                    .local_private_key(&config.keypair.private)
                    .psk(1, &config.psk.unwrap())
                    .build_responder()?
            };
            let _len = noise.read_message(&header.handshake_message, &mut buf)?;
            let state = noise.into_transport_mode()?;
            Ok(Self { state, header })
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

        let len = self.write_header(&mut fo).await?;
        let mut total_size = len;

        for _i in 0..chunks {
            let len = self
                .write_chunk(&mut fi, &mut fo, &mut in_buf, &mut out_buf)
                .await?;
            total_size += len;
        }
        // write the remainder
        let len = self
            .write_chunk(&mut fi, &mut fo, &mut in_buf[..remainder], &mut out_buf)
            .await?;
        total_size += len;
        fo.sync_all().await?;

        Ok(total_size)
    }

    pub async fn decrypt_file(
        keypair: Keypair,
        psk: Option<Psk>,
        infile: impl AsRef<Path>,
        outfile: impl AsRef<Path>,
    ) -> Result<usize, ConcealError> {
        let mut fi = File::open(&infile).await?;
        let (header, len) = Self::read_header(&mut fi).await?;

        let (chunks, remainder) = Self::get_chunks(&infile, NOISE_MESSAGE_MAX_BUFFER, len).await?;

        if header.use_psk && psk.is_none() {
            return Err(ConcealError::InvalidPsk);
        }
        let config = SessionConfig::new(header, None, keypair, psk);
        let mut session = Session::new(config)?;

        let mut fo = File::create(outfile).await?;
        let mut in_buf = vec![0u8; NOISE_MESSAGE_MAX_BUFFER];
        let mut out_buf = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let mut total_size = 0;

        for _i in 0..chunks {
            let len = session
                .read_chunk(&mut fi, &mut fo, &mut in_buf, &mut out_buf)
                .await?;
            total_size += len;
        }
        // read the remainder
        let len = session
            .read_chunk(&mut fi, &mut fo, &mut in_buf[..remainder], &mut out_buf)
            .await?;
        total_size += len;
        fo.sync_all().await?;

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

    async fn write_header(&self, file: &mut File) -> Result<usize, ConcealError> {
        let mut buf = Vec::with_capacity(128);
        self.header.to_bytes(&mut buf)?;
        let len = buf.len() as u16;
        file.write_u16(len).await?;
        file.write(&buf).await?;
        Ok((len + 2) as usize)
    }

    async fn read_header(file: &mut File) -> Result<(Header, usize), ConcealError> {
        let len = file.read_u16().await?;
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf).await?;
        let header = Header::from_bytes(&buf)?;
        Ok((header, (len + 2) as usize))
    }

    async fn write_chunk(
        &mut self,
        fi: &mut File,
        fo: &mut File,
        in_buf: &mut [u8],
        out_buf: &mut [u8],
    ) -> Result<usize, ConcealError> {
        let len = fi.read_exact(in_buf).await?;
        let len = self.state.write_message(&in_buf[..len], out_buf)?;
        fo.write_u16(len as u16).await?;
        fo.write_all(&out_buf[..len]).await?;
        Ok((len + 2) as usize)
    }

    async fn read_chunk(
        &mut self,
        fi: &mut File,
        fo: &mut File,
        in_buf: &mut [u8],
        out_buf: &mut [u8],
    ) -> Result<usize, ConcealError> {
        let len = fi.read_u16().await? as usize;
        let len = fi.read_exact(&mut in_buf[..len]).await?;
        let len = self.state.read_message(&in_buf[..len], out_buf)?;
        fo.write_all(&mut out_buf[..len]).await?;
        Ok((len + 2) as usize)
    }
}

pub fn generate_keypair() -> Result<Keypair, ConcealError> {
    let keypair = Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use rand::RngCore;
    use tokio::fs;

    #[tokio::test]
    async fn default_params_shall_work() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Blake2b,
            false,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024, 4 * 1024 * 1024],
        )
        .await?;

        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn default_params_with_psk_shall_work() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Blake2b,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;

        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn cha_cha_poly_blake2s() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Blake2s,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;

        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn cha_cha_poly_sha512() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Sha512,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;

        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn cha_cha_poly_sha256() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Sha256,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;
        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn aes_blake2b() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::Aesgcm,
            HashMode::Blake2b,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;
        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn aes_blake2s() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::Aesgcm,
            HashMode::Blake2s,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;
        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn aes_sha512() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::Aesgcm,
            HashMode::Sha512,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;
        assert_eq!(result, true);
        Ok(())
    }

    #[tokio::test]
    async fn aes_sha256() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::Aesgcm,
            HashMode::Sha256,
            true,
            vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
        )
        .await?;
        assert_eq!(result, true);
        Ok(())
    }
    // private functions
    async fn encrypt_decrypt(header: Header, file_size: usize) -> Result<bool, ConcealError> {
        let mut in_buf = vec![0; file_size];
        let fi1 = format!("/tmp/cleartext1_{}_{}", header, file_size);
        let fo = format!("/tmp/ciphertext_{}_{}", header, file_size);
        let fi2 = format!("/tmp/cleartext2_{}_{}", header, file_size);
        fill_file(&fi1, &mut in_buf).await;
        // fs::write(fi1, b"hello world").await.unwrap();

        let client_keypair = generate_keypair().unwrap();
        let server_keypair = generate_keypair().unwrap();
        let psk: Option<Psk> = if header.use_psk {
            Some(*b"super secret 32 bytes length str")
        } else {
            None
        };

        // encrypt
        let client_config = SessionConfig::new(
            header,
            Some(server_keypair.public.clone()),
            client_keypair,
            psk,
        );
        let mut client_session = Session::new(client_config)?;
        let _len = client_session.encrypt_file(&fi1, &fo).await?;

        // decrypt
        let _len = Session::decrypt_file(server_keypair, psk, &fo, &fi2).await?;
        let out_buf = fs::read(&fi2).await?;

        Ok(in_buf == out_buf)
    }

    async fn param_combination(
        cipher: CipherMode,
        hash: HashMode,
        use_psk: bool,
        params: Vec<usize>,
    ) -> Result<bool, ConcealError> {
        let header = Header::new(cipher, hash, use_psk, Vec::new());
        let futs: Vec<_> = params
            .iter()
            .map(|size| encrypt_decrypt(header.clone(), size.to_owned()))
            .collect();
        let result = join_all(futs)
            .await
            .iter()
            .all(|v| v.as_ref().unwrap().to_owned());
        Ok(result)
    }

    async fn fill_file(name: impl AsRef<Path>, buf: &mut [u8]) {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buf);
        fs::write(name, buf).await.unwrap();
    }
}
