// use bytes::{BufMut, BytesMut};

use byteorder::{BigEndian, ByteOrder};
use log::{debug, info, warn};
use memmap::{Mmap, MmapMut};
use prost::Message;
use snow::{Builder, TransportState};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

pub mod error;
pub mod protos;
pub use error::ConcealError;
pub use protos::{CipherMode, HashMode, Header, Proto};
pub use snow::Keypair;

pub type PublicKey = [u8; 32];

pub type Psk = [u8; 32];

pub const NOISE_PARAMS: &str = "Noise_X_25519_ChaChaPoly_BLAKE2b";
pub const NOISE_MESSAGE_MAX_BUFFER: usize = 65528;
pub const NOISE_MAC_SIZE: usize = 16;
pub const NOISE_ENCRYPT_LENGTH_SIZE: usize = 2;
pub const NOISE_MESSAGE_MAX_SIZE: usize = NOISE_MESSAGE_MAX_BUFFER - NOISE_MAC_SIZE;

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
struct Pos {
    pub offset: usize,
    pub len: usize,
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
            info!("Initiator handshake finished. Move into transport mode");
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
            info!("Responder handshake finished. Move into transport mode");
            Ok(Self { state, header })
        }
    }

    pub async fn encrypt_file(
        &mut self,
        infile: impl AsRef<Path> + fmt::Debug,
        outfile: impl AsRef<Path> + fmt::Debug,
    ) -> Result<usize, ConcealError> {
        let (chunks, remainder) = Self::get_chunks(&infile, NOISE_MESSAGE_MAX_SIZE, 0).await?;
        let fi = File::open(&infile)?;
        let fo = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&outfile)?;
        let total = self.get_enc_len(chunks, remainder);
        fo.set_len(total)?;
        info!("Encrypted file length: {}", total);

        let mi = unsafe { Mmap::map(&fi)? };
        let mut mo = unsafe { MmapMut::map_mut(&fo)? };

        let len = self.write_header(&mut mo)?;
        debug!("Encrypted file header length: {}", len);
        let mut mi_pos = Pos {
            offset: 0,
            len: NOISE_MESSAGE_MAX_SIZE,
        };
        let mut mo_pos = Pos {
            offset: len,
            len: NOISE_MESSAGE_MAX_BUFFER,
        };

        for i in 0..chunks {
            self.write_chunk(&mi, &mut mo, &mut mi_pos, &mut mo_pos)?;
            debug!("chunk {}: {:#?}, {:#?}", i, mi_pos, mo_pos);
        }
        // write the remainder
        if remainder != 0 {
            mi_pos.len = remainder;
            debug!("Writing the last parts: len {}", remainder);
            self.write_chunk(&mi, &mut mo, &mut mi_pos, &mut mo_pos)?;
        }

        mo.flush()?;
        info!("Finished encrypting {:?} to {:?}", &infile, &outfile);

        Ok(mo_pos.offset)
    }

    pub async fn decrypt_file(
        keypair: Keypair,
        psk: Option<Psk>,
        infile: impl AsRef<Path> + fmt::Debug,
        outfile: impl AsRef<Path> + fmt::Debug,
    ) -> Result<usize, ConcealError> {
        let fi = File::open(&infile)?;
        let mi = unsafe { Mmap::map(&fi)? };

        let (header, len) = Self::read_header(&mi)?;

        if header.use_psk && psk.is_none() {
            return Err(ConcealError::InvalidPsk);
        }
        let config = SessionConfig::new(header, None, keypair, psk);
        let mut session = Session::new(config)?;

        let (chunks, remainder) = Self::get_chunks(
            &infile,
            NOISE_MESSAGE_MAX_BUFFER + NOISE_ENCRYPT_LENGTH_SIZE,
            len,
        )
        .await?;
        let fo = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&outfile)?;
        let total = Self::get_dec_len(chunks, remainder);
        fo.set_len(total)?;
        info!("Decrypted file length: {}", total);
        let mut mo = unsafe { MmapMut::map_mut(&fo)? };

        let mut mi_pos = Pos {
            offset: len,
            len: NOISE_MESSAGE_MAX_BUFFER,
        };
        let mut mo_pos = Pos {
            offset: 0,
            len: NOISE_MESSAGE_MAX_SIZE,
        };

        for _i in 0..chunks {
            session.read_chunk(&mi, &mut mo, &mut mi_pos, &mut mo_pos)?;
        }
        // read the remainder
        if remainder != 0 {
            mi_pos.len = remainder;
            session.read_chunk(&mi, &mut mo, &mut mi_pos, &mut mo_pos)?;
        }
        mo.flush()?;
        info!("Finished decrypting {:?} to {:?}", &infile, &outfile);

        Ok(mo_pos.offset)
    }

    // private functions
    fn get_enc_len(&self, chunks: usize, remainder: usize) -> u64 {
        let len = (chunks * (NOISE_MESSAGE_MAX_BUFFER + NOISE_ENCRYPT_LENGTH_SIZE)
            + (self.header.encoded_len() + NOISE_ENCRYPT_LENGTH_SIZE)) as u64;
        if remainder > 0 {
            len + (remainder + NOISE_MAC_SIZE + NOISE_ENCRYPT_LENGTH_SIZE) as u64
        } else {
            len
        }
    }

    fn get_dec_len(chunks: usize, remainder: usize) -> u64 {
        let len = (chunks * NOISE_MESSAGE_MAX_SIZE) as u64;
        if remainder > 0 {
            len + (remainder - NOISE_MAC_SIZE - NOISE_ENCRYPT_LENGTH_SIZE) as u64
        } else {
            len
        }
    }
    async fn get_chunks(
        name: impl AsRef<Path>,
        size: usize,
        offset: usize,
    ) -> Result<(usize, usize), ConcealError> {
        let metadata = tokio::fs::metadata(name).await?;
        let len = metadata.len() as usize - offset;
        let chunks = len / size;
        let remainder = len % size;
        debug!(
            "get chunks: payload len: {}, chunks {}, remainder {}",
            len, chunks, remainder
        );
        Ok((chunks, remainder))
    }

    fn write_header(&self, mmap: &mut [u8]) -> Result<usize, ConcealError> {
        let mut buf = Vec::with_capacity(128);
        self.header.to_bytes(&mut buf)?;
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut mmap[..NOISE_ENCRYPT_LENGTH_SIZE], len);
        (&mut mmap[NOISE_ENCRYPT_LENGTH_SIZE..]).write_all(&buf[..len as usize])?;
        Ok(len as usize + NOISE_ENCRYPT_LENGTH_SIZE)
    }

    fn read_header(mmap: &[u8]) -> Result<(Header, usize), ConcealError> {
        let len = BigEndian::read_u16(&mmap[..NOISE_ENCRYPT_LENGTH_SIZE]) as usize;
        let end = len + NOISE_ENCRYPT_LENGTH_SIZE;
        let header = Header::from_bytes(&mmap[NOISE_ENCRYPT_LENGTH_SIZE..end])?;
        Ok((header, end))
    }

    fn write_chunk(
        &mut self,
        mi: &[u8],
        mo: &mut [u8],
        mi_pos: &mut Pos,
        mo_pos: &mut Pos,
    ) -> Result<(), ConcealError> {
        let mi_start = mi_pos.offset;
        let mi_end = mi_start + mi_pos.len;
        mi_pos.offset = mi_end;

        let mo_start = mo_pos.offset + NOISE_ENCRYPT_LENGTH_SIZE;
        let mo_end = mo_start + mi_pos.len + NOISE_MAC_SIZE;

        debug!(
            "read cleartext ({}, {}), write ciphertext ({}, {})",
            mi_start, mi_end, mo_start, mo_end
        );
        let len = self
            .state
            .write_message(&mi[mi_start..mi_end], &mut mo[mo_start..mo_end])?;
        if len != mi_pos.len + NOISE_MAC_SIZE {
            warn!(
                "written length: {} is not equal to {} + {}",
                len, mi_pos.len, NOISE_MAC_SIZE
            );
        }
        BigEndian::write_u16(
            &mut mo[mo_start - NOISE_ENCRYPT_LENGTH_SIZE..mo_start],
            len as u16,
        );

        mo_pos.offset = len + NOISE_ENCRYPT_LENGTH_SIZE;

        Ok(())
    }

    fn read_chunk(
        &mut self,
        mi: &[u8],
        mo: &mut [u8],
        mi_pos: &mut Pos,
        mo_pos: &mut Pos,
    ) -> Result<(), ConcealError> {
        let mi_start = mi_pos.offset + NOISE_ENCRYPT_LENGTH_SIZE;
        let len = BigEndian::read_u16(&mi[mi_start - NOISE_ENCRYPT_LENGTH_SIZE..mi_start]) as usize;
        let mi_end = mi_start + len;
        mi_pos.offset = mi_end;

        let mo_start = mo_pos.offset;
        let mo_end = mo_start + len - NOISE_MAC_SIZE;

        info!(
            "read ciphertext ({}, {}), write cleartext ({}, {})",
            mi_start, mi_end, mo_start, mo_end
        );
        let len = self
            .state
            .read_message(&mi[mi_start..mi_end], &mut mo[mo_start..mo_end])?;
        mo_pos.offset = len;
        Ok(())
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

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
    #[tokio::test]
    async fn default_params_shall_work() -> Result<(), ConcealError> {
        let result = param_combination(
            CipherMode::ChaChaPoly,
            HashMode::Blake2b,
            false,
            vec![NOISE_MESSAGE_MAX_SIZE + 1],
        )
        .await?;

        assert_eq!(result, true);
        Ok(())
    }

    // #[tokio::test]
    // async fn default_params_with_psk_shall_work() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::ChaChaPoly,
    //         HashMode::Blake2b,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;

    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn cha_cha_poly_blake2s() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::ChaChaPoly,
    //         HashMode::Blake2s,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;

    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn cha_cha_poly_sha512() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::ChaChaPoly,
    //         HashMode::Sha512,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;

    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn cha_cha_poly_sha256() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::ChaChaPoly,
    //         HashMode::Sha256,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;
    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn aes_blake2b() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::Aesgcm,
    //         HashMode::Blake2b,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;
    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn aes_blake2s() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::Aesgcm,
    //         HashMode::Blake2s,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;
    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn aes_sha512() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::Aesgcm,
    //         HashMode::Sha512,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;
    //     assert_eq!(result, true);
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn aes_sha256() -> Result<(), ConcealError> {
    //     let result = param_combination(
    //         CipherMode::Aesgcm,
    //         HashMode::Sha256,
    //         true,
    //         vec![256, NOISE_MESSAGE_MAX_SIZE + 1, 256 * 1024],
    //     )
    //     .await?;
    //     assert_eq!(result, true);
    //     Ok(())
    // }
    // private functions
    async fn encrypt_decrypt(header: Header, file_size: usize) -> Result<bool, ConcealError> {
        let mut in_buf = vec![0; file_size];
        fs::create_dir_all("/tmp/conceal").await?;
        let fi1 = format!("/tmp/conceal/cleartext1_{}_{}", header, file_size);
        let fo = format!("/tmp/conceal/ciphertext_{}_{}", header, file_size);
        let fi2 = format!("/tmp/conceal/cleartext2_{}_{}", header, file_size);
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
        init();
        let header = Header::new(cipher as i32, hash as i32, use_psk, Vec::new());
        for size in params {
            let good = encrypt_decrypt(header.clone(), size).await?;
            if !good {
                return Ok(false);
            }
        }
        Ok(true)
        // let futs: Vec<_> = params
        //     .iter()
        //     .map(|size| encrypt_decrypt(header.clone(), size.to_owned()))
        //     .collect();
        // let result = join_all(futs)
        //     .await
        //     .iter()
        //     .all(|v| v.as_ref().unwrap().to_owned());
        // Ok(result)
    }

    async fn fill_file(name: impl AsRef<Path>, buf: &mut [u8]) {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buf);
        fs::write(name, buf).await.unwrap();
    }
}
