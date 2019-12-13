use crate::ConcealError;
use std::fmt;

mod header;
pub use header::{CipherMode, HashMode, Header};

impl Header {
    pub fn new(
        cipher: CipherMode,
        hash: HashMode,
        psk: Option<&[u8; 32]>,
        handshake_message: Vec<u8>,
    ) -> Self {
        if psk.is_none() {
            Self {
                cipher: cipher as i32,
                hash: hash as i32,
                psk: Vec::new(),
                handshake_message,
            }
        } else {
            Self {
                cipher: cipher as i32,
                hash: hash as i32,
                psk: psk.unwrap().to_vec(),
                handshake_message,
            }
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cipher_name = match self.cipher {
            1 => "AESGCM",
            _ => "ChaChaPoly",
        };

        let hash_name = match self.hash {
            1 => "BLAKE2s",
            2 => "SHA512",
            3 => "SHA256",
            _ => "BLAKE2b",
        };
        let psk_str = if self.psk.is_empty() { "" } else { "psk1" };
        write!(f, "Noise_X{}_25519_{}_{}", psk_str, cipher_name, hash_name)
    }
}

pub trait Proto<T: prost::Message + Default>: prost::Message + Default {
    fn to_bytes(&self, buffer: &mut Vec<u8>) -> Result<(), ConcealError> {
        self.encode(buffer)
            .map_err(|_e| ConcealError::ProtoEncodeError)
    }
    fn from_bytes(buffer: &[u8]) -> Result<T, ConcealError> {
        T::decode(buffer).map_err(|_e| ConcealError::ProtoDecodeError)
    }
}

impl Proto<Header> for Header {}
