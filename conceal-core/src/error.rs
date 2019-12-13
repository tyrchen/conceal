use thiserror::Error;

/// contains all the errors used in conceal-core. It is pretty general now, will evolve as the code goes.
#[derive(Error, Debug)]
pub enum ConcealError {
    #[error("Error occurred on noise: {0}")]
    NoiseError(#[from] snow::error::Error),
    #[error("data store or file system I/O error")]
    IOError(#[from] std::io::Error),
    #[error("Invalid cipher mode: {0}")]
    InvalidCipher(i32),
    #[error("Invalid hash mode: {0}")]
    InvalidHash(i32),
    #[error("cannot encode data to protobuf")]
    ProtoEncodeError,
    #[error("cannot decode data from protobuf")]
    ProtoDecodeError,
    #[error("unknown error")]
    Unknown,
}
