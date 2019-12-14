use thiserror::Error;

/// contains all the errors used in conceal-core. It is pretty general now, will evolve as the code goes.
#[derive(Error, Debug)]
pub enum ConcealError {
    #[error("{0}")]
    NoiseError(#[from] snow::error::Error),
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    #[error("Invalid cipher mode: {0}")]
    InvalidCipher(i32),
    #[error("Invalid hash mode: {0}")]
    InvalidHash(i32),
    #[error("a valid PSK is required")]
    InvalidPsk,
    #[error("cannot encode data to protobuf")]
    ProtoEncodeError,
    #[error("cannot decode data from protobuf")]
    ProtoDecodeError,
    #[error("unknown error")]
    Unknown,
}
