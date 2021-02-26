/// this is the file header for encrypted files. Note that we deliberately fixed
/// the DH function to ed25519 since it provides same level of security as ed448,
/// but performance is better. The default choise of if all the parameters are
/// default value: Noise_X_25519_ChaChaPoly_BLAKE2b. This fits the most of the
/// security standards. However, initiator and responder can use a pre shared key
/// for extra level of security.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    /// cipher function used by noise protocol
    #[prost(enumeration = "CipherMode", tag = "1")]
    pub cipher: i32,
    /// hash function used by noise protocol
    #[prost(enumeration = "HashMode", tag = "2")]
    pub hash: i32,
    /// if true, we will do a Xpsk1. Note user shall provide the psk upon Session::new.
    /// <- s
    /// ...
    /// -> e, es, s, ss, psk
    #[prost(bool, tag = "3")]
    pub use_psk: bool,
    /// handshake message from the initiator
    #[prost(bytes = "vec", tag = "4")]
    pub handshake_message: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CipherMode {
    ChaChaPoly = 0,
    Aesgcm = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HashMode {
    Blake2b = 0,
    Blake2s = 1,
    Sha512 = 2,
    Sha256 = 3,
}
