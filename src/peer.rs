use crate::priv_prelude::*;

/// Information necessary to connect to peer.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer public address.
    pub addr: SocketAddr,
    /// Peer public key.
    pub pub_key: PublicEncryptKey,
}

impl PeerInfo {
    /// Constructs peer info.
    pub fn new(addr: SocketAddr, pub_key: PublicEncryptKey) -> Self {
        Self { addr, pub_key }
    }
}
