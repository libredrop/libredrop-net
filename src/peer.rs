use crate::priv_prelude::*;
use futures::future;
use tokio::net::TcpStream;

/// Failure to connect.
quick_error! {
    #[derive(Debug)]
    pub enum ConnectError {
        Io(e: io::Error) {
            display("I/O error: {}", e)
            cause(e)
            from()
        }
    }
}

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

/// Connection in handshaking state.
pub struct ConnectionCandidate {
    socket: TcpStream,
}

/// Established connection.
pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    pub fn wrap(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Make connection to given address.
    pub fn make(to: &SocketAddr) -> impl Future<Item = Self, Error = ConnectError> {
        TcpStream::connect(to)
            .map_err(ConnectError::Io)
            .map(Self::wrap)
    }

    /// Returns address of remote peer on the other side of this connection.
    pub fn peer_addr(&self) -> Result<SocketAddr, ConnectError> {
        let addr = self.stream.peer_addr()?;
        Ok(addr)
    }
}
