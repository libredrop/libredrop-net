use crate::message::{HandshakeMessage, Message};
use crate::priv_prelude::*;
use bytes::Bytes;
use futures::{future, AsyncSink, Poll, Sink};
use safe_crypto::SharedSecretKey;
use tokio::codec::{Framed, LengthDelimitedCodec};
use tokio::net::TcpStream;

/// Failure to connect.
quick_error! {
    #[derive(Debug)]
    pub enum ConnectError {
        /// I/O related error.
        Io(e: io::Error) {
            display("I/O error: {}", e)
            cause(e)
            from()
        }
        /// Crypto related error.
        Crypto(e: safe_crypto::Error) {
            display("Crypto related error: {}", e)
            from()
        }
        /// Connection was denied.
        Denied {
            display("Connection was denied by remote peer")
        }
        UnexpectedMessage(msg: HandshakeMessage) {
            display("Unexpected message received: {:?}", msg)
        }
    }
}

/// Error during communications over connection.
quick_error! {
    #[derive(Debug)]
    pub enum ConnectionError {
        /// I/O related error.
        Io(e: io::Error) {
            display("I/O error: {}", e)
            cause(e)
            from()
        }
        /// Crypto related error.
        Crypto(e: safe_crypto::Error) {
            display("Crypto related error: {}", e)
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

/// Tries given expression. Returns boxed future error on failure.
macro_rules! try_bfut {
    ($e:expr) => {
        match $e {
            Ok(t) => t,
            Err(e) => return future::err(e).into_boxed(),
        }
    };
}

/// Established connection.
pub struct Connection {
    stream: Framed<TcpStream, LengthDelimitedCodec>,
    peer_addr: SocketAddr,
    shared_key: SharedSecretKey,
}

/// Attempts the connection with the given peer. Executes encrypted handshake and everything.
pub fn connect_with(
    peer: &PeerInfo,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
) -> impl Future<Item = Connection, Error = ConnectError> {
    let connect_msg = try_bfut!(peer
        .pub_key
        .anonymously_encrypt(&HandshakeMessage::Connect(our_pk))
        .map_err(ConnectError::Crypto));
    let connect_msg = Bytes::from(connect_msg);
    let shared_key = our_sk.shared_secret(&peer.pub_key);

    TcpStream::connect(&peer.addr)
        .map_err(ConnectError::Io)
        .and_then(|stream| {
            stream
                .peer_addr()
                .map(|addr| (stream, addr))
                .map_err(ConnectError::Io)
        })
        // TODO(povilas): see if we can pass addr in some future/task context
        .map(|(stream, addr)| (Framed::new(stream, LengthDelimitedCodec::new()), addr))
        .and_then(|(framed, addr)| {
            framed
                .send(connect_msg)
                .map_err(ConnectError::Io)
                .map(move |framed| (framed, addr))
        })
        .and_then(|(framed, addr)| {
            framed
                .into_future()
                .map_err(|(e, _framed)| ConnectError::Io(e))
                .and_then(move |(msg_opt, framed)| {
                    msg_opt
                        .ok_or(ConnectError::Io(io::ErrorKind::BrokenPipe.into()))
                        .map(move |msg| (framed, addr, msg))
                })
        })
        .and_then(move |(framed, addr, msg)| {
            shared_key
                .decrypt(&msg)
                .map_err(ConnectError::Crypto)
                .map(|msg| (framed, addr, msg, shared_key))
        })
        .and_then(|(framed, addr, msg, shared_key)| match msg {
            HandshakeMessage::AcceptConnect => Ok(Connection::new(framed, addr, shared_key)),
            HandshakeMessage::DenyConnect => Err(ConnectError::Denied),
            msg @ _ => Err(ConnectError::UnexpectedMessage(msg)),
        })
        .into_boxed()
}

impl Connection {
    pub fn new(
        stream: Framed<TcpStream, LengthDelimitedCodec>,
        peer_addr: SocketAddr,
        shared_key: SharedSecretKey,
    ) -> Self {
        Self {
            stream,
            peer_addr,
            shared_key,
        }
    }

    /// Returns address of remote peer on the other side of this connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl Stream for Connection {
    type Item = Message;
    type Error = ConnectionError;

    /// Receive a message from socket, decrypt it and pass through a stream.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.stream.poll() {
            Ok(Async::Ready(Some(buf))) => match self.shared_key.decrypt(&buf) {
                Ok(msg) => Ok(Async::Ready(Some(msg))),
                Err(e) => Err(ConnectionError::Crypto(e)),
            },
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(ConnectionError::Io(e)),
        }
    }
}

impl Sink for Connection {
    type SinkItem = Message;
    type SinkError = ConnectionError;

    fn start_send(
        &mut self,
        item: Self::SinkItem,
    ) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        let buf = self
            .shared_key
            .encrypt(&item)
            .map_err(ConnectionError::Crypto)?;
        self.stream
            .start_send(Bytes::from(buf))
            .map_err(ConnectionError::Io)
            .map(|res| res.map(|_| item))
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete().map_err(ConnectionError::Io)
    }
}
