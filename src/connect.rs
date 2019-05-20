use crate::message::{HandshakeMessage, Message};
use crate::peer::PeerInfo;
use bytes::Bytes;
use err_derive::Error;
use future_utils::StreamExt;
use futures::{stream, Async, AsyncSink, Future, Poll, Sink, Stream};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey, SharedSecretKey};
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use tokio::codec::{Framed, LengthDelimitedCodec};
use tokio::net::TcpStream;

/// Failure to connect.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// I/O related error.
    #[error(display = "I/O error: {}", _0)]
    Io(io::Error),
    /// Crypto related error.
    #[error(display = "Crypto related error: {}", _0)]
    Crypto(safe_crypto::Error),
    /// Connection was denied.
    #[error(display = "Connection was denied by remote peer")]
    Denied,
    #[error(display = "Unexpected message received: {:?}", _0)]
    UnexpectedMessage(HandshakeMessage),
    /// All TCP connection attempts failed.
    #[error(display = "I/O error: {:?}", _0)]
    AllAttemptsFailed(Vec<io::Error>),
}

/// Error during communications over connection.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// I/O related error.
    #[error(display = "I/O error: {}", _0)]
    Io(io::Error),
    /// Crypto related error.
    #[error(display = "Crypto related error: {}", _0)]
    Crypto(safe_crypto::Error),
}

/// Established connection.
#[derive(Debug)]
pub struct Connection {
    stream: Framed<TcpStream, LengthDelimitedCodec>,
    peer_addr: SocketAddr,
    shared_key: SharedSecretKey,
}

/// Attempts the connection with the given peers including encrypted handshake
/// The first successful connection is returned.
pub fn connect_first_ok(
    peers: HashSet<PeerInfo>,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
) -> impl Future<Item = Connection, Error = ConnectError> + Send {
    stream::iter_ok(peers)
        .map(|peer| TcpStream::connect(&peer.addr).map(|stream| (stream, peer)))
        .buffer_unordered(16)
        .first_ok()
        .map_err(ConnectError::AllAttemptsFailed)
        // TODO(povilas): see if we can pass addr in some future/task context. See futures 0.3
        .map(|(stream, peer_info)| (Framed::new(stream, LengthDelimitedCodec::new()), peer_info))
        .and_then(move |(framed, peer_info)| {
            let connect_msg = unwrap!(peer_info
                .pub_key
                .anonymously_encrypt(&HandshakeMessage::Connect(our_pk))
                .map(Bytes::from));
            framed
                .send(connect_msg)
                .map_err(ConnectError::Io)
                .map(move |framed| (framed, peer_info))
        })
        .and_then(|(framed, peer_info)| {
            framed
                .into_future()
                .map_err(|(e, _framed)| ConnectError::Io(e))
                .and_then(move |(msg_opt, framed)| {
                    msg_opt
                        .ok_or_else(|| ConnectError::Io(io::ErrorKind::BrokenPipe.into()))
                        .map(move |msg| (framed, peer_info, msg))
                })
        })
        .and_then(move |(framed, peer_info, msg)| {
            let shared_key = our_sk.shared_secret(&peer_info.pub_key);
            shared_key
                .decrypt(&msg)
                .map_err(ConnectError::Crypto)
                .map(|msg| (framed, peer_info.addr, msg, shared_key))
        })
        .and_then(|(framed, addr, msg, shared_key)| match msg {
            HandshakeMessage::AcceptConnect => Ok(Connection::new(framed, addr, shared_key)),
            HandshakeMessage::DenyConnect => Err(ConnectError::Denied),
            msg => Err(ConnectError::UnexpectedMessage(msg)),
        })
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
