///! Connection listener.
use bytes::Bytes;
use futures::{future, Sink};
use get_if_addrs::{get_if_addrs, IfAddr};
use std::net::SocketAddrV4;
use tokio::codec::{Framed, LengthDelimitedCodec};
use tokio::net::{TcpListener, TcpStream};

use crate::message::HandshakeMessage;
use crate::peer::{ConnectError, Connection};
use crate::priv_prelude::*;
use crate::utils::ipv4_addr;

/// Listens for incoming connections.
pub struct ConnectionListener {
    local_addr: SocketAddr,
    accept_conns: BoxStream<Connection, io::Error>,
}

impl ConnectionListener {
    /// Bind to a given port on all network interfaces and start listening for incoming connections.
    pub fn bind(port: u16, our_sk: SecretEncryptKey, our_pk: PublicEncryptKey) -> io::Result<Self> {
        let listener = TcpListener::bind(&ipv4_addr(0, 0, 0, 0, port))?;
        let local_addr = listener.local_addr()?;
        let accept_conns = listener
            .incoming()
            .and_then(move |stream| {
                let our_sk = our_sk.clone();
                let wont_happen = io::ErrorKind::Other.into();
                handshake_incoming(stream, our_sk, our_pk).map_err(move |_| wont_happen)
            })
            .into_boxed();
        Ok(Self {
            local_addr,
            accept_conns,
        })
    }

    /// Returns port on which listener accepts incoming connections.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Returns local listening address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Construct a list of listening addresses.
    /// Localhost address is excluded.
    pub fn addrs(&self) -> io::Result<HashSet<SocketAddr>> {
        let interfaces = get_if_addrs()?;
        let addrs = interfaces
            .iter()
            .filter_map(|interface| match interface.addr {
                IfAddr::V4(ref ifv4_addr) => Some(ifv4_addr.ip),
                IfAddr::V6(_) => None,
            })
            .filter(|ip| !ip.is_loopback())
            .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, self.local_addr.port())))
            .collect();
        Ok(addrs)
    }
}

/// Accepts incoming TCP connections and executes handshake before returning established connection.
fn handshake_incoming(
    stream: TcpStream,
    our_sk: SecretEncryptKey,
    our_pk: PublicEncryptKey,
) -> impl Future<Item = Connection, Error = ()> {
    future::result(stream.peer_addr())
        .map_err(ConnectError::Io)
        .map(|addr| (Framed::new(stream, LengthDelimitedCodec::new()), addr))
        .and_then(|(framed, addr)| {
            framed
                .into_future()
                .map_err(|(e, _framed)| ConnectError::Io(e))
                .and_then(move |(msg_opt, framed)| {
                    msg_opt
                        .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
                        .map_err(ConnectError::Io)
                        .map(move |msg| (framed, addr, msg))
                })
        })
        .and_then(
            move |(framed, addr, msg)| match our_sk.anonymously_decrypt(&msg[..], &our_pk) {
                Ok(HandshakeMessage::Connect(their_pk)) => {
                    let shared_key = our_sk.shared_secret(&their_pk);
                    Ok((framed, addr, shared_key))
                }
                Ok(msg) => Err(ConnectError::UnexpectedMessage(msg)),
                Err(e) => Err(ConnectError::Crypto(e)),
            },
        )
        .and_then(|(framed, addr, shared_key)| {
            // TODO(povilas): allow to accept or deny
            shared_key
                .encrypt(&HandshakeMessage::AcceptConnect)
                .map_err(ConnectError::Crypto)
                .map(move |buf| (framed, addr, Bytes::from(buf), shared_key))
        })
        .and_then(|(framed, addr, buf, shared_key)| {
            framed
                .send(buf)
                .map_err(ConnectError::Io)
                .map(move |framed| Connection::new(framed, addr, shared_key))
        })
        .map_err(|e| {
            debug!("Connection failed: {}", e);
        })
}

impl Stream for ConnectionListener {
    type Item = Connection;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.accept_conns.poll()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::connect_first_ok;
    use crate::utils::ipv4_addr;
    use safe_crypto::gen_encrypt_keypair;
    use tokio::runtime::current_thread::Runtime;

    mod connection_listener {
        use super::*;
        use std::sync::mpsc;

        #[test]
        fn it_yields_established_connection() {
            let (conn_tx, conn_rx) = mpsc::sync_channel(5);
            let (addr_tx, addr_rx) = mpsc::sync_channel(5);

            let _thread = std::thread::spawn(move || {
                let (our_pk, our_sk) = gen_encrypt_keypair();
                let listener = unwrap!(ConnectionListener::bind(0, our_sk, our_pk));
                let listener_addr = ipv4_addr(127, 0, 0, 1, listener.port());
                let listener_info = PeerInfo::new(listener_addr, our_pk);
                unwrap!(addr_tx.send(listener_info));

                let task = listener.for_each(|conn| {
                    unwrap!(conn_tx.send(conn));
                    Ok(())
                });
                let mut evloop = unwrap!(Runtime::new());
                unwrap!(evloop.block_on(task));
            });

            let (our_pk, our_sk) = gen_encrypt_keypair();
            let listener_info = unwrap!(addr_rx.recv());
            let task = connect_first_ok(hashset! {listener_info}, our_sk, our_pk);
            let mut evloop = unwrap!(Runtime::new());
            unwrap!(evloop.block_on(task));

            let conn = unwrap!(conn_rx.recv());
            assert_eq!(conn.peer_addr().ip(), ipv4!("127.0.0.1"));
        }
    }
}
