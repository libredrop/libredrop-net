use crate::utils::async_read_file;
use crate::{connect_first_ok, discover_peers, Connection, ConnectionListener, Error};
use future_utils::{drop_notify, mpsc, DropNotify, FutureExt};
use futures::{Future, Sink, Stream};
use safe_crypto::{gen_encrypt_keypair, PublicEncryptKey, SecretEncryptKey};
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::runtime::current_thread::Runtime;

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

/// Peer generated event.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PeerEvent {
    DiscoveredPeers(HashSet<PeerInfo>),
    NewConnection(Connection),
}

/// High level API to construct and control a peer who will be connecting and exchanging data with
/// other peers.
pub struct Peer {
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
    listener_addrs: HashSet<SocketAddr>,
    /// Peer specific events will be sent over this channel.
    events_tx: mpsc::UnboundedSender<PeerEvent>,
    service_discovery_port: u16,

    _drop_tx_listener: Option<DropNotify>,
    _drop_tx_discovery: Option<DropNotify>,
}

impl Peer {
    /// Constructs new peer and in addition returns peer event receiver.
    pub fn new(service_discovery_port: u16) -> (Self, mpsc::UnboundedReceiver<PeerEvent>) {
        let (our_pk, our_sk) = gen_encrypt_keypair();
        let (events_tx, events_rx) = mpsc::unbounded();

        (
            Self {
                our_pk,
                our_sk,
                listener_addrs: Default::default(),
                events_tx,
                service_discovery_port,
                _drop_tx_listener: None,
                _drop_tx_discovery: None,
            },
            events_rx,
        )
    }

    /// Starts listening for incoming connections and peer discovery process which will find
    /// libredrop peers on LAN.
    pub fn start(&mut self, evloop: &mut Runtime) -> Result<(), Error> {
        self.spawn_conn_listener(evloop)?;
        self.spawn_peer_discovery(evloop)
    }

    /// Returns a list of endpoints this peer is listening on.
    pub fn endpoints(&self) -> HashSet<PeerInfo> {
        self.listener_addrs
            .iter()
            .map(|addr| PeerInfo::new(*addr, self.our_pk))
            .collect()
    }

    /// Attempts to connect to a peer via one of the given contacts and returns the first successful
    /// connection.
    pub fn connect_to(
        &self,
        endpoints: HashSet<PeerInfo>,
    ) -> impl Future<Item = Connection, Error = Error> {
        connect_first_ok(endpoints, self.our_sk.clone(), self.our_pk).map_err(Error::Connect)
    }

    /// Attempts to connect to a peer via one of the given contacts and sends a file to it.
    pub fn send_file_to(
        &self,
        endpoints: HashSet<PeerInfo>,
        fname: &str,
    ) -> impl Future<Item = (), Error = Error> {
        let fname = fname.to_string();
        self.connect_to(endpoints).and_then(|conn| {
            conn.sink_map_err(Error::Connection)
                .send_all(async_read_file(fname))
                .map(|(_conn, _read)| ())
        })
    }

    /// Starts listening for incoming connections in the background.
    fn spawn_conn_listener(&mut self, evloop: &mut Runtime) -> Result<(), Error> {
        let listener = ConnectionListener::bind(0, self.our_sk.clone(), self.our_pk)?;
        self.listener_addrs = listener.addrs()?;

        let (drop_tx, drop_rx) = drop_notify();
        self._drop_tx_listener = Some(drop_tx);

        let events_tx = self.events_tx.clone();
        let accept_connections = listener
            .for_each(move |conn| {
                let _ = events_tx.unbounded_send(PeerEvent::NewConnection(conn));
                Ok(())
            })
            .log_error(log::Level::Error, "Connection listener errored")
            .until(drop_rx)
            .map(|_| ())
            .infallible();
        evloop.spawn(accept_connections);
        Ok(())
    }

    fn spawn_peer_discovery(&mut self, evloop: &mut Runtime) -> Result<(), Error> {
        let events_tx = self.events_tx.clone();
        let (drop_tx, drop_rx) = drop_notify();
        self._drop_tx_discovery = Some(drop_tx);

        let discover_peers_on_lan = discover_peers(
            self.service_discovery_port,
            self.listener_addrs.clone(),
            &self.our_pk,
            &self.our_sk,
        )?
        .map(move |mut addrs| {
            let addrs = addrs.drain().collect();
            let _ = events_tx.unbounded_send(PeerEvent::DiscoveredPeers(addrs));
        })
        .for_each(|_| Ok(()))
        .log_error(log::Level::Error, "Peer discovery errored")
        .until(drop_rx)
        .map(|_| ())
        .infallible();
        evloop.spawn(discover_peers_on_lan);
        Ok(())
    }
}
