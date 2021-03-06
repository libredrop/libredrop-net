use crate::priv_prelude::*;
use crate::utils::ipv4_addr;
use bincode;
use err_derive::Error;
use future_utils::{BoxSendFuture, BoxSendStream};
use futures::stream::{self, Stream};
use get_if_addrs::{get_if_addrs, IfAddr};
use std::net::SocketAddrV4;
use tokio::net::UdpSocket;
use tokio::prelude::future::empty;
use tokio::timer::timeout::{Error as TimeoutError, Timeout};

/// Broadcast peer discovery requests every N seconds.
const BROADCAST_DISCOVERY_INTERVAL: u64 = 3;

/// Tries given expression. Returns boxed stream error on failure.
macro_rules! try_bstream {
    ($e:expr) => {
        match $e {
            Ok(t) => t,
            Err(e) => return stream::iter_result(vec![Err(e)]).into_send_boxed(),
        }
    };
}

/// Search for peers on LAN and at the same time handle other discovery requests on a given port.
/// This functions wraps `DiscoveryServer` and `shout_for_peers()` and probably will be used
/// the most for its easiest API.
pub fn discover_peers(
    port: u16,
    our_addrs: HashSet<SocketAddr>,
    our_pk: &PublicEncryptKey,
    our_sk: &SecretEncryptKey,
) -> Result<impl Stream<Item = HashSet<PeerInfo>, Error = DiscoveryError>, DiscoveryError> {
    DiscoverPeers::try_new(port, our_addrs, our_pk, our_sk)
}

struct DiscoverPeers {
    // future that never resolves
    server: DiscoveryServer,
    // stream of peer discovery requests awaiting for response
    send_reqs: BoxSendStream<HashSet<PeerInfo>, DiscoveryError>,
}

impl DiscoverPeers {
    fn try_new(
        port: u16,
        our_addrs: HashSet<SocketAddr>,
        our_pk: &PublicEncryptKey,
        our_sk: &SecretEncryptKey,
    ) -> Result<Self, DiscoveryError> {
        let server = DiscoveryServer::try_new(port, our_addrs, our_pk)?;
        let send_reqs = shout_for_peers(port, *our_pk, our_sk.clone());
        Ok(Self { server, send_reqs })
    }
}

impl Stream for DiscoverPeers {
    type Item = HashSet<PeerInfo>;
    type Error = DiscoveryError;

    /// Send peer discovery messages while also driving the discovery server.
    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        self.server.poll()?;
        self.send_reqs.poll()
    }
}

/// Peers discovery error.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error(display = "I/O error: {}", _0)]
    Io(io::Error),
    #[error(display = "Serialization error: {}", _0)]
    SerializeFailure(bincode::Error),
    #[error(display = "Ivalid response")]
    InvalidResponse,
}

impl From<io::Error> for DiscoveryError {
    fn from(e: io::Error) -> Self {
        DiscoveryError::Io(e)
    }
}

impl From<bincode::Error> for DiscoveryError {
    fn from(e: bincode::Error) -> Self {
        DiscoveryError::SerializeFailure(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DiscoveryMsg {
    /// Request has sender's public key which should be used to encrypt response.
    Request(PublicEncryptKey),
    /// Addresses that the peer is accessible with.
    Response(HashSet<PeerInfo>),
}

impl DiscoveryMsg {
    /// Returns serialized but not encrypted peer discovery request.
    fn serialized_request(pk: PublicEncryptKey) -> Result<Vec<u8>, DiscoveryError> {
        let msg = DiscoveryMsg::Request(pk);
        // TODO(povilas): check if serialize can actually fail
        let req = bincode::serialize(&msg)?;
        Ok(req)
    }
}

/// Peer discovery server that listens for other peer requests and responds with the addresses
/// we're listening on so other peers could connect to us.
pub struct DiscoveryServer {
    listener: UdpSocket,
    /// Addresses peer discovery will respond with.
    our_addrs: HashSet<SocketAddr>,
    our_pk: PublicEncryptKey,
    port: u16,
    /// Clients still waiting for response.
    clients: Vec<(SocketAddr, PublicEncryptKey)>,
}

impl DiscoveryServer {
    /// Constructs new peer discovery server that listens for requests on a given port.
    pub fn try_new(
        port: u16,
        our_addrs: HashSet<SocketAddr>,
        our_pk: &PublicEncryptKey,
    ) -> Result<Self, DiscoveryError> {
        let listener = UdpSocket::bind(&ipv4_addr(0, 0, 0, 0, port))?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            listener,
            our_addrs,
            our_pk: *our_pk,
            port,
            clients: Vec::new(),
        })
    }

    /// Returns server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    fn poll_requests(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; 65000];
        loop {
            match self.listener.poll_recv_from(&mut buf)? {
                Async::Ready((bytes_read, sender_addr)) => {
                    self.on_packet_recv(&buf[..bytes_read], sender_addr);
                }
                Async::NotReady => return Ok(()),
            }
        }
    }

    fn on_packet_recv(&mut self, buf: &[u8], sender_addr: SocketAddr) {
        match bincode::deserialize(buf) {
            Ok(DiscoveryMsg::Request(their_pk)) => {
                debug!("Received service discovery request from {}", sender_addr);
                // don't respond to ourselves
                if their_pk != self.our_pk {
                    self.clients.push((sender_addr, their_pk))
                }
            }
            // TODO(povilas): prevent from DDOSing logs and put upper limit for logged buffer
            _ => warn!("Invalid peer discovery request: {:?}", buf),
        }
    }

    fn poll_send_responses(&mut self) -> io::Result<()> {
        while let Some((addr, their_pk)) = self.clients.pop() {
            let resp = if let Some(buf) = self.make_response(&their_pk) {
                buf
            } else {
                continue;
            };
            match self.listener.poll_send_to(&resp, &addr)? {
                Async::Ready(_bytes_sent) => (),
                Async::NotReady => {
                    self.clients.push((addr, their_pk));
                    break;
                }
            }
        }
        Ok(())
    }

    /// Encrypt response with their public key.
    fn make_response(&self, their_pk: &PublicEncryptKey) -> Option<Vec<u8>> {
        let our_addrs = self
            .our_addrs
            .iter()
            .map(|addr| PeerInfo::new(*addr, self.our_pk))
            .collect();
        let resp = DiscoveryMsg::Response(our_addrs);
        their_pk.anonymously_encrypt(&resp).ok()
    }
}

impl Future for DiscoveryServer {
    type Item = Void;
    type Error = DiscoveryError;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        self.poll_requests()?;
        self.poll_send_responses()?;
        Ok(Async::NotReady)
    }
}

/// Sends peer discovery requests to all network interfaces and indefinitely waits for responses
/// until the stream is cancelled. Resends request every 3 seconds.
pub fn shout_for_peers(
    port: u16,
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
) -> BoxSendStream<HashSet<PeerInfo>, DiscoveryError> {
    try_bstream!(ShoutForPeers::try_new(port, our_pk, our_sk).map_err(DiscoveryError::Io))
        .into_send_boxed()
}

/// A stream that sends peer discovery messages to all network interfaces and indefinitely until it
/// is cancelled. This stream yields all peers on LAN that respond to this beacon.
struct ShoutForPeers {
    our_pk: PublicEncryptKey,
    our_sk: SecretEncryptKey,
    /// Serialized `DiscoveryMsg`.
    request: Vec<u8>,
    /// It's optional only to trick borrow checker.
    sockets: Option<HashMap<SocketAddr, UdpSocket>>,
    /// List of socket addresses to send requests to.
    to_send: Vec<SocketAddr>,
    /// Stream results.
    results: Vec<HashSet<PeerInfo>>,
    timeout: BoxSendFuture<(), ()>,
}

impl ShoutForPeers {
    fn try_new(port: u16, our_pk: PublicEncryptKey, our_sk: SecretEncryptKey) -> io::Result<Self> {
        let sockets = broadcast_sockets(port)?;
        // NOTE(povilas): I doubt serialize can fail, will double check though
        let request = unwrap!(DiscoveryMsg::serialized_request(our_pk));
        let timeout = new_timeout(BROADCAST_DISCOVERY_INTERVAL);
        let to_send = sockets.keys().cloned().collect();

        Ok(Self {
            our_pk,
            our_sk,
            request,
            sockets: Some(sockets),
            to_send,
            results: Default::default(),
            timeout,
        })
    }

    /// Sends service discovery requests through all network interfaces.
    fn send_requests(&mut self) {
        let mut sockets = unwrap!(self.sockets.take());
        let mut resend = Vec::new();

        while let Some(addr) = self.to_send.pop() {
            let socket = unwrap!(sockets.get_mut(&addr));
            match socket.poll_send_to(&self.request[..], &addr) {
                Ok(Async::Ready(_)) => {
                    debug!("Service discovery request sent to {}", addr);
                }
                Ok(Async::NotReady) => resend.push(addr),
                Err(e) => {
                    // TODO(povilas): add to self.errors
                    info!(
                        "Failed to send service discovery request to {}: {}",
                        addr, e
                    );
                }
            }
        }

        self.to_send.extend(&resend);
        self.sockets = Some(sockets);
    }

    fn recv_responses(&mut self) {
        let mut buf = [0u8; 65000];
        let mut sockets = unwrap!(self.sockets.take());
        for socket in sockets.values_mut() {
            match socket.poll_recv_from(&mut buf) {
                Ok(Async::NotReady) => (),
                Ok(Async::Ready((bytes_received, _from_addr))) => {
                    self.handle_response(&buf[..bytes_received]);
                }
                Err(e) => {
                    // TODO(povilas): remove from sockets list and add to self.errors
                    info!("Failed to receive service discovery response: {}", e);
                }
            }
        }
        self.sockets = Some(sockets);
    }

    fn handle_response(&mut self, buf: &[u8]) {
        let peers = match self.our_sk.anonymously_decrypt(buf, &self.our_pk) {
            Ok(DiscoveryMsg::Response(peers)) => peers,
            Ok(msg) => {
                info!("Unexpected message received: {:?}", msg);
                return;
            }
            Err(e) => {
                info!("Failed to decrypt service discovery response: {}", e);
                return;
            }
        };
        let peers: HashSet<PeerInfo> = peers
            .iter()
            .filter(|peer| peer.pub_key != self.our_pk)
            .cloned()
            .collect();
        self.results.push(peers);
    }

    /// See if it's time to resend discovery requests.
    fn check_resend_timeout(&mut self) {
        if let Ok(Async::Ready(_)) = self.timeout.poll() {
            self.timeout = new_timeout(BROADCAST_DISCOVERY_INTERVAL);
            if let Some(ref mut sockets) = self.sockets {
                self.to_send = sockets.keys().cloned().collect();
            }
        }
    }
}

impl Stream for ShoutForPeers {
    type Item = HashSet<PeerInfo>;
    type Error = DiscoveryError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.check_resend_timeout();
        self.send_requests();
        self.recv_responses();

        // TODO(povilas): if self.sockets_to_send.is_empty() && self.sockets_to_recv.is_empty() &&
        // self.results.is_empty() return DiscoveryError::AllAttemptsFailed(self.errors)

        // TODO(povilas): return all collected peers at once?
        // Otherwise poll() might not be scheduled anymore depending on how it is notified..
        if let Some(peers) = self.results.pop() {
            Ok(Async::Ready(Some(peers)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// Creates sockets for each broadcast address.
fn broadcast_sockets(port: u16) -> io::Result<HashMap<SocketAddr, UdpSocket>> {
    let mut sockets = HashMap::new();
    for addr in broadcast_addrs(port)? {
        let sock = broadcast_sock()?;
        let _ = sockets.insert(addr, sock);
    }
    Ok(sockets)
}

// TODO(povilas): netsim test for this
/// Returns broadcast addresses for all network interfaces on the system.
fn broadcast_addrs(port: u16) -> io::Result<HashSet<SocketAddr>> {
    let addrs = get_if_addrs()?;
    Ok(addrs
        .iter()
        .filter_map(|iface| match iface.addr {
            IfAddr::V4(ref ifv4_addr) => ifv4_addr.broadcast,
            IfAddr::V6(_) => None,
        })
        .map(move |ip| SocketAddr::V4(SocketAddrV4::new(ip, port)))
        .collect())
}

/// Creates new UDP socket with broadcast enabled.
fn broadcast_sock() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(&addr!("0.0.0.0:0"))?;
    sock.set_broadcast(true)?;
    Ok(sock)
}

fn new_timeout(secs: u64) -> BoxSendFuture<(), ()> {
    Timeout::new(empty(), Duration::from_secs(secs))
        .then(|_res: Result<(), TimeoutError<()>>| Ok(()))
        .into_send_boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hamcrest2::prelude::*;
    use tokio::runtime::current_thread::Runtime;

    #[test]
    fn server_responds() {
        let mut evloop = unwrap!(Runtime::new());

        let (server_pk, _sk) = gen_encrypt_keypair();
        let server = unwrap!(DiscoveryServer::try_new(
            0,
            hashset![addr!("192.168.1.100:1234")],
            &server_pk
        ));
        let server_addr = ipv4_addr(127, 0, 0, 1, server.port());
        let sock = unwrap!(UdpSocket::bind(&addr!("0.0.0.0:0")));

        let (our_pk, our_sk) = gen_encrypt_keypair();
        let request = unwrap!(DiscoveryMsg::serialized_request(our_pk));

        let send_req = sock
            .send_dgram(&request, &server_addr)
            .and_then(|(sock, _buf)| sock.recv_dgram(vec![0; 65000]))
            .map(|(_socket, buf, bytes_received, _from)| buf[..bytes_received].to_vec())
            .with_timeout(Duration::from_secs(2))
            .map(|buf_opt| {
                let buf = unwrap!(buf_opt);
                unwrap!(our_sk.anonymously_decrypt(&buf, &our_pk))
            })
            .while_driving(server);

        match evloop.block_on(send_req) {
            Ok((DiscoveryMsg::Response(addrs), _server_task)) => {
                assert_that!(
                    addrs,
                    eq(hashset![PeerInfo::new(
                        addr!("192.168.1.100:1234"),
                        server_pk
                    )])
                );
            }
            _ => panic!("Failed to send peer discovery request"),
        }
    }

    mod shout_for_peers {
        use super::*;

        #[test]
        fn it_broadcasts_requests_on_lan_and_collects_peer_addresses() {
            let mut evloop = unwrap!(Runtime::new());

            let (server_pk, _server_sk) = gen_encrypt_keypair();
            let server = unwrap!(DiscoveryServer::try_new(
                0,
                hashset![addr!("192.168.1.100:1234"), addr!("127.0.0.1:1234")],
                &server_pk,
            ));
            let server_port = server.port();

            let (our_pk, our_sk) = gen_encrypt_keypair();
            let task = shout_for_peers(server_port, our_pk, our_sk)
                .take(1)
                .collect()
                .with_timeout(Duration::from_secs(10))
                .map(|addrs_opt| unwrap!(addrs_opt, "Peer discovery timed out"))
                .while_driving(server);

            let exp_addrs = hashset![
                PeerInfo::new(addr!("192.168.1.100:1234"), server_pk),
                PeerInfo::new(addr!("127.0.0.1:1234"), server_pk),
            ];
            match evloop.block_on(task) {
                Ok((their_addrs, _server_task)) => assert_eq!(their_addrs[0], exp_addrs),
                _ => panic!("Peer discovery failed"),
            }
        }

        #[test]
        fn it_filters_responses_from_self() {
            let mut evloop = unwrap!(Runtime::new());

            let (server_pk, server_sk) = gen_encrypt_keypair();
            let server = unwrap!(DiscoveryServer::try_new(
                0,
                hashset![addr!("192.168.1.100:1234"), addr!("127.0.0.1:1234")],
                &server_pk,
            ));
            let server_port = server.port();

            let task = shout_for_peers(server_port, server_pk, server_sk)
                .collect()
                .with_timeout(Duration::from_secs(3))
                .while_driving(server);

            match evloop.block_on(task) {
                Ok((their_addrs_opt, _server_task)) => assert_that!(their_addrs_opt, none()),
                Err(e) => panic!("Peer discovery failed: {:?}", e.0),
            }
        }

        #[test]
        fn it_broadcasts_requests_every_n_seconds() {
            let mut evloop = unwrap!(Runtime::new());

            let (server_pk, _server_sk) = gen_encrypt_keypair();
            let server = unwrap!(DiscoveryServer::try_new(
                0,
                hashset![addr!("192.168.1.100:1234")],
                &server_pk,
            ));
            let server_port = server.port();

            let (our_pk, our_sk) = gen_encrypt_keypair();
            let task = shout_for_peers(server_port, our_pk, our_sk)
                .take(2)
                .collect()
                .with_timeout(Duration::from_secs(BROADCAST_DISCOVERY_INTERVAL * 2 + 2))
                .map(|addrs_opt| unwrap!(addrs_opt, "Peer discovery timed out"))
                .while_driving(server);

            let exp_addrs = vec![
                hashset![PeerInfo::new(addr!("192.168.1.100:1234"), server_pk)],
                hashset![PeerInfo::new(addr!("192.168.1.100:1234"), server_pk)],
            ];
            match evloop.block_on(task) {
                Ok((their_addrs, _server_task)) => assert_eq!(their_addrs, exp_addrs),
                _ => panic!("Peer discovery failed"),
            }
        }
    }
}
