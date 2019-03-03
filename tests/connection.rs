#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate maplit;

use futures::{stream, Future, Sink, Stream};
use libredrop_net::{connect_first_ok, ConnectionError, ConnectionListener, Message, PeerInfo};
use safe_crypto::gen_encrypt_keypair;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::runtime::current_thread::Runtime;

#[test]
fn exchange_data() {
    let (our_pk, our_sk) = gen_encrypt_keypair();
    let listener = unwrap!(ConnectionListener::bind(0, our_sk, our_pk));
    let listener_addr = ipv4_addr(127, 0, 0, 1, listener.port());
    let listener_info = PeerInfo::new(listener_addr, our_pk);

    let accept_conn = listener
        .into_future()
        .map(|(conn_opt, _listener)| unwrap!(conn_opt))
        .map_err(|(e, _listener)| panic!(e));
    let (our_pk, our_sk) = gen_encrypt_keypair();
    let connect = connect_first_ok(hashset! {listener_info}, our_sk, our_pk).join(accept_conn);

    let mut evloop = unwrap!(Runtime::new());
    let (conn1, conn2) = unwrap!(evloop.block_on(connect));

    let tx_messages = vec![
        Message::Data(vec![1, 2, 3]),
        Message::Data(vec![4, 5, 6]),
        Message::Data(vec![7, 8, 9]),
    ];
    let msg_count = tx_messages.len();

    let transfer_data = conn1
        .send_all(stream::iter_ok::<_, ConnectionError>(tx_messages.clone()))
        .join(conn2.take(msg_count as u64).collect())
        .map(|(_, messages)| messages);
    let rx_messages = unwrap!(evloop.block_on(transfer_data));

    assert_eq!(rx_messages, tx_messages);
}

/// A convevience method to build IPv4 address with a port number.
fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}
