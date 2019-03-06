//! Demontrates how to discover peers on LAN. You don't need to run any server, just another
//! instance of this example on a different machine.
//!
//! Run:
//! ```
//! $ RUST_LOG=info cargo run --example discover_peers
//! ```

extern crate env_logger;
extern crate libredrop_net;
#[macro_use]
extern crate log;
extern crate futures;
extern crate tokio;
#[macro_use]
extern crate unwrap;
extern crate get_if_addrs;
extern crate safe_crypto;

use futures::Stream;
use get_if_addrs::{get_if_addrs, IfAddr};
use libredrop_net::discover_peers;
use safe_crypto::gen_encrypt_keypair;
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use tokio::runtime::current_thread::Runtime;

fn main() -> io::Result<()> {
    env_logger::init();
    let mut evloop = unwrap!(Runtime::new());

    info!("Looking for peers on LAN on port 6000");
    let addrs = our_addrs(1234)?;
    let (our_pk, our_sk) = gen_encrypt_keypair();
    let find_peers = unwrap!(discover_peers(6000, addrs, &our_pk, &our_sk))
        .map_err(|e| error!("Peer discovery failed: {:?}", e))
        .for_each(|addrs| {
            println!("Peer is listening on: {:?}", addrs);
            Ok(())
        });
    unwrap!(evloop.block_on(find_peers));
    Ok(())
}

/// Construct a list of fake listening addresses.
fn our_addrs(with_port: u16) -> io::Result<HashSet<SocketAddr>> {
    let interfaces = get_if_addrs()?;
    let addrs = interfaces
        .iter()
        .filter_map(|interface| match interface.addr {
            IfAddr::V4(ref ifv4_addr) => Some(ifv4_addr.ip),
            IfAddr::V6(_) => None,
        })
        .filter(|ip| !ip.is_loopback())
        .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, with_port)))
        .collect();
    Ok(addrs)
}
