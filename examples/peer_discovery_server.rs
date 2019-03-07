//! Demontrates how to setup peer discovery server.
//! This server will respond to whoever is looking for peers on LAN.
//!
//! Execute this command to start listening for discovery messages:
//!
//! ```
//! $ RUST_LOG=info cargo run --example peer_discovery_server
//! ```

extern crate get_if_addrs;
extern crate libredrop_net;
#[macro_use]
extern crate unwrap;
extern crate env_logger;
extern crate tokio;
#[macro_use]
extern crate log;
extern crate safe_crypto;

use get_if_addrs::{get_if_addrs, IfAddr};
use libredrop_net::DiscoveryServer;
use safe_crypto::gen_encrypt_keypair;
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use tokio::prelude::Future;

fn main() -> io::Result<()> {
    env_logger::init();

    info!("Starting peer discovery server on port 6000");
    let addrs = our_addrs(1234)?;
    info!("Our advertised addresses: {:?}", addrs);

    let (our_pk, _our_sk) = gen_encrypt_keypair();
    let server = unwrap!(DiscoveryServer::try_new(6000, addrs, &our_pk));
    let run_server = server
        .map(|_| ())
        .map_err(|e| error!("Peer discovery server failure: {:?}", e));
    tokio::run(run_server);

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
