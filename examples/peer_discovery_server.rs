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
extern crate future_utils;
extern crate tokio;
#[macro_use]
extern crate log;

use future_utils::FutureExt;
use get_if_addrs::{get_if_addrs, IfAddr};
use libredrop_net::DiscoveryServer;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use tokio::prelude::Future;

fn main() -> io::Result<()> {
    env_logger::init();

    info!("Starting peer discovery server on port 6000");
    let addrs = our_addrs(1234)?;
    info!("Our advertised addresses: {:?}", addrs);

    let server = unwrap!(DiscoveryServer::new(6000, addrs));
    let run_server = server
        .map(|_| ())
        .log_error(log::LogLevel::Error, "Peer discovery server failure")
        .map_err(|_| ());
    tokio::run(run_server);

    Ok(())
}

/// Construct a list of fake listening addresses.
fn our_addrs(with_port: u16) -> io::Result<Vec<SocketAddr>> {
    let interfaces = get_if_addrs()?;
    let addrs = interfaces
        .iter()
        .filter_map(|interface| match interface.addr {
            IfAddr::V4(ref ifv4_addr) => Some(ifv4_addr.ip),
            IfAddr::V6(_) => None,
        }).filter(|ip| !ip.is_loopback())
        .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, with_port)))
        .collect();
    Ok(addrs)
}
