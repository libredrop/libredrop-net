#[cfg(test)]
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// A convevience method to build IPv4 address with a port number.
#[cfg(test)]
pub fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}
