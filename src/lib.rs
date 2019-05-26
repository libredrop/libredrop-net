//! libredrop-net is LibreDrop networking library.
//! LibreDrop is an alternative for Apple's AirDrop except aims to support all possible
//! platforms. So it enables you to easilly exchange files between Linux <--> Android, iOS <-->
//! Windows, etc.

#![deny(bare_trait_objects)]
#![allow(clippy::implicit_hasher)]

extern crate future_utils;
extern crate futures;
extern crate get_if_addrs;
extern crate maidsafe_utilities;
extern crate safe_crypto;
#[macro_use]
extern crate serde_derive;
extern crate bytes;
extern crate serde;
#[macro_use]
extern crate unwrap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate net_literals;
extern crate bincode;
extern crate void;
#[cfg(test)]
#[macro_use]
extern crate hamcrest2;
#[cfg(test)]
#[macro_use]
extern crate maplit;

mod connect;
mod listener;
mod message;
mod peer;
mod peer_discovery;
mod priv_prelude;
#[macro_use]
mod utils;

pub use crate::connect::{connect_first_ok, ConnectError, Connection, ConnectionError};
pub use crate::listener::ConnectionListener;
pub use crate::message::Message;
pub use crate::peer::{Peer, PeerEvent, PeerInfo};
pub use crate::peer_discovery::{discover_peers, shout_for_peers, DiscoveryError, DiscoveryServer};

use err_derive::Error;
use maidsafe_utilities::serialisation::SerialisationError;
use std::io;

#[derive(Debug, Error)]
pub enum Error {
    /// IO error
    #[error(display = "I/O error: {}", _0)]
    Io(io::Error),
    /// Peer discovery on LAN error.
    #[error(display = "Peer discovery on LAN failed: {}", _0)]
    Discovery(DiscoveryError),
    /// Crypto related error.
    #[error(display = "Crypto related error: {}", _0)]
    Crypto(safe_crypto::Error),
    /// Data (de)serialisation error.
    #[error(display = "Serialisation error: {}", _0)]
    Serialisation(SerialisationError),
    /// Failed to establish connection.
    #[error(display = "Connection handshake failed: {}", _0)]
    Connect(ConnectError),
    /// Active connection failure.
    #[error(display = "Connection failed: {}", _0)]
    Connection(ConnectionError),
}

impl From<DiscoveryError> for Error {
    fn from(e: DiscoveryError) -> Self {
        Error::Discovery(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
