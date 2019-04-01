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

use quick_error::quick_error;

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

use maidsafe_utilities::serialisation::SerialisationError;
use std::io;

// TODO(povilas): use err-derive crate
quick_error! {
    #[derive(Debug)]
    pub enum Error {
        /// IO error
        Io(e: io::Error) {
            display("I/O error: {}", e)
            cause(e)
            from()
        }
        /// Peer discovery on LAN error.
        Discovery(e: DiscoveryError) {
            display("Peer discovery on LAN failed: {}", e)
            cause(e)
            from()
        }
        /// Crypto related error.
        Crypto(e: safe_crypto::Error) {
            display("Crypto related error: {}", e)
            from()
        }
        /// Data (de)serialisation error.
        Serialisation(e: SerialisationError) {
            display("Serialisation error: {}", e)
            cause(e)
            from()
        }
        /// Connection failed.
        Connect(e: ConnectError) {
            display("Connection failed: {}", e)
            cause(e)
            from()
        }
    }
}
