//! libredrop-net is LibreDrop networking library.
//! LibreDrop is an alternative for Apple's AirDrop except aims to support all possible
//! platforms. So it enables you to easilly exchange files between Linux <--> Android, iOS <-->
//! Windows, etc.

extern crate future_utils;
extern crate futures;
extern crate get_if_addrs;
extern crate maidsafe_utilities;
extern crate safe_crypto;
extern crate tokio;
#[macro_use]
extern crate serde_derive;
extern crate bytes;
extern crate serde;
#[cfg(test)]
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

mod peer;
mod peer_discovery;
mod priv_prelude;

pub use peer_discovery::{discover_peers, shout_for_peers, DiscoveryError, DiscoveryServer};
pub use peer::PeerInfo;
