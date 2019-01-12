//! Demontrates how to discover peers on LAN using `shout_for_peers()` method that broadcasts
//! requests.
//!
//! Run the server on other (or same) machine on LAN and then run:
//! ```
//! $ RUST_LOG=info cargo run --example shout_for_peers
//! ```

extern crate env_logger;
extern crate libredrop_net;
#[macro_use]
extern crate log;
extern crate futures;
extern crate tokio;
#[macro_use]
extern crate unwrap;
extern crate safe_crypto;

use futures::Stream;
use libredrop_net::shout_for_peers;
use safe_crypto::gen_encrypt_keypair;
use tokio::runtime::current_thread::Runtime;

fn main() {
    env_logger::init();
    let mut evloop = unwrap!(Runtime::new());

    info!("Looking for peers on LAN on port 6000");
    let (our_pk, our_sk) = gen_encrypt_keypair();
    let find_peers = shout_for_peers(6000, our_pk, our_sk)
        .map_err(|e| error!("Peer discovery failed: {:?}", e))
        .for_each(|addrs| {
            println!("Peer is listening on: {:?}", addrs);
            Ok(())
        });
    unwrap!(evloop.block_on(find_peers));
}
