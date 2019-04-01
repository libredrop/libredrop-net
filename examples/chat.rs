//! Demontrates how to discover peers on LAN, connect and exchange data with them.
//!
//! Usage:
//! ```
//! $ RUST_LOG=info cargo run --example chat
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;

use chrono::Local;
use future_utils::{mpsc, BoxFuture, FutureExt};
use futures::{future, Future, Sink, Stream};
use hex;
use libredrop_net::{Connection, Message, Peer, PeerEvent, PeerInfo};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::{io, thread};
use tokio::runtime::current_thread::Runtime;
use void::Void;

/// Prints current time and given formatted string.
macro_rules! out {
    ($($arg:tt)*) => ({
        let date = Local::now();
        print!("\r{} ", date.format("%H:%M"));
        println!($($arg)*);
        print!("\r> ");
        unwrap!(io::stdout().flush());
    });
}

/// Chat event.
#[derive(Debug)]
enum Event {
    /// Input from stdin received.
    Stdin(String),
    FromPeer(PeerEvent),
}

fn main() {
    env_logger::init();
    let mut evloop = unwrap!(Runtime::new());

    let (quit_tx, quit_rx) = mpsc::unbounded();
    let (events_tx, events_rx) = mpsc::unbounded();
    let mut app = App::new(&mut evloop, quit_tx, events_tx.clone());

    let handle_events = events_rx.for_each(move |event| app.handle_event(event));
    let (read_lines, _thread) = read_lines();
    let handle_stdin = read_lines.map(Event::Stdin).for_each(move |event| {
        let _ = events_tx.unbounded_send(event);
        Ok(())
    });
    let quit = quit_rx.into_future().map(|_| ((), ())).map_err(|(e, _)| e);
    let main_loop = handle_events.join(handle_stdin).select(quit).map(|_| ());
    let _ = evloop.block_on(main_loop);
}

struct App {
    quit_tx: mpsc::UnboundedSender<()>,
    /// Peer addresses associated with their ID. One peer can have multiple addresses.
    peers: HashMap<String, HashSet<PeerInfo>>,
    peer: Peer,
}

impl App {
    fn new(
        evloop: &mut Runtime,
        quit_tx: mpsc::UnboundedSender<()>,
        events_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        let (mut peer, peer_events_rx) = Peer::new(6000);

        let handle_peer_events = peer_events_rx
            .map(Event::FromPeer)
            .for_each(move |event| {
                let _ = events_tx.unbounded_send(event);
                Ok(())
            })
            .map_err(|_| ());
        evloop.spawn(handle_peer_events);

        unwrap!(peer.start(evloop));

        Self {
            quit_tx,
            peers: Default::default(),
            peer,
        }
    }

    fn handle_event(&mut self, event: Event) -> BoxFuture<(), Void> {
        match event {
            Event::Stdin(ln) => self.handle_cmd(ln),
            Event::FromPeer(event) => match event {
                PeerEvent::DiscoveredPeers(peers) => {
                    self.add_peer_addrs(peers);
                    future::ok(()).into_boxed()
                }
                PeerEvent::NewConnection(conn) => self.handle_conn(conn).into_boxed(),
            },
        }
    }

    fn handle_cmd(&self, cmd: String) -> BoxFuture<(), Void> {
        if cmd.len() < 2 || !cmd.starts_with('/') {
            return future::ok(()).into_boxed();
        }

        match cmd[1..2].as_ref() {
            "q" => {
                let _ = self.quit_tx.unbounded_send(());
            }
            "h" => print_help(),
            "l" => self.print_peers(),
            "s" => {
                if let Some((peer_id, text)) = parse_send(&cmd[..]) {
                    if let Some(endpoints) = self.peers.get(&peer_id) {
                        return self.send_msg_to(endpoints.clone(), text).into_boxed();
                    }
                }
            }
            _ => (),
        }
        future::ok(()).into_boxed()
    }

    /// Receives and prints a message.
    fn handle_conn(&self, conn: Connection) -> impl Future<Item = (), Error = Void> {
        conn.into_future()
            .map_err(|(e, _)| e)
            .and_then(|(msg_opt, conn)| {
                if let Some(msg) = msg_opt {
                    if let Some(data) = msg.into_data() {
                        out!("Received: {}", unwrap!(String::from_utf8(data)));
                    }
                } else {
                    info!("Broken pipe: {}", conn.peer_addr());
                }
                Ok(())
            })
            .log_error(log::Level::Info, "Broken pipe")
    }

    fn send_msg_to(
        &self,
        endpoints: HashSet<PeerInfo>,
        text: String,
    ) -> impl Future<Item = (), Error = Void> {
        self.peer
            .connect_to(endpoints)
            .map_err(|errs| {
                info!("All connection attempts failed: {:?}", errs);
                0
            })
            .and_then(|conn| {
                out!("connected with {}", conn.peer_addr());
                conn.send(Message::Data(text.into_bytes())).map_err(|e| {
                    info!("Failed to send a message: {}", e);
                    0
                })
            })
            .map(|_conn| ())
            .log_error(log::Level::Trace, "Connect/send failed")
    }

    fn add_peer_addrs(&mut self, peers: HashSet<PeerInfo>) {
        for peer in peers {
            let peer_id = peer_id(&peer);
            if let Some(ref mut addrs) = self.peers.get_mut(&peer_id) {
                let _ = addrs.insert(peer);
            } else {
                let mut addrs = HashSet::new();
                let _ = addrs.insert(peer);
                let _ = self.peers.insert(peer_id, addrs);
            }
        }
    }

    fn print_peers(&self) {
        println!("\rDiscovered peers:");
        for (peer_id, addrs) in &self.peers {
            let addrs: HashSet<_> = addrs.iter().map(|info| info.addr).collect();
            println!("{} {:?}", peer_id, addrs);
        }
        print!("\r> ");
        unwrap!(io::stdout().flush());
    }
}

/// Returns peer ID and string to send to the peer or None if given string is invalid send command.
fn parse_send(cmd: &str) -> Option<(String, String)> {
    let re = unwrap!(Regex::new(r"/s\s+(\w+)\s+(.*)"));
    let caps = re.captures(cmd)?;
    let peer_id = caps.get(1)?.as_str().to_string();
    let text = caps.get(2)?.as_str().to_string();
    Some((peer_id, text))
}

fn print_help() {
    println!("Available commands:");
    println!("  /q - quit");
    println!("  /h - print this help message.");
    println!("  /l - list discovered peers.");
    println!("  /s <PEER_NUMBER> - send message to a peer. List peers to get a number.");
    print!("\r> ");
    unwrap!(io::stdout().flush());
}

/// Get abbreviated peer ID hash which is more convenient for interactive use from CLI.
fn peer_id(peer: &PeerInfo) -> String {
    hex::encode(&peer.pub_key.into_bytes()[..4])
}

/// Asynchronousl reads lines from stdin.
fn read_lines() -> (
    impl Stream<Item = String, Error = Void>,
    thread::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::unbounded();
    let thread_handle = thread::spawn(move || loop {
        print!("\r> ");
        unwrap!(io::stdout().flush());

        let stdin = io::stdin();
        let mut line = String::new();
        unwrap!(stdin.read_line(&mut line));
        let line = line.trim_end().into();

        if tx.unbounded_send(line).is_err() {
            break;
        }
    });
    (rx, thread_handle)
}
