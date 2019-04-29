//! Demontrates how to discover peers on LAN, connect and exchange data with them.
//!
//! This example merely tries to represnet the libredrop-net API and thus has its own limitation,
//! e.g. only one file can be sent at a time. But those are not the limitations of libredrop-net
//! itself.
//!
//! Usage:
//! ```
//! $ RUST_LOG=info cargo run --example chat
//! ```

#[macro_use]
extern crate log;

use chrono::Local;
use future_utils::{mpsc, BoxFuture, FutureExt};
use futures::{future, Future, Sink, Stream};
use hex;
use libredrop_net::{Connection, Message, Peer, PeerEvent, PeerInfo};
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::{env, thread};
use tokio::runtime::current_thread::Runtime;
use unwrap::unwrap;
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
    println!("Type /h for help");

    let mut evloop = unwrap!(Runtime::new());

    let (quit_tx, quit_rx) = mpsc::unbounded();
    let (events_tx, events_rx) = mpsc::unbounded();
    let mut app = App::new(&mut evloop, quit_tx, events_tx.clone());

    // TODO(povilas): spawn future returned by handle_event?
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
    /// Application context shared among futures.
    ctx: Rc<RefCell<Context>>,
}

#[derive(Default)]
struct Context {
    /// Current file being downloaded.
    file_in_progress: Option<File>,
    /// Where received files will be stored.
    files_dir: PathBuf,
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

        let files_dir = unwrap!(env::current_dir());
        info!("File storage: {:?}", files_dir);

        let ctx = Rc::new(RefCell::new(Context {
            file_in_progress: None,
            files_dir,
        }));
        Self {
            quit_tx,
            peers: Default::default(),
            peer,
            ctx,
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
            "s" => return self.cmd_send_msg(&cmd[2..]),
            "f" => return self.cmd_send_file(&cmd[2..]),
            _ => (),
        }
        future::ok(()).into_boxed()
    }

    fn cmd_send_msg(&self, args: &str) -> BoxFuture<(), Void> {
        if let Some((peer_id, text)) = parse_send(args) {
            if let Some(endpoints) = self.peers.get(&peer_id) {
                return self.send_msg_to(endpoints.clone(), text).into_boxed();
            }
        }
        future::ok(()).into_boxed()
    }

    fn cmd_send_file(&self, args: &str) -> BoxFuture<(), Void> {
        if let Some((peer_id, file_path)) = parse_send(args) {
            if let Some(endpoints) = self.peers.get(&peer_id) {
                return self
                    .peer
                    .send_file_to(endpoints.clone(), &file_path)
                    .log_error(log::Level::Info, "File send failed")
                    .into_boxed();
            }
        }
        future::ok(()).into_boxed()
    }

    /// Receives and prints a message.
    fn handle_conn(&self, conn: Connection) -> impl Future<Item = (), Error = Void> {
        let app_ctx = self.ctx.clone();
        conn.for_each(move |msg| {
            match msg {
                Message::Data(buf) => {
                    out!("Received: {}", unwrap!(String::from_utf8(buf)));
                }
                Message::FileStart(fname, buf) => {
                    out!("Accepting file '{}' of {} bytes", fname, buf.len());

                    let mut file_path = app_ctx.borrow().files_dir.clone();
                    file_path.push(fname);
                    let mut file = unwrap!(File::create(file_path));
                    unwrap!(file.write_all(&buf));
                    app_ctx.borrow_mut().file_in_progress = Some(file);
                }
                Message::FileChunk(buf) => {
                    // out!("Received file chunk: {}", buf.len());
                    if let Some(file) = &mut app_ctx.borrow_mut().file_in_progress {
                        unwrap!(file.write_all(&buf));
                    }
                }
                Message::FileEnd => {
                    out!("File download finished");
                    let _ = app_ctx.borrow_mut().file_in_progress.take();
                }
            }
            Ok(())
        })
        .log_error(log::Level::Info, "Broken pipe")
    }

    /// Connects to a peer via one of the given contacts, sends a message and closes the
    /// connection.
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
    let re = unwrap!(Regex::new(r"\s+(\w+)\s+(.*)"));
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
    println!("  /f <PEER_NUMBER> <FILE_PATH> - send file to a peer. List peers to get a number.");
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
