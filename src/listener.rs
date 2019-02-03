///! Connection listener.
use futures::stream;
use tokio::net::TcpListener;

use crate::peer::Connection;
use crate::priv_prelude::*;

/// Listens for incoming connections.
pub struct ConnectionListener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl ConnectionListener {
    /// Bind to a given address and start listening for incominng connections.
    pub fn bind(addr: &SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Returns port on which listener accepts incoming connections;
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }
}

impl Stream for ConnectionListener {
    type Item = Connection;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.listener
            .poll_accept()
            .map(|res| res.map(|(stream, _addr)| Some(Connection::wrap(stream))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ipv4_addr;
    use tokio::runtime::current_thread::Runtime;

    mod connection_listener {
        use super::*;
        use std::sync::mpsc;

        #[test]
        fn it_yields_established_connection() {
            let listener = unwrap!(ConnectionListener::bind(&addr!("127.0.0.1:0")));
            let listener_addr = ipv4_addr(127, 0, 0, 1, listener.port());

            let (conn_tx, conn_rx) = mpsc::sync_channel(5);

            let _thread = std::thread::spawn(move || {
                let task = listener.for_each(|conn| {
                    unwrap!(conn_tx.send(conn));
                    Ok(())
                });
                let mut evloop = unwrap!(Runtime::new());
                unwrap!(evloop.block_on(task));
            });

            let task = Connection::make(&listener_addr);
            let mut evloop = unwrap!(Runtime::new());
            unwrap!(evloop.block_on(task));

            let conn = unwrap!(conn_rx.recv());
            let peer_addr = unwrap!(conn.peer_addr());
            assert_eq!(peer_addr.ip(), ipv4!("127.0.0.1"));
        }
    }
}
