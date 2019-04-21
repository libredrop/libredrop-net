use crate::{Error, Message};
use futures::{sync, Future, Stream};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::fs::File;
use tokio::runtime::current_thread;
use tokio_codec::{BytesCodec, Decoder};

const FILE_CHUNK_SIZE: usize = 1024 * 8;

/// A convevience method to build IPv4 address with a port number.
pub fn ipv4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

/// Asynchronously reads file from disk.
/// NOTE, this function only works with multithreaded tokio runtime.
#[allow(unused)]
pub fn read_file(fname: String) -> impl Stream<Item = Message, Error = Error> {
    File::open(fname)
        .map(|file| BytesCodec::new().framed(file))
        .flatten_stream()
        .map(|buf| Message::Data(buf.to_vec()))
        .map_err(Error::Io)
}

/// Reads file in a separate thread, hence doesn't block current thread.
/// NOTE, this function only works with singlethreaded tokio runtime.
pub fn async_read_file(fname: String) -> impl Stream<Item = Vec<u8>, Error = Error> {
    use future_utils::thread_future;
    use std::fs::File;
    use std::io::Read;

    let (mut tx, rx) = sync::mpsc::channel(32);
    let task = thread_future(move || {
        let mut buf = [0u8; FILE_CHUNK_SIZE];
        let mut file = match File::open(fname).map_err(Error::Io) {
            Ok(file) => file,
            Err(e) => {
                let _ = tx.try_send(Err(e));
                return tx; // don't drop tx to get error delivered
            }
        };

        loop {
            match file.read(&mut buf).map_err(Error::Io) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        let _ = tx.try_send(Ok(buf[..bytes_read].to_vec()));
                    } else {
                        return tx;
                    }
                }
                Err(e) => {
                    let _ = tx.try_send(Err(e));
                    return tx; // don't drop tx to get error delivered
                }
            }
        }
    })
    .map(|_tx| ())
    .map_err(|_| ());
    current_thread::spawn(task);

    rx.then(|res| match res {
        Ok(msg_or_err) => msg_or_err, // unwrap the result
        Err(()) => unreachable!("mpsc::Receiver should never fail!"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future;
    use rand::{self, RngCore};
    use std::{env, fs::File, io::Write, path::PathBuf};
    use tokio::runtime::current_thread::Runtime;

    /// Generates
    fn tmp_file() -> PathBuf {
        let fname = format!("{:016x}", rand::random::<u64>());
        let mut path = env::temp_dir();
        path.push(fname);
        path
    }

    fn write_to_file(fname: &PathBuf, data: &[u8]) {
        let mut file = unwrap!(File::create(fname));
        unwrap!(file.write_all(data));
    }

    #[allow(unsafe_code)]
    fn random_vec(size: usize) -> Vec<u8> {
        let mut ret = Vec::with_capacity(size);
        unsafe { ret.set_len(size) };
        rand::thread_rng().fill_bytes(&mut ret[..]);
        ret
    }

    mod async_read_file {
        use super::*;

        #[test]
        fn it_yields_data_messages_as_it_reads_the_file() {
            let mut runtime = unwrap!(Runtime::new());

            let fname = tmp_file();
            let sent_data = random_vec(1024 * 1024);
            write_to_file(&fname, &sent_data);

            let fname_str = unwrap!(fname.to_str()).to_string();
            let make_task = future::lazy(move || {
                let read_data =
                    async_read_file(fname_str)
                        .collect()
                        .and_then(move |mut all_chunks| {
                            let received_data: Vec<_> = all_chunks.drain(..).flatten().collect();
                            assert_eq!(received_data, sent_data);
                            Ok(())
                        });
                future::ok::<_, ()>(read_data)
            });

            let read_data = unwrap!(runtime.block_on(make_task));
            unwrap!(runtime.block_on(read_data));
        }
    }

    mod read_file {
        use super::*;
        use tokio;

        #[test]
        fn it_yields_data_messages_as_it_reads_the_file() {
            let fname = tmp_file();
            let sent_data = random_vec(1024 * 1024);
            write_to_file(&fname, &sent_data);

            let fname_str = unwrap!(fname.to_str()).to_string();
            let read_data = read_file(fname_str)
                .map_err(|e| panic!(e))
                .and_then(|msg| {
                    if let Message::Data(buf) = msg {
                        return Ok(buf);
                    } else {
                        panic!("Unexpected message: {:?}", msg);
                    }
                })
                .collect()
                .and_then(move |mut all_chunks| {
                    let received_data: Vec<_> = all_chunks.drain(..).flatten().collect();
                    assert_eq!(received_data, sent_data);
                    Ok(())
                });
            tokio::run(read_data);
        }
    }
}
