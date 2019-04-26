use crate::{Error, Message};
use future_utils::thread_future;
use futures::{sink, sync, Future, Sink, Stream};
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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
    use tokio::fs::File;
    File::open(fname)
        .map(|file| BytesCodec::new().framed(file))
        .flatten_stream()
        .map(|buf| Message::Data(buf.to_vec()))
        .map_err(Error::Io)
}

/// Reads file in a separate thread, hence doesn't block current thread.
/// NOTE, this function only works with singlethreaded tokio runtime.
pub fn async_read_file(fname: String) -> impl Stream<Item = Message, Error = Error> {
    let (tx, rx) = sync::mpsc::channel(32);
    let mut tx = tx.wait();
    let task = thread_future(move || {
        let mut buf = [0u8; FILE_CHUNK_SIZE];

        let mut file = match read_first_file_chunk(fname, &mut buf, &mut tx) {
            Some(file) => file,
            None => {
                let _ = tx.flush();
                return;
            }
        };

        loop {
            let (msg, keep_reading) = read_file_chunk(&mut file, &mut buf);
            let _ = tx.send(msg);
            if !keep_reading {
                let _ = tx.flush();
                return;
            }
        }
    })
    .map_err(|_| ());
    current_thread::spawn(task);

    rx.then(|res| match res {
        Ok(msg_or_err) => msg_or_err, // unwrap the result
        Err(()) => unreachable!("mpsc::Receiver should never fail!"),
    })
}

fn read_first_file_chunk(
    fname: String,
    buf: &mut [u8],
    tx: &mut sink::Wait<sync::mpsc::Sender<Result<Message, Error>>>,
) -> Option<File> {
    let mut file = match File::open(&fname).map_err(Error::Io) {
        Ok(file) => file,
        Err(e) => {
            let _ = tx.send(Err(e));
            return None;
        }
    };
    let bytes_read = match file.read(buf).map_err(Error::Io) {
        Ok(bytes_read) => bytes_read,
        Err(e) => {
            let _ = tx.send(Err(e));
            return None;
        }
    };

    let msg = Message::FileStart(fname, buf[..bytes_read].to_vec());
    let _ = tx.send(Ok(msg));

    if bytes_read == 0 {
        let _ = tx.send(Ok(Message::FileEnd));
        return None;
    }

    Some(file)
}

fn read_file_chunk(file: &mut File, buf: &mut [u8]) -> (Result<Message, Error>, bool) {
    match file.read(buf).map_err(Error::Io) {
        Ok(bytes_read) => {
            if bytes_read > 0 {
                let msg = Message::FileChunk(buf[..bytes_read].to_vec());
                (Ok(msg), true)
            } else {
                (Ok(Message::FileEnd), false)
            }
        }
        Err(e) => (Err(e), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future;
    use hamcrest2::prelude::*;
    use rand::{self, RngCore};
    use speculate::speculate;
    use std::{env, fs::File, io::Write, path::PathBuf};
    use std::{thread, time::Duration};
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

    speculate! {
        describe "read_first_file_chunk" {
            before {
                let mut buf = [0u8; FILE_CHUNK_SIZE];
                let (tx, _rx) = sync::mpsc::channel::<Result<Message, Error>>(8);
                let mut tx = tx.wait();
            }

            describe "when file does not exist" {
                it "returns None" {
                    let file = read_first_file_chunk("some_dummy_file_6762.txt".to_string(), &mut buf, &mut tx);
                    assert_that!(file, none());
                }

                it "sends error event" {
                    let _ = read_first_file_chunk("some_dummy_file_6762.txt".to_string(), &mut buf, &mut tx);
                    let mut msgs = unwrap!(_rx.take(1).collect().wait());
                    let msg = unwrap!(msgs.pop());

                    assert_that!(msg, err());
                }
            }

            describe "when file is empty" {
                it "emits both FileStart and FileEnd events" {
                    let fname = tmp_file();
                    write_to_file(&fname, &[]);

                    let fname_str = unwrap!(fname.to_str()).to_string();
                    let _ = read_first_file_chunk(fname_str.clone(), &mut buf, &mut tx);

                    let msgs: Vec<_> = unwrap!(_rx.take(2).map(|msg| unwrap!(msg)).collect().wait());
                    assert_that!(
                        msgs,
                        eq(vec![
                           Message::FileStart(fname_str, Default::default()),
                           Message::FileEnd,
                        ])
                    );
                }
            }

            describe "when file has content" {
                it "emits FileStart even with the first chunk" {
                    let fname = tmp_file();
                    write_to_file(&fname, &[1, 2, 3]);

                    let fname_str = unwrap!(fname.to_str()).to_string();
                    let _ = read_first_file_chunk(fname_str.clone(), &mut buf, &mut tx);

                    let msgs: Vec<_> = unwrap!(_rx.take(1).map(|msg| unwrap!(msg)).collect().wait());
                    assert_that!(
                        msgs,
                        eq(vec![
                           Message::FileStart(fname_str, vec![1, 2, 3]),
                        ])
                    );
                }
            }
        }

        describe "async_read_file" {
            it "yields data messages as it reads the file" {
                let mut runtime = unwrap!(Runtime::new());

                let fname = tmp_file();
                let sent_data = random_vec(1024 * 1024);
                write_to_file(&fname, &sent_data);

                let fname_str = unwrap!(fname.to_str()).to_string();
                let make_task = future::lazy(move || {
                    let read_data =
                        async_read_file(fname_str)
                            .map(|msg| {
                                // sleep for some time to trigger interthread message buffer
                                // congestion
                                thread::sleep(Duration::from_millis(50));
                                msg
                            })
                            .map(|msg| match msg {
                                Message::FileStart(_, buf) => buf,
                                Message::FileChunk(buf) => buf,
                                Message::FileEnd => vec![],
                                msg => unreachable!("Unexpected message: {:?}", msg),
                            })
                            .collect()
                            .and_then(move |mut all_chunks| {
                                let received_data: Vec<_> = all_chunks.drain(..).flatten().collect();
                                assert_eq!(received_data.len(), sent_data.len());
                                Ok(())
                            });
                    future::ok::<_, ()>(read_data)
                });

                let read_data = unwrap!(runtime.block_on(make_task));
                unwrap!(runtime.block_on(read_data));
            }
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
