use libredrop_net::Peer;
use tokio::runtime::current_thread::Runtime;
use unwrap::unwrap;

use rand::{self, RngCore};
use std::{env, fs::File, io::Write, path::PathBuf};

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

#[test]
fn send_file() {
    let mut evloop = unwrap!(Runtime::new());

    let (mut peer1, _peer1_event_rx) = Peer::new(12345);
    unwrap!(peer1.start(&mut evloop));
    let (mut peer2, _peer2_event_rx) = Peer::new(12346);
    unwrap!(peer2.start(&mut evloop));

    let fname = tmp_file();
    let fname_str = unwrap!(fname.to_str());
    let data = random_vec(1024 * 1024);
    write_to_file(&fname, &data);

    let task = peer1.send_file_to(peer2.endpoints(), fname_str);
    unwrap!(evloop.block_on(task));
}
