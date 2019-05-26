//! Common includes.

pub use crate::peer::PeerInfo;
pub use future_utils::{BoxFuture, BoxStream, FutureExt, StreamExt};
pub use futures::{Async, Future, Poll, Stream};
pub use safe_crypto::{
    gen_encrypt_keypair, Error as EncryptionError, PublicEncryptKey, SecretEncryptKey,
    SharedSecretKey,
};
pub use serde::de::DeserializeOwned;
pub use serde::Serialize;
pub use std::collections::{HashMap, HashSet, VecDeque};
pub use std::io;
pub use std::net::SocketAddr;
pub use std::time::Duration;
pub use void::Void;
