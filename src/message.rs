//! Internal communication messages.

use safe_crypto::PublicEncryptKey;

/// libredrop message during connection handshake.
#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Connection request.
    Connect(PublicEncryptKey),
    /// Connection request was denied.
    DenyConnect,
    /// Connection request was accepted.
    AcceptConnect,
}

/// Message over established connection.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum Message {
    /// Generic data.
    Data(Vec<u8>),
    /// This message indicates file transfer start.
    FileStart(String, Vec<u8>),
    /// Chunk of file currently being sent through the connection. Note that only one file can
    /// be sent over single connection at a time. This might change in the future with the adoption
    /// of QUIC protocol.
    FileChunk(Vec<u8>),
    /// Indicates that all file chunks were sent.
    FileEnd,
}
