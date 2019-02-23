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
    Data(Vec<u8>),
}

impl Message {
    /// Try to convert message into data buffer.
    pub fn into_data(self) -> Option<Vec<u8>> {
        match self {
            Message::Data(buf) => Some(buf),
        }
    }
}
