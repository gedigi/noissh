//! Transport / session layer for noissh — the mini-QUIC-with-Noise spine.
//!
//! Owns the wire packet format, the cryptographic session id, anti-replay,
//! roaming (peer address follows any authenticated packet), the v1 reliable
//! input channel, latest-wins datagram delivery, and the v2 stream multiplexer.
//! Sits *above* the Noise core: Noise encrypts each datagram, the transport
//! sees plaintext frames.

use std::net::SocketAddr;

use noise_core::{NoiseError, Session as NoiseSession};
use thiserror::Error;
use wire::{decode_frames, encode_frames, Frame, WireError};

pub mod input;
pub mod replay;
pub mod stream;

pub use input::{InputReceiver, InputSender};
pub use stream::{Stream, StreamEvent, StreamMux};

use replay::WindowFilter;

/// A cryptographic session id, chosen by the client and constant for the
/// session lifetime. Used for server-side demux *independent of source IP*.
pub type SessionId = [u8; 8];

const PKT_HANDSHAKE: u8 = 0;
const PKT_TRANSPORT: u8 = 1;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("packet too short")]
    Short,
    #[error("unknown packet type {0}")]
    UnknownType(u8),
    #[error("session id mismatch")]
    SessionMismatch,
    #[error("replayed or too-old packet")]
    Replay,
    #[error("noise: {0}")]
    Noise(#[from] NoiseError),
    #[error("wire: {0}")]
    Wire(#[from] WireError),
}

/// Generate a random session id.
pub fn random_session_id() -> SessionId {
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).expect("getrandom");
    id
}

/// What kind of packet a raw datagram is, plus its session id and body.
pub enum Packet<'a> {
    Handshake { session_id: SessionId, body: &'a [u8] },
    Transport { session_id: SessionId, nonce: u64, body: &'a [u8] },
}

/// Parse the outer header of a raw datagram without decrypting.
pub fn parse_packet(buf: &[u8]) -> Result<Packet<'_>, TransportError> {
    if buf.is_empty() {
        return Err(TransportError::Short);
    }
    let ty = buf[0];
    if buf.len() < 9 {
        return Err(TransportError::Short);
    }
    let mut session_id = [0u8; 8];
    session_id.copy_from_slice(&buf[1..9]);
    match ty {
        PKT_HANDSHAKE => Ok(Packet::Handshake { session_id, body: &buf[9..] }),
        PKT_TRANSPORT => {
            if buf.len() < 17 {
                return Err(TransportError::Short);
            }
            let nonce = u64::from_be_bytes(buf[9..17].try_into().unwrap());
            Ok(Packet::Transport { session_id, nonce, body: &buf[17..] })
        }
        other => Err(TransportError::UnknownType(other)),
    }
}

/// Build a raw handshake packet: `[type=0][session_id][noise message]`.
pub fn build_handshake_packet(session_id: &SessionId, noise_msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + noise_msg.len());
    out.push(PKT_HANDSHAKE);
    out.extend_from_slice(session_id);
    out.extend_from_slice(noise_msg);
    out
}

/// A live transport session over an established Noise session.
///
/// Roaming: `open()` updates `peer_addr` to the source address of any packet
/// that authenticates — and only after it authenticates, so a forged packet
/// from a new address can never hijack the session.
pub struct Session {
    pub session_id: SessionId,
    noise: NoiseSession,
    send_nonce: u64,
    replay: WindowFilter,
    peer_addr: Option<SocketAddr>,
}

impl Session {
    pub fn new(session_id: SessionId, noise: NoiseSession, peer_addr: Option<SocketAddr>) -> Self {
        Session {
            session_id,
            noise,
            send_nonce: 0,
            replay: WindowFilter::new(),
            peer_addr,
        }
    }

    /// The authenticated peer static public key.
    pub fn remote_static(&self) -> &[u8] {
        self.noise.remote_static()
    }

    /// Current known peer address (where to send), if any.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Encrypt and frame outgoing frames into a transport packet.
    pub fn seal(&mut self, frames: &[Frame]) -> Result<Vec<u8>, TransportError> {
        let plaintext = encode_frames(frames);
        let nonce = self.send_nonce;
        self.send_nonce += 1;
        let ct = self.noise.encrypt(nonce, &plaintext)?;
        let mut out = Vec::with_capacity(17 + ct.len());
        out.push(PKT_TRANSPORT);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Authenticate and decode an incoming transport packet from `src`.
    /// On success, updates the roaming peer address to `src`.
    pub fn open(&mut self, src: SocketAddr, packet: &[u8]) -> Result<Vec<Frame>, TransportError> {
        let (session_id, nonce, body) = match parse_packet(packet)? {
            Packet::Transport { session_id, nonce, body } => (session_id, nonce, body),
            Packet::Handshake { .. } => return Err(TransportError::UnknownType(PKT_HANDSHAKE)),
        };
        if session_id != self.session_id {
            return Err(TransportError::SessionMismatch);
        }
        // Decrypt FIRST. Only an authenticated packet may move our peer address.
        let plaintext = self.noise.decrypt(nonce, body)?;
        // Then enforce anti-replay (authentic but replayed packets are dropped).
        if !self.replay.check_and_set(nonce) {
            return Err(TransportError::Replay);
        }
        self.peer_addr = Some(src);
        Ok(decode_frames(&plaintext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noise_core::{generate_keypair, handshake_in_memory};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn pair() -> (Session, Session) {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, rsess) = handshake_in_memory(&ik, &rk).unwrap();
        let sid = random_session_id();
        let client = Session::new(sid, isess, Some(addr("10.0.0.1:5000")));
        let server = Session::new(sid, rsess, Some(addr("10.0.0.1:5000")));
        (client, server)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut client, mut server) = pair();
        let frames = vec![Frame::Input { offset: 0, data: b"ls\n".to_vec() }];
        let pkt = client.seal(&frames).unwrap();
        let got = server.open(addr("10.0.0.1:5000"), &pkt).unwrap();
        assert_eq!(got, frames);
    }

    #[test]
    fn replayed_packet_rejected() {
        let (mut client, mut server) = pair();
        let pkt = client.seal(&[Frame::Ack { seq: 1 }]).unwrap();
        assert!(server.open(addr("10.0.0.1:5000"), &pkt).is_ok());
        assert!(matches!(
            server.open(addr("10.0.0.1:5000"), &pkt),
            Err(TransportError::Replay)
        ));
    }

    #[test]
    fn session_id_mismatch_rejected() {
        let (mut client, mut server) = pair();
        server.session_id = [9; 8];
        let pkt = client.seal(&[Frame::Ack { seq: 1 }]).unwrap();
        assert!(matches!(
            server.open(addr("10.0.0.1:5000"), &pkt),
            Err(TransportError::SessionMismatch)
        ));
    }

    #[test]
    fn roaming_updates_peer_addr_on_authenticated_packet() {
        let (mut client, mut server) = pair();
        assert_eq!(server.peer_addr(), Some(addr("10.0.0.1:5000")));
        // Client moved networks: new source address.
        let pkt = client.seal(&[Frame::Ping { stamp: 1 }]).unwrap();
        server.open(addr("203.0.113.7:40000"), &pkt).unwrap();
        assert_eq!(server.peer_addr(), Some(addr("203.0.113.7:40000")));
    }

    #[test]
    fn forged_packet_from_new_addr_does_not_hijack_peer_addr() {
        let (mut client, mut server) = pair();
        // An attacker at a new address sends garbage claiming the session id.
        let mut forged = client.seal(&[Frame::Ping { stamp: 1 }]).unwrap();
        let last = forged.len() - 1;
        forged[last] ^= 0xff; // corrupt the AEAD tag
        let before = server.peer_addr();
        assert!(server.open(addr("198.51.100.9:1234"), &forged).is_err());
        // Peer address must NOT have moved to the attacker.
        assert_eq!(server.peer_addr(), before);
    }

    #[test]
    fn out_of_order_within_window_all_delivered() {
        let (mut client, mut server) = pair();
        let p0 = client.seal(&[Frame::Ack { seq: 0 }]).unwrap();
        let p1 = client.seal(&[Frame::Ack { seq: 1 }]).unwrap();
        let p2 = client.seal(&[Frame::Ack { seq: 2 }]).unwrap();
        // Deliver reordered.
        assert_eq!(server.open(addr("10.0.0.1:5000"), &p2).unwrap(), vec![Frame::Ack { seq: 2 }]);
        assert_eq!(server.open(addr("10.0.0.1:5000"), &p0).unwrap(), vec![Frame::Ack { seq: 0 }]);
        assert_eq!(server.open(addr("10.0.0.1:5000"), &p1).unwrap(), vec![Frame::Ack { seq: 1 }]);
    }

    #[test]
    fn parse_packet_rejects_short_and_unknown() {
        assert!(matches!(parse_packet(&[]), Err(TransportError::Short)));
        assert!(matches!(parse_packet(&[PKT_TRANSPORT, 0, 0]), Err(TransportError::Short)));
        let mut buf = vec![7u8]; // unknown type
        buf.extend_from_slice(&[0u8; 8]);
        assert!(matches!(parse_packet(&buf), Err(TransportError::UnknownType(7))));
    }

    #[test]
    fn handshake_packet_roundtrips_header() {
        let sid = random_session_id();
        let pkt = build_handshake_packet(&sid, b"noise-msg");
        match parse_packet(&pkt).unwrap() {
            Packet::Handshake { session_id, body } => {
                assert_eq!(session_id, sid);
                assert_eq!(body, b"noise-msg");
            }
            _ => panic!("expected handshake packet"),
        }
    }
}
