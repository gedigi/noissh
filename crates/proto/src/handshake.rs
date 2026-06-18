//! XX handshake driver over the transport packet layer.
//!
//! Produces and consumes raw handshake packets (`[type=0][session_id][msg]`)
//! and, on completion, yields a [`transport::Session`]. Auth decisions
//! (authorized_keys on the server, TOFU known_hosts on the client) are made by
//! the caller using the peer's authenticated static key, which is available
//! once the handshake finishes.

use std::net::SocketAddr;

use noise_core::{Handshake, NoiseError, Role};
use thiserror::Error;
use transport::{Session, SessionId, build_handshake_packet};

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("noise: {0}")]
    Noise(#[from] NoiseError),
    #[error("handshake already finished")]
    AlreadyFinished,
    #[error("handshake not finished")]
    NotFinished,
}

/// Drives one side of the XX handshake.
pub struct Handshaker {
    hs: Option<Handshake>,
    session_id: SessionId,
    finished: bool,
}

/// Result of feeding a handshake message.
pub struct HsOutcome {
    /// A reply packet to send to the peer, if any.
    pub reply: Option<Vec<u8>>,
    /// Whether the handshake is now complete.
    pub finished: bool,
}

impl Handshaker {
    /// Begin as the client. Returns the driver and the first packet to send.
    pub fn client(
        local_private: &[u8],
        session_id: SessionId,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let mut hs = Handshake::new(Role::Initiator, local_private)?;
        let msg1 = hs.write_message(&[])?;
        let pkt = build_handshake_packet(&session_id, &msg1);
        Ok((
            Handshaker {
                hs: Some(hs),
                session_id,
                finished: false,
            },
            pkt,
        ))
    }

    /// Begin as the server, awaiting the client's first message.
    pub fn server(local_private: &[u8], session_id: SessionId) -> Result<Self, HandshakeError> {
        let hs = Handshake::new(Role::Responder, local_private)?;
        Ok(Handshaker {
            hs: Some(hs),
            session_id,
            finished: false,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Feed an incoming handshake message body (the part after the packet
    /// header). Returns any reply packet to send and whether we are done.
    pub fn read(&mut self, body: &[u8]) -> Result<HsOutcome, HandshakeError> {
        let hs = self.hs.as_mut().ok_or(HandshakeError::AlreadyFinished)?;
        hs.read_message(body)?;
        if hs.is_finished() {
            // Responder completes upon reading the final message.
            self.finished = true;
            return Ok(HsOutcome {
                reply: None,
                finished: true,
            });
        }
        // Otherwise we owe the peer the next message.
        let out = hs.write_message(&[])?;
        self.finished = hs.is_finished();
        let pkt = build_handshake_packet(&self.session_id, &out);
        Ok(HsOutcome {
            reply: Some(pkt),
            finished: self.finished,
        })
    }

    /// The peer's authenticated static public key (once available).
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.hs.as_ref().and_then(|h| h.remote_static())
    }

    /// Consume into a live transport session anchored at `peer_addr`. Errors if
    /// the handshake has not completed.
    pub fn into_session(self, peer_addr: Option<SocketAddr>) -> Result<Session, HandshakeError> {
        if !self.finished {
            return Err(HandshakeError::NotFinished);
        }
        let hs = self.hs.ok_or(HandshakeError::AlreadyFinished)?;
        let noise = hs.into_transport()?;
        Ok(Session::new(self.session_id, noise, peer_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noise_core::generate_keypair;
    use transport::{Packet, parse_packet, random_session_id};

    fn body(pkt: &[u8]) -> Vec<u8> {
        match parse_packet(pkt).unwrap() {
            Packet::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected handshake packet"),
        }
    }

    #[test]
    fn full_handshake_completes_and_exchanges_keys() {
        let ck = generate_keypair().unwrap();
        let sk = generate_keypair().unwrap();
        let sid = random_session_id();

        let (mut client, p1) = Handshaker::client(&ck.private, sid).unwrap();
        let mut server = Handshaker::server(&sk.private, sid).unwrap();

        // server reads msg1 -> replies msg2
        let r1 = server.read(&body(&p1)).unwrap();
        assert!(!r1.finished);
        let p2 = r1.reply.unwrap();

        // client reads msg2 -> replies msg3, finished
        let r2 = client.read(&body(&p2)).unwrap();
        assert!(r2.finished);
        let p3 = r2.reply.unwrap();

        // server reads msg3 -> finished
        let r3 = server.read(&body(&p3)).unwrap();
        assert!(r3.finished);
        assert!(r3.reply.is_none());

        // Both learned each other's true static key.
        assert_eq!(client.remote_static().unwrap(), sk.public);
        assert_eq!(server.remote_static().unwrap(), ck.public);

        // Both produce working transport sessions.
        let csess = client.into_session(None).unwrap();
        let ssess = server.into_session(None).unwrap();
        assert_eq!(csess.remote_static(), sk.public.as_slice());
        assert_eq!(ssess.remote_static(), ck.public.as_slice());
    }
}
