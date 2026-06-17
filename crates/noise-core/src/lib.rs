//! Noise session core for noissh.
//!
//! Wraps `snow` to provide the `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake
//! and a stateless transport mode (explicit per-message nonce) suitable for
//! out-of-order UDP datagrams. Pure bytes-in / bytes-out: knows nothing about
//! UDP, terminals, or PAM.

use thiserror::Error;

/// The fixed Noise pattern noissh uses for all sessions.
pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Length of an X25519 public/private key in bytes.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("snow error: {0}")]
    Snow(String),
    #[error("handshake not finished")]
    HandshakeNotFinished,
    #[error("remote static key unavailable")]
    NoRemoteStatic,
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        NoiseError::Snow(format!("{e:?}"))
    }
}

/// A static X25519 keypair.
#[derive(Clone)]
pub struct Keypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// Generate a fresh static keypair.
pub fn generate_keypair() -> Result<Keypair, NoiseError> {
    let params = PATTERN.parse().map_err(NoiseError::from)?;
    let builder = snow::Builder::new(params);
    let kp = builder.generate_keypair()?;
    Ok(Keypair { private: kp.private, public: kp.public })
}

/// Which side of the handshake we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// In-progress Noise handshake. Drive it with `write_message`/`read_message`
/// until `is_finished()`, then call `into_transport()`.
pub struct Handshake {
    state: snow::HandshakeState,
}

impl Handshake {
    /// Start a handshake with our static private key.
    pub fn new(role: Role, local_private: &[u8]) -> Result<Self, NoiseError> {
        let params = PATTERN.parse().map_err(NoiseError::from)?;
        let builder = snow::Builder::new(params).local_private_key(local_private)?;
        let state = match role {
            Role::Initiator => builder.build_initiator()?,
            Role::Responder => builder.build_responder()?,
        };
        Ok(Handshake { state })
    }

    /// Write the next handshake message (with optional payload) into a fresh buffer.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; payload.len() + 256];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read an incoming handshake message, returning any payload it carried.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; message.len() + 256];
        let n = self.state.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// The peer's static public key (available once it has been transmitted).
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(|s| s.to_vec())
    }

    /// Transition into the stateless transport session.
    pub fn into_transport(self) -> Result<Session, NoiseError> {
        if !self.state.is_handshake_finished() {
            return Err(NoiseError::HandshakeNotFinished);
        }
        let remote = self
            .state
            .get_remote_static()
            .ok_or(NoiseError::NoRemoteStatic)?
            .to_vec();
        let transport = self.state.into_stateless_transport_mode()?;
        Ok(Session { transport, remote_static: remote })
    }
}

/// A live transport-mode session. AEAD with an explicit caller-supplied nonce
/// per message, so reordered/lost datagrams are fine.
pub struct Session {
    transport: snow::StatelessTransportState,
    remote_static: Vec<u8>,
}

impl Session {
    /// The authenticated peer static public key.
    pub fn remote_static(&self) -> &[u8] {
        &self.remote_static
    }

    /// Encrypt `plaintext` under `nonce`, returning the ciphertext (incl. tag).
    pub fn encrypt(&self, nonce: u64, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self.transport.write_message(nonce, plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt `ciphertext` produced under `nonce`. Fails on tamper/wrong nonce.
    pub fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self.transport.read_message(nonce, ciphertext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Run a full XX handshake between two parties in memory. Returns both sessions.
/// Useful for tests and in-process wiring.
pub fn handshake_in_memory(
    initiator_key: &Keypair,
    responder_key: &Keypair,
) -> Result<(Session, Session), NoiseError> {
    let mut i = Handshake::new(Role::Initiator, &initiator_key.private)?;
    let mut r = Handshake::new(Role::Responder, &responder_key.private)?;

    let m1 = i.write_message(&[])?; // -> e
    r.read_message(&m1)?;
    let m2 = r.write_message(&[])?; // <- e, ee, s, es
    i.read_message(&m2)?;
    let m3 = i.write_message(&[])?; // -> s, se
    r.read_message(&m3)?;

    Ok((i.into_transport()?, r.into_transport()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_32_bytes() {
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.public.len(), KEY_LEN);
        assert_eq!(kp.private.len(), KEY_LEN);
    }

    #[test]
    fn xx_handshake_completes_and_exchanges_static_keys() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();

        let mut i = Handshake::new(Role::Initiator, &ik.private).unwrap();
        let mut r = Handshake::new(Role::Responder, &rk.private).unwrap();

        let m1 = i.write_message(&[]).unwrap();
        r.read_message(&m1).unwrap();
        let m2 = r.write_message(&[]).unwrap();
        i.read_message(&m2).unwrap();
        let m3 = i.write_message(&[]).unwrap();
        r.read_message(&m3).unwrap();

        assert!(i.is_finished() && r.is_finished());
        // Each side learned the other's true static public key.
        assert_eq!(i.remote_static().unwrap(), rk.public);
        assert_eq!(r.remote_static().unwrap(), ik.public);
    }

    #[test]
    fn transport_roundtrip_out_of_order() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, rsess) = handshake_in_memory(&ik, &rk).unwrap();

        // Encrypt three messages at increasing nonces, decrypt out of order.
        let c0 = isess.encrypt(0, b"zero").unwrap();
        let c1 = isess.encrypt(1, b"one").unwrap();
        let c2 = isess.encrypt(2, b"two").unwrap();

        assert_eq!(rsess.decrypt(2, &c2).unwrap(), b"two");
        assert_eq!(rsess.decrypt(0, &c0).unwrap(), b"zero");
        assert_eq!(rsess.decrypt(1, &c1).unwrap(), b"one");
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_is_longer() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, _r) = handshake_in_memory(&ik, &rk).unwrap();
        let ct = isess.encrypt(0, b"secret payload").unwrap();
        assert_ne!(&ct[..], b"secret payload");
        assert_eq!(ct.len(), b"secret payload".len() + 16); // AEAD tag
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, rsess) = handshake_in_memory(&ik, &rk).unwrap();
        let mut ct = isess.encrypt(0, b"trust me").unwrap();
        ct[0] ^= 0xff;
        assert!(rsess.decrypt(0, &ct).is_err());
    }

    #[test]
    fn wrong_nonce_fails_to_decrypt() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, rsess) = handshake_in_memory(&ik, &rk).unwrap();
        let ct = isess.encrypt(5, b"payload").unwrap();
        assert!(rsess.decrypt(6, &ct).is_err());
    }

    #[test]
    fn into_transport_before_finished_errors() {
        let ik = generate_keypair().unwrap();
        let hs = Handshake::new(Role::Initiator, &ik.private).unwrap();
        assert!(matches!(hs.into_transport(), Err(NoiseError::HandshakeNotFinished)));
    }

    #[test]
    fn both_directions_independent() {
        let ik = generate_keypair().unwrap();
        let rk = generate_keypair().unwrap();
        let (isess, rsess) = handshake_in_memory(&ik, &rk).unwrap();
        // initiator -> responder
        let a = isess.encrypt(0, b"ping").unwrap();
        assert_eq!(rsess.decrypt(0, &a).unwrap(), b"ping");
        // responder -> initiator, same nonce value, different key direction
        let b = rsess.encrypt(0, b"pong").unwrap();
        assert_eq!(isess.decrypt(0, &b).unwrap(), b"pong");
    }
}
