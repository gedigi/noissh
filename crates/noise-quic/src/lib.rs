#![forbid(unsafe_code)]
//! Noise XX as the crypto layer of a QUIC connection.
//!
//! QUIC (RFC 9000) delegates its handshake to a pluggable crypto layer; TLS 1.3
//! is the usual one (RFC 9001). This crate implements `quinn_proto`'s crypto
//! traits with the Noise protocol instead, so noissh keeps its identity model
//! (static X25519 keys, `known_hosts` pinning, `authorized_keys`) on top of
//! QUIC's transport.
//!
//! # Handshake
//!
//! `Noise_XX_25519_ChaChaPoly_BLAKE2s`, prologue `"noissh-quic"` + the QUIC
//! version. Noise messages travel in QUIC CRYPTO frames, each prefixed with
//! its length (u16, big endian):
//!
//! ```text
//! client                                         server
//!   Initial:   msg1 → e           payload: client transport parameters
//!   Handshake: msg2 ← e, ee, s, es payload: server transport parameters
//!   Handshake: msg3 → s, se        payload: empty
//!   1-RTT keys from Noise Split()
//! ```
//!
//! - Initial and Handshake packet keys are derived from public values (the
//!   client's destination connection id, and the Noise handshake hash after
//!   msg1), as QUIC's Initial keys are: they only obfuscate. Everything the
//!   handshake has to protect is protected by Noise itself: the static keys and
//!   the server's transport parameters are encrypted, and the client's
//!   parameters (msg1, unencrypted) are bound to the handshake transcript, so
//!   tampering with them makes the handshake fail.
//! - The client checks the server's static key with [`PeerCheck`] as soon as
//!   msg2 arrives; the server checks the client's after msg3. A rejected key
//!   aborts the handshake with a crypto error before any 1-RTT key exists.
//! - 1-RTT keys come from Noise's `Split()` (the raw cipher keys, via `snow`'s
//!   `risky-raw-split`). From each direction's secret, keyed BLAKE2s derives the
//!   ChaCha20-Poly1305 packet key and IV and the ChaCha20 header-protection key,
//!   applied as in RFC 9001 §5.3–5.4. Key update (RFC 9001 §6) derives the next
//!   secret from the current one.
//!
//! The QUIC version is noissh's own ([`VERSION`]), so a noissh endpoint never
//! talks to a standard QUIC/TLS endpoint and a later incompatible change can
//! use a new version.

use std::any::Any;
use std::sync::Arc;

use blake2::Blake2sMac256;
use blake2::digest::{KeyInit, Mac};
use bytes::BytesMut;
use chacha20::cipher::consts::U10;
use chacha20::cipher::{KeyIvInit, StreamCipherCore, StreamCipherSeekCore};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use quinn_proto::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey, HeaderKey, HmacKey, KeyPair,
    Keys, PacketKey, UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// noissh's QUIC version: "nois" in ASCII.
pub const VERSION: u32 = 0x6e6f_6973;

/// The Noise pattern, identical to the one noissh 0.6 uses.
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Length of a static X25519 key.
pub const KEY_LEN: usize = 32;

/// AEAD tag length (ChaCha20-Poly1305).
const TAG_LEN: usize = 16;

/// Header-protection sample length (RFC 9001 §5.4.2).
const SAMPLE_LEN: usize = 16;

/// Largest Noise message (the Noise spec's limit).
const MAX_NOISE_MSG: usize = 65_535;

/// Decides whether a peer's static public key is acceptable: the client checks
/// the server against `known_hosts` or the ssh-bootstrap pin, the server checks
/// the client against `authorized_keys`.
pub type PeerCheck = Arc<dyn Fn(&[u8; KEY_LEN]) -> bool + Send + Sync>;

/// The peer's authenticated static public key, as returned (boxed) by
/// `Session::peer_identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity(pub [u8; KEY_LEN]);

// --- key derivation --------------------------------------------------------

/// Keyed BLAKE2s-256 as a PRF: `kdf(key, parts…)`. All secrets here are 32
/// bytes and every label is distinct, so a single PRF call per derived value is
/// sufficient (no expand step is needed).
fn kdf(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("BLAKE2s key <= 32 bytes");
    for p in parts {
        Mac::update(&mut mac, p);
    }
    mac.finalize().into_bytes().into()
}

/// Domain-separation salts for the public (obfuscation-only) key levels.
const INITIAL_SALT: &[u8] = b"noissh-quic initial v1 salt";
const HANDSHAKE_SALT: &[u8] = b"noissh-quic handshake v1 salt";

/// Per-direction secrets for one encryption level (wiped when dropped).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Secrets {
    client: [u8; 32],
    server: [u8; 32],
}

impl Secrets {
    fn from_base(base: &[u8; 32]) -> Self {
        Secrets {
            client: kdf(base, &[b"client"]),
            server: kdf(base, &[b"server"]),
        }
    }

    fn keys(&self, side: Side) -> Keys {
        let (local, remote) = match side {
            Side::Client => (&self.client, &self.server),
            Side::Server => (&self.server, &self.client),
        };
        Keys {
            header: KeyPair {
                local: Box::new(HeaderProtection::from_secret(local)),
                remote: Box::new(HeaderProtection::from_secret(remote)),
            },
            packet: KeyPair {
                local: Box::new(PacketProtection::from_secret(local)),
                remote: Box::new(PacketProtection::from_secret(remote)),
            },
        }
    }

    /// The next generation of 1-RTT secrets (key update, RFC 9001 §6).
    fn update(&self) -> Self {
        Secrets {
            client: kdf(&self.client, &[b"key update"]),
            server: kdf(&self.server, &[b"key update"]),
        }
    }
}

fn initial_secrets(dst_cid: &ConnectionId) -> Secrets {
    Secrets::from_base(&kdf(INITIAL_SALT, &[&dst_cid[..]]))
}

// --- packet and header protection ------------------------------------------

/// ChaCha20-Poly1305 packet protection (RFC 9001 §5.3): nonce = IV XOR packet
/// number, AAD = the packet header.
struct PacketProtection {
    aead: ChaCha20Poly1305,
    iv: [u8; 12],
}

impl PacketProtection {
    fn from_secret(secret: &[u8; 32]) -> Self {
        let key = kdf(secret, &[b"quic key"]);
        let iv_full = kdf(secret, &[b"quic iv"]);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_full[..12]);
        PacketProtection {
            aead: ChaCha20Poly1305::new((&key).into()),
            iv,
        }
    }

    fn nonce(&self, packet: u64) -> Nonce {
        let mut n = self.iv;
        for (b, p) in n[4..].iter_mut().zip(packet.to_be_bytes()) {
            *b ^= p;
        }
        n.into()
    }
}

impl PacketKey for PacketProtection {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_out) = payload_tag.split_at_mut(payload_tag.len() - TAG_LEN);
        let tag = self
            .aead
            .encrypt_in_place_detached(&self.nonce(packet), header, payload)
            .expect("ChaCha20-Poly1305 encryption cannot fail for QUIC-sized packets");
        tag_out.copy_from_slice(&tag);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let len = payload.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
        let (data, tag) = payload.split_at_mut(len);
        let tag = Tag::clone_from_slice(tag);
        self.aead
            .decrypt_in_place_detached(&self.nonce(packet), header, data, &tag)
            .map_err(|_| CryptoError)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    // RFC 9001 §6.6: ChaCha20-Poly1305 has no practical confidentiality limit;
    // its integrity limit is 2^36 forged packets.
    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        1 << 36
    }
}

/// ChaCha20 header protection (RFC 9001 §5.4.4).
struct HeaderProtection {
    key: [u8; 32],
}

impl HeaderProtection {
    fn from_secret(secret: &[u8; 32]) -> Self {
        HeaderProtection {
            key: kdf(secret, &[b"quic hp"]),
        }
    }

    /// The 5-byte mask for a 16-byte sample: the first four bytes are the
    /// block counter (little endian), the rest the nonce.
    ///
    /// The counter comes from the packet, so an attacker chooses it freely,
    /// any of 2^32 values. The keystream block is computed with the ChaCha20
    /// core directly: the stream-cipher wrapper refuses (panics on) a
    /// position in the last block of the counter space, which a single forged
    /// packet with a sample starting `ff ff ff ff` would reach.
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let counter = u32::from_le_bytes(sample[..4].try_into().expect("4 bytes"));
        let nonce: [u8; 12] = sample[4..SAMPLE_LEN].try_into().expect("12 bytes");
        let mut core = chacha20::ChaChaCore::<U10>::new((&self.key).into(), (&nonce).into());
        core.set_block_pos(counter);
        let mut block = Default::default();
        core.write_keystream_block(&mut block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }

    /// Mask bits for the first byte: 4 for long headers, 5 for short ones.
    fn first_byte_bits(first: u8) -> u8 {
        if first & 0x80 != 0 { 0x0f } else { 0x1f }
    }
}

impl HeaderKey for HeaderProtection {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample_at = pn_offset + 4;
        let mask = self.mask(&packet[sample_at..sample_at + SAMPLE_LEN]);
        packet[0] ^= mask[0] & Self::first_byte_bits(packet[0]);
        let pn_len = usize::from(packet[0] & 0x03) + 1;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample_at = pn_offset + 4;
        let mask = self.mask(&packet[sample_at..sample_at + SAMPLE_LEN]);
        let pn_len = usize::from(packet[0] & 0x03) + 1;
        packet[0] ^= mask[0] & Self::first_byte_bits(packet[0]);
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }

    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

// --- the handshake -----------------------------------------------------------

/// Where the handshake is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Client: msg1 not written yet.
    ClientStart,
    /// Client: msg1 written, Handshake keys handed out; waiting for msg2.
    ClientAwaitMsg2,
    /// Client: msg2 read and the server accepted; msg3 to write.
    ClientSendMsg3,
    /// Server: waiting for msg1.
    ServerAwaitMsg1,
    /// Server: msg1 read; Handshake keys to hand out.
    ServerSendHandshakeKeys,
    /// Server: Handshake keys handed out; msg2 to write at that level.
    ServerSendMsg2,
    /// Server: msg2 written; waiting for msg3.
    ServerAwaitMsg3,
    /// Server: msg3 read and the client accepted; 1-RTT keys to hand out.
    ServerSend1Rtt,
    /// Both: handshake complete.
    Done,
}

struct NoiseSession {
    side: Side,
    stage: Stage,
    noise: Option<snow::HandshakeState>,
    /// Our transport parameters, encoded, to send in our Noise payload.
    local_params: Vec<u8>,
    /// The peer's transport parameters once received.
    peer_params: Option<TransportParameters>,
    /// The peer's static key once authenticated by the handshake.
    peer_static: Option<[u8; KEY_LEN]>,
    check_peer: PeerCheck,
    /// Handshake-level secrets (from the handshake hash after msg1).
    handshake_secrets: Option<Secrets>,
    /// Current 1-RTT secrets, for key updates.
    one_rtt: Option<Secrets>,
    /// Secret for `export_keying_material`.
    exporter: Option<Zeroizing<[u8; 32]>>,
    /// CRYPTO bytes received but not yet forming a whole framed Noise message.
    inbound: Vec<u8>,
    got_handshake_data: bool,
}

fn crypto_error(alert: u8, reason: impl Into<String>) -> TransportError {
    TransportError {
        code: TransportErrorCode::crypto(alert),
        frame: None,
        reason: reason.into(),
    }
}

/// TLS-style alert codes reused for the crypto error space (RFC 9001 §4.8).
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_DECODE_ERROR: u8 = 50;

impl NoiseSession {
    fn new(
        side: Side,
        version: u32,
        local_private: &[u8],
        params: &TransportParameters,
        check_peer: PeerCheck,
    ) -> Result<Self, snow::Error> {
        let mut prologue = b"noissh-quic".to_vec();
        prologue.extend_from_slice(&version.to_be_bytes());
        let builder = snow::Builder::new(PATTERN.parse()?)
            .local_private_key(local_private)?
            .prologue(&prologue)?;
        let noise = match side {
            Side::Client => builder.build_initiator()?,
            Side::Server => builder.build_responder()?,
        };
        let mut local_params = Vec::new();
        params.write(&mut local_params);
        Ok(NoiseSession {
            side,
            stage: match side {
                Side::Client => Stage::ClientStart,
                Side::Server => Stage::ServerAwaitMsg1,
            },
            noise: Some(noise),
            local_params,
            peer_params: None,
            peer_static: None,
            check_peer,
            handshake_secrets: None,
            one_rtt: None,
            exporter: None,
            inbound: Vec::new(),
            got_handshake_data: false,
        })
    }

    fn noise(&mut self) -> &mut snow::HandshakeState {
        self.noise
            .as_mut()
            .expect("handshake state present until Done")
    }

    /// Write the next Noise message, framed, into `out`.
    fn write_noise(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let mut msg = vec![0u8; payload.len() + 256];
        let n = self
            .noise()
            .write_message(payload, &mut msg)
            .expect("writing our own handshake message cannot fail");
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&msg[..n]);
    }

    /// Pop one complete framed Noise message from the inbound buffer.
    fn next_message(&mut self) -> Option<Vec<u8>> {
        if self.inbound.len() < 2 {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([self.inbound[0], self.inbound[1]]));
        if self.inbound.len() < 2 + len {
            return None;
        }
        let msg = self.inbound[2..2 + len].to_vec();
        self.inbound.drain(..2 + len);
        Some(msg)
    }

    fn read_noise(&mut self, msg: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut payload = vec![0u8; msg.len()];
        let n = self
            .noise()
            .read_message(msg, &mut payload)
            .map_err(|e| crypto_error(ALERT_HANDSHAKE_FAILURE, format!("noise: {e}")))?;
        payload.truncate(n);
        Ok(payload)
    }

    fn take_peer_params(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let params = TransportParameters::read(self.side, &mut &payload[..])
            .map_err(|e| crypto_error(ALERT_DECODE_ERROR, format!("transport parameters: {e}")))?;
        self.peer_params = Some(params);
        Ok(())
    }

    /// Check the peer's static key (now known) with the caller's policy.
    fn authenticate_peer(&mut self) -> Result<(), TransportError> {
        let key: [u8; KEY_LEN] = self
            .noise()
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| crypto_error(ALERT_HANDSHAKE_FAILURE, "peer static key missing"))?;
        if !(self.check_peer)(&key) {
            return Err(crypto_error(
                ALERT_BAD_CERTIFICATE,
                match self.side {
                    Side::Client => "server key not trusted",
                    Side::Server => "client key not authorized",
                },
            ));
        }
        self.peer_static = Some(key);
        Ok(())
    }

    /// After msg1: both sides derive the (public) Handshake-level secrets from
    /// the handshake hash, which covers msg1 and the prologue.
    fn derive_handshake_secrets(&mut self) {
        let h = self.noise().get_handshake_hash().to_vec();
        self.handshake_secrets = Some(Secrets::from_base(&kdf(HANDSHAKE_SALT, &[&h])));
    }

    /// After msg3: Noise Split() gives the 1-RTT secrets.
    fn derive_one_rtt(&mut self) {
        let mut noise = self.noise.take().expect("handshake state present");
        let h = noise.get_handshake_hash().to_vec();
        // Initiator→responder (client→server) first, as in Noise's Split().
        let (c2s, s2c) = noise.dangerously_get_raw_split();
        self.one_rtt = Some(Secrets {
            client: kdf(&c2s, &[b"noissh 1rtt", &h]),
            server: kdf(&s2c, &[b"noissh 1rtt", &h]),
        });
        self.exporter = Some(Zeroizing::new(kdf(&c2s, &[b"noissh exporter", &s2c, &h])));
    }
}

impl crypto::Session for NoiseSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_secrets(dst_cid).keys(side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data
            .then(|| Box::new(()) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.peer_static
            .map(|k| Box::new(PeerIdentity(k)) as Box<dyn Any>)
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None // no 0-RTT (yet)
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.stage != Stage::Done
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inbound.extend_from_slice(buf);
        if self.inbound.len() > 2 + MAX_NOISE_MSG {
            return Err(crypto_error(
                ALERT_DECODE_ERROR,
                "oversized handshake message",
            ));
        }
        let mut handshake_data_ready = false;
        while let Some(msg) = self.next_message() {
            match self.stage {
                Stage::ServerAwaitMsg1 => {
                    let payload = self.read_noise(&msg)?;
                    self.take_peer_params(&payload)?;
                    self.derive_handshake_secrets();
                    self.stage = Stage::ServerSendHandshakeKeys;
                    self.got_handshake_data = true;
                    handshake_data_ready = true;
                }
                Stage::ClientAwaitMsg2 => {
                    let payload = self.read_noise(&msg)?;
                    // The server's identity is known now: check it before
                    // sending anything that depends on it.
                    self.authenticate_peer()?;
                    self.take_peer_params(&payload)?;
                    self.stage = Stage::ClientSendMsg3;
                    self.got_handshake_data = true;
                    handshake_data_ready = true;
                }
                Stage::ServerAwaitMsg3 => {
                    let payload = self.read_noise(&msg)?;
                    if !payload.is_empty() {
                        return Err(crypto_error(ALERT_DECODE_ERROR, "unexpected msg3 payload"));
                    }
                    self.authenticate_peer()?;
                    self.derive_one_rtt();
                    self.stage = Stage::ServerSend1Rtt;
                }
                _ => {
                    return Err(crypto_error(
                        ALERT_DECODE_ERROR,
                        "unexpected handshake message",
                    ));
                }
            }
            // Each side receives exactly one message per encryption level,
            // and the level changes after it (RFC 9001 §4.1.3: a message must
            // not span a key change). Bytes after it are outside the Noise
            // transcript: refuse them rather than carry them into the next
            // message.
            if !self.inbound.is_empty() {
                return Err(crypto_error(
                    ALERT_DECODE_ERROR,
                    "data after a handshake message",
                ));
            }
        }
        Ok(handshake_data_ready)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.stage {
            Stage::ClientStart => {
                let params = self.local_params.clone();
                self.write_noise(&params, buf);
                // msg1 goes out at the Initial level; from here on the client
                // can also read the Handshake level.
                self.derive_handshake_secrets();
                self.stage = Stage::ClientAwaitMsg2;
                Some(self.handshake_secrets.as_ref()?.keys(self.side))
            }
            Stage::ServerSendHandshakeKeys => {
                // The Initial level gets no data from us: msg2 is written on the
                // next call, at the Handshake level these keys open.
                self.stage = Stage::ServerSendMsg2;
                Some(self.handshake_secrets.as_ref()?.keys(self.side))
            }
            Stage::ServerSendMsg2 => {
                let params = self.local_params.clone();
                self.write_noise(&params, buf);
                self.stage = Stage::ServerAwaitMsg3;
                None
            }
            Stage::ClientSendMsg3 => {
                self.write_noise(&[], buf);
                self.derive_one_rtt();
                self.stage = Stage::Done;
                Some(self.one_rtt.as_ref()?.keys(self.side))
            }
            Stage::ServerSend1Rtt => {
                self.stage = Stage::Done;
                Some(self.one_rtt.as_ref()?.keys(self.side))
            }
            _ => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let next = self.one_rtt.as_ref()?.update();
        let (local, remote) = match self.side {
            Side::Client => (&next.client, &next.server),
            Side::Server => (&next.server, &next.client),
        };
        let pair = KeyPair {
            local: Box::new(PacketProtection::from_secret(local)) as Box<dyn PacketKey>,
            remote: Box::new(PacketProtection::from_secret(remote)) as Box<dyn PacketKey>,
        };
        self.one_rtt = Some(next);
        Some(pair)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_at) = payload.len().checked_sub(TAG_LEN) else {
            return false;
        };
        let mut pseudo = Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + payload.len());
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid);
        pseudo.extend_from_slice(header);
        pseudo.extend_from_slice(&payload[..tag_at]);
        let expected = retry_integrity_tag(&pseudo);
        constant_time_eq(&expected, &payload[tag_at..])
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let secret = self.exporter.as_ref().ok_or(ExportKeyingMaterialError)?;
        // Length-prefixed fields, and the output length bound in, so no two
        // (label, context, length) requests share any output.
        let (label_len, context_len, out_len) = (
            (label.len() as u64).to_be_bytes(),
            (context.len() as u64).to_be_bytes(),
            (output.len() as u64).to_be_bytes(),
        );
        for (i, chunk) in output.chunks_mut(32).enumerate() {
            let block = kdf(
                &secret[..],
                &[
                    &label_len,
                    label,
                    &context_len,
                    context,
                    &out_len,
                    &(i as u64).to_be_bytes(),
                ],
            );
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Retry integrity tag (RFC 9001 §5.8, with noissh's own fixed key): an AEAD
/// tag over the retry pseudo-packet with an empty plaintext.
fn retry_integrity_tag(pseudo: &[u8]) -> [u8; TAG_LEN] {
    let key = kdf(b"noissh-quic retry v1", &[b"key"]);
    let aead = ChaCha20Poly1305::new((&key).into());
    let tag = aead
        .encrypt_in_place_detached(&Nonce::default(), pseudo, &mut [])
        .expect("empty plaintext");
    tag.into()
}

// --- configs -------------------------------------------------------------------

/// Client side: our static key and how to check the server's.
pub struct ClientConfig {
    private_key: Zeroizing<[u8; KEY_LEN]>,
    verify_server: PeerCheck,
}

impl ClientConfig {
    pub fn new(private_key: [u8; KEY_LEN], verify_server: PeerCheck) -> Self {
        ClientConfig {
            private_key: Zeroizing::new(private_key),
            verify_server,
        }
    }
}

impl crypto::ClientConfig for ClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != VERSION {
            return Err(ConnectError::UnsupportedVersion);
        }
        let session = NoiseSession::new(
            Side::Client,
            version,
            &self.private_key[..],
            params,
            self.verify_server.clone(),
        )
        .map_err(|_| ConnectError::UnsupportedVersion)?;
        Ok(Box::new(session))
    }
}

/// Server side: our static key and how to authorize clients.
pub struct ServerConfig {
    private_key: Zeroizing<[u8; KEY_LEN]>,
    authorize_client: PeerCheck,
}

impl ServerConfig {
    pub fn new(private_key: [u8; KEY_LEN], authorize_client: PeerCheck) -> Self {
        ServerConfig {
            private_key: Zeroizing::new(private_key),
            authorize_client,
        }
    }
}

impl crypto::ServerConfig for ServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        if version != VERSION {
            return Err(UnsupportedVersion);
        }
        Ok(initial_secrets(dst_cid).keys(Side::Server))
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo = Vec::with_capacity(1 + orig_dst_cid.len() + packet.len());
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid);
        pseudo.extend_from_slice(packet);
        retry_integrity_tag(&pseudo)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        Box::new(
            NoiseSession::new(
                Side::Server,
                version,
                &self.private_key[..],
                params,
                self.authorize_client.clone(),
            )
            .expect("the Noise pattern and a 32-byte key are always valid"),
        )
    }
}

// --- endpoint-level keys -------------------------------------------------------

fn random_32() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).expect("OS random number generator");
    k
}

/// Keyed BLAKE2s, used by quinn-proto for stateless reset tokens and connection
/// id authentication.
pub struct Blake2sHmac {
    key: [u8; 32],
}

impl Blake2sHmac {
    /// A key from the OS RNG: fine for a server that doesn't need reset tokens
    /// to survive a restart.
    pub fn random() -> Self {
        Blake2sHmac { key: random_32() }
    }
}

impl HmacKey for Blake2sHmac {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        signature_out.copy_from_slice(&kdf(&self.key, &[data]));
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if constant_time_eq(&kdf(&self.key, &[data]), signature) {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}

/// Key for quinn-proto's address-validation (retry / NEW_TOKEN) tokens: each
/// token gets its own ChaCha20-Poly1305 key derived from the master key and the
/// token's random bytes, so a fixed nonce is safe.
pub struct TokenKey {
    master: [u8; 32],
}

impl TokenKey {
    pub fn random() -> Self {
        TokenKey {
            master: random_32(),
        }
    }
}

impl HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        Box::new(TokenAead(ChaCha20Poly1305::new(
            (&kdf(&self.master, &[b"token", random_bytes])).into(),
        )))
    }
}

struct TokenAead(ChaCha20Poly1305);

impl crypto::AeadKey for TokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let tag = self
            .0
            .encrypt_in_place_detached(&Nonce::default(), additional_data, data)
            .map_err(|_| CryptoError)?;
        data.extend_from_slice(&tag);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let len = data.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
        let (body, tag) = data.split_at_mut(len);
        let tag = Tag::clone_from_slice(tag);
        self.0
            .decrypt_in_place_detached(&Nonce::default(), additional_data, body, &tag)
            .map_err(|_| CryptoError)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::Session as _;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut b = snow::Builder::new(PATTERN.parse().unwrap());
        b = b.prologue(b"").unwrap();
        let kp = b.generate_keypair().unwrap();
        (
            kp.private.try_into().unwrap(),
            kp.public.try_into().unwrap(),
        )
    }

    fn sessions(server_pub_expected: Option<[u8; 32]>) -> (NoiseSession, NoiseSession) {
        let (cpriv, cpub) = keypair();
        let (spriv, spub) = keypair();
        let expect = server_pub_expected.unwrap_or(spub);
        let params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();
        let client = NoiseSession::new(
            Side::Client,
            VERSION,
            &cpriv,
            &params,
            Arc::new(move |k| *k == expect),
        )
        .unwrap();
        let server = NoiseSession::new(
            Side::Server,
            VERSION,
            &spriv,
            &params,
            Arc::new(move |k| *k == cpub),
        )
        .unwrap();
        (client, server)
    }

    /// Run the three-message exchange by hand, letting `tamper_msg1` edit the
    /// client's first flight. Returns the first error, if any.
    fn exchange(
        client: &mut NoiseSession,
        server: &mut NoiseSession,
        tamper_msg1: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), TransportError> {
        let mut msg1 = Vec::new();
        assert!(
            client.write_handshake(&mut msg1).is_some(),
            "client: Handshake keys"
        );
        tamper_msg1(&mut msg1);
        server.read_handshake(&msg1)?;
        let mut none = Vec::new();
        assert!(
            server.write_handshake(&mut none).is_some(),
            "server: Handshake keys"
        );
        assert!(none.is_empty(), "no server data at the Initial level");
        let mut msg2 = Vec::new();
        assert!(server.write_handshake(&mut msg2).is_none());
        client.read_handshake(&msg2)?;
        let mut msg3 = Vec::new();
        assert!(
            client.write_handshake(&mut msg3).is_some(),
            "client: 1-RTT keys"
        );
        server.read_handshake(&msg3)?;
        assert!(
            server.write_handshake(&mut Vec::new()).is_some(),
            "server: 1-RTT keys"
        );
        Ok(())
    }

    #[test]
    fn clean_exchange_completes_with_matching_secrets() {
        let (mut c, mut s) = sessions(None);
        exchange(&mut c, &mut s, |_| {}).unwrap();
        assert!(!c.is_handshaking() && !s.is_handshaking());
        let (cs, ss) = (c.one_rtt.clone().unwrap(), s.one_rtt.clone().unwrap());
        assert_eq!((cs.client, cs.server), (ss.client, ss.server));
        assert_ne!(cs.client, cs.server, "directions use different keys");
        // Key update derives the same next generation on both sides.
        let (cn, sn) = (c.next_1rtt_keys().unwrap(), s.next_1rtt_keys().unwrap());
        let mut pkt = vec![0u8; 20 + 50 + TAG_LEN];
        pkt[20..70].copy_from_slice(&[7u8; 50]);
        cn.local.encrypt(9, &mut pkt, 20);
        let mut payload = BytesMut::from(&pkt[20..]);
        sn.remote.decrypt(9, &pkt[..20], &mut payload).unwrap();
        assert_eq!(&payload[..], &[7u8; 50]);
        // Exported keying material agrees and depends on the label.
        let (mut a, mut b, mut d) = ([0u8; 40], [0u8; 40], [0u8; 40]);
        c.export_keying_material(&mut a, b"label", b"ctx").unwrap();
        s.export_keying_material(&mut b, b"label", b"ctx").unwrap();
        c.export_keying_material(&mut d, b"other", b"ctx").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, d);
    }

    #[test]
    fn tampered_client_parameters_break_the_transcript() {
        // msg1's payload (the client's transport parameters) is not encrypted,
        // and Initial packets are only obfuscated, so an on-path attacker can
        // rewrite it. Noise binds it into the transcript: the change must make
        // the handshake fail, not silently apply.
        let (mut c, mut s) = sessions(None);
        let err = exchange(&mut c, &mut s, |m| {
            let last = m.len() - 1;
            m[last] ^= 0x01;
        });
        // The server can't tell (the edited parameters still decode); the
        // client's transcript no longer matches, so msg2 fails to decrypt.
        let err = err.expect_err("tampered msg1 must fail the handshake");
        assert_eq!(err.reason, "noise: decrypt error");
        assert!(c.is_handshaking(), "client must not complete");
    }

    #[test]
    fn client_checks_the_server_before_sending_msg3() {
        let (_, unexpected) = keypair();
        let (mut c, mut s) = sessions(Some(unexpected));
        let err = exchange(&mut c, &mut s, |_| {}).unwrap_err();
        assert!(
            err.reason.contains("server key not trusted"),
            "{}",
            err.reason
        );
        assert!(c.one_rtt.is_none(), "no 1-RTT keys for an untrusted server");
    }

    #[test]
    fn handshake_messages_reassemble_across_crypto_chunks() {
        // CRYPTO data can arrive split at arbitrary points.
        let (mut c, mut s) = sessions(None);
        let mut msg1 = Vec::new();
        c.write_handshake(&mut msg1).unwrap();
        for b in &msg1[..msg1.len() - 1] {
            assert!(!s.read_handshake(std::slice::from_ref(b)).unwrap());
        }
        assert!(
            s.read_handshake(&msg1[msg1.len() - 1..]).unwrap(),
            "complete msg1"
        );
    }

    #[test]
    fn packet_protection_round_trips_and_detects_tampering() {
        let p = PacketProtection::from_secret(&[3u8; 32]);
        let mut pkt = vec![0u8; 12 + 30 + TAG_LEN];
        pkt[..12].copy_from_slice(b"header-bytes");
        pkt[12..42].copy_from_slice(&[0xab; 30]);
        p.encrypt(77, &mut pkt, 12);
        assert_ne!(&pkt[12..42], &[0xab; 30]);
        let mut ok = BytesMut::from(&pkt[12..]);
        p.decrypt(77, &pkt[..12], &mut ok).unwrap();
        assert_eq!(&ok[..], &[0xab; 30]);
        // Wrong packet number, header or ciphertext all fail.
        let mut wrong_pn = BytesMut::from(&pkt[12..]);
        assert!(p.decrypt(78, &pkt[..12], &mut wrong_pn).is_err());
        let mut wrong_hdr = BytesMut::from(&pkt[12..]);
        assert!(p.decrypt(77, b"header-byteZ", &mut wrong_hdr).is_err());
        let mut flipped = BytesMut::from(&pkt[12..]);
        flipped[0] ^= 1;
        assert!(p.decrypt(77, &pkt[..12], &mut flipped).is_err());
    }

    #[test]
    fn header_protection_is_its_own_inverse() {
        let h = HeaderProtection::from_secret(&[5u8; 32]);
        for first in [0x40u8 | 0x03, 0xc0 | 0x01] {
            // short (5 masked bits) and long (4) headers, 4- and 2-byte pns
            let mut pkt: Vec<u8> = (0..64u8).collect();
            pkt[0] = first;
            let orig = pkt.clone();
            h.encrypt(10, &mut pkt);
            assert_ne!(pkt, orig);
            assert_eq!(pkt[0] & 0x80, orig[0] & 0x80, "header form bit stays clear");
            h.decrypt(10, &mut pkt);
            assert_eq!(pkt, orig);
        }
    }

    #[test]
    fn header_protection_mask_matches_chacha20_over_the_whole_counter_range() {
        use chacha20::cipher::{StreamCipher, StreamCipherSeek};
        let h = HeaderProtection::from_secret(&[7u8; 32]);
        let mut sample = [0u8; SAMPLE_LEN];
        sample[4..].copy_from_slice(&[3u8; 12]);
        // Where the stream-cipher API works, the core gives the same mask.
        for counter in [0u32, 1, 0x1234_5678, 0xffff_fffe] {
            sample[..4].copy_from_slice(&counter.to_le_bytes());
            let mut c = chacha20::ChaCha20::new((&h.key).into(), (&[3u8; 12]).into());
            c.seek(u64::from(counter) * 64);
            let mut want = [0u8; 5];
            c.apply_keystream(&mut want);
            assert_eq!(h.mask(&sample), want, "counter {counter:#x}");
        }
        // The last counter value: the stream-cipher API panics here, and the
        // sample is attacker-controlled. This must simply work.
        sample[..4].copy_from_slice(&[0xff; 4]);
        let mut pkt = vec![0u8; 64];
        pkt[0] = 0xc1;
        pkt[14..30].copy_from_slice(&sample);
        h.decrypt(10, &mut pkt);
        h.encrypt(10, &mut pkt);
    }

    #[test]
    fn data_after_a_handshake_message_is_refused() {
        // Bytes appended to msg1 are outside the Noise transcript (the
        // Initial keys are public, so anyone can add them).
        let (mut c, mut s) = sessions(None);
        let err = exchange(&mut c, &mut s, |m| m.extend_from_slice(&[0, 9, 1, 2]))
            .expect_err("trailing bytes must be refused");
        assert!(format!("{err:?}").contains("data after a handshake message"));
    }

    #[test]
    fn exporter_separates_label_context_and_length() {
        let (mut c, mut s) = sessions(None);
        exchange(&mut c, &mut s, |_| {}).unwrap();
        let export = |sess: &NoiseSession, label: &[u8], ctx: &[u8], n: usize| {
            let mut out = vec![0u8; n];
            sess.export_keying_material(&mut out, label, ctx).unwrap();
            out
        };
        assert_eq!(export(&c, b"a", b"b", 32), export(&s, b"a", b"b", 32));
        assert_ne!(export(&c, b"a", b"\0b", 32), export(&c, b"a\0", b"b", 32));
        assert_ne!(
            export(&c, b"a", b"b", 64)[..32],
            export(&c, b"a", b"b", 32)[..]
        );
    }

    #[test]
    fn retry_tag_verifies_only_for_the_right_packet() {
        let cid = ConnectionId::new(&[1, 2, 3, 4]);
        let (c, _) = sessions(None);
        let server = ServerConfig::new([9u8; 32], Arc::new(|_| true));
        let header = b"retry-header";
        let tag = crypto::ServerConfig::retry_tag(&server, VERSION, &cid, header);
        let mut payload = Vec::new();
        payload.extend_from_slice(&tag);
        assert!(c.is_valid_retry(&cid, header, &payload));
        assert!(!c.is_valid_retry(&ConnectionId::new(&[9]), header, &payload));
        assert!(!c.is_valid_retry(&cid, b"retry-headeX", &payload));
    }
}
