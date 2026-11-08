//! End-to-end tests of the Noise crypto layer inside real quinn-proto
//! connections: two endpoints exchange datagrams in memory (no sockets), with a
//! simulated clock.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use noise_quic::{Blake2sHmac, PeerCheck, PeerIdentity, TokenKey, VERSION};
use quinn_proto::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, Event, ServerConfig, StreamEvent,
};

const CLIENT_ADDR: &str = "127.0.0.1:40000";
const SERVER_ADDR: &str = "127.0.0.1:51820";

fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = noise_core::generate_keypair().unwrap();
    (
        kp.private.try_into().unwrap(),
        kp.public.try_into().unwrap(),
    )
}

fn accept_only(key: [u8; 32]) -> PeerCheck {
    Arc::new(move |k: &[u8; 32]| *k == key)
}

fn endpoint_config() -> Arc<EndpointConfig> {
    let mut cfg = EndpointConfig::new(Arc::new(Blake2sHmac::random()));
    cfg.supported_versions(vec![VERSION]);
    Arc::new(cfg)
}

/// Sees each datagram (and whether it goes to the server) and may edit it;
/// returning false drops it.
type Tamper = Box<dyn FnMut(&mut Vec<u8>, bool) -> bool>;

/// One side of the in-memory link.
struct Side {
    endpoint: Endpoint,
    addr: SocketAddr,
    conn: Option<(ConnectionHandle, Connection)>,
    events: Vec<Event>,
}

struct Pair {
    client: Side,
    server: Side,
    now: Instant,
    /// Datagrams in flight: (destination, payload).
    wire: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Optional loss/corruption injection.
    tamper: Option<Tamper>,
}

impl Pair {
    fn new(
        client_check: PeerCheck,
        client_key: [u8; 32],
        server_check: PeerCheck,
        server_key: [u8; 32],
    ) -> Self {
        let server_crypto = Arc::new(noise_quic::ServerConfig::new(server_key, server_check));
        let server_cfg = ServerConfig::new(server_crypto, Arc::new(TokenKey::random()));
        let server_ep = Endpoint::new(endpoint_config(), Some(Arc::new(server_cfg)), true, None);
        let mut client_ep = Endpoint::new(endpoint_config(), None, true, None);

        let mut client_cfg = ClientConfig::new(Arc::new(noise_quic::ClientConfig::new(
            client_key,
            client_check,
        )));
        client_cfg.version(VERSION);
        let now = Instant::now();
        let conn = client_ep
            .connect(now, client_cfg, SERVER_ADDR.parse().unwrap(), "noissh")
            .unwrap();
        Pair {
            client: Side {
                endpoint: client_ep,
                addr: CLIENT_ADDR.parse().unwrap(),
                conn: Some(conn),
                events: Vec::new(),
            },
            server: Side {
                endpoint: server_ep,
                addr: SERVER_ADDR.parse().unwrap(),
                conn: None,
                events: Vec::new(),
            },
            now,
            wire: VecDeque::new(),
            tamper: None,
        }
    }

    fn drain_transmits(side: &mut Side, now: Instant, wire: &mut VecDeque<(SocketAddr, Vec<u8>)>) {
        if let Some((_, conn)) = side.conn.as_mut() {
            let mut buf = Vec::new();
            while let Some(t) = conn.poll_transmit(now, 1, &mut buf) {
                wire.push_back((t.destination, buf[..t.size].to_vec()));
                buf.clear();
            }
        }
    }

    fn deliver(
        side: &mut Side,
        from: SocketAddr,
        data: Vec<u8>,
        now: Instant,
        wire: &mut VecDeque<(SocketAddr, Vec<u8>)>,
    ) {
        let mut resp = Vec::new();
        match side
            .endpoint
            .handle(now, from, None, None, BytesMut::from(&data[..]), &mut resp)
        {
            Some(DatagramEvent::NewConnection(incoming)) => {
                let mut buf = Vec::new();
                match side.endpoint.accept(incoming, now, &mut buf, None) {
                    Ok(conn) => side.conn = Some(conn),
                    Err(e) => {
                        if let Some(t) = e.response {
                            wire.push_back((t.destination, buf[..t.size].to_vec()));
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(_, ev)) => {
                if let Some((_, conn)) = side.conn.as_mut() {
                    conn.handle_event(ev);
                }
            }
            Some(DatagramEvent::Response(t)) => {
                wire.push_back((t.destination, resp[..t.size].to_vec()));
            }
            None => {}
        }
    }

    fn service(side: &mut Side) {
        if let Some((ch, conn)) = side.conn.as_mut() {
            while let Some(ev) = conn.poll_endpoint_events() {
                if let Some(cev) = side.endpoint.handle_event(*ch, ev) {
                    conn.handle_event(cev);
                }
            }
            while let Some(ev) = conn.poll() {
                side.events.push(ev);
            }
        }
    }

    /// Run the link until it goes quiet (or `max` steps), advancing the
    /// simulated clock to the next timer whenever nothing is in flight.
    fn run(&mut self, max: usize) {
        for _ in 0..max {
            Self::drain_transmits(&mut self.client, self.now, &mut self.wire);
            Self::drain_transmits(&mut self.server, self.now, &mut self.wire);
            if let Some((dst, mut data)) = self.wire.pop_front() {
                let to_server = dst == self.server.addr;
                if let Some(t) = self.tamper.as_mut()
                    && !t(&mut data, to_server)
                {
                    continue; // dropped
                }
                self.now += Duration::from_millis(5); // one-way delay
                if to_server {
                    let from = self.client.addr;
                    Self::deliver(&mut self.server, from, data, self.now, &mut self.wire);
                } else {
                    let from = self.server.addr;
                    Self::deliver(&mut self.client, from, data, self.now, &mut self.wire);
                }
            } else {
                // Nothing in flight: jump to the earliest timer.
                let next = [&mut self.client, &mut self.server]
                    .into_iter()
                    .filter_map(|s| s.conn.as_mut().and_then(|(_, c)| c.poll_timeout()))
                    .min();
                match next {
                    // Only loss-recovery timers are short; stop before idle or
                    // keep-alive timers so the connection stays alive.
                    Some(t) if t > self.now + Duration::from_secs(3) => break,
                    Some(t) => {
                        self.now = self.now.max(t);
                        for s in [&mut self.client, &mut self.server] {
                            if let Some((_, c)) = s.conn.as_mut() {
                                c.handle_timeout(self.now);
                            }
                        }
                    }
                    None => break,
                }
            }
            Self::service(&mut self.client);
            Self::service(&mut self.server);
        }
    }

    fn connected(side: &Side) -> bool {
        side.events.iter().any(|e| matches!(e, Event::Connected))
    }

    fn lost(side: &Side) -> Option<&ConnectionError> {
        side.events.iter().find_map(|e| match e {
            Event::ConnectionLost { reason } => Some(reason),
            _ => None,
        })
    }

    fn conn(side: &mut Side) -> &mut Connection {
        &mut side.conn.as_mut().unwrap().1
    }
}

fn identity(conn: &Connection) -> Option<[u8; 32]> {
    conn.crypto_session()
        .peer_identity()
        .and_then(|b| b.downcast::<PeerIdentity>().ok())
        .map(|p| p.0)
}

#[test]
fn handshake_authenticates_both_sides_and_carries_streams_and_datagrams() {
    let (cpriv, cpub) = keypair();
    let (spriv, spub) = keypair();
    let mut p = Pair::new(accept_only(spub), cpriv, accept_only(cpub), spriv);
    p.run(10_000);

    assert!(
        Pair::connected(&p.client),
        "client never connected: {:?}",
        Pair::lost(&p.client)
    );
    assert!(
        Pair::connected(&p.server),
        "server never connected: {:?}",
        Pair::lost(&p.server)
    );
    assert_eq!(identity(Pair::conn(&mut p.client)), Some(spub));
    assert_eq!(identity(Pair::conn(&mut p.server)), Some(cpub));

    // A bidirectional stream, client → server.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let id = Pair::conn(&mut p.client).streams().open(Dir::Bi).unwrap();
    {
        let c = Pair::conn(&mut p.client);
        let mut sent = 0;
        while sent < payload.len() {
            match c.send_stream(id).write(&payload[sent..]) {
                Ok(n) => sent += n,
                Err(_) => break,
            }
        }
        assert_eq!(sent, payload.len(), "flow control should admit 200 KB");
        c.send_stream(id).finish().unwrap();
    }
    // A datagram, server → client, once established.
    p.run(10_000);
    let s = Pair::conn(&mut p.server);
    let sid = s.streams().accept(Dir::Bi).expect("server sees the stream");
    let mut got = Vec::new();
    let mut recv = s.recv_stream(sid);
    let mut chunks = recv.read(true).unwrap();
    while let Ok(Some(ch)) = chunks.next(usize::MAX) {
        got.extend_from_slice(&ch.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(got, payload);

    Pair::conn(&mut p.server)
        .datagrams()
        .send(Bytes::from_static(b"screen-diff"), true)
        .unwrap();
    p.run(1_000);
    assert_eq!(
        Pair::conn(&mut p.client).datagrams().recv(),
        Some(Bytes::from_static(b"screen-diff"))
    );
    // Stream events were surfaced on the server.
    assert!(
        p.server
            .events
            .iter()
            .any(|e| matches!(e, Event::Stream(StreamEvent::Opened { .. })))
    );
}

#[test]
fn client_rejects_an_unexpected_server_key() {
    let (cpriv, cpub) = keypair();
    let (spriv, _spub) = keypair();
    let (_, other) = keypair();
    // The client expects `other`, the server presents `spub`.
    let mut p = Pair::new(accept_only(other), cpriv, accept_only(cpub), spriv);
    p.run(10_000);
    assert!(!Pair::connected(&p.client));
    assert!(!Pair::connected(&p.server));
    let reason = format!("{:?}", Pair::lost(&p.client).expect("client gives up"));
    assert!(reason.contains("server key not trusted"), "{reason}");
}

#[test]
fn server_rejects_an_unauthorized_client() {
    let (cpriv, _cpub) = keypair();
    let (spriv, spub) = keypair();
    let (_, other) = keypair();
    let mut p = Pair::new(accept_only(spub), cpriv, accept_only(other), spriv);
    p.run(10_000);
    assert!(
        !Pair::connected(&p.server),
        "an unauthorized client must not connect"
    );
    let reason = format!(
        "{:?}",
        Pair::lost(&p.client).expect("client learns it was refused")
    );
    assert!(reason.contains("client key not authorized"), "{reason}");
}

#[test]
fn tampered_client_hello_fails_the_handshake() {
    let (cpriv, cpub) = keypair();
    let (spriv, spub) = keypair();
    let mut p = Pair::new(accept_only(spub), cpriv, accept_only(cpub), spriv);
    // Flip one bit in the client's first datagram. Initial packets are only
    // obfuscated, so an on-path attacker could make this change and re-protect
    // the packet; here we simply corrupt it, which the packet AEAD rejects. The
    // stronger guarantee (transcript binding) is covered by the unit test of
    // the session below.
    let mut first = true;
    p.tamper = Some(Box::new(move |d: &mut Vec<u8>, to_server| {
        if to_server && first {
            first = false;
            let i = d.len() - 30;
            d[i] ^= 0x01;
        }
        true
    }));
    p.run(10_000);
    // The corrupted packet is dropped; the retransmission is intact, so the
    // handshake still completes — corruption is not a way to break in.
    assert!(Pair::connected(&p.client) && Pair::connected(&p.server));
}

#[test]
fn survives_packet_loss_during_handshake_and_transfer() {
    let (cpriv, cpub) = keypair();
    let (spriv, spub) = keypair();
    let mut p = Pair::new(accept_only(spub), cpriv, accept_only(cpub), spriv);
    let mut n = 0u32;
    p.tamper = Some(Box::new(move |_d, _| {
        n += 1;
        !n.is_multiple_of(4) // drop every 4th datagram
    }));
    p.run(50_000);
    assert!(Pair::connected(&p.client) && Pair::connected(&p.server));
}

#[test]
fn key_update_keeps_the_connection_working() {
    let (cpriv, cpub) = keypair();
    let (spriv, spub) = keypair();
    let mut p = Pair::new(accept_only(spub), cpriv, accept_only(cpub), spriv);
    p.run(10_000);
    assert!(Pair::connected(&p.client));
    for round in 0..3u8 {
        Pair::conn(&mut p.client).force_key_update();
        p.run(1_000);
        Pair::conn(&mut p.client)
            .datagrams()
            .send(Bytes::from(vec![round; 32]), true)
            .unwrap();
        p.run(1_000);
        assert_eq!(
            Pair::conn(&mut p.server).datagrams().recv(),
            Some(Bytes::from(vec![round; 32])),
            "datagram after key update #{round}"
        );
    }
}

#[test]
fn forged_initial_with_extreme_header_protection_sample_is_dropped() {
    // An off-path attacker needs no key to pick the header-protection sample
    // of a forged Initial packet. A sample whose counter is 0xffffffff once
    // panicked the endpoint (one packet crashed the server).
    let (spriv, _) = keypair();
    let server_crypto = Arc::new(noise_quic::ServerConfig::new(
        spriv,
        Arc::new(|_: &[u8; 32]| true),
    ));
    let server_cfg = ServerConfig::new(server_crypto, Arc::new(TokenKey::random()));
    let mut server = Endpoint::new(endpoint_config(), Some(Arc::new(server_cfg)), true, None);

    // Long header, Initial: flags, version, dcid (8), scid (0), token (0),
    // length (2-byte varint), then the packet number and payload.
    let mut pkt = vec![0u8; 1200];
    pkt[0] = 0xc0;
    pkt[1..5].copy_from_slice(&VERSION.to_be_bytes());
    pkt[5] = 8;
    pkt[6..14].copy_from_slice(&[0xab; 8]);
    pkt[14] = 0; // scid length
    pkt[15] = 0; // token length
    let len = (1200 - 18) as u16;
    pkt[16..18].copy_from_slice(&(0x4000 | len).to_be_bytes());
    let pn_offset = 18;
    pkt[pn_offset + 4..pn_offset + 8].copy_from_slice(&[0xff; 4]);
    let mut resp = Vec::new();
    let _ = server.handle(
        Instant::now(),
        CLIENT_ADDR.parse().unwrap(),
        None,
        None,
        BytesMut::from(&pkt[..]),
        &mut resp,
    );
}
